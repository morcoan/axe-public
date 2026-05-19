use crate::pe::{
    CfgRecord, EdgeRecord, FunctionRecord, InstructionRecord, JumpTableRecord, StructuredFlowRecord,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn build_structured_flow(
    functions: &[FunctionRecord],
    cfg: &[CfgRecord],
    instructions: &[InstructionRecord],
) -> Vec<StructuredFlowRecord> {
    let cfg_by_function: BTreeMap<u64, &CfgRecord> =
        cfg.iter().map(|row| (row.function, row)).collect();
    let instructions_by_function = return_blocks_by_function(functions, instructions);
    functions
        .iter()
        .map(|function| {
            let cfg_record = cfg_by_function.get(&function.start).copied();
            let block_order = cfg_record
                .map(|row| row.blocks.iter().map(|block| block.start).collect())
                .unwrap_or_default();
            let edges = cfg_record.map(|row| row.edges.clone()).unwrap_or_default();
            let branch_edges: Vec<EdgeRecord> = edges
                .iter()
                .filter(|edge| edge.edge_type == "branch")
                .cloned()
                .collect();
            let fallthrough_edges: Vec<EdgeRecord> = edges
                .iter()
                .filter(|edge| edge.edge_type == "fallthrough")
                .cloned()
                .collect();
            let backedges = cfg_record
                .map(natural_backedges)
                .unwrap_or_else(|| fallback_backedges(&edges));
            let shared_return_blocks = shared_return_blocks(&edges);
            let switch_candidates: Vec<u64> = edges
                .iter()
                .filter(|edge| {
                    edge.edge_type == "branch"
                        && edges
                            .iter()
                            .filter(|candidate| candidate.from == edge.from)
                            .count()
                            >= 3
                })
                .map(|edge| edge.from)
                .collect();
            StructuredFlowRecord {
                structured_flow_id: format!("structured:{:016X}", function.start),
                function: function.start,
                block_order,
                branch_edges,
                fallthrough_edges,
                return_blocks: instructions_by_function
                    .get(&function.start)
                    .cloned()
                    .unwrap_or_default(),
                has_loop_like_backedge: !backedges.is_empty(),
                backedges: backedges.clone(),
                switch_candidates,
                switch_cases: Vec::new(),
                goto_edges: Vec::new(),
                regions: Vec::new(),
                natural_loops: backedges.clone(),
                shared_return_blocks,
                structuring_notes: Vec::new(),
                refined: false,
                confidence: if cfg_record.is_some() {
                    "medium".to_string()
                } else {
                    "low".to_string()
                },
            }
        })
        .collect()
}

pub fn refine_selected_structured_flow(
    structured: &mut [StructuredFlowRecord],
    selected_functions: &[u64],
    jump_tables: &[JumpTableRecord],
) -> usize {
    let selected: BTreeSet<u64> = selected_functions.iter().copied().collect();
    let jump_by_function: BTreeMap<u64, Vec<&JumpTableRecord>> = {
        let mut map: BTreeMap<u64, Vec<&JumpTableRecord>> = BTreeMap::new();
        for table in jump_tables {
            map.entry(table.function).or_default().push(table);
        }
        map
    };
    let mut refined_count = 0usize;
    for row in structured {
        if !selected.is_empty() && !selected.contains(&row.function) {
            continue;
        }
        let mut regions = BTreeSet::new();
        if row.has_loop_like_backedge {
            regions.insert("loop".to_string());
            row.structuring_notes
                .push("natural_loop_backedge".to_string());
        }
        if !row.branch_edges.is_empty() {
            regions.insert("if".to_string());
        }
        if let Some(tables) = jump_by_function.get(&row.function) {
            for table in tables {
                for target in &table.targets {
                    if !row.switch_cases.contains(target) {
                        row.switch_cases.push(*target);
                    }
                }
            }
            if !tables.is_empty() {
                regions.insert("switch".to_string());
            }
        }
        row.switch_cases.sort_unstable();
        row.switch_cases.dedup();

        let block_order: BTreeSet<u64> = row.block_order.iter().copied().collect();
        row.goto_edges = row
            .branch_edges
            .iter()
            .filter(|edge| {
                edge.to < edge.from
                    || (!block_order.is_empty()
                        && (!block_order.contains(&edge.from) || !block_order.contains(&edge.to)))
            })
            .cloned()
            .collect();
        if !row.goto_edges.is_empty() {
            regions.insert("goto".to_string());
            row.structuring_notes
                .push("tail_merge_or_backward_branch".to_string());
        }
        if !row.return_blocks.is_empty() {
            regions.insert("return".to_string());
        }
        if !row.shared_return_blocks.is_empty() {
            row.structuring_notes
                .push("shared_return_or_common_epilogue".to_string());
        }
        row.structuring_notes.sort();
        row.structuring_notes.dedup();
        row.regions = regions.into_iter().collect();
        row.refined = true;
        row.confidence = if row.switch_cases.is_empty() && row.goto_edges.is_empty() {
            "medium".to_string()
        } else {
            "high".to_string()
        };
        refined_count += 1;
    }
    refined_count
}

fn shared_return_blocks(edges: &[EdgeRecord]) -> Vec<u64> {
    let mut incoming: BTreeMap<u64, usize> = BTreeMap::new();
    for edge in edges {
        *incoming.entry(edge.to).or_default() += 1;
    }
    incoming
        .into_iter()
        .filter_map(|(target, count)| (count >= 2).then_some(target))
        .collect()
}

fn natural_backedges(cfg: &CfgRecord) -> Vec<EdgeRecord> {
    if cfg.blocks.is_empty() || cfg.blocks.len() > 768 || cfg.edges.len() > 4096 {
        return fallback_backedges(&cfg.edges);
    }
    let dominators = dominator_sets(cfg);
    cfg.edges
        .iter()
        .filter_map(|edge| {
            // Address-order sanity gate (A3.1): a real backedge has the
            // destination at or before the source in linear order. The
            // dominator analysis can occasionally claim a forward edge is a
            // backedge when CFG block boundaries don't line up with
            // conditional-jump fallthrough targets — that yields a "natural
            // loop" header at a `ret` instruction, which is impossible. The
            // fallback path already uses this predicate; matching it here
            // unifies the two paths.
            if edge.to > edge.from {
                return None;
            }
            let from_block = block_for_address(cfg, edge.from)?;
            let to_block = block_for_address(cfg, edge.to).unwrap_or(edge.to);
            dominators
                .get(&from_block)
                .is_some_and(|doms| doms.contains(&to_block))
                .then_some(edge.clone())
        })
        .collect()
}

fn fallback_backedges(edges: &[EdgeRecord]) -> Vec<EdgeRecord> {
    edges
        .iter()
        .filter(|edge| edge.to <= edge.from)
        .cloned()
        .collect()
}

fn dominator_sets(cfg: &CfgRecord) -> BTreeMap<u64, BTreeSet<u64>> {
    let blocks = cfg
        .blocks
        .iter()
        .map(|block| block.start)
        .collect::<Vec<_>>();
    let Some(entry) = blocks.first().copied() else {
        return BTreeMap::new();
    };
    let all_blocks: BTreeSet<u64> = blocks.iter().copied().collect();
    let preds = predecessors_by_block(cfg);
    let mut doms = BTreeMap::new();
    for block in &blocks {
        if *block == entry {
            doms.insert(*block, BTreeSet::from([entry]));
        } else {
            doms.insert(*block, all_blocks.clone());
        }
    }

    let mut changed = true;
    while changed {
        changed = false;
        for block in blocks.iter().copied().filter(|block| *block != entry) {
            let incoming = preds.get(&block).cloned().unwrap_or_default();
            let mut next = if incoming.is_empty() {
                BTreeSet::new()
            } else {
                incoming
                    .iter()
                    .filter_map(|pred| doms.get(pred).cloned())
                    .reduce(|left, right| {
                        left.intersection(&right).copied().collect::<BTreeSet<_>>()
                    })
                    .unwrap_or_default()
            };
            next.insert(block);
            if doms.get(&block) != Some(&next) {
                doms.insert(block, next);
                changed = true;
            }
        }
    }
    doms
}

fn predecessors_by_block(cfg: &CfgRecord) -> BTreeMap<u64, Vec<u64>> {
    let mut map: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for edge in &cfg.edges {
        let Some(from_block) = block_for_address(cfg, edge.from) else {
            continue;
        };
        let to_block = block_for_address(cfg, edge.to).unwrap_or(edge.to);
        map.entry(to_block).or_default().push(from_block);
    }
    map
}

fn block_for_address(cfg: &CfgRecord, address: u64) -> Option<u64> {
    cfg.blocks
        .iter()
        .find(|block| block.start <= address && address < block.end)
        .map(|block| block.start)
        .or_else(|| {
            cfg.blocks
                .iter()
                .any(|block| block.start == address)
                .then_some(address)
        })
}

#[cfg(test)]
mod natural_backedges_tests {
    use super::{fallback_backedges, natural_backedges};
    use crate::pe::{BasicBlockRecord, CfgRecord, EdgeRecord};

    fn block(start: u64, end: u64) -> BasicBlockRecord {
        BasicBlockRecord {
            start,
            end,
            instruction_count: 1,
        }
    }

    fn edge(from: u64, to: u64, kind: &str) -> EdgeRecord {
        EdgeRecord {
            from,
            to,
            edge_type: kind.to_string(),
        }
    }

    /// A simple counted loop: block A → block B → backedge B → A.
    /// One real backedge expected.
    #[test]
    fn simple_loop_one_backedge() {
        let cfg = CfgRecord {
            function: 0,
            blocks: vec![block(0, 4), block(4, 12)],
            edges: vec![
                edge(2, 4, "fallthrough"),   // A → B
                edge(10, 4, "branch"),       // B → A (backedge)
                edge(10, 12, "fallthrough"), // B → exit
            ],
        };
        let backs = natural_backedges(&cfg);
        // Exactly the (10, 4) backedge.
        assert_eq!(backs.len(), 1);
        assert_eq!((backs[0].from, backs[0].to), (10, 4));
    }

    /// A3.1 regression test: a forward edge (to > from) must NOT be
    /// classified as a backedge even if dominator analysis somehow says so.
    /// Synthesise the pathological case directly: an edge where to > from,
    /// in a CFG small enough that the analyzer might otherwise
    /// mis-classify it.
    #[test]
    fn forward_edge_filtered_by_address_order_gate() {
        let cfg = CfgRecord {
            function: 0,
            blocks: vec![block(0, 4), block(4, 8), block(8, 12)],
            edges: vec![
                edge(2, 4, "fallthrough"),
                edge(6, 8, "fallthrough"),
                // A forward edge with to > from. If a future regression in
                // dominator analysis ever claimed this as a backedge, the
                // address-order gate would still filter it out.
                edge(6, 12, "branch"),
            ],
        };
        let backs = natural_backedges(&cfg);
        // No real backedges — none of these edges go backward.
        assert!(
            backs.is_empty(),
            "expected zero backedges, got {:?}",
            backs.iter().map(|e| (e.from, e.to)).collect::<Vec<_>>()
        );
    }

    /// Fallback path predicate (used when CFG is too large for dominator
    /// analysis): same `to <= from` rule. Confirms the two paths agree on
    /// the address-order invariant.
    #[test]
    fn fallback_uses_same_address_order_predicate() {
        let edges = vec![
            edge(10, 4, "branch"),     // backedge
            edge(2, 4, "fallthrough"), // forward
            edge(6, 12, "branch"),     // forward
        ];
        let backs = fallback_backedges(&edges);
        assert_eq!(backs.len(), 1);
        assert_eq!((backs[0].from, backs[0].to), (10, 4));
    }

    /// Self-edges (to == from) qualify as backedges in both paths — they
    /// represent infinite-loop one-block degenerate cases.
    #[test]
    fn self_edge_treated_as_backedge_in_fallback() {
        let edges = vec![edge(4, 4, "branch")];
        let backs = fallback_backedges(&edges);
        assert_eq!(backs.len(), 1);
    }
}

fn return_blocks_by_function(
    functions: &[FunctionRecord],
    instructions: &[InstructionRecord],
) -> BTreeMap<u64, Vec<u64>> {
    let addresses: Vec<u64> = instructions.iter().map(|row| row.address).collect();
    let mut rows = BTreeMap::new();
    for function in functions {
        let start = addresses.partition_point(|addr| *addr < function.start);
        let end = addresses.partition_point(|addr| *addr < function.end);
        let returns = instructions[start..end]
            .iter()
            .filter(|ins| ins.is_ret)
            .map(|ins| ins.address)
            .collect();
        rows.insert(function.start, returns);
    }
    rows
}
