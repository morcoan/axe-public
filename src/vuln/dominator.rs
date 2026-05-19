//! Dominator + post-dominator computation over a function's CFG.
//!
//! Uses `petgraph::algo::dominators::simple_fast`, which implements
//! the Cooper-Harvey-Kennedy iterative algorithm (O((V+E)α(V)) like
//! Lengauer-Tarjan, simpler implementation, equivalent results).
//!
//! Per-function on demand: chain queries ask "does block X dominate
//! sink Y?" and we build the dominator tree for the containing
//! function lazily. v1.0 doesn't cache results across queries; the
//! whole vuln-discovery session is one batch and re-computation
//! costs are bounded by per-function CFG size.
//!
//! Returns `None` when:
//! - The function isn't in the graph
//! - The function has no `BasicBlock` nodes (e.g. an import pseudo-
//!   function from `ingest_imports`)
//! - The entry block can't be unambiguously identified (no block
//!   starts at `function_va`)

#![allow(dead_code)]

use std::collections::HashMap;

use petgraph::algo::dominators::{self, Dominators as PetgraphDominators};
use petgraph::graph::{Graph, NodeIndex};

use crate::vuln::graph::{EdgeKind, EvidenceGraph, NodeId, NodeKind, NodePayload};

/// Dominator tree for one function. Wraps petgraph's `Dominators`
/// with a VA-keyed lookup so call sites don't have to track
/// `NodeIndex` instances.
pub struct DominatorTree {
    inner: PetgraphDominators<NodeIndex<u32>>,
    /// block_start_va → subgraph NodeIndex
    block_to_node: HashMap<u64, NodeIndex<u32>>,
    /// reverse map
    node_to_block: HashMap<NodeIndex<u32>, u64>,
}

impl DominatorTree {
    /// Return `true` iff block `a_va` dominates block `b_va` in this
    /// function. A block trivially dominates itself.
    pub fn dominates(&self, a_va: u64, b_va: u64) -> bool {
        if a_va == b_va {
            return self.block_to_node.contains_key(&a_va);
        }
        let a = match self.block_to_node.get(&a_va) {
            Some(n) => *n,
            None => return false,
        };
        let b = match self.block_to_node.get(&b_va) {
            Some(n) => *n,
            None => return false,
        };
        // Walk b's dominator chain looking for a.
        let mut cur = self.inner.immediate_dominator(b);
        while let Some(idom) = cur {
            if idom == a {
                return true;
            }
            cur = self.inner.immediate_dominator(idom);
        }
        false
    }

    /// Immediate dominator block VA, if any (entry block has none).
    pub fn immediate_dominator(&self, block_va: u64) -> Option<u64> {
        let node = self.block_to_node.get(&block_va)?;
        let idom = self.inner.immediate_dominator(*node)?;
        self.node_to_block.get(&idom).copied()
    }

    /// Number of blocks in the tree (== reachable blocks from entry).
    pub fn len(&self) -> usize {
        self.block_to_node.len()
    }

    pub fn is_empty(&self) -> bool {
        self.block_to_node.is_empty()
    }
}

/// Compute the dominator tree for `function_va`. Returns `None` when
/// the function is unknown or has no reachable basic blocks.
pub fn dominators_for_function(graph: &EvidenceGraph, function_va: u64) -> Option<DominatorTree> {
    build_tree(graph, function_va, /* reverse = */ false)
}

/// Compute the post-dominator tree for `function_va` by reversing
/// the CFG before running dominators.
pub fn post_dominators_for_function(
    graph: &EvidenceGraph,
    function_va: u64,
) -> Option<DominatorTree> {
    build_tree(graph, function_va, /* reverse = */ true)
}

fn build_tree(graph: &EvidenceGraph, function_va: u64, reverse: bool) -> Option<DominatorTree> {
    // Collect all BasicBlock nodes belonging to this function.
    let mut blocks: Vec<(NodeId, u64)> = Vec::new();
    for (id, payload) in graph.nodes_of_kind(NodeKind::BasicBlock) {
        if let NodePayload::BasicBlock {
            function_va: fva,
            start_va,
            ..
        } = payload
        {
            if *fva == function_va {
                blocks.push((id, *start_va));
            }
        }
    }
    if blocks.is_empty() {
        return None;
    }

    // Build a per-function subgraph keyed on block_start_va.
    let mut sub: Graph<u64, ()> = Graph::new();
    let mut block_to_node: HashMap<u64, NodeIndex<u32>> = HashMap::new();
    let mut node_to_block: HashMap<NodeIndex<u32>, u64> = HashMap::new();
    for (_, start_va) in &blocks {
        let n = sub.add_node(*start_va);
        block_to_node.insert(*start_va, n);
        node_to_block.insert(n, *start_va);
    }

    // Walk ControlFlow edges and re-add into the subgraph.
    for (block_id, start_va) in &blocks {
        for (other_id, _edge_id) in graph.outgoing_of_kind(*block_id, EdgeKind::ControlFlow) {
            if let Some(NodePayload::BasicBlock {
                function_va: fva2,
                start_va: other_start,
                ..
            }) = graph.node(other_id)
            {
                if *fva2 != function_va {
                    continue;
                }
                let from = block_to_node[start_va];
                let to = block_to_node[other_start];
                if reverse {
                    sub.add_edge(to, from, ());
                } else {
                    sub.add_edge(from, to, ());
                }
            }
        }
    }

    // Entry block = the one with VA == function_va. (For post-doms
    // we run from any block that has no successors in the reversed
    // graph — i.e. originally a sink/exit block — but for v1.0 we
    // just use the entry block in both directions since we don't
    // have a unique virtual exit yet.)
    let entry = if reverse {
        // Find any block with no outgoing ControlFlow edge in the
        // forward graph; that becomes a root in the reversed graph.
        // If multiple exits exist, take the one with the lowest VA
        // for determinism.
        let mut candidates: Vec<u64> = blocks
            .iter()
            .filter(|(id, _)| {
                graph
                    .outgoing_of_kind(*id, EdgeKind::ControlFlow)
                    .next()
                    .is_none()
            })
            .map(|(_, va)| *va)
            .collect();
        candidates.sort();
        candidates.first().copied().unwrap_or(function_va)
    } else {
        function_va
    };
    let entry_node = block_to_node.get(&entry).copied()?;

    let inner = dominators::simple_fast(&sub, entry_node);

    Some(DominatorTree {
        inner,
        block_to_node,
        node_to_block,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{BasicBlockRecord, CfgRecord, EdgeRecord, FunctionRecord};
    use crate::vuln::graph_builder::{ingest_cfg, ingest_functions};

    fn func(start: u64) -> FunctionRecord {
        FunctionRecord {
            start,
            end: start + 0x100,
            size: 0x100,
            source: "test".into(),
            calls: vec![],
            calls_imports: vec![],
            strings: vec![],
            xrefs: 0,
        }
    }

    fn block(start: u64, end: u64) -> BasicBlockRecord {
        BasicBlockRecord {
            start,
            end,
            instruction_count: 4,
        }
    }

    fn edge(from: u64, to: u64) -> EdgeRecord {
        EdgeRecord {
            from,
            to,
            edge_type: "branch".into(),
        }
    }

    /// Build a 4-block diamond CFG:
    ///   A → B → D
    ///   A → C → D
    /// A dominates B, C, D. D post-dominates B, C, A.
    fn diamond_graph() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_cfg(
            &mut g,
            &[CfgRecord {
                function: 0x1000,
                blocks: vec![
                    block(0x1000, 0x1010), // A (entry)
                    block(0x1010, 0x1020), // B
                    block(0x1020, 0x1030), // C
                    block(0x1030, 0x1040), // D
                ],
                edges: vec![
                    edge(0x1000, 0x1010),
                    edge(0x1000, 0x1020),
                    edge(0x1010, 0x1030),
                    edge(0x1020, 0x1030),
                ],
            }],
        );
        g
    }

    #[test]
    fn dominators_diamond_entry_dominates_all_blocks() {
        let g = diamond_graph();
        let dom = dominators_for_function(&g, 0x1000).unwrap();
        assert!(dom.dominates(0x1000, 0x1010));
        assert!(dom.dominates(0x1000, 0x1020));
        assert!(dom.dominates(0x1000, 0x1030));
        assert!(dom.dominates(0x1000, 0x1000)); // reflexive
    }

    #[test]
    fn dominators_diamond_b_does_not_dominate_c() {
        let g = diamond_graph();
        let dom = dominators_for_function(&g, 0x1000).unwrap();
        assert!(!dom.dominates(0x1010, 0x1020));
        assert!(!dom.dominates(0x1020, 0x1010));
        // B doesn't dominate D because the path through C bypasses B.
        assert!(!dom.dominates(0x1010, 0x1030));
    }

    #[test]
    fn dominators_returns_none_for_unknown_function() {
        let g = diamond_graph();
        assert!(dominators_for_function(&g, 0xdead_beef).is_none());
    }

    #[test]
    fn dominators_returns_none_for_function_without_blocks() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        // No CFG ingested → no blocks for 0x1000.
        assert!(dominators_for_function(&g, 0x1000).is_none());
    }

    #[test]
    fn immediate_dominator_of_diamond_blocks_is_entry() {
        let g = diamond_graph();
        let dom = dominators_for_function(&g, 0x1000).unwrap();
        assert_eq!(dom.immediate_dominator(0x1010), Some(0x1000));
        assert_eq!(dom.immediate_dominator(0x1020), Some(0x1000));
        // D's idom is also A in a pure diamond.
        assert_eq!(dom.immediate_dominator(0x1030), Some(0x1000));
        // Entry has no idom.
        assert_eq!(dom.immediate_dominator(0x1000), None);
    }

    #[test]
    fn post_dominators_diamond_d_postdominates_all() {
        let g = diamond_graph();
        let pdom = post_dominators_for_function(&g, 0x1000).unwrap();
        // In post-dom: D post-dominates A, B, C.
        assert!(pdom.dominates(0x1030, 0x1000));
        assert!(pdom.dominates(0x1030, 0x1010));
        assert!(pdom.dominates(0x1030, 0x1020));
    }

    #[test]
    fn dominators_loop_back_edge_does_not_break_invariants() {
        // Loop: A → B → C → B (back edge)
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x2000)]);
        ingest_cfg(
            &mut g,
            &[CfgRecord {
                function: 0x2000,
                blocks: vec![
                    block(0x2000, 0x2010),
                    block(0x2010, 0x2020),
                    block(0x2020, 0x2030),
                ],
                edges: vec![
                    edge(0x2000, 0x2010),
                    edge(0x2010, 0x2020),
                    edge(0x2020, 0x2010), // back edge
                ],
            }],
        );
        let dom = dominators_for_function(&g, 0x2000).unwrap();
        // A dominates everything. B dominates C (since the only path
        // to C goes through B).
        assert!(dom.dominates(0x2000, 0x2010));
        assert!(dom.dominates(0x2000, 0x2020));
        assert!(dom.dominates(0x2010, 0x2020));
        // C doesn't dominate B even though there's a back edge —
        // B is reachable without going through C from the entry.
        assert!(!dom.dominates(0x2020, 0x2010));
    }

    #[test]
    fn dominator_tree_len_matches_block_count() {
        let g = diamond_graph();
        let dom = dominators_for_function(&g, 0x1000).unwrap();
        assert_eq!(dom.len(), 4);
        assert!(!dom.is_empty());
    }
}
