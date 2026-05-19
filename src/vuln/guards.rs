//! Guard extraction — finds branches in a function's CFG and pairs
//! them with the dominator tree so chain queries can ask "does block
//! X dominate sink Y AND act as a bound check?"
//!
//! v1.0 ships a deliberately simple model: a `GuardCandidate` is "a
//! block that has multiple ControlFlow successors, anchored at the
//! branching instruction's VA." We don't extract the textual
//! condition expression in v1.0 — that requires full predicate
//! recovery (branch lifting + symbolic-expression building) which
//! axe's existing `src/structured.rs` only partially provides. The
//! chain query (Step 20) decorates each `GuardCandidate` with
//! `dominates_sink` (via the dominator tree) and a template-derived
//! `missing_bound` string.
//!
//! v1.1 deliverable: real predicate recovery so `condition_expr`
//! carries the textual condition (e.g. `"record_len <= 1024"`).

#![allow(dead_code)]

use serde::Serialize;

use crate::vuln::dominator::DominatorTree;
use crate::vuln::graph::{EdgeKind, EvidenceGraph, NodeKind, NodePayload};

/// A branch found in a function's CFG. Carries enough information
/// for the chain query to decide whether it protects a sink and to
/// emit a wire-shape `Guard` for the LLM consumer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuardCandidate {
    pub function_va: u64,
    /// Start VA of the block that contains the branch.
    pub block_va: u64,
    /// VA of the branching instruction itself (end_va - 1 in the
    /// common single-instruction-branch case; just use block.end as
    /// a stable approximation in v1.0).
    pub condition_va: u64,
    /// Successor block VAs reachable from this block.
    pub successors: Vec<u64>,
}

impl GuardCandidate {
    /// `true` iff this guard's block dominates `sink_block_va` in the
    /// containing function's dominator tree.
    pub fn dominates_sink(&self, dom: &DominatorTree, sink_block_va: u64) -> bool {
        dom.dominates(self.block_va, sink_block_va)
    }
}

/// Extract every guard candidate from `function_va`'s CFG. Returns an
/// empty vec when the function has no blocks (e.g. an import
/// pseudo-function). Each candidate carries successor VAs so chain
/// queries can reason about which branch path leads to the sink.
pub fn extract_guards(graph: &EvidenceGraph, function_va: u64) -> Vec<GuardCandidate> {
    let mut out = Vec::new();
    for (block_id, payload) in graph.nodes_of_kind(NodeKind::BasicBlock) {
        let (fva, start_va, end_va) = match payload {
            NodePayload::BasicBlock {
                function_va: fva,
                start_va,
                end_va,
            } => (*fva, *start_va, *end_va),
            _ => continue,
        };
        if fva != function_va {
            continue;
        }
        let mut successors: Vec<u64> = Vec::new();
        for (target, _edge_id) in graph.outgoing_of_kind(block_id, EdgeKind::ControlFlow) {
            if let Some(NodePayload::BasicBlock {
                function_va: tfva,
                start_va: tstart,
                ..
            }) = graph.node(target)
            {
                if *tfva == function_va {
                    successors.push(*tstart);
                }
            }
        }
        // A guard is a block with >1 successor — that's a branch.
        if successors.len() > 1 {
            successors.sort();
            // condition_va: approximate as one byte before block.end
            // (the branch instruction is typically the last one).
            let condition_va = end_va.saturating_sub(1);
            out.push(GuardCandidate {
                function_va,
                block_va: start_va,
                condition_va,
                successors,
            });
        }
    }
    out.sort_by_key(|g| g.block_va);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{BasicBlockRecord, CfgRecord, EdgeRecord, FunctionRecord};
    use crate::vuln::dominator::dominators_for_function;
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

    /// 4-block diamond CFG (same fixture as dominator.rs tests):
    ///   A → B → D
    ///   A → C → D
    /// A is the only branching block; D is a merge.
    fn diamond_graph() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_cfg(
            &mut g,
            &[CfgRecord {
                function: 0x1000,
                blocks: vec![
                    block(0x1000, 0x1010),
                    block(0x1010, 0x1020),
                    block(0x1020, 0x1030),
                    block(0x1030, 0x1040),
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
    fn extract_guards_identifies_branching_block_only() {
        let g = diamond_graph();
        let guards = extract_guards(&g, 0x1000);
        assert_eq!(guards.len(), 1, "diamond has one branching block (A)");
        assert_eq!(guards[0].block_va, 0x1000);
        assert_eq!(guards[0].successors, vec![0x1010, 0x1020]);
    }

    #[test]
    fn extract_guards_skips_non_branching_blocks() {
        let g = diamond_graph();
        let guards = extract_guards(&g, 0x1000);
        // Blocks B (0x1010) and C (0x1020) each have ONE successor;
        // they should not be guards.
        for g in &guards {
            assert_ne!(g.block_va, 0x1010);
            assert_ne!(g.block_va, 0x1020);
        }
    }

    #[test]
    fn extract_guards_returns_empty_for_function_with_no_branches() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x2000)]);
        ingest_cfg(
            &mut g,
            &[CfgRecord {
                function: 0x2000,
                blocks: vec![block(0x2000, 0x2010), block(0x2010, 0x2020)],
                edges: vec![edge(0x2000, 0x2010)],
            }],
        );
        let guards = extract_guards(&g, 0x2000);
        assert!(guards.is_empty());
    }

    #[test]
    fn extract_guards_returns_empty_for_unknown_function() {
        let g = diamond_graph();
        let guards = extract_guards(&g, 0xdead_beef);
        assert!(guards.is_empty());
    }

    #[test]
    fn guard_dominates_sink_checks_via_dominator_tree() {
        let g = diamond_graph();
        let dom = dominators_for_function(&g, 0x1000).unwrap();
        let guards = extract_guards(&g, 0x1000);
        // The branch at A dominates D (the merge block).
        let guard = &guards[0];
        assert!(guard.dominates_sink(&dom, 0x1030));
        // It also dominates B and C (its own successors).
        assert!(guard.dominates_sink(&dom, 0x1010));
        assert!(guard.dominates_sink(&dom, 0x1020));
    }

    #[test]
    fn condition_va_is_within_block_extent() {
        let g = diamond_graph();
        let guards = extract_guards(&g, 0x1000);
        let guard = &guards[0];
        // condition_va should be within [block_va, end_va).
        assert!(guard.condition_va >= 0x1000);
        assert!(guard.condition_va < 0x1010);
    }

    #[test]
    fn successors_are_sorted_for_deterministic_output() {
        // Build a graph where the edges happen to be added in
        // reverse order; verify successors come out sorted.
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x3000)]);
        ingest_cfg(
            &mut g,
            &[CfgRecord {
                function: 0x3000,
                blocks: vec![
                    block(0x3000, 0x3010),
                    block(0x3010, 0x3020),
                    block(0x3020, 0x3030),
                    block(0x3030, 0x3040),
                ],
                edges: vec![
                    edge(0x3000, 0x3030), // largest target first
                    edge(0x3000, 0x3020),
                    edge(0x3000, 0x3010),
                ],
            }],
        );
        let guards = extract_guards(&g, 0x3000);
        let g0 = &guards[0];
        assert_eq!(g0.successors, vec![0x3010, 0x3020, 0x3030]);
    }

    #[test]
    fn three_way_branch_produces_one_guard_with_three_successors() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x4000)]);
        ingest_cfg(
            &mut g,
            &[CfgRecord {
                function: 0x4000,
                blocks: vec![
                    block(0x4000, 0x4010),
                    block(0x4010, 0x4020),
                    block(0x4020, 0x4030),
                    block(0x4030, 0x4040),
                ],
                edges: vec![
                    edge(0x4000, 0x4010),
                    edge(0x4000, 0x4020),
                    edge(0x4000, 0x4030),
                ],
            }],
        );
        let guards = extract_guards(&g, 0x4000);
        assert_eq!(guards.len(), 1);
        assert_eq!(guards[0].successors.len(), 3);
    }
}
