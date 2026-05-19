//! Best-effort may-alias — v1.0 ships SSA-equality only.
//!
//! Two SSA values may alias if they share the same SSA id (which is
//! tautological — they ARE the same value) OR if a DataFlow edge
//! connects them with no intervening transformation. v1.0's
//! `AliasGraph::may_alias` answers conservatively: returns `true`
//! only when proof exists; returns `false` for everything else
//! (intentional false negatives).
//!
//! **v1.0 deliberately does NOT consume this for any lifetime
//! template** — UAF/double-free require real points-to analysis,
//! which is a v2 deliverable. SSA-equality aliasing would produce
//! either trivial true positives or noisy false positives on
//! field-store / wrapper-free / RAII-drop patterns; opt-in only.

#![allow(dead_code)]

use rustc_hash::{FxHashMap, FxHashSet};

use crate::vuln::graph::{EdgeKind, EvidenceGraph, NodeId, NodeKind, NodePayload};

/// SSA-equality may-alias relation.
pub struct AliasGraph {
    /// For each Copy node id, the set of other Copy node ids it may
    /// alias (transitively, via DataFlow edges).
    classes: FxHashMap<NodeId, FxHashSet<NodeId>>,
}

impl Default for AliasGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl AliasGraph {
    pub fn new() -> Self {
        Self {
            classes: FxHashMap::default(),
        }
    }

    /// Build from the evidence graph by union-finding SSA Copy nodes
    /// connected via DataFlow edges. Two nodes end up in the same
    /// equivalence class iff there's a DataFlow path between them.
    pub fn build(graph: &EvidenceGraph) -> Self {
        let mut classes: FxHashMap<NodeId, FxHashSet<NodeId>> = FxHashMap::default();
        // BFS from each Copy node; assign to a class shared with every
        // reachable Copy. v1.0 doesn't use union-find for compactness —
        // the BFS is O(V+E) per starting node but the per-template
        // queries are small.
        for (start, _) in graph.nodes_of_kind(NodeKind::Copy) {
            if classes.contains_key(&start) {
                continue;
            }
            let mut class: FxHashSet<NodeId> = FxHashSet::default();
            let mut stack = vec![start];
            while let Some(n) = stack.pop() {
                if !class.insert(n) {
                    continue;
                }
                for (next, _) in graph.outgoing_of_kind(n, EdgeKind::DataFlow) {
                    if matches!(graph.node(next), Some(NodePayload::Copy { .. })) {
                        stack.push(next);
                    }
                }
                for (prev, _) in graph.incoming_of_kind(n, EdgeKind::DataFlow) {
                    if matches!(graph.node(prev), Some(NodePayload::Copy { .. })) {
                        stack.push(prev);
                    }
                }
            }
            for &member in &class {
                classes.insert(member, class.clone());
            }
        }
        Self { classes }
    }

    /// `true` iff the two nodes share an SSA-equality class. Always
    /// `false` for non-Copy nodes.
    pub fn may_alias(&self, a: NodeId, b: NodeId) -> bool {
        if a == b {
            return self.classes.contains_key(&a);
        }
        match self.classes.get(&a) {
            Some(class) => class.contains(&b),
            None => false,
        }
    }

    pub fn class_size(&self, n: NodeId) -> usize {
        self.classes.get(&n).map(|c| c.len()).unwrap_or(0)
    }

    pub fn class_count(&self) -> usize {
        let mut representatives: FxHashSet<usize> = FxHashSet::default();
        for class in self.classes.values() {
            if let Some(&first) = class.iter().min_by_key(|n| n.index()) {
                representatives.insert(first.index());
            }
        }
        representatives.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{DataflowEdgeRecord, SsaValueRecord};
    use crate::vuln::graph_builder::{ingest_dataflow, ingest_ssa};

    fn ssa(id: &str, va: u64) -> SsaValueRecord {
        SsaValueRecord {
            ssa_id: id.into(),
            function: 0x1000,
            block: Some(0x1000),
            site_va: va,
            storage: "rax".into(),
            version: 1,
            kind: "def".into(),
            source: "test".into(),
            value: None,
            evidence: vec![],
            confidence: "medium".into(),
        }
    }

    fn dflow(from: &str, to: &str) -> DataflowEdgeRecord {
        DataflowEdgeRecord {
            edge_id: format!("e_{from}_{to}"),
            function: 0x1000,
            from_value: Some(from.into()),
            to_value: to.into(),
            from_va: None,
            to_va: 0x2000,
            from_storage: None,
            to_storage: "rax".into(),
            edge_kind: "def_use".into(),
            type_tag: None,
            evidence: vec![],
        }
    }

    #[test]
    fn same_node_always_aliases_itself() {
        let mut g = EvidenceGraph::new();
        let idx = ingest_ssa(&mut g, &[ssa("a", 0x1000)]);
        let alias = AliasGraph::build(&g);
        assert!(alias.may_alias(idx["a"], idx["a"]));
    }

    #[test]
    fn dataflow_connected_nodes_alias() {
        let mut g = EvidenceGraph::new();
        let idx = ingest_ssa(
            &mut g,
            &[ssa("a", 0x1000), ssa("b", 0x1010), ssa("c", 0x1020)],
        );
        ingest_dataflow(&mut g, &[dflow("a", "b"), dflow("b", "c")], &idx);
        let alias = AliasGraph::build(&g);
        assert!(alias.may_alias(idx["a"], idx["b"]));
        assert!(alias.may_alias(idx["b"], idx["c"]));
        // Transitive: a → c via b.
        assert!(alias.may_alias(idx["a"], idx["c"]));
    }

    #[test]
    fn disconnected_nodes_do_not_alias() {
        let mut g = EvidenceGraph::new();
        let idx = ingest_ssa(
            &mut g,
            &[ssa("a", 0x1000), ssa("b", 0x1010), ssa("c", 0x1020)],
        );
        // Only a→b; c is isolated.
        ingest_dataflow(&mut g, &[dflow("a", "b")], &idx);
        let alias = AliasGraph::build(&g);
        assert!(alias.may_alias(idx["a"], idx["b"]));
        assert!(!alias.may_alias(idx["a"], idx["c"]));
        assert!(!alias.may_alias(idx["b"], idx["c"]));
    }

    #[test]
    fn class_size_counts_equivalent_members() {
        let mut g = EvidenceGraph::new();
        let idx = ingest_ssa(
            &mut g,
            &[ssa("a", 0x1000), ssa("b", 0x1010), ssa("c", 0x1020)],
        );
        ingest_dataflow(&mut g, &[dflow("a", "b"), dflow("b", "c")], &idx);
        let alias = AliasGraph::build(&g);
        assert_eq!(alias.class_size(idx["a"]), 3);
        assert_eq!(alias.class_size(idx["b"]), 3);
        assert_eq!(alias.class_size(idx["c"]), 3);
    }

    #[test]
    fn empty_graph_has_no_aliases() {
        let g = EvidenceGraph::new();
        let alias = AliasGraph::build(&g);
        assert_eq!(alias.class_count(), 0);
    }
}
