//! Call-distance metric — how many call-graph hops separate two
//! functions. Distinct from `src/fuzzer/reachability.rs`, which is
//! fuzzer-internal and only available behind `--features fuzzer`.
//!
//! Used by scoring (`reachability_score`) to weight findings by how
//! reachable the source function is from an exported entry point.

#![allow(dead_code)]

use petgraph::algo::dijkstra;
use rustc_hash::FxHashMap;

use crate::vuln::graph::{EdgeKind, EvidenceGraph, NodeId};

/// Shortest-path call distance from `from` to `to`. `0` when
/// `from == to`. `None` when `to` is unreachable from `from`.
pub fn call_distance(graph: &EvidenceGraph, from: NodeId, to: NodeId) -> Option<u32> {
    if from == to {
        return Some(0);
    }
    // dijkstra's edge_cost takes a tuple-like `EdgeReference` whose
    // weight is the edge weight (here `EdgeKind`). Non-call edges get
    // a cost large enough to make any path that uses them lose to
    // any pure-call path, but small enough to not overflow on
    // accumulation. We then filter results that look like they only
    // got there via non-call edges.
    let raw = graph.raw();
    let scores = dijkstra(raw, from, Some(to), |edge_ref| {
        if *edge_ref.weight() == EdgeKind::Calls {
            1u32
        } else {
            u32::MAX / 4
        }
    });
    scores.get(&to).copied().filter(|d| *d < u32::MAX / 4)
}

/// Compute call distances from `from` to EVERY reachable function in
/// one dijkstra run. More efficient when scoring many chains from
/// the same entry function.
pub fn call_distances_from(graph: &EvidenceGraph, from: NodeId) -> FxHashMap<NodeId, u32> {
    let raw = graph.raw();
    let scores = dijkstra(raw, from, None, |edge_ref| {
        if *edge_ref.weight() == EdgeKind::Calls {
            1u32
        } else {
            u32::MAX / 4
        }
    });
    scores
        .into_iter()
        .filter(|(_, d)| *d < u32::MAX / 4)
        .collect()
}

// petgraph 0.6 EdgeRef extension trait for `.weight()` in the closure.
use petgraph::visit::EdgeRef;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::FunctionRecord;
    use crate::vuln::graph_builder::ingest_functions;

    fn func(va: u64, calls: Vec<u64>) -> FunctionRecord {
        FunctionRecord {
            start: va,
            end: va + 0x100,
            size: 0x100,
            source: "test".into(),
            calls,
            calls_imports: vec![],
            strings: vec![],
            xrefs: 0,
        }
    }

    #[test]
    fn distance_to_self_is_zero() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![])]);
        let a = g.function_by_va(0x1000).unwrap();
        assert_eq!(call_distance(&g, a, a), Some(0));
    }

    #[test]
    fn direct_call_distance_is_one() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![0x2000]), func(0x2000, vec![])]);
        let a = g.function_by_va(0x1000).unwrap();
        let b = g.function_by_va(0x2000).unwrap();
        assert_eq!(call_distance(&g, a, b), Some(1));
    }

    #[test]
    fn three_hop_chain_distance_is_three() {
        let mut g = EvidenceGraph::new();
        ingest_functions(
            &mut g,
            &[
                func(0x1000, vec![0x2000]),
                func(0x2000, vec![0x3000]),
                func(0x3000, vec![0x4000]),
                func(0x4000, vec![]),
            ],
        );
        let a = g.function_by_va(0x1000).unwrap();
        let d = g.function_by_va(0x4000).unwrap();
        assert_eq!(call_distance(&g, a, d), Some(3));
    }

    #[test]
    fn unreachable_returns_none() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![]), func(0x2000, vec![])]);
        let a = g.function_by_va(0x1000).unwrap();
        let b = g.function_by_va(0x2000).unwrap();
        assert!(call_distance(&g, a, b).is_none());
    }

    #[test]
    fn call_distances_from_one_dijkstra_covers_all_reachable() {
        let mut g = EvidenceGraph::new();
        ingest_functions(
            &mut g,
            &[
                func(0x1000, vec![0x2000, 0x3000]),
                func(0x2000, vec![0x4000]),
                func(0x3000, vec![]),
                func(0x4000, vec![]),
            ],
        );
        let a = g.function_by_va(0x1000).unwrap();
        let map = call_distances_from(&g, a);
        // Reaches a, b, c, d at distances 0, 1, 1, 2.
        assert_eq!(map.len(), 4);
    }
}
