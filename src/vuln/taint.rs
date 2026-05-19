//! Taint propagation engine.
//!
//! v1.0 ships TWO modes (combined in `propagate`):
//!
//! 1. **Intraprocedural exact** — BFS from each `Source` node along
//!    `DataFlow` edges. Every node reached is marked tainted with
//!    the source as its origin. Honest within a function.
//!
//! 2. **Summary-based interprocedural** — once intraprocedural taint
//!    is computed, walk `Calls` edges using `CallSummary` records
//!    (Step 17 / `call_summaries.rs`) to propagate taint across
//!    function boundaries. Each cross-boundary hop drops the
//!    `propagation_mode` from `"exact"` to `"summary"` and lowers
//!    the chain's `taint_confidence` weight in scoring.

#![allow(dead_code)]

use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

use crate::vuln::call_summaries::CallSummary;
use crate::vuln::graph::{EdgeKind, EvidenceGraph, NodeId, NodeKind, NodePayload};
use crate::vuln::sources::SourceCatalog;

/// How the taint reached a given node — exact intraprocedural BFS
/// versus a summary-based interprocedural transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PropagationMode {
    Exact,
    Summary,
}

/// One taint mark on a node. Multiple sources can taint the same
/// node — the map stores all origins. `source_node` is the internal
/// petgraph NodeIndex — not Serialize-able directly, exposed as a
/// `u32` for wire shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintMark {
    pub source_node: NodeId,
    pub source_kind: String,
    pub mode: PropagationMode,
    /// Number of `Calls` edges crossed on the way from source to
    /// this node. `0` for intraprocedural; ≥1 for summary hops.
    pub hop_count: u32,
}

/// Map of node → all taint marks that flow into it. Empty entry =
/// untainted.
pub struct TaintMap {
    marks: FxHashMap<NodeId, Vec<TaintMark>>,
}

impl Default for TaintMap {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintMap {
    pub fn new() -> Self {
        Self {
            marks: FxHashMap::default(),
        }
    }

    pub fn is_tainted(&self, node: NodeId) -> bool {
        self.marks.contains_key(&node)
    }

    pub fn marks(&self, node: NodeId) -> Option<&[TaintMark]> {
        self.marks.get(&node).map(|v| v.as_slice())
    }

    pub fn tainted_nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.marks.keys()
    }

    pub fn len(&self) -> usize {
        self.marks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }

    /// `true` iff ANY taint mark on `node` has `mode == Exact`.
    /// Templates use this to filter summary-only marks (which carry
    /// lower confidence).
    pub fn has_exact(&self, node: NodeId) -> bool {
        self.marks
            .get(&node)
            .map(|v| v.iter().any(|m| m.mode == PropagationMode::Exact))
            .unwrap_or(false)
    }

    fn add(&mut self, node: NodeId, mark: TaintMark) -> bool {
        let entry = self.marks.entry(node).or_default();
        // De-dup by (source_node, mode); keep the lowest hop count.
        if let Some(existing) = entry
            .iter_mut()
            .find(|m| m.source_node == mark.source_node && m.mode == mark.mode)
        {
            if mark.hop_count < existing.hop_count {
                existing.hop_count = mark.hop_count;
                return true;
            }
            return false;
        }
        entry.push(mark);
        true
    }
}

/// Identify the `Source` nodes in the graph by matching `CallSite`
/// nodes against the [`SourceCatalog`]. A CallSite whose API is in
/// the catalog's source list is itself the source.
fn discover_source_nodes(graph: &EvidenceGraph, catalog: &SourceCatalog) -> Vec<(NodeId, String)> {
    let mut out = Vec::new();
    for (id, payload) in graph.nodes_of_kind(NodeKind::CallSite) {
        if let NodePayload::CallSite { api: Some(api), .. } = payload {
            if let Some(src) = catalog.match_api(api) {
                out.push((id, src.kind.to_string()));
            }
        }
    }
    out
}

/// **Step 16**: intraprocedural taint propagation.
///
/// BFS from each source node along `DataFlow` edges. Marks every
/// reached node with `PropagationMode::Exact`. Doesn't cross
/// function boundaries (the BFS only follows `DataFlow`, not
/// `Calls`).
pub fn propagate_intraprocedural(graph: &EvidenceGraph, catalog: &SourceCatalog) -> TaintMap {
    let mut map = TaintMap::new();
    let sources = discover_source_nodes(graph, catalog);
    for (source_id, source_kind) in &sources {
        let mut seen: FxHashSet<NodeId> = FxHashSet::default();
        let mut stack = vec![*source_id];
        while let Some(n) = stack.pop() {
            if !seen.insert(n) {
                continue;
            }
            map.add(
                n,
                TaintMark {
                    source_node: *source_id,
                    source_kind: source_kind.clone(),
                    mode: PropagationMode::Exact,
                    hop_count: 0,
                },
            );
            for (next, _) in graph.outgoing_of_kind(n, EdgeKind::DataFlow) {
                stack.push(next);
            }
        }
    }
    map
}

/// **Step 18**: summary-based interprocedural taint propagation.
///
/// Starts from the result of `propagate_intraprocedural` and walks
/// `Calls` edges in the EvidenceGraph. When a tainted node lives in
/// function F and F has a `CallSummary` mapping its tainted inputs
/// to tainted outputs in callee G, taint is propagated to G's
/// entry node with `mode = Summary` + `hop_count += 1`.
///
/// v1.0 uses a coarse summary: if function F has `taint_out` for
/// argument index N, and G is called from F at a callsite where
/// G's arg N is the data destination, taint flows. Field-sensitive
/// propagation is v2.
pub fn propagate_interprocedural(
    graph: &EvidenceGraph,
    intra_map: TaintMap,
    summaries: &FxHashMap<u64, CallSummary>,
) -> TaintMap {
    let mut map = intra_map;
    let max_rounds = graph.node_count().max(1);
    for _ in 0..max_rounds {
        let mut changed = false;
        for (function_id, function_payload) in graph.nodes_of_kind(NodeKind::Function) {
            let function_va = match function_payload {
                NodePayload::Function { va, .. } => *va,
                _ => continue,
            };
            let function_marks = taint_marks_in_function(graph, &map, function_id);
            if function_marks.is_empty() {
                continue;
            }
            if let Some(summary) = summaries.get(&function_va) {
                let sink_marks: Vec<TaintMark> = map
                    .marks(function_id)
                    .into_iter()
                    .flatten()
                    .filter(|mark| mark.mode == PropagationMode::Summary)
                    .cloned()
                    .collect();
                for (sink_api, sink_va) in &summary.sinks_reached {
                    let Some(sink_id) = graph.sink_by_va(*sink_va) else {
                        continue;
                    };
                    for mark in &sink_marks {
                        changed |= map.add(
                            sink_id,
                            TaintMark {
                                source_node: mark.source_node,
                                source_kind: mark.source_kind.clone(),
                                mode: PropagationMode::Summary,
                                hop_count: mark.hop_count.saturating_add(1),
                            },
                        );
                    }
                    let _ = sink_api;
                }
            }
            for (callee_id, _) in graph.outgoing_of_kind(function_id, EdgeKind::Calls) {
                let callee_summary = match graph.node(callee_id) {
                    Some(NodePayload::Function { va, .. }) => summaries.get(va),
                    _ => None,
                };
                if !callee_summary.is_some_and(summary_accepts_taint) {
                    continue;
                }
                for mark in &function_marks {
                    changed |= map.add(
                        callee_id,
                        TaintMark {
                            source_node: mark.source_node,
                            source_kind: mark.source_kind.clone(),
                            mode: PropagationMode::Summary,
                            hop_count: mark.hop_count.saturating_add(1),
                        },
                    );
                }
            }
        }
        if !changed {
            break;
        }
    }
    map
}

fn taint_marks_in_function(
    graph: &EvidenceGraph,
    map: &TaintMap,
    function_id: NodeId,
) -> Vec<TaintMark> {
    let mut marks = Vec::new();
    if let Some(existing) = map.marks(function_id) {
        marks.extend_from_slice(existing);
    }
    for (child_id, _) in graph.outgoing_of_kind(function_id, EdgeKind::ControlFlow) {
        if let Some(existing) = map.marks(child_id) {
            marks.extend_from_slice(existing);
        }
    }
    marks
}

fn summary_accepts_taint(summary: &CallSummary) -> bool {
    summary.taint_in.iter().any(|bit| *bit)
        || summary.taint_out.iter().any(|bit| *bit)
        || !summary.sinks_reached.is_empty()
}

/// **Combined**: run intraprocedural then interprocedural.
pub fn propagate(
    graph: &EvidenceGraph,
    catalog: &SourceCatalog,
    summaries: &FxHashMap<u64, CallSummary>,
) -> TaintMap {
    let intra = propagate_intraprocedural(graph, catalog);
    propagate_interprocedural(graph, intra, summaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{ApiFlowRecord, FunctionRecord};
    use crate::vuln::graph_builder::{ingest_api_flows, ingest_functions};

    fn func(va: u64) -> FunctionRecord {
        FunctionRecord {
            start: va,
            end: va + 0x100,
            size: 0x100,
            source: "test".into(),
            calls: vec![],
            calls_imports: vec![],
            strings: vec![],
            xrefs: 0,
        }
    }

    fn api_flow(function: u64, callsite: u64, api: &str) -> ApiFlowRecord {
        ApiFlowRecord {
            flow_id: format!("af_{callsite:x}"),
            function,
            callsite,
            api: api.into(),
            normalized_api: api.into(),
            api_tier: "user".into(),
            api_family: "memory".into(),
            semantic_relevance: "high".into(),
            noise_reason: None,
            api_categories: vec![],
            value: "rcx".into(),
            value_tags: vec![],
            argument: "rcx".into(),
            argument_register: Some("rcx".into()),
            argument_index: Some(0),
            argument_name: Some("dst".into()),
            confidence: "high".into(),
            mode: "static".into(),
            resolved_api: None,
            wrapper_chain: vec![],
            evidence: vec![],
        }
    }

    #[test]
    fn intraprocedural_marks_source_callsites() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(&mut g, &[api_flow(0x1000, 0x1100, "recv")]);
        let cat = SourceCatalog::v1_0();
        let map = propagate_intraprocedural(&g, &cat);
        // The recv callsite should be tainted.
        assert!(!map.is_empty(), "recv source should produce ≥1 taint mark");
    }

    #[test]
    fn intraprocedural_skips_non_source_apis() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(&mut g, &[api_flow(0x1000, 0x1100, "memcpy")]);
        let cat = SourceCatalog::v1_0();
        let map = propagate_intraprocedural(&g, &cat);
        // memcpy is a sink, not a source — no taint marks.
        assert!(map.is_empty());
    }

    #[test]
    fn taint_mark_records_propagation_mode() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(&mut g, &[api_flow(0x1000, 0x1100, "recv")]);
        let cat = SourceCatalog::v1_0();
        let map = propagate_intraprocedural(&g, &cat);
        // All marks from intra-only run should be Exact.
        for node in map.tainted_nodes() {
            assert!(map.has_exact(*node));
        }
    }

    #[test]
    fn taint_map_dedupes_marks_keeping_lowest_hop_count() {
        let mut map = TaintMap::new();
        // Manufacture two NodeIds via a small graph.
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        let n = g.function_by_va(0x1000).unwrap();
        map.add(
            n,
            TaintMark {
                source_node: n,
                source_kind: "x".into(),
                mode: PropagationMode::Exact,
                hop_count: 3,
            },
        );
        map.add(
            n,
            TaintMark {
                source_node: n,
                source_kind: "x".into(),
                mode: PropagationMode::Exact,
                hop_count: 1,
            },
        );
        assert_eq!(map.marks(n).unwrap().len(), 1);
        assert_eq!(map.marks(n).unwrap()[0].hop_count, 1);
    }

    #[test]
    fn interprocedural_fixpoint_marks_sink_reached_through_callee() {
        let mut caller = func(0x1000);
        caller.calls = vec![0x2000];
        let callee = func(0x2000);
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[caller, callee]);
        ingest_api_flows(
            &mut g,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x2000, 0x2100, "memcpy"),
            ],
        );
        let summaries = crate::vuln::call_summaries::compute_summaries(&g);
        let cat = SourceCatalog::v1_0();

        let map = propagate(&g, &cat, &summaries);
        let sink = g.sink_by_va(0x2100).expect("sink node");

        assert!(
            map.marks(sink).is_some_and(|marks| {
                marks
                    .iter()
                    .any(|mark| mark.mode == PropagationMode::Summary && mark.hop_count >= 1)
            }),
            "taint should reach a callee sink through the call-graph fixpoint"
        );
    }
}
