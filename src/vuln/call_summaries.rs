//! Function call summaries for interprocedural taint propagation.
//!
//! v1.0 ships a **coarse summary**: per function, record which of its
//! N parameters can be tainted-in and which of its M return values
//! / output parameters can be tainted-out. Bit-set representation
//! via `bitvec` for compactness.
//!
//! v2 deliverable: field-sensitive summaries with per-arg shape
//! information (struct fields, container element types). v1.0
//! summaries are deliberately approximate — chains crossing summary
//! boundaries carry `propagation_mode: "summary"` and lose
//! confidence in scoring.

#![allow(dead_code)]

use bitvec::prelude::*;
use rustc_hash::FxHashMap;

use crate::vuln::graph::{EdgeKind, EvidenceGraph, NodeKind, NodePayload};

const SUMMARY_BITS: usize = 8;

/// Per-function summary used by interprocedural taint propagation.
/// Internal-only — never serialized to disk (BitVec's serde support
/// requires the `serde` feature on the bitvec crate; we don't need
/// that for v1.0).
#[derive(Clone, Debug, Default)]
pub struct CallSummary {
    /// Bit i = 1 means parameter i can be taint-source for this fn.
    pub taint_in: BitVec,
    /// Bit i = 1 means output i (return value or out-param) is
    /// tainted-out when SOME taint-in is tainted.
    pub taint_out: BitVec,
    /// Sink call sites this function (directly) reaches. Each entry
    /// is `(sink_api, callsite_va)`.
    pub sinks_reached: Vec<(String, u64)>,
    /// Allocation sites this function makes.
    pub allocations: Vec<u64>,
    /// `free`-family call sites this function makes (v1.1 lifetime
    /// templates consume these; v1.0 doesn't).
    pub free_calls: Vec<u64>,
}

/// Compute summaries for every function in the graph. v1.0 uses a
/// single-pass approximation:
/// - `taint_in` and `taint_out` are stubbed at 4 bits each (the most
///   common arg-arity for the templates we care about) and marked
///   uniformly TRUE so callers conservatively propagate taint. This
///   is intentionally over-approximate; chains crossing summaries
///   carry `propagation_mode: "summary"` and scoring drops their
///   taint confidence.
/// - `sinks_reached` is populated from the graph's `CallSite` →
///   `Sink` DataFlow edges within each function.
///
/// A real fixpoint computation (per-bit propagation across the call
/// graph) is v1.1 work.
pub fn compute_summaries(graph: &EvidenceGraph) -> FxHashMap<u64, CallSummary> {
    let mut out: FxHashMap<u64, CallSummary> = FxHashMap::default();
    // Initialize a summary for every function.
    for (_, payload) in graph.nodes_of_kind(NodeKind::Function) {
        if let NodePayload::Function { va, .. } = payload {
            out.insert(
                *va,
                CallSummary {
                    taint_in: bitvec![0; SUMMARY_BITS],
                    taint_out: bitvec![0; SUMMARY_BITS],
                    sinks_reached: Vec::new(),
                    allocations: Vec::new(),
                    free_calls: Vec::new(),
                },
            );
        }
    }
    // Populate sinks_reached / allocations by walking each function's
    // CallSite/Sink/Allocation nodes via incoming Function→CallSite
    // ControlFlow edges. v1.0 simplification: every Sink in the
    // graph is recorded under EVERY function that has a Calls edge
    // to a CallSite that reaches the sink. This is over-approximate
    // (a chain query then refines with the real ControlFlow path).
    for (callsite_id, callsite_payload) in graph.nodes_of_kind(NodeKind::CallSite) {
        let callsite_api = match callsite_payload {
            NodePayload::CallSite { api: Some(api), .. } => Some(api.as_str()),
            _ => continue,
        };
        for (fn_id, _) in graph.incoming_of_kind(callsite_id, EdgeKind::ControlFlow) {
            if let Some(NodePayload::Function { va, .. }) = graph.node(fn_id) {
                if let Some(summary) = out.get_mut(va) {
                    if let Some(api) = callsite_api {
                        apply_api_semantics(summary, api);
                    }
                }
            }
        }
        for (sink_id, _) in graph.outgoing_of_kind(callsite_id, EdgeKind::DataFlow) {
            let Some(NodePayload::Sink { api, site_va }) = graph.node(sink_id) else {
                continue;
            };
            for (fn_id, _) in graph.incoming_of_kind(callsite_id, EdgeKind::ControlFlow) {
                if let Some(NodePayload::Function { va, .. }) = graph.node(fn_id) {
                    if let Some(summary) = out.get_mut(va) {
                        summary.sinks_reached.push((api.clone(), *site_va));
                    }
                }
            }
        }
    }
    propagate_summary_fixpoint(graph, &mut out);
    out
}

fn propagate_summary_fixpoint(graph: &EvidenceGraph, summaries: &mut FxHashMap<u64, CallSummary>) {
    let call_edges: Vec<(u64, u64)> = graph
        .nodes_of_kind(NodeKind::Function)
        .filter_map(|(caller_id, caller_payload)| {
            let NodePayload::Function { va: caller_va, .. } = caller_payload else {
                return None;
            };
            let callees: Vec<u64> = graph
                .outgoing_of_kind(caller_id, EdgeKind::Calls)
                .filter_map(|(callee_id, _)| match graph.node(callee_id) {
                    Some(NodePayload::Function { va, .. }) => Some(*va),
                    _ => None,
                })
                .collect();
            Some((*caller_va, callees))
        })
        .flat_map(|(caller, callees)| callees.into_iter().map(move |callee| (caller, callee)))
        .collect();

    let max_rounds = summaries.len().max(1);
    for _ in 0..max_rounds {
        let mut changed = false;
        for (caller_va, callee_va) in &call_edges {
            let Some(callee_summary) = summaries.get(callee_va).cloned() else {
                continue;
            };
            let Some(caller_summary) = summaries.get_mut(caller_va) else {
                continue;
            };
            changed |= merge_summary(caller_summary, &callee_summary);
        }
        if !changed {
            break;
        }
    }
}

fn merge_summary(dst: &mut CallSummary, src: &CallSummary) -> bool {
    let mut changed = false;
    changed |= merge_bits(&mut dst.taint_in, &src.taint_in);
    changed |= merge_bits(&mut dst.taint_out, &src.taint_out);
    changed |= merge_unique_pairs(&mut dst.sinks_reached, &src.sinks_reached);
    changed |= merge_unique_u64(&mut dst.allocations, &src.allocations);
    changed |= merge_unique_u64(&mut dst.free_calls, &src.free_calls);
    changed
}

fn merge_bits(dst: &mut BitVec, src: &BitVec) -> bool {
    let mut changed = false;
    if dst.len() < src.len() {
        dst.resize(src.len(), false);
        changed = true;
    }
    for (idx, bit) in src.iter().enumerate() {
        if *bit && !dst[idx] {
            dst.set(idx, true);
            changed = true;
        }
    }
    changed
}

fn merge_unique_pairs(dst: &mut Vec<(String, u64)>, src: &[(String, u64)]) -> bool {
    let mut changed = false;
    for item in src {
        if !dst.iter().any(|existing| existing == item) {
            dst.push(item.clone());
            changed = true;
        }
    }
    changed
}

fn merge_unique_u64(dst: &mut Vec<u64>, src: &[u64]) -> bool {
    let mut changed = false;
    for &item in src {
        if !dst.contains(&item) {
            dst.push(item);
            changed = true;
        }
    }
    changed
}

fn apply_api_semantics(summary: &mut CallSummary, api: &str) {
    let lower = api.to_ascii_lowercase();
    if contains_any(
        &lower,
        &["recv", "wsarecv", "readfile", "fread", "fgets", "_read"],
    ) {
        set_bits(&mut summary.taint_out, &[0, 1]);
    }
    if contains_any(&lower, &["internetreadfile", "winhttpreaddata"]) {
        set_bits(&mut summary.taint_out, &[0, 1]);
    }
    if contains_any(&lower, &["deviceiocontrol", "ntdeviceiocontrolfile"]) {
        set_bits(&mut summary.taint_in, &[2, 3]);
        set_bits(&mut summary.taint_out, &[4, 5]);
    }
    if contains_any(
        &lower,
        &[
            "memcpy",
            "memmove",
            "rtlcopymemory",
            "strcpy",
            "strncpy",
            "strcat",
        ],
    ) {
        set_bits(&mut summary.taint_in, &[1, 2]);
        set_bits(&mut summary.taint_out, &[0]);
    }
    if contains_any(
        &lower,
        &[
            "printf",
            "sprintf",
            "snprintf",
            "fprintf",
            "vfprintf",
            "vsprintf",
            "__stdio_common_vfprintf",
        ],
    ) {
        set_bits(&mut summary.taint_in, &[0, 1, 2]);
        if contains_any(&lower, &["sprintf", "snprintf", "vsprintf"]) {
            set_bits(&mut summary.taint_out, &[0]);
        }
    }
    if contains_any(&lower, &["malloc", "calloc", "realloc", "virtualalloc"]) {
        set_bits(&mut summary.taint_in, &[0, 1, 2, 3]);
        set_bits(&mut summary.taint_out, &[0]);
    }
    if contains_any(
        &lower,
        &[
            "createfile",
            "fopen",
            "open",
            "unlink",
            "deletefile",
            "rename",
        ],
    ) {
        set_bits(&mut summary.taint_in, &[0, 1]);
    }
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn set_bits(bits: &mut BitVec, indexes: &[usize]) {
    for &idx in indexes {
        if idx >= bits.len() {
            bits.resize(idx + 1, false);
        }
        bits.set(idx, true);
    }
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

    fn af(function: u64, callsite: u64, api: &str) -> ApiFlowRecord {
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
    fn empty_graph_produces_empty_summary_map() {
        let g = EvidenceGraph::new();
        let s = compute_summaries(&g);
        assert!(s.is_empty());
    }

    #[test]
    fn every_function_gets_a_summary_with_default_taint_bits() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000), func(0x2000)]);
        let s = compute_summaries(&g);
        assert_eq!(s.len(), 2);
        let s1 = &s[&0x1000];
        assert_eq!(s1.taint_in.len(), 8);
        assert_eq!(s1.taint_out.len(), 8);
        assert!(s1.taint_in.iter().all(|b| !*b));
        assert!(s1.taint_out.iter().all(|b| !*b));
    }

    #[test]
    fn recv_marks_only_semantic_output_bits() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(&mut g, &[af(0x1000, 0x1100, "recv")]);
        let s = compute_summaries(&g);
        let summary = &s[&0x1000];
        assert!(
            summary.taint_out.iter().any(|b| *b),
            "recv should mark an output buffer as tainted"
        );
        assert!(
            !summary.taint_in.iter().all(|b| *b),
            "recv must not force every argument to tainted-in"
        );
    }

    #[test]
    fn memcpy_marks_copy_semantics_without_uniform_taint() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(&mut g, &[af(0x1000, 0x1200, "memcpy")]);
        let s = compute_summaries(&g);
        let summary = &s[&0x1000];
        assert!(
            summary.taint_in.iter().any(|b| *b),
            "memcpy should record attacker-relevant input arguments"
        );
        assert!(
            summary.taint_out.iter().any(|b| *b),
            "memcpy should record destination output semantics"
        );
        assert!(
            !summary.taint_in.iter().all(|b| *b),
            "copy summaries must stay argument-specific"
        );
    }

    #[test]
    fn function_with_memcpy_call_records_sink_reached() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(&mut g, &[af(0x1000, 0x4022a4, "memcpy")]);
        let s = compute_summaries(&g);
        let summary = &s[&0x1000];
        assert!(!summary.sinks_reached.is_empty());
        assert_eq!(summary.sinks_reached[0].0, "memcpy");
        assert_eq!(summary.sinks_reached[0].1, 0x4022a4);
    }

    #[test]
    fn function_with_no_calls_has_empty_sinks_reached() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        let s = compute_summaries(&g);
        assert!(s[&0x1000].sinks_reached.is_empty());
    }

    #[test]
    fn fixpoint_lifts_callee_sink_summaries_to_callers() {
        let mut caller = func(0x1000);
        caller.calls = vec![0x2000];
        let callee = func(0x2000);
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[caller, callee]);
        ingest_api_flows(&mut g, &[af(0x2000, 0x2100, "memcpy")]);

        let summaries = compute_summaries(&g);
        let caller_summary = &summaries[&0x1000];

        assert!(
            caller_summary
                .sinks_reached
                .iter()
                .any(|(api, site)| api == "memcpy" && *site == 0x2100),
            "call-summary fixpoint should lift callee sink reachability to callers"
        );
    }
}
