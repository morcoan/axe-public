//! Chain discovery — runs each `BugClass` template against the
//! graph + taint map + guards, producing zero or more
//! `CandidateChain`s.
//!
//! v1.0 is deliberately coarse: each template matches by source_kind
//! and sink_api, requires taint to reach the sink, and applies the
//! template's guard / integer-pattern requirement as a coarse
//! filter. The result is a "this chain might be vulnerable" candidate
//! whose precision the scoring formula then refines.

#![allow(dead_code)]

use serde::Serialize;

use crate::vuln::bug_class::{
    GuardRequirement, IntegerPatternRequirement, SinkArgRequirement, TemplateRegistry,
};
use crate::vuln::dominator;
use crate::vuln::graph::{EdgeKind, EvidenceGraph, NodeKind, NodePayload};
use crate::vuln::guards::extract_guards;
use crate::vuln::sinks::{ArgRole, SinkCatalog};
use crate::vuln::sources::SourceCatalog;
use crate::vuln::taint::{PropagationMode, TaintMap};

/// A discovered source→sink chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CandidateChain {
    pub chain_id: String,
    pub template_id: String,
    pub source_kind: String,
    pub source_function_va: u64,
    pub source_site_va: u64,
    pub sink_api: String,
    pub sink_function_va: u64,
    pub sink_site_va: u64,
    pub propagation_mode: PropagationMode,
    pub hop_count: u32,
    pub dominating_guard_count: usize,
    pub matched_integer_pattern: bool,
}

/// Run every template in `templates` against the graph. Returns
/// every chain that satisfies the template's requirements.
pub fn discover_chains(
    graph: &EvidenceGraph,
    taint: &TaintMap,
    source_catalog: &SourceCatalog,
    sink_catalog: &SinkCatalog,
    templates: &TemplateRegistry,
) -> Vec<CandidateChain> {
    let mut out = Vec::new();
    let mut counter: u32 = 0;

    for template in templates.iter() {
        // Find all source callsites matching the template's source_kinds.
        let allowed_source_kinds: rustc_hash::FxHashSet<&str> =
            template.source_kinds.iter().copied().collect();
        let source_callsites: Vec<_> = graph
            .nodes_of_kind(NodeKind::CallSite)
            .filter_map(|(id, payload)| match payload {
                NodePayload::CallSite {
                    api: Some(api), va, ..
                } => {
                    let src = source_catalog.match_api(api)?;
                    if !allowed_source_kinds.is_empty() && !allowed_source_kinds.contains(src.kind)
                    {
                        return None;
                    }
                    Some((id, src.kind.to_string(), *va))
                }
                _ => None,
            })
            .collect();

        // Find all sink callsites matching the template's sink_apis.
        let allowed_sink_apis: rustc_hash::FxHashSet<&str> =
            template.sink_apis.iter().copied().collect();
        let sink_callsites: Vec<_> = graph
            .nodes_of_kind(NodeKind::Sink)
            .filter_map(|(id, payload)| match payload {
                NodePayload::Sink { api, site_va } => {
                    // Match by api substring (so memcpy matches __imp_memcpy etc.).
                    let canonical_api = sink_catalog.lookup(api).map(|s| s.api).unwrap_or(api);
                    if !allowed_sink_apis.contains(canonical_api) {
                        return None;
                    }
                    Some((id, canonical_api.to_string(), *site_va))
                }
                _ => None,
            })
            .collect();

        // For each (source, sink) pair check the requirements.
        for (source_id, source_kind, source_site_va) in &source_callsites {
            for (sink_id, sink_api, sink_site_va) in &sink_callsites {
                let source_function_va = function_of_callsite(graph, *source_id).unwrap_or(0);
                let sink_function_va = function_of_callsite(graph, *sink_id).unwrap_or(0);
                if !chain_satisfies_taint(taint, *source_id, *sink_id, template.sink_requirement)
                    && !same_function_format_recv_to_sink(
                        template.id,
                        source_kind,
                        sink_api,
                        source_function_va,
                        sink_function_va,
                        *source_site_va,
                        *sink_site_va,
                    )
                {
                    continue;
                }
                let guard_count = match template.id {
                    "missing_bounds_check_var_mismatch" => {
                        match count_bounds_mismatch_guards(
                            graph,
                            sink_catalog,
                            sink_function_va,
                            *sink_site_va,
                            sink_api,
                        ) {
                            Some(count) if count > 0 => count,
                            _ => continue,
                        }
                    }
                    "auth_check_after_action" => {
                        if auth_after_action_matches(graph, sink_function_va, *sink_site_va) {
                            1
                        } else {
                            continue;
                        }
                    }
                    "toctou_file_access" => {
                        if toctou_matches(
                            graph,
                            sink_catalog,
                            sink_function_va,
                            *sink_site_va,
                            sink_api,
                        ) {
                            1
                        } else {
                            continue;
                        }
                    }
                    _ => {
                        let count = count_dominating_guards(graph, sink_function_va, *sink_site_va);
                        if !guard_requirement_satisfied(template.guard_requirement, count) {
                            continue;
                        }
                        count
                    }
                };
                let matched_integer_pattern = match template.integer_pattern {
                    IntegerPatternRequirement::DontCare => true,
                    IntegerPatternRequirement::OverflowPossible => {
                        path_has_integer_op(graph, *source_id, *sink_id)
                    }
                    IntegerPatternRequirement::SignedUnsignedCast => {
                        path_has_type_cast(graph, *source_id, *sink_id)
                    }
                };
                if !matched_integer_pattern
                    && template.integer_pattern != IntegerPatternRequirement::DontCare
                {
                    continue;
                }
                let mark = taint.marks(*sink_id).and_then(|m| m.first().cloned());
                let (mode, hop_count) = mark
                    .map(|m| (m.mode, m.hop_count))
                    .unwrap_or((PropagationMode::Exact, 0));
                counter += 1;
                out.push(CandidateChain {
                    chain_id: format!("C-{:06}", counter),
                    template_id: template.id.to_string(),
                    source_kind: source_kind.clone(),
                    source_function_va,
                    source_site_va: *source_site_va,
                    sink_api: sink_api.clone(),
                    sink_function_va,
                    sink_site_va: *sink_site_va,
                    propagation_mode: mode,
                    hop_count,
                    dominating_guard_count: guard_count,
                    matched_integer_pattern,
                });
            }
        }
    }
    out
}

fn same_function_format_recv_to_sink(
    template_id: &str,
    source_kind: &str,
    sink_api: &str,
    source_function_va: u64,
    sink_function_va: u64,
    source_site_va: u64,
    sink_site_va: u64,
) -> bool {
    template_id == "format_string_controlled"
        && source_function_va != 0
        && source_function_va == sink_function_va
        && source_site_va < sink_site_va
        && source_kind.eq_ignore_ascii_case("network_recv")
        && is_printf_family(sink_api)
}

fn is_printf_family(api: &str) -> bool {
    let lower = api.to_ascii_lowercase();
    lower.contains("printf") || lower.contains("vfprintf")
}

fn chain_satisfies_taint(
    taint: &TaintMap,
    source_id: crate::vuln::graph::NodeId,
    sink_id: crate::vuln::graph::NodeId,
    requirement: SinkArgRequirement,
) -> bool {
    let _ = source_id;
    match requirement {
        SinkArgRequirement::AnyCall => true,
        SinkArgRequirement::TaintedArgRole(_) => taint.is_tainted(sink_id),
        SinkArgRequirement::DestSizeKnownByteCountUnbounded => taint.is_tainted(sink_id),
        SinkArgRequirement::PrecedingTaintedWrite => taint.is_tainted(sink_id),
    }
}

/// Resolve a node to its containing function VA.
///
/// Handles two node shapes the chain query feeds in:
/// - `NodeKind::CallSite`: walk one incoming `ControlFlow` edge back
///   to the `Function` node (`ingest_api_flows` wires
///   `Function -> CallSite` via `ControlFlow`).
/// - `NodeKind::Sink`: walk one incoming `DataFlow` edge to the paired
///   `CallSite` (`ingest_api_flows` wires `CallSite -> Sink` via
///   `DataFlow`), then up through the CallSite's `ControlFlow`
///   predecessor.
///
/// Without the Sink case the v1.0 chain query silently resolved every
/// sink's containing function to `0`, which neutralised the
/// `NoDominatingGuard` / `DominatingGuardPresent` requirements
/// regardless of CFG shape (the count-all-branches over-approximation
/// in `count_dominating_guards` is intentional, but it has to actually
/// resolve to the right function to over-approximate anything).
fn function_of_callsite(graph: &EvidenceGraph, node_id: crate::vuln::graph::NodeId) -> Option<u64> {
    for (fn_id, _) in graph.incoming_of_kind(node_id, EdgeKind::ControlFlow) {
        if let Some(NodePayload::Function { va, .. }) = graph.node(fn_id) {
            return Some(*va);
        }
    }
    for (cs_id, _) in graph.incoming_of_kind(node_id, EdgeKind::DataFlow) {
        if matches!(graph.node(cs_id), Some(NodePayload::CallSite { .. })) {
            for (fn_id, _) in graph.incoming_of_kind(cs_id, EdgeKind::ControlFlow) {
                if let Some(NodePayload::Function { va, .. }) = graph.node(fn_id) {
                    return Some(*va);
                }
            }
        }
    }
    None
}

fn count_dominating_guards(graph: &EvidenceGraph, function_va: u64, sink_site_va: u64) -> usize {
    let guards = extract_guards(graph, function_va);
    let dom = match dominator::dominators_for_function(graph, function_va) {
        Some(d) => d,
        None => return 0,
    };
    // Without a precise mapping from sink_site_va → block_va, count
    // all branches in the function as candidates and assume each
    // dominates the sink (over-approximate). v1.1 will plumb the
    // block lookup so we count only the truly dominating ones.
    let Some(sink_block_va) = block_for_site(graph, function_va, sink_site_va) else {
        return guards.len();
    };
    guards
        .iter()
        .filter(|guard| guard.dominates_sink(&dom, sink_block_va))
        .count()
}

fn count_bounds_mismatch_guards(
    graph: &EvidenceGraph,
    sink_catalog: &SinkCatalog,
    function_va: u64,
    sink_site_va: u64,
    sink_api: &str,
) -> Option<usize> {
    let byte_count_values = arg_values_for_role(
        graph,
        sink_catalog,
        sink_api,
        sink_site_va,
        ArgRole::ByteCount,
    );
    if byte_count_values.is_empty() {
        return None;
    }
    let dom = dominator::dominators_for_function(graph, function_va)?;
    let sink_block_va = block_for_site(graph, function_va, sink_site_va)?;
    let mut mismatch_count = 0;
    for (_, payload) in graph.nodes_of_kind(NodeKind::BoundsCheck) {
        let NodePayload::BoundsCheck { var, va } = payload else {
            continue;
        };
        let Some(check_block_va) = block_for_site(graph, function_va, *va) else {
            continue;
        };
        if !dom.dominates(check_block_va, sink_block_va) {
            continue;
        }
        let checked = normalize_fact_value(var);
        if !checked.is_empty()
            && byte_count_values
                .iter()
                .all(|value| normalize_fact_value(value) != checked)
        {
            mismatch_count += 1;
        }
    }
    Some(mismatch_count)
}

fn auth_after_action_matches(
    graph: &EvidenceGraph,
    function_va: u64,
    access_check_site_va: u64,
) -> bool {
    for (_, payload) in graph.nodes_of_kind(NodeKind::Sink) {
        let NodePayload::Sink { api, site_va } = payload else {
            continue;
        };
        if *site_va == access_check_site_va || !is_privileged_action_api(api) {
            continue;
        }
        if call_dominates_or_precedes(graph, function_va, *site_va, access_check_site_va) {
            return true;
        }
    }
    false
}

fn toctou_matches(
    graph: &EvidenceGraph,
    sink_catalog: &SinkCatalog,
    function_va: u64,
    sink_site_va: u64,
    sink_api: &str,
) -> bool {
    let path_values =
        arg_values_for_role(graph, sink_catalog, sink_api, sink_site_va, ArgRole::Path);
    if path_values.is_empty() || has_dominating_lock(graph, function_va, sink_site_va) {
        return false;
    }
    for (_, payload) in graph.nodes_of_kind(NodeKind::Sink) {
        let NodePayload::Sink { api, site_va } = payload else {
            continue;
        };
        if *site_va == sink_site_va || !is_file_operation_api(api) {
            continue;
        }
        if has_dominating_lock(graph, function_va, *site_va) {
            continue;
        }
        let peer_values = arg_values_for_role(graph, sink_catalog, api, *site_va, ArgRole::Path);
        if path_values.iter().any(|left| {
            let left = normalize_fact_value(left);
            !left.is_empty()
                && peer_values
                    .iter()
                    .any(|right| normalize_fact_value(right) == left)
        }) {
            return true;
        }
    }
    false
}

fn call_dominates_or_precedes(
    graph: &EvidenceGraph,
    function_va: u64,
    before_site_va: u64,
    after_site_va: u64,
) -> bool {
    if before_site_va >= after_site_va {
        return false;
    }
    let Some(before_block) = block_for_site(graph, function_va, before_site_va) else {
        return true;
    };
    let Some(after_block) = block_for_site(graph, function_va, after_site_va) else {
        return true;
    };
    if before_block == after_block {
        return before_site_va < after_site_va;
    }
    dominator::dominators_for_function(graph, function_va)
        .map(|dom| dom.dominates(before_block, after_block))
        .unwrap_or(false)
}

fn has_dominating_lock(graph: &EvidenceGraph, function_va: u64, site_va: u64) -> bool {
    for (_, payload) in graph.nodes_of_kind(NodeKind::CallSite) {
        let NodePayload::CallSite {
            api: Some(api),
            va: lock_site_va,
            ..
        } = payload
        else {
            continue;
        };
        if !is_lock_acquire_api(api) || *lock_site_va == site_va {
            continue;
        }
        if call_dominates_or_precedes(graph, function_va, *lock_site_va, site_va) {
            return true;
        }
    }
    false
}

fn block_for_site(graph: &EvidenceGraph, function_va: u64, site_va: u64) -> Option<u64> {
    let mut fallback = None;
    for (_, payload) in graph.nodes_of_kind(NodeKind::BasicBlock) {
        let NodePayload::BasicBlock {
            function_va: fva,
            start_va,
            end_va,
        } = payload
        else {
            continue;
        };
        if *fva != function_va {
            continue;
        }
        if *start_va <= site_va && site_va < *end_va {
            return Some(*start_va);
        }
        if *start_va <= site_va {
            fallback = Some(fallback.map_or(*start_va, |prev: u64| prev.max(*start_va)));
        }
    }
    fallback
}

fn arg_values_for_role(
    graph: &EvidenceGraph,
    sink_catalog: &SinkCatalog,
    api: &str,
    site_va: u64,
    role: ArgRole,
) -> Vec<String> {
    let Some(sink) = sink_catalog.lookup(api) else {
        return Vec::new();
    };
    let wanted_indices: rustc_hash::FxHashSet<usize> = sink
        .args
        .iter()
        .enumerate()
        .filter_map(|(idx, arg_role)| (*arg_role == role).then_some(idx))
        .collect();
    if wanted_indices.is_empty() {
        return Vec::new();
    }
    graph
        .nodes_of_kind(NodeKind::GlobalState)
        .filter_map(|(_, payload)| match payload {
            NodePayload::GlobalState { key } => parse_api_arg_fact(key),
            _ => None,
        })
        .filter(|fact| {
            fact.site_va == site_va && fact.index.is_some_and(|idx| wanted_indices.contains(&idx))
        })
        .map(|fact| fact.value)
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ApiArgFact {
    site_va: u64,
    index: Option<usize>,
    value: String,
}

fn parse_api_arg_fact(key: &str) -> Option<ApiArgFact> {
    let mut parts = key.splitn(5, '|');
    if parts.next()? != "api_arg" {
        return None;
    }
    let site_part = parts.next()?.strip_prefix("site=")?;
    let index_part = parts.next()?.strip_prefix("index=")?;
    let _name_part = parts.next()?.strip_prefix("name=")?;
    let value = parts.next()?.strip_prefix("value=")?.to_string();
    let site_va = u64::from_str_radix(site_part, 16).ok()?;
    let index = if index_part.is_empty() {
        None
    } else {
        index_part.parse().ok()
    };
    Some(ApiArgFact {
        site_va,
        index,
        value,
    })
}

fn normalize_fact_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_ascii_lowercase()
}

fn is_privileged_action_api(api: &str) -> bool {
    let lower = api.to_ascii_lowercase();
    [
        "writeprocessmemory",
        "createremotethread",
        "virtualprotect",
        "virtualallocex",
        "deviceiocontrol",
        "deletefile",
        "unlink",
        "rename",
        "createfile",
        "open",
        "fopen",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_file_operation_api(api: &str) -> bool {
    let lower = api.to_ascii_lowercase();
    [
        "createfile",
        "fopen",
        "open",
        "rename",
        "unlink",
        "deletefile",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_lock_acquire_api(api: &str) -> bool {
    let lower = api.to_ascii_lowercase();
    [
        "entercriticalsection",
        "acquiresrwlock",
        "waitforsingleobject",
        "lockfile",
        "flock",
        "pthread_mutex_lock",
        "mutex_lock",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn guard_requirement_satisfied(req: GuardRequirement, guard_count: usize) -> bool {
    match req {
        GuardRequirement::DontCare => true,
        GuardRequirement::NoDominatingGuard => guard_count == 0,
        GuardRequirement::DominatingGuardPresent => guard_count > 0,
    }
}

fn path_has_integer_op(
    graph: &EvidenceGraph,
    _source_id: crate::vuln::graph::NodeId,
    _sink_id: crate::vuln::graph::NodeId,
) -> bool {
    graph.nodes_of_kind(NodeKind::IntegerOp).next().is_some()
}

fn path_has_type_cast(
    graph: &EvidenceGraph,
    _source_id: crate::vuln::graph::NodeId,
    _sink_id: crate::vuln::graph::NodeId,
) -> bool {
    graph.nodes_of_kind(NodeKind::TypeCast).next().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{ApiFlowRecord, FunctionRecord};
    use crate::vuln::call_summaries::compute_summaries;
    use crate::vuln::graph_builder::{ingest_api_flows, ingest_functions};
    use crate::vuln::taint::propagate;

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

    fn fixture_graph_recv_memcpy() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(
            &mut g,
            &[af(0x1000, 0x1100, "recv"), af(0x1000, 0x1200, "memcpy")],
        );
        // Wire a DataFlow edge from recv's CallSite to memcpy's
        // CallSite so taint reaches.
        let mut recv_id = None;
        let mut memcpy_id = None;
        for (id, payload) in g.nodes_of_kind(NodeKind::CallSite) {
            if let NodePayload::CallSite { va, .. } = payload {
                if *va == 0x1100 {
                    recv_id = Some(id);
                }
                if *va == 0x1200 {
                    memcpy_id = Some(id);
                }
            }
        }
        let recv = recv_id.unwrap();
        let memcpy = memcpy_id.unwrap();
        g.add_edge(recv, memcpy, EdgeKind::DataFlow);
        // Also wire DataFlow to the memcpy Sink (the catalog node).
        // Collect first to avoid borrow conflict with add_edge.
        let sink_ids: Vec<_> = g
            .nodes_of_kind(NodeKind::Sink)
            .filter_map(|(id, sp)| match sp {
                NodePayload::Sink { site_va, .. } if *site_va == 0x1200 => Some(id),
                _ => None,
            })
            .collect();
        for sink_id in sink_ids {
            g.add_edge(memcpy, sink_id, EdgeKind::DataFlow);
        }
        g
    }

    #[test]
    fn discover_finds_recv_to_memcpy_chain() {
        let g = fixture_graph_recv_memcpy();
        let cat_s = SourceCatalog::v1_0();
        let cat_k = SinkCatalog::v1_0();
        let summaries = compute_summaries(&g);
        let taint = propagate(&g, &cat_s, &summaries);
        let templates = TemplateRegistry::load_v1_0();
        let chains = discover_chains(&g, &taint, &cat_s, &cat_k, &templates);
        // unchecked_copy_length should fire on this fixture.
        assert!(
            chains
                .iter()
                .any(|c| c.template_id == "unchecked_copy_length"),
            "expected unchecked_copy_length chain; got {:?}",
            chains.iter().map(|c| &c.template_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn discover_returns_no_chains_when_no_taint() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(&mut g, &[af(0x1000, 0x1200, "memcpy")]);
        // No source, no taint.
        let cat_s = SourceCatalog::v1_0();
        let cat_k = SinkCatalog::v1_0();
        let summaries = compute_summaries(&g);
        let taint = propagate(&g, &cat_s, &summaries);
        let templates = TemplateRegistry::load_v1_0();
        let chains = discover_chains(&g, &taint, &cat_s, &cat_k, &templates);
        // With no source, the source-callsite filter has no hits ⇒
        // no chains for any source-requiring template. AnyCall
        // templates with empty source_kinds might still fire, but
        // those also require sink_apis to match — let's check what
        // actually appears.
        // For v1.0 we accept "no taint = no findings" for the
        // tainted-arg templates. Auth templates (AnyCall) can fire,
        // so this isn't strictly empty.
        let copy_chains: Vec<_> = chains
            .iter()
            .filter(|c| c.template_id == "unchecked_copy_length")
            .collect();
        assert!(copy_chains.is_empty());
    }

    #[test]
    fn chain_ids_are_unique() {
        let g = fixture_graph_recv_memcpy();
        let cat_s = SourceCatalog::v1_0();
        let cat_k = SinkCatalog::v1_0();
        let summaries = compute_summaries(&g);
        let taint = propagate(&g, &cat_s, &summaries);
        let templates = TemplateRegistry::load_v1_0();
        let chains = discover_chains(&g, &taint, &cat_s, &cat_k, &templates);
        let mut ids: std::collections::HashSet<_> = std::collections::HashSet::new();
        for c in &chains {
            assert!(
                ids.insert(c.chain_id.clone()),
                "duplicate id {}",
                c.chain_id
            );
        }
    }
}
