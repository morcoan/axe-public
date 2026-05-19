//! Lifetime templates — **Codex round-1 finding 3 fix**.
//!
//! The plan's round-1 review flagged lifetime detectors (UAF,
//! double-free) as too noisy for default emission: SSA-equality
//! aliasing catches trivial cases, misses real chains through
//! field-store / wrapper-free / pointer-copy patterns, and false-
//! positives on benign cleanup. The fix has three layers, all
//! enforced from this module:
//!
//! 1. **Opt-in only.** This module is gated by the
//!    `vuln-discovery-lifetime` Cargo feature AND by the runtime
//!    flag `--vuln-include-lifetime` (Step 35). Build a binary
//!    without the feature and lifetime code does not compile.
//! 2. **Separate artifact.** Lifetime findings emit to
//!    `vuln/lifetime_candidates.jsonl`, never `findings.jsonl`
//!    (wired in Step 34). The `evidence_bundle.json` top-N
//!    selection EXCLUDES them by construction.
//! 3. **Candidate tier + 0.65 confidence cap.** Even when a chain
//!    is emitted, the wire shape signals "best-guess, manually
//!    verify" via [`EvidenceTier::Candidate`] and a hard
//!    `confidence_cap` of 0.65.
//!
//! [`V1_1_LIFETIME_ALIAS_LIMITED_DETECTORS`] is a doc constant
//! enumerating every template id in this module — Step 36 reads it
//! to enforce the separate-artifact split at the session boundary.
//!
//! **Negative-fixture discipline** (Codex finding 3): each detector
//! has three negative fixtures (safe ownership patterns) that MUST
//! produce zero chains. These are inline tests below; CI will fail
//! before any lifetime template ships if a safe pattern produces a
//! candidate.

#![cfg(feature = "vuln-discovery-lifetime")]
#![allow(dead_code)]

use crate::vuln::alias::AliasGraph;
use crate::vuln::bug_class::{
    BugClass, EvidenceTier, GuardRequirement, IntegerPatternRequirement, SinkArgRequirement,
};
use crate::vuln::graph::{EdgeKind, EvidenceGraph, NodeId, NodeKind, NodePayload};
use crate::vuln::query::CandidateChain;
use crate::vuln::taint::PropagationMode;

/// Every lifetime template id. The session orchestrator (Step 36)
/// uses this list to decide which discovered chains route to
/// `lifetime_candidates.jsonl` vs `findings.jsonl`.
pub const V1_1_LIFETIME_ALIAS_LIMITED_DETECTORS: &[&str] =
    &["uaf_candidate", "double_free_candidate"];

/// Lifetime templates registered when the
/// `vuln-discovery-lifetime` feature is enabled. Both are
/// [`EvidenceTier::Candidate`] with a 0.65 confidence cap.
pub fn register() -> Vec<BugClass> {
    vec![
        BugClass {
            id: "uaf_candidate",
            name: "Use-after-free candidate",
            category: "lifetime",
            // source_kinds / sink_apis intentionally empty so the
            // generic `discover_chains` skips this template — UAF
            // detection lives in `discover_lifetime_candidates` below.
            source_kinds: &[],
            sink_apis: &[],
            sink_requirement: SinkArgRequirement::AnyCall,
            guard_requirement: GuardRequirement::DontCare,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::Candidate,
            confidence_cap: Some(0.65),
            description: "Pointer used after a free()-class call (SSA-equality alias only; intentionally limited per Codex finding 3 — manually verify before action).",
        },
        BugClass {
            id: "double_free_candidate",
            name: "Double-free candidate",
            category: "lifetime",
            source_kinds: &[],
            sink_apis: &[],
            sink_requirement: SinkArgRequirement::AnyCall,
            guard_requirement: GuardRequirement::DontCare,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::Candidate,
            confidence_cap: Some(0.65),
            description: "Same pointer passed to a free()-class call twice (SSA-equality alias only; intentionally limited per Codex finding 3 — manually verify before action).",
        },
    ]
}

/// Discover lifetime candidates on the evidence graph.
///
/// Run as a SEPARATE pass from the generic `discover_chains` (which
/// skips these templates because their source_kinds / sink_apis are
/// empty). The session orchestrator (Step 36) calls this only when
/// `--vuln-include-lifetime` is on.
///
/// Detection is SSA-equality-only via [`AliasGraph`]; this means:
/// - Many real UAF / double-free chains will be MISSED (field stores,
///   pointer-copy through wrapper structs, opaque allocator
///   ownership).
/// - Some safe patterns may FIRE (alias overflow into post-free
///   instructions that compiler reordered).
///
/// Both directions of error are why the templates ship as
/// `Candidate` tier with a `confidence_cap` of 0.65.
pub fn discover_lifetime_candidates(graph: &EvidenceGraph) -> Vec<CandidateChain> {
    let alias = AliasGraph::build(graph);
    let free_sites = collect_free_callsites(graph);
    let mut out = Vec::new();
    let mut counter: u32 = 0;
    out.extend(discover_double_free(
        graph,
        &alias,
        &free_sites,
        &mut counter,
    ));
    out.extend(discover_uaf(graph, &alias, &free_sites, &mut counter));
    out
}

/// One free()-class callsite + its incoming SSA pointer (if any).
#[derive(Clone, Copy, Debug)]
struct FreeCallsite {
    callsite_id: NodeId,
    callsite_va: u64,
    pointer_ssa: Option<NodeId>,
}

fn collect_free_callsites(graph: &EvidenceGraph) -> Vec<FreeCallsite> {
    let mut out = Vec::new();
    for (id, payload) in graph.nodes_of_kind(NodeKind::CallSite) {
        if let NodePayload::CallSite {
            api: Some(api), va, ..
        } = payload
        {
            if !is_free_api(api) {
                continue;
            }
            // First incoming DataFlow from a Copy node is the
            // pointer argument (canonical convention from
            // ingest_api_flows: arg 0 is the first incoming edge).
            let pointer_ssa =
                graph
                    .incoming_of_kind(id, EdgeKind::DataFlow)
                    .find_map(|(src, _)| match graph.node(src) {
                        Some(NodePayload::Copy { .. }) => Some(src),
                        _ => None,
                    });
            out.push(FreeCallsite {
                callsite_id: id,
                callsite_va: *va,
                pointer_ssa,
            });
        }
    }
    out
}

/// `true` for canonical free()-class APIs. Substring-insensitive
/// match to handle decorated symbols (`__imp_free`, `kernel32!HeapFree`).
fn is_free_api(api: &str) -> bool {
    let lower = api.to_lowercase();
    [
        "free",
        "heapfree",
        "localfree",
        "globalfree",
        "rtlfreeheap",
        "virtualfree",
        "operator delete",
        "kfree",
        "g_free",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn discover_double_free(
    graph: &EvidenceGraph,
    alias: &AliasGraph,
    free_sites: &[FreeCallsite],
    counter: &mut u32,
) -> Vec<CandidateChain> {
    let mut out = Vec::new();
    for i in 0..free_sites.len() {
        let a = free_sites[i];
        let Some(ptr_a) = a.pointer_ssa else { continue };
        for j in (i + 1)..free_sites.len() {
            let b = free_sites[j];
            let Some(ptr_b) = b.pointer_ssa else { continue };
            if !alias.may_alias(ptr_a, ptr_b) {
                continue;
            }
            *counter += 1;
            out.push(CandidateChain {
                chain_id: format!("L-DF-{:06}", *counter),
                template_id: "double_free_candidate".into(),
                source_kind: "free".into(),
                source_function_va: callsite_function_va(graph, a.callsite_id).unwrap_or(0),
                source_site_va: a.callsite_va,
                sink_api: "free".into(),
                sink_function_va: callsite_function_va(graph, b.callsite_id).unwrap_or(0),
                sink_site_va: b.callsite_va,
                propagation_mode: PropagationMode::Exact,
                hop_count: 0,
                dominating_guard_count: 0,
                matched_integer_pattern: false,
            });
        }
    }
    out
}

fn discover_uaf(
    graph: &EvidenceGraph,
    alias: &AliasGraph,
    free_sites: &[FreeCallsite],
    counter: &mut u32,
) -> Vec<CandidateChain> {
    let mut out = Vec::new();
    for free in free_sites {
        let Some(ptr) = free.pointer_ssa else {
            continue;
        };
        // Look for OTHER CallSites that consume an SSA-aliased
        // pointer. Free→free pairs are double-free, not UAF — exclude
        // those by skipping free callsites.
        let mut found_non_free_use = false;
        let mut other_use_va: u64 = 0;
        let mut other_use_function_va: u64 = 0;
        for (other_id, payload) in graph.nodes_of_kind(NodeKind::CallSite) {
            if other_id == free.callsite_id {
                continue;
            }
            let (api, va) = match payload {
                NodePayload::CallSite {
                    api: Some(api), va, ..
                } => (api, *va),
                _ => continue,
            };
            if is_free_api(api) {
                continue; // double-free territory, handled separately
            }
            // Is any incoming Copy pointer for `other` aliased to ptr?
            for (src, _) in graph.incoming_of_kind(other_id, EdgeKind::DataFlow) {
                if matches!(graph.node(src), Some(NodePayload::Copy { .. }))
                    && alias.may_alias(src, ptr)
                {
                    found_non_free_use = true;
                    other_use_va = va;
                    other_use_function_va = callsite_function_va(graph, other_id).unwrap_or(0);
                    break;
                }
            }
            if found_non_free_use {
                break;
            }
        }
        if !found_non_free_use {
            continue;
        }
        *counter += 1;
        out.push(CandidateChain {
            chain_id: format!("L-UAF-{:06}", *counter),
            template_id: "uaf_candidate".into(),
            source_kind: "free".into(),
            source_function_va: callsite_function_va(graph, free.callsite_id).unwrap_or(0),
            source_site_va: free.callsite_va,
            sink_api: "use_after_free".into(),
            sink_function_va: other_use_function_va,
            sink_site_va: other_use_va,
            propagation_mode: PropagationMode::Exact,
            hop_count: 0,
            dominating_guard_count: 0,
            matched_integer_pattern: false,
        });
    }
    out
}

fn callsite_function_va(graph: &EvidenceGraph, callsite_id: NodeId) -> Option<u64> {
    for (fn_id, _) in graph.incoming_of_kind(callsite_id, EdgeKind::ControlFlow) {
        if let Some(NodePayload::Function { va, .. }) = graph.node(fn_id) {
            return Some(*va);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{ApiFlowRecord, DataflowEdgeRecord, FunctionRecord, SsaValueRecord};
    use crate::vuln::bug_class::TemplateRegistry;
    use crate::vuln::graph_builder::{
        ingest_api_flows, ingest_dataflow, ingest_functions, ingest_ssa,
    };

    // ----- Doc constant + template registration -----

    #[test]
    fn v1_1_lifetime_constant_lists_both_detectors() {
        assert_eq!(V1_1_LIFETIME_ALIAS_LIMITED_DETECTORS.len(), 2);
        assert!(V1_1_LIFETIME_ALIAS_LIMITED_DETECTORS.contains(&"uaf_candidate"));
        assert!(V1_1_LIFETIME_ALIAS_LIMITED_DETECTORS.contains(&"double_free_candidate"));
    }

    #[test]
    fn lifetime_templates_are_candidate_tier_with_0_65_cap() {
        // Codex finding 3 invariant baked in: never GroundTruth /
        // BestEffort; cap always 0.65.
        for t in register() {
            assert_eq!(t.evidence_tier, EvidenceTier::Candidate);
            assert_eq!(t.confidence_cap, Some(0.65));
            assert_eq!(t.category, "lifetime");
        }
    }

    #[test]
    fn lifetime_templates_have_empty_sink_apis_so_generic_query_skips_them() {
        // The lifetime detector runs as a SEPARATE pass; the generic
        // chain query MUST skip these templates so they don't fire
        // through the wrong code path.
        for t in register() {
            assert!(t.sink_apis.is_empty(), "{} must have empty sink_apis", t.id);
            assert!(
                t.source_kinds.is_empty(),
                "{} must have empty source_kinds",
                t.id
            );
        }
    }

    #[test]
    fn registry_loads_two_lifetime_templates_separately_from_v1_0() {
        // Existing TemplateRegistry::load_v1_0 must still return 12;
        // lifetime templates are explicitly NOT loaded into the
        // default registry. (Step 35 will wire the opt-in registry
        // builder.)
        assert_eq!(TemplateRegistry::load_v1_0().len(), 12);
        assert_eq!(register().len(), 2);
    }

    // ----- Helpers for building fixtures -----

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
            argument_name: Some("ptr".into()),
            confidence: "high".into(),
            mode: "static".into(),
            resolved_api: None,
            wrapper_chain: vec![],
            evidence: vec![],
        }
    }

    fn find_callsite_by_va(g: &EvidenceGraph, va: u64) -> NodeId {
        for (id, payload) in g.nodes_of_kind(NodeKind::CallSite) {
            if let NodePayload::CallSite { va: site, .. } = payload {
                if *site == va {
                    return id;
                }
            }
        }
        panic!("no callsite at 0x{va:x}");
    }

    // ----- Positive UAF fixture -----

    /// Shape: alloc → Copy a → free, also Copy a → use_other.
    /// Detector MUST fire.
    fn positive_uaf_fixture() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(
            &mut g,
            &[
                api_flow(0x1000, 0x1100, "malloc"),
                api_flow(0x1000, 0x1200, "free"),
                api_flow(0x1000, 0x1300, "memcpy"),
            ],
        );
        let idx = ingest_ssa(&mut g, &[ssa("p_a", 0x1100)]);
        ingest_dataflow(&mut g, &[dflow("p_a", "p_a")], &idx); // self-loop to ensure Copy
                                                               // Wire Copy p_a into both free and memcpy as their pointer arg.
        let p_a = idx["p_a"];
        let free_cs = find_callsite_by_va(&g, 0x1200);
        let use_cs = find_callsite_by_va(&g, 0x1300);
        g.add_edge(p_a, free_cs, EdgeKind::DataFlow);
        g.add_edge(p_a, use_cs, EdgeKind::DataFlow);
        g
    }

    #[test]
    fn positive_uaf_fixture_fires_uaf_candidate() {
        let g = positive_uaf_fixture();
        let chains = discover_lifetime_candidates(&g);
        assert!(
            chains.iter().any(|c| c.template_id == "uaf_candidate"),
            "expected uaf_candidate; got {:?}",
            chains.iter().map(|c| &c.template_id).collect::<Vec<_>>()
        );
    }

    // ----- Negative UAF fixtures (Codex finding 3, 3 patterns) -----

    /// NEGATIVE 1: "no use elsewhere" — free is called but the
    /// pointer's SSA is not consumed by any other callsite.
    /// Equivalent to a clean cleanup.
    fn negative_uaf_no_other_use() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(
            &mut g,
            &[
                api_flow(0x1000, 0x1100, "malloc"),
                api_flow(0x1000, 0x1200, "free"),
            ],
        );
        let idx = ingest_ssa(&mut g, &[ssa("p", 0x1100)]);
        ingest_dataflow(&mut g, &[dflow("p", "p")], &idx);
        let p = idx["p"];
        let free_cs = find_callsite_by_va(&g, 0x1200);
        g.add_edge(p, free_cs, EdgeKind::DataFlow);
        g
    }

    /// NEGATIVE 2: "move breaks SSA equality" — the use happens on a
    /// DIFFERENT SSA value (e.g. after a wrapper move). No alias
    /// between the freed pointer and the used pointer.
    fn negative_uaf_move_breaks_ssa() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(
            &mut g,
            &[
                api_flow(0x1000, 0x1100, "malloc"),
                api_flow(0x1000, 0x1200, "free"),
                api_flow(0x1000, 0x1300, "memcpy"),
            ],
        );
        // p_freed and p_used are DIFFERENT SSAs with no DataFlow
        // edge between them — alias class disjoint.
        let idx = ingest_ssa(&mut g, &[ssa("p_freed", 0x1100), ssa("p_used", 0x1150)]);
        // Self-loops to materialize the Copy nodes.
        ingest_dataflow(
            &mut g,
            &[dflow("p_freed", "p_freed"), dflow("p_used", "p_used")],
            &idx,
        );
        let pf = idx["p_freed"];
        let pu = idx["p_used"];
        let free_cs = find_callsite_by_va(&g, 0x1200);
        let use_cs = find_callsite_by_va(&g, 0x1300);
        g.add_edge(pf, free_cs, EdgeKind::DataFlow);
        g.add_edge(pu, use_cs, EdgeKind::DataFlow);
        g
    }

    /// NEGATIVE 3: "RAII wrapper" — no direct `free` call in the
    /// observable chain. The wrapper consumes the pointer; from the
    /// outside, all we see is the wrapper call. Without an explicit
    /// free callsite, the detector cannot fire.
    fn negative_uaf_raii_wrapper() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(
            &mut g,
            &[
                api_flow(0x1000, 0x1100, "malloc"),
                // wrapper_destroy is a non-free callsite that
                // internally cleans up; from this graph's perspective
                // there is NO free.
                api_flow(0x1000, 0x1200, "wrapper_destroy"),
            ],
        );
        let idx = ingest_ssa(&mut g, &[ssa("p", 0x1100)]);
        ingest_dataflow(&mut g, &[dflow("p", "p")], &idx);
        let p = idx["p"];
        let wrapper_cs = find_callsite_by_va(&g, 0x1200);
        g.add_edge(p, wrapper_cs, EdgeKind::DataFlow);
        g
    }

    #[test]
    fn negative_uaf_no_other_use_produces_zero_candidates() {
        let g = negative_uaf_no_other_use();
        let chains = discover_lifetime_candidates(&g);
        let uaf: Vec<_> = chains
            .iter()
            .filter(|c| c.template_id == "uaf_candidate")
            .collect();
        assert!(
            uaf.is_empty(),
            "safe-cleanup pattern fired UAF; got {:?}",
            chains
        );
    }

    #[test]
    fn negative_uaf_move_breaks_ssa_produces_zero_candidates() {
        let g = negative_uaf_move_breaks_ssa();
        let chains = discover_lifetime_candidates(&g);
        let uaf: Vec<_> = chains
            .iter()
            .filter(|c| c.template_id == "uaf_candidate")
            .collect();
        assert!(
            uaf.is_empty(),
            "move-breaks-SSA pattern fired UAF; got {:?}",
            chains
        );
    }

    #[test]
    fn negative_uaf_raii_wrapper_produces_zero_candidates() {
        let g = negative_uaf_raii_wrapper();
        let chains = discover_lifetime_candidates(&g);
        let uaf: Vec<_> = chains
            .iter()
            .filter(|c| c.template_id == "uaf_candidate")
            .collect();
        assert!(
            uaf.is_empty(),
            "RAII wrapper pattern fired UAF; got {:?}",
            chains
        );
    }

    // ----- Positive double-free fixture -----

    /// Shape: Copy p → free A, Copy p → free B (same SSA).
    fn positive_double_free_fixture() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(
            &mut g,
            &[
                api_flow(0x1000, 0x1200, "free"),
                api_flow(0x1000, 0x1300, "free"),
            ],
        );
        let idx = ingest_ssa(&mut g, &[ssa("p", 0x1100)]);
        ingest_dataflow(&mut g, &[dflow("p", "p")], &idx);
        let p = idx["p"];
        let free1 = find_callsite_by_va(&g, 0x1200);
        let free2 = find_callsite_by_va(&g, 0x1300);
        g.add_edge(p, free1, EdgeKind::DataFlow);
        g.add_edge(p, free2, EdgeKind::DataFlow);
        g
    }

    #[test]
    fn positive_double_free_fixture_fires_double_free_candidate() {
        let g = positive_double_free_fixture();
        let chains = discover_lifetime_candidates(&g);
        assert!(
            chains
                .iter()
                .any(|c| c.template_id == "double_free_candidate"),
            "expected double_free_candidate; got {:?}",
            chains.iter().map(|c| &c.template_id).collect::<Vec<_>>()
        );
    }

    // ----- Negative double-free fixtures (3 patterns) -----

    /// NEGATIVE 1: single free — no pair to compare.
    fn negative_df_single_free() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(&mut g, &[api_flow(0x1000, 0x1200, "free")]);
        let idx = ingest_ssa(&mut g, &[ssa("p", 0x1100)]);
        ingest_dataflow(&mut g, &[dflow("p", "p")], &idx);
        let p = idx["p"];
        let free_cs = find_callsite_by_va(&g, 0x1200);
        g.add_edge(p, free_cs, EdgeKind::DataFlow);
        g
    }

    /// NEGATIVE 2: two free calls with NON-aliased pointer args
    /// (different SSA classes; common when two distinct objects are
    /// cleaned up in the same function).
    fn negative_df_different_pointers() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(
            &mut g,
            &[
                api_flow(0x1000, 0x1200, "free"),
                api_flow(0x1000, 0x1300, "free"),
            ],
        );
        let idx = ingest_ssa(&mut g, &[ssa("p1", 0x1100), ssa("p2", 0x1110)]);
        ingest_dataflow(&mut g, &[dflow("p1", "p1"), dflow("p2", "p2")], &idx);
        let p1 = idx["p1"];
        let p2 = idx["p2"];
        let free1 = find_callsite_by_va(&g, 0x1200);
        let free2 = find_callsite_by_va(&g, 0x1300);
        g.add_edge(p1, free1, EdgeKind::DataFlow);
        g.add_edge(p2, free2, EdgeKind::DataFlow);
        g
    }

    /// NEGATIVE 3: free→realloc→free pattern. Both frees are on
    /// DIFFERENT SSA versions (the realloc returns a new SSA). Safe.
    fn negative_df_free_realloc_free() -> EvidenceGraph {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000)]);
        ingest_api_flows(
            &mut g,
            &[
                api_flow(0x1000, 0x1200, "free"),
                api_flow(0x1000, 0x1250, "realloc"),
                api_flow(0x1000, 0x1300, "free"),
            ],
        );
        let idx = ingest_ssa(&mut g, &[ssa("p_v1", 0x1100), ssa("p_v2", 0x1260)]);
        ingest_dataflow(
            &mut g,
            &[dflow("p_v1", "p_v1"), dflow("p_v2", "p_v2")],
            &idx,
        );
        let pv1 = idx["p_v1"];
        let pv2 = idx["p_v2"];
        let free1 = find_callsite_by_va(&g, 0x1200);
        let free2 = find_callsite_by_va(&g, 0x1300);
        g.add_edge(pv1, free1, EdgeKind::DataFlow);
        g.add_edge(pv2, free2, EdgeKind::DataFlow);
        g
    }

    #[test]
    fn negative_df_single_free_produces_zero_candidates() {
        let g = negative_df_single_free();
        let chains = discover_lifetime_candidates(&g);
        let df: Vec<_> = chains
            .iter()
            .filter(|c| c.template_id == "double_free_candidate")
            .collect();
        assert!(df.is_empty(), "single-free fired DF; got {chains:?}");
    }

    #[test]
    fn negative_df_different_pointers_produces_zero_candidates() {
        let g = negative_df_different_pointers();
        let chains = discover_lifetime_candidates(&g);
        let df: Vec<_> = chains
            .iter()
            .filter(|c| c.template_id == "double_free_candidate")
            .collect();
        assert!(df.is_empty(), "different-pointers fired DF; got {chains:?}");
    }

    #[test]
    fn negative_df_free_realloc_free_produces_zero_candidates() {
        let g = negative_df_free_realloc_free();
        let chains = discover_lifetime_candidates(&g);
        let df: Vec<_> = chains
            .iter()
            .filter(|c| c.template_id == "double_free_candidate")
            .collect();
        assert!(df.is_empty(), "free-realloc-free fired DF; got {chains:?}");
    }

    // ----- API surface checks -----

    #[test]
    fn is_free_api_recognizes_canonical_names() {
        assert!(is_free_api("free"));
        assert!(is_free_api("__imp_free"));
        assert!(is_free_api("HeapFree"));
        assert!(is_free_api("kernel32!HeapFree"));
        assert!(is_free_api("RtlFreeHeap"));
        assert!(is_free_api("operator delete"));
        assert!(!is_free_api("malloc"));
        assert!(!is_free_api("memcpy"));
        assert!(!is_free_api("freopen")); // not a free
    }

    #[test]
    fn empty_graph_produces_zero_lifetime_candidates() {
        let g = EvidenceGraph::new();
        let chains = discover_lifetime_candidates(&g);
        assert!(chains.is_empty());
    }

    #[test]
    fn lifetime_chain_template_ids_match_v1_1_constant() {
        // Every produced chain's template_id must appear in the
        // documented constant — keeps the artifact split (Step 34)
        // synchronized with the detector output.
        let g = positive_uaf_fixture();
        let chains = discover_lifetime_candidates(&g);
        for c in &chains {
            assert!(
                V1_1_LIFETIME_ALIAS_LIMITED_DETECTORS.contains(&c.template_id.as_str()),
                "chain template_id {} not in V1_1_LIFETIME_ALIAS_LIMITED_DETECTORS",
                c.template_id
            );
        }
    }
}
