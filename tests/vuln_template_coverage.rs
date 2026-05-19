//! Per-template positive + negative fixture coverage for the 12 v1.0
//! templates.
//!
//! Closes two verification gaps from the v1.0 plan
//! (`~/.claude/plans/implement-the-right-design-rippling-acorn.md`):
//!
//! - **Step 20 verification**: "Each of 12 templates produces ≥1 chain
//!   on a tailored fixture." Each `*_fires_on_*` test exercises one
//!   template via the real `discover_chains` pipeline and asserts it
//!   produces a `CandidateChain` with the expected `template_id`.
//!
//! - **Step 23 / Codex preempt B (negative-fixture discipline)**:
//!   "Each template's negative fixture (with proper guard / cast /
//!   validation present) produces ZERO chains." Each
//!   `*_does_not_fire_when_*` test runs the corresponding template's
//!   defensive shape and asserts the template id is ABSENT from the
//!   chain set. Other templates may still fire on the same fixture;
//!   the tests only assert the specific template's behavior.
//!
//! Three historically coarse templates have explicit sharpened
//! positives and negatives here:
//! - `missing_bounds_check_var_mismatch` requires a BoundsCheck on a
//!   different variable than the copy byte-count arg.
//! - `auth_check_after_action` requires a privileged action before
//!   AccessCheck.
//! - `toctou_file_access` requires two file ops on the same path and
//!   no dominating lock call.

#![cfg(feature = "vuln-discovery")]

use axe_core::vuln::bug_class::TemplateRegistry;
use axe_core::vuln::call_summaries::compute_summaries;
use axe_core::vuln::graph::{EdgeKind, EvidenceGraph, NodeKind, NodePayload};
use axe_core::vuln::graph_builder::{ingest_api_flows, ingest_cfg, ingest_functions};
use axe_core::vuln::query::{discover_chains, CandidateChain};
use axe_core::vuln::sinks::SinkCatalog;
use axe_core::vuln::sources::SourceCatalog;
use axe_core::vuln::taint::propagate;
use axe_core::{ApiFlowRecord, BasicBlockRecord, CfgRecord, EdgeRecord, FunctionRecord};

// ---------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------

fn func(va: u64) -> FunctionRecord {
    FunctionRecord {
        start: va,
        end: va + 0x1000,
        size: 0x1000,
        source: "test".into(),
        calls: vec![],
        calls_imports: vec![],
        strings: vec![],
        xrefs: 0,
    }
}

fn api_flow(function: u64, callsite: u64, api: &str) -> ApiFlowRecord {
    api_flow_arg(function, callsite, api, 0, "dst", "rcx")
}

fn api_flow_arg(
    function: u64,
    callsite: u64,
    api: &str,
    argument_index: usize,
    argument_name: &str,
    value: &str,
) -> ApiFlowRecord {
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
        value: value.into(),
        value_tags: vec![],
        argument: argument_name.into(),
        argument_register: Some(argument_name.into()),
        argument_index: Some(argument_index),
        argument_name: Some(argument_name.into()),
        confidence: "high".into(),
        mode: "static".into(),
        resolved_api: None,
        wrapper_chain: vec![],
        evidence: vec![],
    }
}

fn bounds_check(g: &mut EvidenceGraph, var: &str, va: u64) {
    g.add_node(NodePayload::BoundsCheck {
        var: var.into(),
        va,
    });
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

/// Diamond CFG anchored at `function_va`: A -> B -> D, A -> C -> D.
/// Block A is the one dominating branch.
fn diamond_cfg(function_va: u64) -> CfgRecord {
    CfgRecord {
        function: function_va,
        blocks: vec![
            block(function_va, function_va + 0x10),
            block(function_va + 0x10, function_va + 0x20),
            block(function_va + 0x20, function_va + 0x30),
            block(function_va + 0x30, function_va + 0x40),
        ],
        edges: vec![
            edge(function_va, function_va + 0x10),
            edge(function_va, function_va + 0x20),
            edge(function_va + 0x10, function_va + 0x30),
            edge(function_va + 0x20, function_va + 0x30),
        ],
    }
}

/// Add a free-standing `IntegerOp` node to satisfy the
/// `OverflowPossible` integer pattern requirement (the v1.0 chain
/// query's `path_has_integer_op` is a global existence check).
fn add_integer_op(g: &mut EvidenceGraph, va: u64) {
    g.add_node(NodePayload::IntegerOp {
        op: "mul".into(),
        va,
    });
}

/// Add a free-standing `TypeCast` node to satisfy the
/// `SignedUnsignedCast` integer pattern requirement.
fn add_type_cast(g: &mut EvidenceGraph, va: u64) {
    g.add_node(NodePayload::TypeCast {
        from_bits: 32,
        to_bits: 64,
        signed: true,
        va,
    });
}

/// Wire `EdgeKind::DataFlow` from the CallSite at `from_va` to the
/// CallSite at `to_va`. Both must already exist in the graph.
fn wire_callsite_dataflow(g: &mut EvidenceGraph, from_va: u64, to_va: u64) {
    let mut from_id = None;
    let mut to_id = None;
    for (id, payload) in g.nodes_of_kind(NodeKind::CallSite) {
        if let NodePayload::CallSite { va, .. } = payload {
            if *va == from_va {
                from_id = Some(id);
            }
            if *va == to_va {
                to_id = Some(id);
            }
        }
    }
    g.add_edge(
        from_id.expect("from CallSite must exist"),
        to_id.expect("to CallSite must exist"),
        EdgeKind::DataFlow,
    );
}

/// Build (functions, api_flows, optional CFG, optional source→sink
/// wiring) into a discovery-ready EvidenceGraph and run the chain
/// query. Returns every chain emitted.
fn discover_on(
    apis_in_function: u64,
    api_flows: &[ApiFlowRecord],
    cfg: Option<CfgRecord>,
    source_to_sink: Option<(u64, u64)>,
    extra: impl FnOnce(&mut EvidenceGraph),
) -> Vec<CandidateChain> {
    let mut g = EvidenceGraph::new();
    ingest_functions(&mut g, &[func(apis_in_function)]);
    if let Some(cfg) = cfg {
        ingest_cfg(&mut g, &[cfg]);
    }
    ingest_api_flows(&mut g, api_flows);
    extra(&mut g);
    if let Some((s, t)) = source_to_sink {
        wire_callsite_dataflow(&mut g, s, t);
    }
    let cat_s = SourceCatalog::v1_0();
    let cat_k = SinkCatalog::v1_0();
    let summaries = compute_summaries(&g);
    let taint = propagate(&g, &cat_s, &summaries);
    let templates = TemplateRegistry::load_v1_0();
    discover_chains(&g, &taint, &cat_s, &cat_k, &templates)
}

fn fires(chains: &[CandidateChain], template_id: &str) -> bool {
    chains.iter().any(|c| c.template_id == template_id)
}

// ---------------------------------------------------------------------
// 1. unchecked_copy_length — memory_corruption, NoDominatingGuard
// ---------------------------------------------------------------------

#[test]
fn unchecked_copy_length_fires_on_tainted_recv_to_memcpy() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "memcpy"),
        ],
        None,
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(
        fires(&chains, "unchecked_copy_length"),
        "expected unchecked_copy_length; got {:?}",
        chains.iter().map(|c| &c.template_id).collect::<Vec<_>>()
    );
}

#[test]
fn unchecked_copy_length_does_not_fire_when_dominating_guard_present() {
    // Same shape but with a branching CFG -> a dominating guard exists
    // -> NoDominatingGuard requirement fails.
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "memcpy"),
        ],
        Some(diamond_cfg(0x1000)),
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(
        !fires(&chains, "unchecked_copy_length"),
        "guard present -> should NOT fire; got {:?}",
        chains.iter().map(|c| &c.template_id).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------
// 2. tainted_allocation_size — memory_corruption, NoDominatingGuard,
//    TaintedArgRole(Size), sink in {malloc, calloc, realloc,
//    VirtualAlloc, VirtualAllocEx}
// ---------------------------------------------------------------------

#[test]
fn tainted_allocation_size_fires_on_tainted_recv_to_malloc() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "malloc"),
        ],
        None,
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(fires(&chains, "tainted_allocation_size"));
}

#[test]
fn tainted_allocation_size_does_not_fire_when_dominating_guard_present() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "malloc"),
        ],
        Some(diamond_cfg(0x1000)),
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(!fires(&chains, "tainted_allocation_size"));
}

// ---------------------------------------------------------------------
// 3. integer_overflow_before_alloc — OverflowPossible (needs IntegerOp)
// ---------------------------------------------------------------------

#[test]
fn integer_overflow_before_alloc_fires_when_integer_op_on_path() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "malloc"),
        ],
        None,
        Some((0x1100, 0x1200)),
        |g| add_integer_op(g, 0x1150),
    );
    assert!(fires(&chains, "integer_overflow_before_alloc"));
}

#[test]
fn integer_overflow_before_alloc_does_not_fire_without_integer_op() {
    // No IntegerOp anywhere -> path_has_integer_op returns false ->
    // template's matched_integer_pattern is false -> skipped.
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "malloc"),
        ],
        None,
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(!fires(&chains, "integer_overflow_before_alloc"));
}

// ---------------------------------------------------------------------
// 4. signed_unsigned_length_confusion — SignedUnsignedCast (TypeCast)
// ---------------------------------------------------------------------

#[test]
fn signed_unsigned_length_confusion_fires_when_type_cast_present() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "memcpy"),
        ],
        None,
        Some((0x1100, 0x1200)),
        |g| add_type_cast(g, 0x1150),
    );
    assert!(fires(&chains, "signed_unsigned_length_confusion"));
}

#[test]
fn signed_unsigned_length_confusion_does_not_fire_without_type_cast() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "memcpy"),
        ],
        None,
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(!fires(&chains, "signed_unsigned_length_confusion"));
}

// ---------------------------------------------------------------------
// 5. missing_bounds_check_var_mismatch — DominatingGuardPresent +
//    TaintedArgRole(ByteCount).
//
//    The positive fixture uses a BoundsCheck on a different variable
//    than the memcpy byte-count arg; the negative checks the guarded
//    variable matches that byte count.
// ---------------------------------------------------------------------

#[test]
fn missing_bounds_check_var_mismatch_fires_when_guard_and_taint_present() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "memcpy"),
            api_flow_arg(0x1000, 0x1200, "memcpy", 2, "n", "len"),
        ],
        Some(diamond_cfg(0x1000)),
        Some((0x1100, 0x1200)),
        |g| bounds_check(g, "cap", 0x1008),
    );
    assert!(fires(&chains, "missing_bounds_check_var_mismatch"));
}

#[test]
fn missing_bounds_check_var_mismatch_does_not_fire_when_guard_matches_size_arg() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "memcpy"),
            api_flow_arg(0x1000, 0x1200, "memcpy", 2, "n", "len"),
        ],
        Some(diamond_cfg(0x1000)),
        Some((0x1100, 0x1200)),
        |g| bounds_check(g, "len", 0x1008),
    );
    assert!(!fires(&chains, "missing_bounds_check_var_mismatch"));
}

// ---------------------------------------------------------------------
// 6. dangerous_memory_perm_transition — PrecedingTaintedWrite (= taint
//    reaches sink_id), sink = VirtualProtect
// ---------------------------------------------------------------------

#[test]
fn dangerous_memory_perm_transition_fires_on_tainted_virtualprotect() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "VirtualProtect"),
        ],
        None,
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(fires(&chains, "dangerous_memory_perm_transition"));
}

#[test]
fn dangerous_memory_perm_transition_does_not_fire_when_taint_does_not_reach() {
    // Source + sink present but NO DataFlow edge between them -> taint
    // never reaches the VirtualProtect sink.
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "VirtualProtect"),
        ],
        None,
        None,
        |_| {},
    );
    assert!(!fires(&chains, "dangerous_memory_perm_transition"));
}

// ---------------------------------------------------------------------
// 7. auth_check_after_action — AnyCall + DominatingGuardPresent
//
//    Fires only when a privileged action dominates/precedes
//    AccessCheck.
// ---------------------------------------------------------------------

#[test]
fn auth_check_after_action_fires_when_privileged_action_precedes_check() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1180, "WriteProcessMemory"),
            api_flow(0x1000, 0x1200, "AccessCheck"),
        ],
        None,
        None,
        |_| {},
    );
    assert!(fires(&chains, "auth_check_after_action"));
}

#[test]
fn auth_check_after_action_does_not_fire_when_check_precedes_action() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1180, "AccessCheck"),
            api_flow(0x1000, 0x1200, "WriteProcessMemory"),
        ],
        None,
        None,
        |_| {},
    );
    assert!(!fires(&chains, "auth_check_after_action"));
}

// ---------------------------------------------------------------------
// 8. missing_caller_validation — AnyCall + NoDominatingGuard,
//    source must be one of network_recv / ipc_pipe / com_server_ingress
//    / rpc_inbound / ioctl_input_buffer
// ---------------------------------------------------------------------

#[test]
fn missing_caller_validation_fires_on_recv_to_write_process_memory() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "WriteProcessMemory"),
        ],
        None,
        None,
        |_| {},
    );
    assert!(fires(&chains, "missing_caller_validation"));
}

#[test]
fn missing_caller_validation_does_not_fire_on_plain_memcpy() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "memcpy"),
        ],
        None,
        None,
        |_| {},
    );
    assert!(!fires(&chains, "missing_caller_validation"));
}

#[test]
fn missing_caller_validation_does_not_fire_when_dominating_guard_present() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "WriteProcessMemory"),
        ],
        Some(diamond_cfg(0x1000)),
        None,
        |_| {},
    );
    assert!(!fires(&chains, "missing_caller_validation"));
}

// ---------------------------------------------------------------------
// 9. deserialization_to_dangerous_type — BestEffort tier,
//    TaintedArgRole(Source), sink in {BinaryFormatter::Deserialize,
//    pickle.loads}
// ---------------------------------------------------------------------

#[test]
fn deserialization_to_dangerous_type_fires_on_tainted_pickle_loads() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "pickle.loads"),
        ],
        None,
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(fires(&chains, "deserialization_to_dangerous_type"));
}

#[test]
fn deserialization_to_dangerous_type_does_not_fire_when_taint_does_not_reach() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "pickle.loads"),
        ],
        None,
        None,
        |_| {},
    );
    assert!(!fires(&chains, "deserialization_to_dangerous_type"));
}

// ---------------------------------------------------------------------
// 10. format_string_controlled — TaintedArgRole(FormatString), sink in
//     {sprintf, snprintf, printf, fprintf, vfprintf, vsprintf,
//      __stdio_common_vfprintf}
// ---------------------------------------------------------------------

#[test]
fn format_string_controlled_fires_on_tainted_recv_to_sprintf() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "sprintf"),
        ],
        None,
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(fires(&chains, "format_string_controlled"));
}

#[test]
fn format_string_controlled_fires_on_tainted_recv_to_msvc_vfprintf_wrapper() {
    let cat = SinkCatalog::v1_0();
    let wrapper = cat
        .lookup("__stdio_common_vfprintf")
        .expect("MSVC vfprintf wrapper should be modeled");
    assert_eq!(wrapper.api, "__stdio_common_vfprintf");
    assert!(
        wrapper
            .args
            .contains(&axe_core::vuln::sinks::ArgRole::FormatString),
        "wrapper sink should identify the format-string argument"
    );

    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow_arg(
                0x1000,
                0x1200,
                "__stdio_common_vfprintf",
                2,
                "format",
                "rdx",
            ),
        ],
        None,
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(
        chains.iter().any(|chain| {
            chain.template_id == "format_string_controlled"
                && chain.sink_api == "__stdio_common_vfprintf"
        }),
        "expected format-string chain through MSVC wrapper, got {chains:?}"
    );
}

#[test]
fn format_string_controlled_fires_on_same_function_recv_before_printf_wrapper() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow_arg(
                0x1000,
                0x1200,
                "__stdio_common_vfprintf",
                2,
                "format",
                "rdx",
            ),
        ],
        None,
        None,
        |_| {},
    );
    assert!(
        chains.iter().any(|chain| {
            chain.template_id == "format_string_controlled"
                && chain.source_site_va == 0x1100
                && chain.sink_site_va == 0x1200
        }),
        "same-function recv before printf-family sink should produce a candidate"
    );
}

#[test]
fn format_string_controlled_does_not_fire_when_taint_does_not_reach() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1300, "recv"),
            api_flow(0x1000, 0x1200, "sprintf"),
        ],
        None,
        None,
        |_| {},
    );
    assert!(!fires(&chains, "format_string_controlled"));
}

// ---------------------------------------------------------------------
// 11. path_traversal_to_file_op — TaintedArgRole(Path) +
//     NoDominatingGuard, sink in {CreateFile, fopen, open, unlink,
//     DeleteFile}
// ---------------------------------------------------------------------

#[test]
fn path_traversal_to_file_op_fires_on_tainted_recv_to_create_file() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "CreateFile"),
        ],
        None,
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(fires(&chains, "path_traversal_to_file_op"));
}

#[test]
fn path_traversal_to_file_op_does_not_fire_when_dominating_guard_present() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1200, "CreateFile"),
        ],
        Some(diamond_cfg(0x1000)),
        Some((0x1100, 0x1200)),
        |_| {},
    );
    assert!(!fires(&chains, "path_traversal_to_file_op"));
}

// ---------------------------------------------------------------------
// 12. toctou_file_access — AnyCall + DominatingGuardPresent
//
//    Requires two file operations on the same path and rejects the
//    candidate when a lock acquisition dominates/precedes either op.
// ---------------------------------------------------------------------

#[test]
fn toctou_file_access_fires_on_two_file_ops_same_path_without_lock() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow_arg(0x1000, 0x1200, "CreateFile", 0, "lpFileName", "user_path"),
            api_flow_arg(0x1000, 0x1300, "unlink", 0, "path", "user_path"),
        ],
        None,
        None,
        |_| {},
    );
    assert!(fires(&chains, "toctou_file_access"));
}

#[test]
fn toctou_file_access_does_not_fire_for_different_paths() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow_arg(0x1000, 0x1200, "CreateFile", 0, "lpFileName", "path_a"),
            api_flow_arg(0x1000, 0x1300, "unlink", 0, "path", "path_b"),
        ],
        None,
        None,
        |_| {},
    );
    assert!(!fires(&chains, "toctou_file_access"));
}

#[test]
fn toctou_file_access_does_not_fire_under_dominating_lock() {
    let chains = discover_on(
        0x1000,
        &[
            api_flow(0x1000, 0x1100, "recv"),
            api_flow(0x1000, 0x1150, "EnterCriticalSection"),
            api_flow_arg(0x1000, 0x1200, "CreateFile", 0, "lpFileName", "user_path"),
            api_flow_arg(0x1000, 0x1300, "unlink", 0, "path", "user_path"),
        ],
        None,
        None,
        |_| {},
    );
    assert!(!fires(&chains, "toctou_file_access"));
}

// ---------------------------------------------------------------------
// Coverage assertion: at least 12 distinct template IDs fired across
// all positive fixtures. Catches accidental template-id renames or
// loss of any template's discovery surface.
// ---------------------------------------------------------------------

#[test]
fn all_12_v1_0_templates_have_at_least_one_positive_fire_test() {
    let all_pos_fixtures: Vec<Vec<CandidateChain>> = vec![
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1200, "memcpy"),
            ],
            None,
            Some((0x1100, 0x1200)),
            |_| {},
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1200, "malloc"),
            ],
            None,
            Some((0x1100, 0x1200)),
            |_| {},
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1200, "malloc"),
            ],
            None,
            Some((0x1100, 0x1200)),
            |g| add_integer_op(g, 0x1150),
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1200, "memcpy"),
            ],
            None,
            Some((0x1100, 0x1200)),
            |g| add_type_cast(g, 0x1150),
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1200, "memcpy"),
                api_flow_arg(0x1000, 0x1200, "memcpy", 2, "n", "len"),
            ],
            Some(diamond_cfg(0x1000)),
            Some((0x1100, 0x1200)),
            |g| bounds_check(g, "cap", 0x1008),
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1200, "VirtualProtect"),
            ],
            None,
            Some((0x1100, 0x1200)),
            |_| {},
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1180, "WriteProcessMemory"),
                api_flow(0x1000, 0x1200, "AccessCheck"),
            ],
            None,
            None,
            |_| {},
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1200, "WriteProcessMemory"),
            ],
            None,
            None,
            |_| {},
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1200, "pickle.loads"),
            ],
            None,
            Some((0x1100, 0x1200)),
            |_| {},
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1200, "sprintf"),
            ],
            None,
            Some((0x1100, 0x1200)),
            |_| {},
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow(0x1000, 0x1200, "CreateFile"),
            ],
            None,
            Some((0x1100, 0x1200)),
            |_| {},
        ),
        discover_on(
            0x1000,
            &[
                api_flow(0x1000, 0x1100, "recv"),
                api_flow_arg(0x1000, 0x1200, "CreateFile", 0, "lpFileName", "user_path"),
                api_flow_arg(0x1000, 0x1300, "unlink", 0, "path", "user_path"),
            ],
            None,
            None,
            |_| {},
        ),
    ];
    let mut fired: std::collections::HashSet<String> = std::collections::HashSet::new();
    for chains in &all_pos_fixtures {
        for c in chains {
            fired.insert(c.template_id.clone());
        }
    }
    assert!(
        fired.len() >= 12,
        "expected at least 12 distinct templates to fire across positive fixtures; got {}: {:?}",
        fired.len(),
        fired
    );
}
