//! Ingestors that turn existing axe analysis records into
//! `EvidenceGraph` nodes + edges.
//!
//! Each ingestor is a pure function `Fn(&mut EvidenceGraph,
//! &[Record])` — no `Result`, no side-effects beyond mutating the
//! graph. Missing data is recorded as `None` payload fields, not as
//! errors; the chain-query engine treats `None` fields as
//! uncertainty rather than as failures.
//!
//! Step 3 (this file) lands the **call/CFG/xref** ingestors. Step 4
//! adds SSA + dataflow + value_graph + VSA. Step 5 adds attack +
//! behavior + api_flows + imports.

#![allow(dead_code)]

use crate::attack::AttackTechniqueRecord;
use crate::pe::{
    ApiFlowRecord, BehaviorDossierRecord, CfgRecord, DataflowEdgeRecord, FunctionRecord,
    ImportRecord, SsaValueRecord, ValueGraphRecord, VsaValueRecord, XrefRecord,
};
use crate::vuln::graph::{EdgeKind, EvidenceGraph, NodeId, NodePayload};

/// Maps SSA value IDs to graph node IDs so dataflow + value_graph +
/// VSA ingestors can wire their edges into the same nodes.
pub type SsaNodeIndex = rustc_hash::FxHashMap<String, NodeId>;

/// Add `Function` nodes for every record. Returns the map of
/// `function_va -> NodeId` (also indexed inside the graph; the
/// returned map is convenient for downstream ingestors that don't
/// want a second lookup).
pub fn ingest_functions(
    graph: &mut EvidenceGraph,
    functions: &[FunctionRecord],
) -> rustc_hash::FxHashMap<u64, NodeId> {
    let mut out: rustc_hash::FxHashMap<u64, NodeId> = rustc_hash::FxHashMap::default();
    for f in functions {
        let id = graph.add_node(NodePayload::Function {
            va: f.start,
            name: None,
        });
        out.insert(f.start, id);
    }
    // Calls edges. Skip calls to imports (resolved later in Step 5).
    // Skip calls whose target isn't a known function (e.g. dynamic
    // dispatch via register).
    for f in functions {
        let from = match graph.function_by_va(f.start) {
            Some(id) => id,
            None => continue,
        };
        for &callee_va in &f.calls {
            if let Some(to) = graph.function_by_va(callee_va) {
                graph.add_edge(from, to, EdgeKind::Calls);
            }
        }
    }
    out
}

/// Add `BasicBlock` nodes for every block of every CFG record + the
/// ControlFlow edges between them. Skips CFGs whose owning function
/// isn't already in the graph (caller should run [`ingest_functions`]
/// first).
pub fn ingest_cfg(graph: &mut EvidenceGraph, cfgs: &[CfgRecord]) {
    for cfg in cfgs {
        if graph.function_by_va(cfg.function).is_none() {
            continue;
        }
        for block in &cfg.blocks {
            // De-dup: ingestors may run multiple times in tests.
            if graph.block_by_va(cfg.function, block.start).is_some() {
                continue;
            }
            graph.add_node(NodePayload::BasicBlock {
                function_va: cfg.function,
                start_va: block.start,
                end_va: block.end,
            });
        }
        for edge in &cfg.edges {
            let from = match graph.block_by_va(cfg.function, edge.from) {
                Some(id) => id,
                None => continue,
            };
            let to = match graph.block_by_va(cfg.function, edge.to) {
                Some(id) => id,
                None => continue,
            };
            graph.add_edge(from, to, EdgeKind::ControlFlow);
        }
    }
}

/// Add cross-reference edges. Maps `XrefRecord::kind` to a graph
/// edge kind:
/// - `"code"` xrefs → `Calls` (if both ends resolve to functions)
///   or `ControlFlow` (if both ends resolve to blocks in the same
///   function).
/// - `"data"` xrefs (read/write/etc.) → `DataFlow` between functions.
///   v1.0 doesn't model individual data refs as nodes; the xref is
///   anchored at the function level.
/// - `"string"` xrefs → ignored at the graph layer; they're consumed
///   directly by templates that need them (e.g.
///   `path_traversal_to_file_op`).
pub fn ingest_xrefs(graph: &mut EvidenceGraph, xrefs: &[XrefRecord]) {
    for x in xrefs {
        match x.kind.as_str() {
            "code" => {
                if let (Some(from), Some(to)) =
                    (graph.function_by_va(x.from), graph.function_by_va(x.target))
                {
                    graph.add_edge(from, to, EdgeKind::Calls);
                }
            }
            "data" => {
                if let (Some(from), Some(to)) =
                    (graph.function_by_va(x.from), graph.function_by_va(x.target))
                {
                    let kind = match x.role.as_str() {
                        "write" => EdgeKind::WritesTo,
                        "read" => EdgeKind::ReadsFrom,
                        _ => EdgeKind::DataFlow,
                    };
                    graph.add_edge(from, to, kind);
                }
            }
            _ => {}
        }
    }
}

/// Add a `Copy` node for every SSA value (each value represents an
/// assignment / def). Returns the `ssa_id -> NodeId` map for the
/// dataflow + value_graph ingestors to wire edges into.
pub fn ingest_ssa(graph: &mut EvidenceGraph, ssa: &[SsaValueRecord]) -> SsaNodeIndex {
    let mut index: SsaNodeIndex = rustc_hash::FxHashMap::default();
    for s in ssa {
        let id = graph.add_node(NodePayload::Copy {
            dst_var: s.ssa_id.clone(),
            src_var: s.storage.clone(),
            va: s.site_va,
        });
        index.insert(s.ssa_id.clone(), id);
    }
    index
}

/// Add `DataFlow` edges between SSA value nodes. Requires the
/// `ssa_index` from [`ingest_ssa`] to resolve from/to endpoints.
/// Edges whose endpoints aren't in the index are silently dropped
/// (e.g. cross-function flow records the SSA pass didn't materialize).
pub fn ingest_dataflow(
    graph: &mut EvidenceGraph,
    dataflow: &[DataflowEdgeRecord],
    ssa_index: &SsaNodeIndex,
) {
    for d in dataflow {
        let to = match ssa_index.get(&d.to_value) {
            Some(id) => *id,
            None => continue,
        };
        let from = match d.from_value.as_deref().and_then(|v| ssa_index.get(v)) {
            Some(id) => *id,
            None => continue,
        };
        graph.add_edge(from, to, EdgeKind::DataFlow);
    }
}

/// Add `TypeCast` nodes when value-graph records indicate a width
/// change. Otherwise the value-graph row is captured implicitly by
/// the SSA Copy node — no need to duplicate.
///
/// Width inference is approximate in v1.0: we look for `"i8"`,
/// `"i16"`, `"i32"`, `"i64"`, `"u8"`, etc. tokens in
/// `inferred_type`. Records with no recognizable width hint are
/// skipped (the SSA Copy already exists for them).
pub fn ingest_value_graph(
    graph: &mut EvidenceGraph,
    values: &[ValueGraphRecord],
    ssa_index: &SsaNodeIndex,
) {
    for v in values {
        let to_bits = match width_of(&v.inferred_type) {
            Some(b) => b,
            None => continue,
        };
        // value_id may or may not match an SSA id; only add a TypeCast
        // node when we can chain it from a Copy (DerivedFrom edge to
        // the SSA Copy node would otherwise dangle).
        let from_node = match ssa_index.get(&v.value_id) {
            Some(id) => *id,
            None => continue,
        };
        let signed = v.inferred_type.starts_with('i');
        let tc = graph.add_node(NodePayload::TypeCast {
            from_bits: 0, // unknown source width; recorded as 0
            to_bits,
            signed,
            va: v.source_instruction,
        });
        graph.add_edge(tc, from_node, EdgeKind::DerivedFrom);
    }
}

fn width_of(s: &str) -> Option<u32> {
    // Recognize i8/i16/i32/i64/i128, u8/u16/u32/u64/u128, plus
    // common synonyms. Order matters because we use substring
    // matching — longer / more-specific tokens are checked first so
    // (e.g.) `int64_t` doesn't match `int` (32) before `i64` (64).
    let lower = s.to_lowercase();
    for (token, bits) in &[
        // 128-bit
        ("i128", 128u32),
        ("u128", 128),
        // 64-bit: explicit-width tokens first, then synonyms
        ("int64", 64),
        ("uint64", 64),
        ("i64", 64),
        ("u64", 64),
        ("long", 64),
        ("qword", 64),
        ("ptr", 64),
        // 32-bit
        ("int32", 32),
        ("uint32", 32),
        ("i32", 32),
        ("u32", 32),
        ("dword", 32),
        ("int", 32),
        ("uint", 32),
        // 16-bit
        ("int16", 16),
        ("uint16", 16),
        ("i16", 16),
        ("u16", 16),
        ("short", 16),
        ("word", 16),
        // 8-bit
        ("int8", 8),
        ("uint8", 8),
        ("i8", 8),
        ("u8", 8),
        ("byte", 8),
    ] {
        if lower.contains(token) {
            return Some(*bits);
        }
    }
    None
}

/// Add a `CallSite` node + `Sink` node for every API-flow record.
/// Wires `CallSite → Sink (DataFlow)` and `Function → CallSite
/// (ControlFlow)` so chain queries can pivot from a sink back to its
/// containing function. API-flow records are how axe represents
/// resolved import calls (e.g. `memcpy(rcx, rdx, r8)`); they're the
/// primary feeder for the `SinkCatalog` in Step 7.
pub fn ingest_api_flows(graph: &mut EvidenceGraph, flows: &[ApiFlowRecord]) {
    for flow in flows {
        let function = match graph.function_by_va(flow.function) {
            Some(id) => id,
            None => continue,
        };
        // De-dup: many ApiFlowRecords can share a callsite (one per
        // argument). Reuse an existing CallSite/Sink pair when found.
        let call_site = graph.add_node(NodePayload::CallSite {
            va: flow.callsite,
            target_va: None,
            api: Some(flow.normalized_api.clone()),
        });
        let sink = graph.add_node(NodePayload::Sink {
            api: flow.normalized_api.clone(),
            site_va: flow.callsite,
        });
        graph.add_edge(function, call_site, EdgeKind::ControlFlow);
        graph.add_edge(call_site, sink, EdgeKind::DataFlow);
        if let Some(arg_fact) = api_arg_fact_key(flow) {
            let arg_node = graph.add_node(NodePayload::GlobalState { key: arg_fact });
            graph.add_edge(call_site, arg_node, EdgeKind::ReadsFrom);
        }
    }
}

/// Add synthetic sink callsites for local wrapper calls that forward
/// into known sink imports. MinGW/MSVC often compiles `printf(msg)`
/// into `call local_printf_wrapper`, and the wrapper then calls
/// `__stdio_common_vfprintf`. Without this bridge, the import sink is
/// present but disconnected from the caller where attacker data flows.
pub fn ingest_local_sink_wrappers(
    graph: &mut EvidenceGraph,
    functions: &[FunctionRecord],
    xrefs: &[XrefRecord],
) {
    let functions_by_start: rustc_hash::FxHashMap<u64, &FunctionRecord> =
        functions.iter().map(|f| (f.start, f)).collect();
    let import_by_thunk_va: rustc_hash::FxHashMap<u64, String> = xrefs
        .iter()
        .filter(|xref| xref.kind == "import")
        .filter_map(|xref| {
            xref.symbol
                .as_ref()
                .map(|symbol| (xref.from, symbol.clone()))
        })
        .collect();
    for xref in xrefs {
        if xref.kind != "code" || xref.role != "call" {
            continue;
        }
        let Some(callee) = functions_by_start.get(&xref.target).copied() else {
            continue;
        };
        let Some(sink_api) =
            forwarded_sink_api(callee, &functions_by_start, &import_by_thunk_va, 0)
        else {
            continue;
        };
        if graph.sink_by_va(xref.from).is_some() {
            continue;
        }
        let Some(caller) = containing_function(functions, xref.from) else {
            continue;
        };
        let Some(function) = graph.function_by_va(caller.start) else {
            continue;
        };
        let call_site = graph.add_node(NodePayload::CallSite {
            va: xref.from,
            target_va: Some(xref.target),
            api: Some(sink_api.clone()),
        });
        let sink = graph.add_node(NodePayload::Sink {
            api: sink_api,
            site_va: xref.from,
        });
        graph.add_edge(function, call_site, EdgeKind::ControlFlow);
        graph.add_edge(call_site, sink, EdgeKind::DataFlow);
    }
}

fn forwarded_sink_api(
    function: &FunctionRecord,
    functions_by_start: &rustc_hash::FxHashMap<u64, &FunctionRecord>,
    import_by_thunk_va: &rustc_hash::FxHashMap<u64, String>,
    depth: usize,
) -> Option<String> {
    for import in &function.calls_imports {
        if let Some(api) = format_sink_from_name(import) {
            return Some(api);
        }
    }
    for callee_va in &function.calls {
        if let Some(import) = import_by_thunk_va.get(callee_va) {
            if let Some(api) = format_sink_from_name(import) {
                return Some(api);
            }
        }
    }
    if depth >= 2 {
        return None;
    }
    for callee_va in &function.calls {
        if let Some(callee) = functions_by_start.get(callee_va).copied() {
            if let Some(api) =
                forwarded_sink_api(callee, functions_by_start, import_by_thunk_va, depth + 1)
            {
                return Some(api);
            }
        }
    }
    None
}

fn format_sink_from_name(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("__stdio_common_vfprintf") {
        return Some("__stdio_common_vfprintf".to_string());
    }
    if lower.contains("vfprintf") {
        return Some("vfprintf".to_string());
    }
    if lower.contains("printf") {
        return Some("printf".to_string());
    }
    None
}

fn containing_function(functions: &[FunctionRecord], va: u64) -> Option<&FunctionRecord> {
    functions
        .iter()
        .filter(|function| function.start <= va && va < function.end)
        .max_by_key(|function| function.start)
}

fn api_arg_fact_key(flow: &ApiFlowRecord) -> Option<String> {
    let has_arg_detail =
        flow.argument_index.is_some() || flow.argument_name.is_some() || !flow.value.is_empty();
    if !has_arg_detail {
        return None;
    }
    let index = flow
        .argument_index
        .map(|idx| idx.to_string())
        .unwrap_or_default();
    let name = flow
        .argument_name
        .as_deref()
        .unwrap_or(flow.argument.as_str())
        .replace('|', "/");
    let value = flow.value.replace('\n', " ").replace('\r', " ");
    Some(format!(
        "api_arg|site={:016x}|index={}|name={}|value={}",
        flow.callsite, index, name, value
    ))
}

/// **v1.0.1 coverage fix** (per docs/vuln-calibration.md). Bridges
/// `CallSite` nodes to nearby SSA `Copy` nodes so taint can propagate
/// across call boundaries on real binaries.
///
/// **Why exact-VA matching fails**: the SSA pass assigns `site_va` to
/// the instruction that *defines* a value, not the instruction that
/// *consumes* it. For a `call recv; mov rdi, rax` sequence the rax
/// SSA def lives at the `mov` VA, not the `call` VA. On notepad.exe,
/// 0 of 1439 api_flow callsite VAs match an SSA site_va exactly; 42%
/// have an SSA within 16 bytes.
///
/// **What this pass does**: for each CallSite, find SSA values in the
/// same function whose `site_va` is within `[callsite_va,
/// callsite_va + 16)` (the typical next-instruction window where the
/// call's outputs become usable) AND whose `storage` is a caller-saved
/// register that holds call inputs or outputs on x64
/// (`rax`/`rcx`/`rdx`/`r8`/`r9`/`r10`/`r11`). Wire bidirectional
/// `DataFlow` so source CallSites can spread taint into the SSA
/// dataflow graph and sink CallSites can absorb taint from it.
///
/// **Bidirectional wiring**: at v1.0 we don't distinguish input vs
/// output SSA values at a callsite — taint propagation BFS only walks
/// forward edges, so the backward direction is a no-op for spread but
/// lets sink CallSites collect taint that arrives via SSA.
///
/// **Cost**: O(api_flows × ssa_in_window). With 16-byte windows and
/// the register filter, observed wiring on notepad.exe is ~1.5
/// edges per api_flow.
pub fn ingest_callsite_ssa_bridge(
    graph: &mut EvidenceGraph,
    _api_flows: &[ApiFlowRecord],
    ssa: &[SsaValueRecord],
    ssa_index: &SsaNodeIndex,
) {
    if ssa.is_empty() {
        return;
    }
    // Index SSA values by (function, site_va) so we can do a windowed
    // lookup. The same SSA pass-assigned site_va may hold multiple
    // values (one per register at that instruction).
    let mut ssa_by_fn: rustc_hash::FxHashMap<u64, Vec<&SsaValueRecord>> =
        rustc_hash::FxHashMap::default();
    for s in ssa {
        if is_call_register_storage(&s.storage) {
            ssa_by_fn.entry(s.function).or_default().push(s);
        }
    }
    // Sort by site_va within each function for efficient window scans.
    for entries in ssa_by_fn.values_mut() {
        entries.sort_by_key(|s| s.site_va);
    }
    // Index CallSites by VA so the api_flow loop can look up the
    // CallSite NodeId(s) for each call instruction.
    let mut callsites_by_va: rustc_hash::FxHashMap<u64, Vec<NodeId>> =
        rustc_hash::FxHashMap::default();
    for (id, payload) in graph.nodes_of_kind(crate::vuln::graph::NodeKind::CallSite) {
        if let NodePayload::CallSite { va, .. } = payload {
            callsites_by_va.entry(*va).or_default().push(id);
        }
    }
    // Bidirectional window in bytes:
    // - BACKWARD (call_va - 16, call_va): catches arg-setup defs
    //   (`mov rcx, X` before `call memcpy` — rcx-def is at -3 bytes
    //   from the call but is the actual taint sink for the call's
    //   first arg).
    // - FORWARD [call_va, call_va + 16): catches call-output uses
    //   (`call recv; mov rdi, rax` — rdi-def is at +3 bytes from the
    //   call but carries the call's return value).
    const WINDOW_BEFORE: u64 = 16;
    const WINDOW_AFTER: u64 = 16;
    for (callsite_va, cs_ids) in &callsites_by_va {
        let function_va = match cs_ids
            .iter()
            .find_map(|cs_id| callsite_function_va(graph, *cs_id))
        {
            Some(va) => va,
            None => continue,
        };
        let ssa_entries = match ssa_by_fn.get(&function_va) {
            Some(v) => v,
            None => continue,
        };
        let lo = callsite_va.saturating_sub(WINDOW_BEFORE);
        let hi = callsite_va.saturating_add(WINDOW_AFTER);
        let start = ssa_entries.partition_point(|s| s.site_va < lo);
        for entry in ssa_entries[start..].iter() {
            if entry.site_va >= hi {
                break;
            }
            let ssa_node = match ssa_index.get(&entry.ssa_id) {
                Some(id) => *id,
                None => continue,
            };
            for cs_id in cs_ids {
                graph.add_edge(*cs_id, ssa_node, EdgeKind::DataFlow);
                graph.add_edge(ssa_node, *cs_id, EdgeKind::DataFlow);
            }
        }
    }
}

fn callsite_function_va(graph: &EvidenceGraph, callsite_id: NodeId) -> Option<u64> {
    graph
        .incoming_of_kind(callsite_id, EdgeKind::ControlFlow)
        .find_map(|(function_id, _)| match graph.node(function_id) {
            Some(NodePayload::Function { va, .. }) => Some(*va),
            _ => None,
        })
}

/// x64 caller-saved registers that hold call inputs (rcx/rdx/r8/r9
/// on Windows; rdi/rsi/rdx/rcx/r8/r9 on System V) or outputs
/// (rax/rdx). Restricts the bridge to "interesting" SSA values that
/// actually correspond to the call's input/output arguments, avoiding
/// the unrelated stack-slot SSAs that share the call-VA-adjacent
/// instructions.
fn is_call_register_storage(storage: &str) -> bool {
    matches!(
        storage,
        "rax"
            | "rcx"
            | "rdx"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "rdi"
            | "rsi"
            | "eax"
            | "ecx"
            | "edx"
            | "r8d"
            | "r9d"
            | "r10d"
            | "r11d"
            | "edi"
            | "esi"
    )
}

/// Add `Function` pseudo-nodes for imports that aren't already in
/// the graph (real functions get their nodes from
/// [`ingest_functions`]). Imports are anchored at their IAT VA so
/// downstream sink lookups can resolve `memcpy@KERNEL32.dll` to a
/// node. `categories` is hashed into the node's `name` so behavior
/// detectors can filter by API family without re-reading import
/// records.
pub fn ingest_imports(graph: &mut EvidenceGraph, imports: &[ImportRecord]) {
    for imp in imports {
        if graph.function_by_va(imp.va).is_some() {
            continue;
        }
        let label = if imp.categories.is_empty() {
            format!("{}::{}", imp.dll, imp.symbol)
        } else {
            format!("{}::{} [{}]", imp.dll, imp.symbol, imp.categories.join(","))
        };
        graph.add_node(NodePayload::Function {
            va: imp.va,
            name: Some(label),
        });
    }
}

/// Add `GlobalState` nodes for each ATT&CK technique mapped to this
/// binary. Wires the technique to every function in its
/// `evidence_vas` via `Reaches` edges so chain queries can ask "which
/// chains contribute to T1055?".
pub fn ingest_attack(graph: &mut EvidenceGraph, attack: &[AttackTechniqueRecord]) {
    for tech in attack {
        let tech_node = graph.add_node(NodePayload::GlobalState {
            key: format!("attack:{}", tech.technique_id),
        });
        for va in &tech.evidence_vas {
            if let Some(function) = graph.function_by_va(*va) {
                graph.add_edge(function, tech_node, EdgeKind::Reaches);
            }
        }
    }
}

/// Add `GlobalState` nodes for each behavior-dossier capability.
/// Wires the dossier to its evidence VAs via `Reaches` edges.
/// Templates that want to pivot on capability (e.g.
/// "process_injection" → look for code_injection chains) read from
/// these nodes.
pub fn ingest_behavior_dossiers(graph: &mut EvidenceGraph, dossiers: &[BehaviorDossierRecord]) {
    for d in dossiers {
        let dossier_node = graph.add_node(NodePayload::GlobalState {
            key: format!("behavior:{}", d.capability),
        });
        for va in &d.evidence_vas {
            if let Some(function) = graph.function_by_va(*va) {
                graph.add_edge(function, dossier_node, EdgeKind::Reaches);
            }
        }
    }
}

/// Add `Allocation` or `PointerDerivation` nodes based on the VSA
/// record's `kind` and `location`. Range information is read directly
/// by `ranges.rs` from the VSA records themselves — we don't
/// duplicate ranges into the graph.
pub fn ingest_vsa(graph: &mut EvidenceGraph, vsa: &[VsaValueRecord]) {
    for v in vsa {
        let lower_kind = v.kind.to_lowercase();
        let is_pointer = v.location.starts_with('[') || lower_kind.contains("pointer");
        let is_alloc = lower_kind.contains("alloc") || lower_kind.contains("heap");
        if is_alloc {
            graph.add_node(NodePayload::Allocation {
                size_expr: v.expression.clone().unwrap_or_else(|| v.kind.clone()),
                va: v.site_va,
            });
        } else if is_pointer {
            graph.add_node(NodePayload::PointerDerivation {
                base: v.base.clone().unwrap_or_default(),
                offset: v.displacement,
                va: v.site_va,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{BasicBlockRecord, EdgeRecord};
    use crate::vuln::graph::NodeKind;

    fn func(start: u64, calls: Vec<u64>) -> FunctionRecord {
        FunctionRecord {
            start,
            end: start + 0x100,
            size: 0x100,
            source: "test".into(),
            calls,
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

    fn edge(from: u64, to: u64, t: &str) -> EdgeRecord {
        EdgeRecord {
            from,
            to,
            edge_type: t.into(),
        }
    }

    fn xref(from: u64, target: u64, kind: &str, role: &str) -> XrefRecord {
        XrefRecord {
            kind: kind.into(),
            from,
            target,
            role: role.into(),
            symbol: None,
            text: None,
            encoding: None,
            section: None,
        }
    }

    #[test]
    fn ingest_functions_creates_one_node_per_record() {
        let mut g = EvidenceGraph::new();
        let funcs = vec![
            func(0x1000, vec![]),
            func(0x2000, vec![]),
            func(0x3000, vec![]),
        ];
        let map = ingest_functions(&mut g, &funcs);
        assert_eq!(g.node_count(), 3);
        assert_eq!(map.len(), 3);
        assert!(map.contains_key(&0x1000));
    }

    #[test]
    fn ingest_functions_adds_calls_edges_for_known_targets() {
        let mut g = EvidenceGraph::new();
        let funcs = vec![
            func(0x1000, vec![0x2000, 0x3000]),
            func(0x2000, vec![]),
            func(0x3000, vec![0xdead_beef]), // dead_beef is unknown — should skip
        ];
        ingest_functions(&mut g, &funcs);
        // 2 Calls edges from 0x1000 to known targets; 0 from 0x3000 to unknown.
        let main = g.function_by_va(0x1000).unwrap();
        let calls: Vec<_> = g.outgoing_of_kind(main, EdgeKind::Calls).collect();
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn ingest_cfg_skips_unknown_functions() {
        let mut g = EvidenceGraph::new();
        // No functions added → CFG should be ignored.
        let cfgs = vec![CfgRecord {
            function: 0x1000,
            blocks: vec![block(0x1000, 0x1010)],
            edges: vec![],
        }];
        ingest_cfg(&mut g, &cfgs);
        assert_eq!(g.node_count(), 0);
    }

    #[test]
    fn ingest_cfg_adds_blocks_and_control_flow_edges() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![])]);
        let cfgs = vec![CfgRecord {
            function: 0x1000,
            blocks: vec![
                block(0x1000, 0x1010),
                block(0x1010, 0x1020),
                block(0x1020, 0x1030),
            ],
            edges: vec![
                edge(0x1000, 0x1010, "fallthrough"),
                edge(0x1010, 0x1020, "branch"),
            ],
        }];
        ingest_cfg(&mut g, &cfgs);
        let blocks: Vec<_> = g.nodes_of_kind(NodeKind::BasicBlock).collect();
        assert_eq!(blocks.len(), 3);
        let b0 = g.block_by_va(0x1000, 0x1000).unwrap();
        let cf: Vec<_> = g.outgoing_of_kind(b0, EdgeKind::ControlFlow).collect();
        assert_eq!(cf.len(), 1);
    }

    #[test]
    fn ingest_cfg_dedupes_repeat_runs() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![])]);
        let cfgs = vec![CfgRecord {
            function: 0x1000,
            blocks: vec![block(0x1000, 0x1010)],
            edges: vec![],
        }];
        ingest_cfg(&mut g, &cfgs);
        ingest_cfg(&mut g, &cfgs);
        // Block was added once; second run should be a no-op.
        let blocks: Vec<_> = g.nodes_of_kind(NodeKind::BasicBlock).collect();
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn ingest_xrefs_code_kind_adds_calls_edge() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![]), func(0x2000, vec![])]);
        ingest_xrefs(&mut g, &[xref(0x1000, 0x2000, "code", "call")]);
        let main = g.function_by_va(0x1000).unwrap();
        let calls: Vec<_> = g.outgoing_of_kind(main, EdgeKind::Calls).collect();
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn ingest_xrefs_data_role_chooses_writes_or_reads() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![]), func(0x2000, vec![])]);
        ingest_xrefs(
            &mut g,
            &[
                xref(0x1000, 0x2000, "data", "write"),
                xref(0x2000, 0x1000, "data", "read"),
            ],
        );
        let f1 = g.function_by_va(0x1000).unwrap();
        let f2 = g.function_by_va(0x2000).unwrap();
        let writes: Vec<_> = g.outgoing_of_kind(f1, EdgeKind::WritesTo).collect();
        let reads: Vec<_> = g.outgoing_of_kind(f2, EdgeKind::ReadsFrom).collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(reads.len(), 1);
    }

    #[test]
    fn ingest_xrefs_skips_unknown_endpoints() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![])]);
        ingest_xrefs(&mut g, &[xref(0x1000, 0xdead_beef, "code", "call")]);
        // 0xdead_beef isn't a known function → no edge.
        let f1 = g.function_by_va(0x1000).unwrap();
        let calls: Vec<_> = g.outgoing_of_kind(f1, EdgeKind::Calls).collect();
        assert_eq!(calls.len(), 0);
    }

    // ----- Step 4 fixtures ----------------------------------------

    fn ssa(id: &str, va: u64, storage: &str) -> SsaValueRecord {
        SsaValueRecord {
            ssa_id: id.into(),
            function: 0x1000,
            block: Some(0x1000),
            site_va: va,
            storage: storage.into(),
            version: 1,
            kind: "def".into(),
            source: "test".into(),
            value: None,
            evidence: vec![],
            confidence: "medium".into(),
        }
    }

    fn dflow(from: Option<&str>, to: &str) -> DataflowEdgeRecord {
        DataflowEdgeRecord {
            edge_id: format!("e_{from:?}_{to}"),
            function: 0x1000,
            from_value: from.map(String::from),
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

    fn vg(id: &str, va: u64, ty: &str) -> ValueGraphRecord {
        ValueGraphRecord {
            value_id: id.into(),
            function: 0x1000,
            source_instruction: va,
            location: "rax".into(),
            inferred_type: ty.into(),
            value: None,
            target_va: None,
            evidence: vec![],
            confidence: "medium".into(),
        }
    }

    fn vsa(kind: &str, location: &str, va: u64) -> VsaValueRecord {
        VsaValueRecord {
            value_id: format!("vsa_{va:x}"),
            function: 0x1000,
            site_va: va,
            location: location.into(),
            kind: kind.into(),
            lo: None,
            hi: None,
            stride: 0,
            value: None,
            target_va: None,
            evidence: vec![],
            confidence: "medium".into(),
            region: "stack".into(),
            expression: Some("len".into()),
            base: Some("rbp".into()),
            index: None,
            scale: 1,
            displacement: 0x10,
            possible_values: vec![],
            work_budget_exhausted: false,
        }
    }

    #[test]
    fn ingest_ssa_creates_copy_node_per_value_with_index() {
        let mut g = EvidenceGraph::new();
        let ssa_vals = vec![ssa("v1", 0x2000, "rax"), ssa("v2", 0x2010, "rcx")];
        let idx = ingest_ssa(&mut g, &ssa_vals);
        assert_eq!(idx.len(), 2);
        let copies: Vec<_> = g.nodes_of_kind(NodeKind::Copy).collect();
        assert_eq!(copies.len(), 2);
        assert!(idx.contains_key("v1"));
    }

    #[test]
    fn ingest_dataflow_wires_edges_between_known_ssa_nodes() {
        let mut g = EvidenceGraph::new();
        let idx = ingest_ssa(&mut g, &[ssa("a", 0x2000, "rax"), ssa("b", 0x2010, "rcx")]);
        ingest_dataflow(&mut g, &[dflow(Some("a"), "b")], &idx);
        let a = idx["a"];
        let edges: Vec<_> = g.outgoing_of_kind(a, EdgeKind::DataFlow).collect();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].0, idx["b"]);
    }

    #[test]
    fn ingest_dataflow_skips_edges_with_unknown_endpoint() {
        let mut g = EvidenceGraph::new();
        let idx = ingest_ssa(&mut g, &[ssa("a", 0x2000, "rax")]);
        ingest_dataflow(
            &mut g,
            &[dflow(Some("a"), "z"), dflow(Some("z"), "a")],
            &idx,
        );
        // Neither edge has both endpoints known → no edges added.
        assert_eq!(g.edge_count(), 0);
    }

    #[test]
    fn ingest_value_graph_adds_typecast_when_width_hint_present() {
        let mut g = EvidenceGraph::new();
        let idx = ingest_ssa(&mut g, &[ssa("a", 0x2000, "rax")]);
        ingest_value_graph(&mut g, &[vg("a", 0x2008, "u32")], &idx);
        let casts: Vec<_> = g.nodes_of_kind(NodeKind::TypeCast).collect();
        assert_eq!(casts.len(), 1);
    }

    #[test]
    fn ingest_value_graph_skips_records_with_no_width_hint() {
        let mut g = EvidenceGraph::new();
        let idx = ingest_ssa(&mut g, &[ssa("a", 0x2000, "rax")]);
        ingest_value_graph(&mut g, &[vg("a", 0x2008, "MysteryT")], &idx);
        let casts: Vec<_> = g.nodes_of_kind(NodeKind::TypeCast).collect();
        assert_eq!(casts.len(), 0);
    }

    #[test]
    fn ingest_vsa_recognizes_allocation_kind() {
        let mut g = EvidenceGraph::new();
        ingest_vsa(&mut g, &[vsa("heap_alloc", "rax", 0x3000)]);
        let allocs: Vec<_> = g.nodes_of_kind(NodeKind::Allocation).collect();
        assert_eq!(allocs.len(), 1);
    }

    #[test]
    fn ingest_vsa_recognizes_pointer_via_bracket_location() {
        let mut g = EvidenceGraph::new();
        ingest_vsa(&mut g, &[vsa("ptr", "[rbp+0x10]", 0x3000)]);
        let ptrs: Vec<_> = g.nodes_of_kind(NodeKind::PointerDerivation).collect();
        assert_eq!(ptrs.len(), 1);
    }

    #[test]
    fn ingest_vsa_skips_records_that_are_neither_alloc_nor_pointer() {
        let mut g = EvidenceGraph::new();
        ingest_vsa(&mut g, &[vsa("constant", "rax", 0x3000)]);
        assert_eq!(g.node_count(), 0);
    }

    #[test]
    fn width_of_recognizes_common_type_tokens() {
        assert_eq!(width_of("u32"), Some(32));
        assert_eq!(width_of("int64_t"), Some(64));
        assert_eq!(width_of("byte_buf"), Some(8));
        assert_eq!(width_of("ptr"), Some(64));
        assert!(width_of("CustomThing").is_none());
    }

    // ----- Step 5 fixtures ----------------------------------------

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
            api_categories: vec!["memory".into()],
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

    fn import(dll: &str, symbol: &str, va: u64, cats: Vec<&str>) -> ImportRecord {
        ImportRecord {
            dll: dll.into(),
            name: symbol.into(),
            symbol: symbol.into(),
            va,
            rva: va & 0xFFFF,
            hint: None,
            categories: cats.into_iter().map(String::from).collect(),
        }
    }

    fn attack(id: &str, evidence_vas: Vec<u64>) -> AttackTechniqueRecord {
        AttackTechniqueRecord {
            schema: "attack_technique/1",
            technique_id: id.into(),
            name: id.into(),
            tactic: "execution".into(),
            confidence: "medium",
            evidence: vec![],
            evidence_vas,
            source: "test".into(),
        }
    }

    fn dossier(cap: &str, evidence_vas: Vec<u64>) -> BehaviorDossierRecord {
        BehaviorDossierRecord {
            behavior_id: format!("bd_{cap}"),
            sample_sha256: "0".into(),
            function: 0x1000,
            capability: cap.into(),
            title: cap.into(),
            supporting_features: vec![],
            api_flow_ids: vec![],
            recovered_string_ids: vec![],
            type_hint_ids: vec![],
            evidence_vas,
            confidence: 0.8,
            uncertainty: None,
        }
    }

    #[test]
    fn ingest_api_flows_adds_callsite_and_sink_nodes() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![])]);
        ingest_api_flows(
            &mut g,
            &[
                api_flow(0x1000, 0x4022a4, "memcpy"),
                api_flow(0x1000, 0x4022a4, "memcpy"),
            ],
        );
        let call_sites: Vec<_> = g.nodes_of_kind(NodeKind::CallSite).collect();
        let sinks: Vec<_> = g.nodes_of_kind(NodeKind::Sink).collect();
        assert_eq!(call_sites.len(), 2); // one per flow record (no dedup in v1.0)
        assert_eq!(sinks.len(), 2);
        assert_eq!(g.nodes_of_kind(NodeKind::GlobalState).count(), 2);
    }

    #[test]
    fn ingest_api_flows_skips_unknown_function() {
        let mut g = EvidenceGraph::new();
        ingest_api_flows(&mut g, &[api_flow(0x9000, 0x4022a4, "memcpy")]);
        // No function with VA 0x9000 → flow ignored.
        assert_eq!(g.node_count(), 0);
    }

    #[test]
    fn ingest_imports_adds_function_nodes_for_iat_vas() {
        let mut g = EvidenceGraph::new();
        ingest_imports(
            &mut g,
            &[import(
                "KERNEL32.dll",
                "VirtualProtect",
                0x402100,
                vec!["memory"],
            )],
        );
        let fns: Vec<_> = g.nodes_of_kind(NodeKind::Function).collect();
        assert_eq!(fns.len(), 1);
        assert!(g.function_by_va(0x402100).is_some());
        // Name carries the dll::symbol + categories.
        let payload = g.node(fns[0].0).unwrap();
        if let NodePayload::Function { name, .. } = payload {
            let n = name.as_ref().unwrap();
            assert!(n.contains("VirtualProtect"));
            assert!(n.contains("memory"));
        } else {
            panic!("expected Function payload");
        }
    }

    #[test]
    fn ingest_imports_skips_va_already_owned_by_real_function() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x402100, vec![])]);
        ingest_imports(&mut g, &[import("X.dll", "foo", 0x402100, vec![])]);
        // Only the real function — not a duplicate pseudo-node.
        let fns: Vec<_> = g.nodes_of_kind(NodeKind::Function).collect();
        assert_eq!(fns.len(), 1);
    }

    #[test]
    fn ingest_attack_adds_global_state_node_and_reaches_edge() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![])]);
        ingest_attack(&mut g, &[attack("T1055", vec![0x1000])]);
        let globals: Vec<_> = g.nodes_of_kind(NodeKind::GlobalState).collect();
        assert_eq!(globals.len(), 1);
        let f1 = g.function_by_va(0x1000).unwrap();
        let reaches: Vec<_> = g.outgoing_of_kind(f1, EdgeKind::Reaches).collect();
        assert_eq!(reaches.len(), 1);
    }

    #[test]
    fn ingest_behavior_dossiers_keys_global_state_by_capability() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![])]);
        ingest_behavior_dossiers(&mut g, &[dossier("process_injection", vec![0x1000])]);
        let globals: Vec<_> = g.nodes_of_kind(NodeKind::GlobalState).collect();
        assert_eq!(globals.len(), 1);
        let payload = g.node(globals[0].0).unwrap();
        if let NodePayload::GlobalState { key } = payload {
            assert_eq!(key, "behavior:process_injection");
        } else {
            panic!("expected GlobalState payload");
        }
    }

    #[test]
    fn full_step_5_pipeline_against_synthetic_binary() {
        let mut g = EvidenceGraph::new();
        ingest_functions(&mut g, &[func(0x1000, vec![]), func(0x2000, vec![])]);
        ingest_imports(
            &mut g,
            &[import("KERNEL32.dll", "memcpy", 0x9100, vec!["memory"])],
        );
        ingest_api_flows(&mut g, &[api_flow(0x1000, 0x1080, "memcpy")]);
        ingest_attack(&mut g, &[attack("T1055", vec![0x1000])]);
        ingest_behavior_dossiers(&mut g, &[dossier("process_injection", vec![0x1000])]);
        // Functions=3 (2 real + 1 import); CallSite=1; Sink=1; GlobalState=3
        // (2 behavior/attack facts + 1 API-argument fact).
        assert_eq!(g.nodes_of_kind(NodeKind::Function).count(), 3);
        assert_eq!(g.nodes_of_kind(NodeKind::CallSite).count(), 1);
        assert_eq!(g.nodes_of_kind(NodeKind::Sink).count(), 1);
        assert_eq!(g.nodes_of_kind(NodeKind::GlobalState).count(), 3);
    }
}
