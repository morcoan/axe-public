use crate::pe::{
    ApiFlowRecord, ApiHashResolutionRecord, DataflowEdgeRecord, FunctionRecord, JumpTableRecord,
    PseudoIrRecord, ResolvedCallRecord, SsaValueRecord, StructuredFlowRecord, TypeHintRecord,
    ValueGraphRecord, VsaValueRecord,
};
use std::collections::BTreeMap;

pub fn build_pseudo_ir(
    functions: &[FunctionRecord],
    values: &[ValueGraphRecord],
    ssa_values: &[SsaValueRecord],
    dataflow_edges: &[DataflowEdgeRecord],
    api_flows: &[ApiFlowRecord],
    resolved_calls: &[ResolvedCallRecord],
    structured_flow: &[StructuredFlowRecord],
    vsa_values: &[VsaValueRecord],
    type_hints: &[TypeHintRecord],
    jump_tables: &[JumpTableRecord],
    api_hash_resolutions: &[ApiHashResolutionRecord],
    mode: &str,
) -> Vec<PseudoIrRecord> {
    if mode == "off" {
        return Vec::new();
    }
    let mut values_by_function: BTreeMap<u64, Vec<&ValueGraphRecord>> = BTreeMap::new();
    for value in values {
        values_by_function
            .entry(value.function)
            .or_default()
            .push(value);
    }
    let mut ssa_by_function: BTreeMap<u64, Vec<&SsaValueRecord>> = BTreeMap::new();
    for value in ssa_values {
        ssa_by_function
            .entry(value.function)
            .or_default()
            .push(value);
    }
    let mut edges_by_function: BTreeMap<u64, Vec<&DataflowEdgeRecord>> = BTreeMap::new();
    for edge in dataflow_edges {
        edges_by_function
            .entry(edge.function)
            .or_default()
            .push(edge);
    }
    let mut flows_by_function: BTreeMap<u64, Vec<&ApiFlowRecord>> = BTreeMap::new();
    for flow in api_flows {
        flows_by_function
            .entry(flow.function)
            .or_default()
            .push(flow);
    }
    let mut resolved_by_function: BTreeMap<u64, Vec<&ResolvedCallRecord>> = BTreeMap::new();
    for call in resolved_calls {
        resolved_by_function
            .entry(call.caller)
            .or_default()
            .push(call);
    }
    let structured_by_function: BTreeMap<u64, &StructuredFlowRecord> = structured_flow
        .iter()
        .map(|row| (row.function, row))
        .collect();
    let mut vsa_by_function: BTreeMap<u64, Vec<&VsaValueRecord>> = BTreeMap::new();
    for value in vsa_values {
        vsa_by_function
            .entry(value.function)
            .or_default()
            .push(value);
    }
    let mut types_by_function: BTreeMap<u64, Vec<&TypeHintRecord>> = BTreeMap::new();
    for hint in type_hints {
        types_by_function
            .entry(hint.function)
            .or_default()
            .push(hint);
    }
    let mut jump_tables_by_function: BTreeMap<u64, Vec<&JumpTableRecord>> = BTreeMap::new();
    for table in jump_tables {
        jump_tables_by_function
            .entry(table.function)
            .or_default()
            .push(table);
    }
    let mut hashes_by_function: BTreeMap<u64, Vec<&ApiHashResolutionRecord>> = BTreeMap::new();
    for hash in api_hash_resolutions {
        hashes_by_function
            .entry(hash.function)
            .or_default()
            .push(hash);
    }

    functions
        .iter()
        .map(|function| {
            let mut lines = Vec::new();
            let mut evidence = Vec::new();
            for value in values_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(12)
            {
                if let Some(text) = &value.value {
                    lines.push(format!(
                        "{} = {}({:?})",
                        value.location, value.inferred_type, text
                    ));
                    evidence.push(value.source_instruction);
                }
            }
            for flow in flows_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|flow| flow.semantic_relevance != "low")
                .take(12)
            {
                lines.push(format!(
                    "call {} {} <= {} {:?}",
                    flow.api_family, flow.api, flow.argument, flow.value
                ));
                evidence.push(flow.callsite);
            }
            for value in ssa_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|row| row.kind != "flag")
                .take(8)
            {
                lines.push(format!(
                    "ssa {}@v{} {} from 0x{:016X}",
                    value.storage, value.version, value.kind, value.site_va
                ));
                evidence.push(value.site_va);
            }
            for edge in edges_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(8)
            {
                lines.push(format!(
                    "dataflow {} -> {} ({})",
                    edge.from_storage
                        .clone()
                        .unwrap_or_else(|| "input".to_string()),
                    edge.to_storage,
                    edge.edge_kind
                ));
                evidence.push(edge.to_va);
                if let Some(from_va) = edge.from_va {
                    evidence.push(from_va);
                }
            }
            for value in vsa_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(8)
            {
                let rendered = value
                    .value
                    .clone()
                    .or_else(|| value.lo.map(|lo| format!("0x{lo:X}")))
                    .unwrap_or_else(|| "unknown".to_string());
                let expr = value
                    .expression
                    .as_ref()
                    .map(|expr| format!(" expr={expr}"))
                    .unwrap_or_default();
                lines.push(format!(
                    "vsa {}:{} = {} region={}{}",
                    value.location, value.kind, rendered, value.region, expr
                ));
                evidence.push(value.site_va);
            }
            for hint in types_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(8)
            {
                lines.push(format!("type {} = {}", hint.location, hint.type_tag));
                evidence.push(hint.site_va);
            }
            for table in jump_tables_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(4)
            {
                lines.push(format!(
                    "switch/jumptable 0x{:016X} targets={}",
                    table.jump_va,
                    table.targets.len()
                ));
                evidence.push(table.jump_va);
            }
            for hash in hashes_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(8)
            {
                lines.push(format!(
                    "api_hash {} {} => {}",
                    hash.algorithm, hash.hash_value, hash.resolved_api
                ));
                if let Some(site) = hash.site_va {
                    evidence.push(site);
                }
            }
            for call in resolved_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(8)
            {
                if call.resolution_kind.as_deref() == Some("virtual_dispatch") {
                    lines.push(format!(
                        "call virtual class={} vtable=0x{:016X} slot={} target=0x{:016X}",
                        call.class_id.as_deref().unwrap_or("unknown"),
                        call.vtable_va.unwrap_or(0),
                        call.vtable_slot.unwrap_or(0),
                        call.target.unwrap_or(0)
                    ));
                } else if call.resolution_kind.as_deref() == Some("ambiguous_virtual_dispatch") {
                    lines.push(format!(
                        "unknown(ambiguous_virtual_dispatch slot={} candidates={})",
                        call.vtable_slot.unwrap_or(0),
                        call.candidate_targets.len()
                    ));
                } else {
                    lines.push(format!(
                        "call wrapper 0x{:016X} => {}",
                        call.original_callee, call.resolved_api
                    ));
                }
                evidence.push(call.callsite);
            }
            if let Some(structured) = structured_by_function.get(&function.start) {
                if structured.has_loop_like_backedge {
                    lines.push(format!(
                        "loop_like_backedges = {}",
                        structured.backedges.len()
                    ));
                }
                if !structured.return_blocks.is_empty() {
                    lines.push(format!("returns = {}", structured.return_blocks.len()));
                }
                if structured.refined {
                    lines.push(format!(
                        "structured_regions = {}",
                        structured.regions.join(",")
                    ));
                    if !structured.structuring_notes.is_empty() {
                        lines.push(format!(
                            "structuring_notes = {}",
                            structured.structuring_notes.join(",")
                        ));
                    }
                    for case in structured.switch_cases.iter().take(8) {
                        evidence.push(*case);
                    }
                }
            }
            if lines.is_empty() {
                lines.push(format!(
                    "unknown(static_semantics_unresolved function=0x{:016X})",
                    function.start
                ));
            }
            evidence.sort();
            evidence.dedup();
            PseudoIrRecord {
                pseudo_ir_id: format!("pseudo:{:016X}", function.start),
                function: function.start,
                confidence: if evidence.is_empty() {
                    "low".to_string()
                } else {
                    "medium".to_string()
                },
                lines,
                evidence,
            }
        })
        .collect()
}
