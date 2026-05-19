use crate::ir::IrInstruction;
use crate::pe::{
    ApiFlowRecord, CallGraphRecord, FunctionRecord, ResolvedCallRecord, StringRecord,
    ValueGraphRecord, XrefRecord,
};
use crate::semantic_index::{
    flow_id, FunctionSemanticIndex, SemanticBudget, SemanticCapsHit, SemanticCounters,
};
use crate::strings::{classify_string, import_categories};
use crate::winapi;
use std::collections::BTreeMap;

#[derive(Clone)]
struct TrackedValue {
    value: String,
    tags: Vec<String>,
    evidence: Vec<u64>,
}

pub fn build_api_flows(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    xrefs: &[XrefRecord],
    strings: &[StringRecord],
    values: &[ValueGraphRecord],
    resolved_calls: &[ResolvedCallRecord],
    budget: &SemanticBudget,
    counters: &mut SemanticCounters,
    caps_hit: &mut SemanticCapsHit,
) -> Vec<ApiFlowRecord> {
    let strings_by_va: BTreeMap<u64, &StringRecord> =
        strings.iter().map(|row| (row.va, row)).collect();
    // Collect direct import-call xrefs (kind=import role=call): code
    // that calls an import symbol via the standard import descriptor.
    // Captures both direct calls AND the IAT-operand pattern.
    let import_call_by_site: BTreeMap<u64, (String, Option<ResolvedCallRecord>)> = xrefs
        .iter()
        .filter(|xref| xref.kind == "import" && (xref.role == "call" || xref.role == "operand"))
        .filter_map(|xref| {
            xref.symbol
                .as_ref()
                .map(|symbol| (xref.from, (symbol.clone(), None::<ResolvedCallRecord>)))
        })
        .collect();
    let mut call_by_site = import_call_by_site;

    // **v1.0.2 fix**: Resolve MinGW/VS-style import THUNKS. The MinGW
    // x86_64 pattern for importing `memcpy` is:
    //
    //   user_code:    call thunk_va       ; kind=code role=call xref
    //                                     ; target=thunk_va
    //   thunk_va:     jmp [iat_va]        ; kind=import role=operand
    //                                     ; xref symbol=memcpy
    //
    // The direct call to thunk_va has no `symbol` field on its xref,
    // so the api_flows pass above never resolves it. We bridge by
    // building a thunk_va -> import_symbol map from import-operand
    // xrefs (restricted to JMP instructions, which is the thunk
    // shape), then synthesize an entry in call_by_site for every
    // code-call xref whose target is a thunk.
    //
    // Without this, MinGW/VS PE binaries lose almost every memcpy /
    // malloc / printf / sprintf / RegQuery / file-IO call site
    // because all such calls go through thunks, and the vuln-
    // discovery sink-arg templates can't fire.
    use std::collections::HashSet;
    let ir_jmp_addresses: HashSet<u64> = ir
        .iter()
        .filter(|ins| !ins.is_call && ins.mnemonic == "jmp")
        .map(|ins| ins.address)
        .collect();
    let thunk_to_import: BTreeMap<u64, String> = xrefs
        .iter()
        .filter(|xref| {
            xref.kind == "import"
                && xref.role == "operand"
                && xref.symbol.is_some()
                && ir_jmp_addresses.contains(&xref.from)
        })
        .filter_map(|xref| xref.symbol.as_ref().map(|s| (xref.from, s.clone())))
        .collect();
    for xref in xrefs
        .iter()
        .filter(|x| x.kind == "code" && x.role == "call")
    {
        if let Some(symbol) = thunk_to_import.get(&xref.target) {
            // Don't overwrite an existing direct import-call resolution.
            call_by_site
                .entry(xref.from)
                .or_insert((symbol.clone(), None));
        }
    }

    // **v1.0.2 fix part 2**: Resolve register-indirect import calls.
    // MinGW/VS sometimes emit:
    //
    //   mov  rax, qword ptr [iat]       ; kind=import role=operand
    //                                   ; xref symbol=recv
    //   ...
    //   call rax                         ; is_call=true but no symbol
    //
    // for imports that aren't routed through a thunk (typically those
    // from DLLs without a small import library, like WS2_32!recv on
    // MinGW). The MOV-to-import xref carries the symbol; we need to
    // forward it to the eventual CALL.
    //
    // Approach: collect mov_va -> import_symbol from import-operand
    // xrefs whose source is a non-call non-jmp IR instruction (i.e.,
    // a memory-load like MOV/LEA). Then track per-function reg state:
    // when an IR instruction is at a mov_to_import VA, record
    // write_reg -> symbol; when we see an indirect call (is_call with
    // no resolved symbol), look up read_regs[0] in this tracker.
    //
    // The per-instruction tracking happens inside the inner loop;
    // here we just build the static mov_va -> symbol map.
    let ir_by_va: BTreeMap<u64, &IrInstruction> = ir.iter().map(|ins| (ins.address, ins)).collect();
    let mov_to_import: BTreeMap<u64, String> = xrefs
        .iter()
        .filter(|xref| {
            xref.kind == "import"
                && xref.role == "operand"
                && xref.symbol.is_some()
                && !ir_jmp_addresses.contains(&xref.from)
                && ir_by_va
                    .get(&xref.from)
                    .map(|ins| !ins.is_call && ins.write_reg.is_some())
                    .unwrap_or(false)
        })
        .filter_map(|xref| xref.symbol.as_ref().map(|s| (xref.from, s.clone())))
        .collect();

    for call in resolved_calls {
        call_by_site.insert(
            call.callsite,
            (call.resolved_api.clone(), Some(call.clone())),
        );
    }
    let value_index = index_values(values);

    let mut rows = Vec::new();
    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        let mut reg_state: BTreeMap<String, TrackedValue> = BTreeMap::new();
        let mut stack_state: BTreeMap<i64, TrackedValue> = BTreeMap::new();
        // v1.0.2 part 2: per-function tracker for register-indirect
        // import calls. Mirrors `reg_state` lifetime (reset per
        // function so cross-function noise doesn't leak).
        let mut reg_to_import: BTreeMap<String, String> = BTreeMap::new();

        for ins in &ir[slice.ir_range.clone()] {
            update_state(ins, &strings_by_va, &mut reg_state, &mut stack_state);

            // Track register-to-import bindings. When the instruction
            // is a known import-load MOV, record the destination
            // register. When some other write overwrites the same
            // register, evict.
            if let Some(symbol) = mov_to_import.get(&ins.address) {
                if let Some(reg) = ins.write_reg.as_ref() {
                    reg_to_import.insert(reg.clone(), symbol.clone());
                }
            } else if let Some(reg) = ins.write_reg.as_ref() {
                // Any other write to a tracked register evicts.
                reg_to_import.remove(reg);
            }

            if !ins.is_call {
                continue;
            }
            // Resolve: first try the static call_by_site map (direct
            // calls + thunks). If that misses, check whether this is
            // an indirect call via a register that holds an import
            // address (the `mov reg, [iat]; ... ; call reg` pattern).
            let resolved = call_by_site.get(&ins.address).cloned().or_else(|| {
                ins.read_regs
                    .first()
                    .and_then(|reg| reg_to_import.get(reg))
                    .map(|sym| (sym.clone(), None))
            });
            let Some((api, resolved_call)) = resolved else {
                continue;
            };
            let api = &api;
            let resolved_call = &resolved_call;
            let meta = winapi::metadata(api);
            let classification = winapi::classify_api(api);
            let mut proven_for_call = 0usize;
            for arg in &meta.args {
                if let Some(value) =
                    latest_indexed_value(&value_index, function.start, arg.register, ins.address)
                {
                    let index = rows.len();
                    rows.push(ApiFlowRecord {
                        flow_id: flow_id(function.start, ins.address, index),
                        function: function.start,
                        callsite: ins.address,
                        api: api.clone(),
                        normalized_api: classification.normalized_symbol.clone(),
                        api_tier: classification.tier.clone(),
                        api_family: classification.family.clone(),
                        semantic_relevance: classification.semantic_relevance.clone(),
                        noise_reason: classification.noise_reason.clone(),
                        api_categories: meta.categories.clone(),
                        value: value
                            .value
                            .clone()
                            .unwrap_or_default()
                            .chars()
                            .take(500)
                            .collect(),
                        value_tags: classify_string(value.value.as_deref().unwrap_or_default()),
                        argument: arg.name.to_string(),
                        argument_register: Some(arg.register.to_string()),
                        argument_index: Some(arg.index),
                        argument_name: Some(arg.name.to_string()),
                        confidence: "high".to_string(),
                        mode: "proven".to_string(),
                        resolved_api: resolved_call.as_ref().map(|row| row.resolved_api.clone()),
                        wrapper_chain: resolved_call
                            .as_ref()
                            .map(|row| row.wrapper_chain.clone())
                            .unwrap_or_default(),
                        evidence: value
                            .evidence
                            .iter()
                            .copied()
                            .chain([ins.address])
                            .collect(),
                    });
                    proven_for_call += 1;
                    counters.api_flows_proven += 1;
                } else if let Some(value) = reg_state.get(arg.register) {
                    let index = rows.len();
                    rows.push(ApiFlowRecord {
                        flow_id: flow_id(function.start, ins.address, index),
                        function: function.start,
                        callsite: ins.address,
                        api: api.clone(),
                        normalized_api: classification.normalized_symbol.clone(),
                        api_tier: classification.tier.clone(),
                        api_family: classification.family.clone(),
                        semantic_relevance: classification.semantic_relevance.clone(),
                        noise_reason: classification.noise_reason.clone(),
                        api_categories: meta.categories.clone(),
                        value: value.value.chars().take(500).collect(),
                        value_tags: value.tags.clone(),
                        argument: arg.name.to_string(),
                        argument_register: Some(arg.register.to_string()),
                        argument_index: Some(arg.index),
                        argument_name: Some(arg.name.to_string()),
                        confidence: "high".to_string(),
                        mode: "proven".to_string(),
                        resolved_api: resolved_call.as_ref().map(|row| row.resolved_api.clone()),
                        wrapper_chain: resolved_call
                            .as_ref()
                            .map(|row| row.wrapper_chain.clone())
                            .unwrap_or_default(),
                        evidence: value
                            .evidence
                            .iter()
                            .copied()
                            .chain([ins.address])
                            .collect(),
                    });
                    proven_for_call += 1;
                    counters.api_flows_proven += 1;
                }
            }
            if proven_for_call == 0 {
                let start_len = rows.len();
                rows.extend(heuristic_flows(
                    function,
                    ins.address,
                    api,
                    budget,
                    caps_hit,
                    start_len,
                    resolved_call.as_ref(),
                ));
                counters.api_flows_heuristic += rows.len().saturating_sub(start_len);
            }
        }
    }
    rows
}

pub fn build_callgraph(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    xrefs: &[XrefRecord],
    resolved_calls: &[ResolvedCallRecord],
) -> Vec<CallGraphRecord> {
    let mut rows = Vec::new();
    let resolved_by_site: BTreeMap<u64, &ResolvedCallRecord> = resolved_calls
        .iter()
        .map(|row| (row.callsite, row))
        .collect();
    for slice in &semantic_index.slices {
        let Some(caller) = functions.get(slice.function_index) else {
            continue;
        };
        for xref in &xrefs[slice.xref_range.clone()] {
            if xref.role != "call" && xref.role != "branch" {
                continue;
            }
            if xref.kind == "import" {
                let resolved = resolved_by_site.get(&xref.from);
                rows.push(CallGraphRecord {
                    caller: caller.start,
                    callee: None,
                    import: xref.symbol.clone(),
                    callsite: xref.from,
                    call_kind: "import".to_string(),
                    confidence: "high".to_string(),
                    resolved_api: resolved.map(|row| row.resolved_api.clone()),
                    wrapper_chain: resolved
                        .map(|row| row.wrapper_chain.clone())
                        .unwrap_or_default(),
                });
            } else if xref.kind == "code" {
                let resolved = resolved_by_site.get(&xref.from);
                rows.push(CallGraphRecord {
                    caller: caller.start,
                    callee: Some(xref.target),
                    import: None,
                    callsite: xref.from,
                    call_kind: if xref.role == "branch" {
                        "tail_or_jump".to_string()
                    } else {
                        "direct".to_string()
                    },
                    confidence: if xref.role == "branch" {
                        "medium"
                    } else {
                        "high"
                    }
                    .to_string(),
                    resolved_api: resolved.map(|row| row.resolved_api.clone()),
                    wrapper_chain: resolved
                        .map(|row| row.wrapper_chain.clone())
                        .unwrap_or_default(),
                });
            }
        }
    }
    rows
}

fn index_values<'a>(
    values: &'a [ValueGraphRecord],
) -> BTreeMap<u64, BTreeMap<String, Vec<&'a ValueGraphRecord>>> {
    let mut index: BTreeMap<u64, BTreeMap<String, Vec<&'a ValueGraphRecord>>> = BTreeMap::new();
    for value in values {
        index
            .entry(value.function)
            .or_default()
            .entry(value.location.clone())
            .or_default()
            .push(value);
    }
    index
}

fn latest_indexed_value<'a>(
    index: &'a BTreeMap<u64, BTreeMap<String, Vec<&'a ValueGraphRecord>>>,
    function: u64,
    location: &str,
    before_or_at: u64,
) -> Option<&'a ValueGraphRecord> {
    let values = index.get(&function)?.get(location)?;
    let idx = values.partition_point(|row| row.source_instruction <= before_or_at);
    idx.checked_sub(1)
        .and_then(|position| values.get(position).copied())
}

fn update_state(
    ins: &IrInstruction,
    strings_by_va: &BTreeMap<u64, &StringRecord>,
    reg_state: &mut BTreeMap<String, TrackedValue>,
    stack_state: &mut BTreeMap<i64, TrackedValue>,
) {
    if ins.mnemonic == "xor" {
        if let Some(write) = &ins.write_reg {
            if ins.read_regs.iter().any(|reg| reg == write) {
                reg_state.remove(write);
            }
        }
        return;
    }

    if ins.memory_write {
        if let Some(slot) = ins.stack_slot {
            if let Some(source) = ins
                .read_regs
                .first()
                .and_then(|reg| reg_state.get(reg))
                .cloned()
            {
                stack_state.insert(slot, source);
            }
        }
    }

    let Some(write_reg) = &ins.write_reg else {
        return;
    };
    if let Some(value) = string_value(ins.rip_target, strings_by_va, ins.address) {
        reg_state.insert(write_reg.clone(), value);
        return;
    }
    if let Some(value) = string_value(ins.immediate, strings_by_va, ins.address) {
        reg_state.insert(write_reg.clone(), value);
        return;
    }
    if ins.memory_read {
        if let Some(slot) = ins.stack_slot {
            if let Some(value) = stack_state.get(&slot).cloned() {
                reg_state.insert(write_reg.clone(), value);
                return;
            }
        }
    }
    if let Some(value) = ins
        .read_regs
        .first()
        .and_then(|reg| reg_state.get(reg))
        .cloned()
    {
        reg_state.insert(write_reg.clone(), value);
        return;
    }
    if !matches!(ins.mnemonic.as_str(), "mov" | "lea" | "movzx" | "movsxd") {
        reg_state.remove(write_reg);
    }
}

fn string_value(
    target: Option<u64>,
    strings_by_va: &BTreeMap<u64, &StringRecord>,
    evidence_va: u64,
) -> Option<TrackedValue> {
    let string = strings_by_va.get(&target?)?;
    Some(TrackedValue {
        value: string.text.clone(),
        tags: string.classifiers.clone(),
        evidence: vec![evidence_va],
    })
}

fn heuristic_flows(
    function: &FunctionRecord,
    callsite: u64,
    api: &str,
    budget: &SemanticBudget,
    caps_hit: &mut SemanticCapsHit,
    start_index: usize,
    resolved_call: Option<&ResolvedCallRecord>,
) -> Vec<ApiFlowRecord> {
    let categories = import_categories(api);
    let classification = winapi::classify_api(api);
    if categories.is_empty() {
        return Vec::new();
    }
    if function.strings.len() > budget.heuristic_strings_per_call {
        caps_hit.heuristic_api_flows = true;
    }
    function
        .strings
        .iter()
        .take(budget.heuristic_strings_per_call)
        .enumerate()
        .filter_map(|value| {
            let (idx, value) = value;
            let value_tags = classify_string(value);
            if value_tags.is_empty() {
                return None;
            }
            Some(ApiFlowRecord {
                flow_id: flow_id(function.start, callsite, start_index + idx),
                function: function.start,
                callsite,
                api: api.to_string(),
                normalized_api: classification.normalized_symbol.clone(),
                api_tier: classification.tier.clone(),
                api_family: classification.family.clone(),
                semantic_relevance: classification.semantic_relevance.clone(),
                noise_reason: classification.noise_reason.clone(),
                api_categories: categories.clone(),
                value: value.chars().take(500).collect(),
                value_tags,
                argument: "unknown_static_candidate".to_string(),
                argument_register: None,
                argument_index: None,
                argument_name: None,
                confidence: "low".to_string(),
                mode: "heuristic".to_string(),
                resolved_api: resolved_call.map(|row| row.resolved_api.clone()),
                wrapper_chain: resolved_call
                    .map(|row| row.wrapper_chain.clone())
                    .unwrap_or_default(),
                evidence: vec![function.start, callsite],
            })
        })
        .collect()
}
