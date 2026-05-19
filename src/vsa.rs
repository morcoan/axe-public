use crate::ir::IrInstruction;
use crate::pe::{CfgRecord, FunctionRecord, SecondPassTargetRecord, StringRecord, VsaValueRecord};
use crate::semantic_index::FunctionSemanticIndex;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug)]
struct AbstractValue {
    kind: String,
    lo: Option<u64>,
    hi: Option<u64>,
    stride: u64,
    value: Option<String>,
    target_va: Option<u64>,
    evidence: Vec<u64>,
    confidence: String,
    region: String,
    expression: Option<String>,
    base: Option<String>,
    index: Option<String>,
    scale: u32,
    displacement: i64,
    possible_values: Vec<u64>,
}

#[derive(Clone, Debug, Default)]
struct AbstractState {
    regs: BTreeMap<String, AbstractValue>,
    stack: BTreeMap<i64, AbstractValue>,
}

#[allow(dead_code)]
pub fn analyze_targets(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    strings: &[StringRecord],
    targets: &[SecondPassTargetRecord],
    budget_name: &str,
) -> Vec<VsaValueRecord> {
    let target_functions: BTreeSet<u64> = targets.iter().map(|row| row.function).collect();
    if target_functions.is_empty() {
        return Vec::new();
    }
    let strings_by_va: BTreeMap<u64, &StringRecord> =
        strings.iter().map(|row| (row.va, row)).collect();
    let per_function_cap = match budget_name {
        "max" => usize::MAX,
        "high" => 512,
        _ => 128,
    };
    let instruction_budget = match budget_name {
        "max" => usize::MAX,
        "high" => 1024,
        _ => 128,
    };
    let mut rows = Vec::new();

    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        if !target_functions.contains(&function.start) {
            continue;
        }
        let mut emitted = 0usize;
        let mut regs: BTreeMap<String, AbstractValue> = BTreeMap::new();
        let mut stack: BTreeMap<i64, AbstractValue> = BTreeMap::new();
        let mut processed = 0usize;

        for ins in &ir[slice.ir_range.clone()] {
            if emitted >= per_function_cap || processed >= instruction_budget {
                rows.push(cap_record(function.start, ins.address, rows.len()));
                break;
            }
            processed += 1;
            if ins.memory_write {
                if let Some(slot) = ins.stack_slot {
                    if let Some(value) = value_for_instruction(ins, &strings_by_va, &regs, &stack) {
                        let value = with_evidence(value, ins.address);
                        stack.insert(slot, value.clone());
                        rows.push(record(
                            function.start,
                            ins.address,
                            format!("stack[{slot:+}]"),
                            &value,
                            rows.len(),
                        ));
                        emitted += 1;
                    }
                }
            }

            let Some(write_reg) = &ins.write_reg else {
                continue;
            };
            if let Some(value) = value_for_instruction(ins, &strings_by_va, &regs, &stack) {
                let value = with_evidence(value, ins.address);
                regs.insert(write_reg.clone(), value.clone());
                rows.push(record(
                    function.start,
                    ins.address,
                    write_reg.clone(),
                    &value,
                    rows.len(),
                ));
                emitted += 1;
            } else if !matches!(ins.mnemonic.as_str(), "mov" | "lea" | "movzx" | "movsxd") {
                regs.remove(write_reg);
            }
        }
    }

    rows
}

pub fn analyze_targets_with_cfg(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    cfg: &[CfgRecord],
    strings: &[StringRecord],
    targets: &[SecondPassTargetRecord],
    budget_name: &str,
) -> Vec<VsaValueRecord> {
    let target_functions: BTreeSet<u64> = targets.iter().map(|row| row.function).collect();
    if target_functions.is_empty() {
        return Vec::new();
    }
    let strings_by_va: BTreeMap<u64, &StringRecord> =
        strings.iter().map(|row| (row.va, row)).collect();
    let cfg_by_function: BTreeMap<u64, &CfgRecord> =
        cfg.iter().map(|row| (row.function, row)).collect();
    let per_function_cap = match budget_name {
        "max" => usize::MAX,
        "high" => 512,
        _ => 128,
    };
    let loop_limit = match budget_name {
        "max" => 16,
        "high" => 8,
        _ => 4,
    };
    let mut rows = Vec::new();

    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        if !target_functions.contains(&function.start) {
            continue;
        }
        let instruction_budget = match budget_name {
            "max" => usize::MAX,
            "high" => 1024,
            _ => 128,
        };
        let Some(cfg_record) = cfg_by_function.get(&function.start).copied() else {
            rows.extend(analyze_linear_slice(
                function.start,
                &ir[slice.ir_range.clone()],
                &strings_by_va,
                per_function_cap,
                instruction_budget,
                rows.len(),
            ));
            continue;
        };
        if cfg_record.blocks.is_empty() {
            rows.extend(analyze_linear_slice(
                function.start,
                &ir[slice.ir_range.clone()],
                &strings_by_va,
                per_function_cap,
                instruction_budget,
                rows.len(),
            ));
            continue;
        }
        let function_ir = &ir[slice.ir_range.clone()];
        rows.extend(analyze_cfg_function(
            function.start,
            function_ir,
            cfg_record,
            &strings_by_va,
            per_function_cap,
            loop_limit,
            rows.len(),
        ));
    }

    rows.sort_by(|left, right| {
        left.function
            .cmp(&right.function)
            .then_with(|| left.site_va.cmp(&right.site_va))
            .then_with(|| left.location.cmp(&right.location))
            .then_with(|| left.kind.cmp(&right.kind))
    });
    rows
}

fn analyze_linear_slice(
    function: u64,
    ir: &[IrInstruction],
    strings_by_va: &BTreeMap<u64, &StringRecord>,
    per_function_cap: usize,
    instruction_budget: usize,
    row_base: usize,
) -> Vec<VsaValueRecord> {
    let mut rows = Vec::new();
    let mut regs: BTreeMap<String, AbstractValue> = BTreeMap::new();
    let mut stack: BTreeMap<i64, AbstractValue> = BTreeMap::new();
    let mut processed = 0usize;
    for ins in ir {
        if rows.len() >= per_function_cap || processed >= instruction_budget {
            rows.push(cap_record(function, ins.address, row_base + rows.len()));
            break;
        }
        processed += 1;
        let mut state = AbstractState { regs, stack };
        if let Some((location, value)) = transfer_instruction(ins, strings_by_va, &mut state) {
            rows.push(record(
                function,
                ins.address,
                location,
                &value,
                row_base + rows.len(),
            ));
        }
        regs = state.regs;
        stack = state.stack;
    }
    rows
}

fn analyze_cfg_function(
    function: u64,
    ir: &[IrInstruction],
    cfg: &CfgRecord,
    strings_by_va: &BTreeMap<u64, &StringRecord>,
    per_function_cap: usize,
    loop_limit: usize,
    row_base: usize,
) -> Vec<VsaValueRecord> {
    let ins_by_block = instructions_by_block(ir, cfg);
    let outgoing_edges = outgoing_edges_by_block(cfg);
    let preds = predecessors_by_block(cfg);
    let entries = entry_blocks(cfg, &preds);
    let mut worklist = VecDeque::new();
    let mut in_state: BTreeMap<u64, AbstractState> = BTreeMap::new();
    for entry in entries {
        in_state.entry(entry).or_default();
        worklist.push_back(entry);
    }
    let mut iterations: BTreeMap<u64, usize> = BTreeMap::new();
    let mut capped_blocks = BTreeSet::new();
    let mut rows = Vec::new();

    while let Some(block) = worklist.pop_front() {
        if rows.len() >= per_function_cap {
            rows.push(cap_record(function, block, row_base + rows.len()));
            break;
        }
        let count = iterations.entry(block).or_default();
        *count += 1;
        if *count > loop_limit {
            if capped_blocks.insert(block) {
                rows.push(loop_cap_record(function, block, row_base + rows.len()));
            }
            continue;
        }

        let mut state = in_state.get(&block).cloned().unwrap_or_default();
        for ins in ins_by_block.get(&block).into_iter().flatten() {
            if rows.len() >= per_function_cap {
                rows.push(cap_record(function, ins.address, row_base + rows.len()));
                return rows;
            }
            if let Some((location, value)) = transfer_instruction(ins, strings_by_va, &mut state) {
                rows.push(record(
                    function,
                    ins.address,
                    location,
                    &value,
                    row_base + rows.len(),
                ));
            }
        }

        let block_ins = ins_by_block.get(&block).map(Vec::as_slice).unwrap_or(&[]);
        for edge in outgoing_edges.get(&block).into_iter().flatten().copied() {
            let successor = edge.to;
            let edge_state = refine_state_for_edge(&state, block_ins, edge);
            let old = in_state.get(&successor).cloned().unwrap_or_default();
            let joined = join_states(&old, &edge_state);
            if state_signature(&old) != state_signature(&joined) || successor == block {
                in_state.insert(successor, joined);
                worklist.push_back(successor);
            }
        }
    }

    rows
}

fn refine_state_for_edge(
    state: &AbstractState,
    block_ins: &[&IrInstruction],
    edge: &crate::pe::EdgeRecord,
) -> AbstractState {
    let mut refined = state.clone();
    let Some(branch) = block_ins
        .iter()
        .rev()
        .find(|ins| ins.is_jump && ins.direct_target.is_some())
        .copied()
    else {
        return refined;
    };
    let Some(cmp) = block_ins
        .iter()
        .rev()
        .skip_while(|ins| ins.address >= branch.address)
        .find(|ins| matches!(ins.mnemonic.as_str(), "cmp" | "test"))
        .copied()
    else {
        return refined;
    };
    let Some(reg) = cmp.read_regs.first() else {
        return refined;
    };
    let Some(imm) = cmp.immediate else {
        return refined;
    };
    let taken = branch.direct_target == Some(edge.to);
    let fallthrough = edge.edge_type == "fallthrough" && !taken;
    match branch.mnemonic.as_str() {
        "jbe" | "jle" | "jng" | "jna" => {
            if taken {
                refine_upper_bound(&mut refined, reg, imm, cmp.address);
            } else if fallthrough {
                refine_lower_bound(&mut refined, reg, imm.saturating_add(1), cmp.address);
            }
        }
        "jb" | "jl" | "jnge" | "jnae" => {
            if taken {
                refine_upper_bound(&mut refined, reg, imm.saturating_sub(1), cmp.address);
            } else if fallthrough {
                refine_lower_bound(&mut refined, reg, imm, cmp.address);
            }
        }
        "jae" | "jge" | "jnl" | "jnb" => {
            if taken {
                refine_lower_bound(&mut refined, reg, imm, cmp.address);
            } else if fallthrough {
                refine_upper_bound(&mut refined, reg, imm.saturating_sub(1), cmp.address);
            }
        }
        "ja" | "jg" | "jnle" | "jnbe" => {
            if taken {
                refine_lower_bound(&mut refined, reg, imm.saturating_add(1), cmp.address);
            } else if fallthrough {
                refine_upper_bound(&mut refined, reg, imm, cmp.address);
            }
        }
        "je" | "jz" => {
            if taken {
                refine_exact_value(&mut refined, reg, imm, cmp.address);
            }
        }
        _ => {}
    }
    refined
}

fn refine_upper_bound(state: &mut AbstractState, reg: &str, hi: u64, evidence_va: u64) {
    if let Some(value) = state.regs.get_mut(reg) {
        let lo = value.lo.unwrap_or(0);
        let new_hi = value.hi.map(|old| old.min(hi)).unwrap_or(hi);
        value.kind = if lo == new_hi {
            "constant".to_string()
        } else {
            "interval".to_string()
        };
        value.lo = Some(lo.min(new_hi));
        value.hi = Some(new_hi);
        value.possible_values = if lo == new_hi {
            vec![lo]
        } else {
            vec![lo, new_hi]
        };
        value.value = None;
        value.confidence = "medium".to_string();
        value.region = if value.region == "unknown" {
            "integer".to_string()
        } else {
            value.region.clone()
        };
        value.evidence.push(evidence_va);
        value.evidence.sort_unstable();
        value.evidence.dedup();
    }
}

fn refine_lower_bound(state: &mut AbstractState, reg: &str, lo: u64, evidence_va: u64) {
    if let Some(value) = state.regs.get_mut(reg) {
        let hi = value.hi.unwrap_or(lo);
        let new_lo = value.lo.map(|old| old.max(lo)).unwrap_or(lo);
        value.kind = if new_lo == hi {
            "constant".to_string()
        } else {
            "interval".to_string()
        };
        value.lo = Some(new_lo.min(hi));
        value.hi = Some(hi.max(new_lo));
        value.possible_values = if new_lo == hi {
            vec![new_lo]
        } else {
            vec![new_lo, hi]
        };
        value.value = None;
        value.confidence = "medium".to_string();
        value.evidence.push(evidence_va);
        value.evidence.sort_unstable();
        value.evidence.dedup();
    }
}

fn refine_exact_value(state: &mut AbstractState, reg: &str, value: u64, evidence_va: u64) {
    if let Some(existing) = state.regs.get_mut(reg) {
        existing.kind = "constant".to_string();
        existing.lo = Some(value);
        existing.hi = Some(value);
        existing.possible_values = vec![value];
        existing.value = Some(format!("0x{value:X}"));
        existing.target_va = None;
        existing.confidence = "medium".to_string();
        existing.region = "integer".to_string();
        existing.evidence.push(evidence_va);
        existing.evidence.sort_unstable();
        existing.evidence.dedup();
    }
}

fn transfer_instruction(
    ins: &IrInstruction,
    strings_by_va: &BTreeMap<u64, &StringRecord>,
    state: &mut AbstractState,
) -> Option<(String, AbstractValue)> {
    if ins.memory_write {
        if let Some(slot) = ins.stack_slot {
            if let Some(value) =
                value_for_instruction(ins, strings_by_va, &state.regs, &state.stack)
            {
                let value = with_evidence(value, ins.address);
                state.stack.insert(slot, value.clone());
                return Some((format!("stack[{slot:+}]"), value));
            }
        }
    }

    let Some(write_reg) = &ins.write_reg else {
        return None;
    };
    if let Some(value) = value_for_instruction(ins, strings_by_va, &state.regs, &state.stack) {
        let value = with_evidence(value, ins.address);
        state.regs.insert(write_reg.clone(), value.clone());
        Some((write_reg.clone(), value))
    } else if !matches!(ins.mnemonic.as_str(), "mov" | "lea" | "movzx" | "movsxd") {
        state.regs.remove(write_reg);
        None
    } else {
        None
    }
}

fn join_states(left: &AbstractState, right: &AbstractState) -> AbstractState {
    let mut regs = left.regs.clone();
    for (name, value) in &right.regs {
        regs.entry(name.clone())
            .and_modify(|existing| *existing = join_values(existing, value))
            .or_insert_with(|| value.clone());
    }
    let mut stack = left.stack.clone();
    for (slot, value) in &right.stack {
        stack
            .entry(*slot)
            .and_modify(|existing| *existing = join_values(existing, value))
            .or_insert_with(|| value.clone());
    }
    AbstractState { regs, stack }
}

fn join_values(left: &AbstractValue, right: &AbstractValue) -> AbstractValue {
    if value_signature(left) == value_signature(right) {
        return left.clone();
    }
    let mut values = possible_values(left);
    values.extend(possible_values(right));
    values.sort_unstable();
    values.dedup();
    let lo = values
        .iter()
        .copied()
        .min()
        .or_else(|| left.lo.into_iter().chain(right.lo).min());
    let hi = values
        .iter()
        .copied()
        .max()
        .or_else(|| left.hi.into_iter().chain(right.hi).max());
    let mut evidence = left.evidence.clone();
    evidence.extend(right.evidence.iter().copied());
    evidence.sort_unstable();
    evidence.dedup();
    AbstractValue {
        kind: if values.len() <= 8 && values.len() > 1 {
            "constant_set".to_string()
        } else {
            "interval".to_string()
        },
        lo,
        hi,
        stride: stride_for_values(&values),
        value: None,
        target_va: if left.target_va == right.target_va {
            left.target_va
        } else {
            None
        },
        evidence,
        confidence: "medium".to_string(),
        region: if left.region == right.region {
            left.region.clone()
        } else {
            "unknown".to_string()
        },
        expression: if left.expression == right.expression {
            left.expression.clone()
        } else {
            None
        },
        base: if left.base == right.base {
            left.base.clone()
        } else {
            None
        },
        index: if left.index == right.index {
            left.index.clone()
        } else {
            None
        },
        scale: if left.scale == right.scale {
            left.scale
        } else {
            0
        },
        displacement: if left.displacement == right.displacement {
            left.displacement
        } else {
            0
        },
        possible_values: values,
    }
}

fn possible_values(value: &AbstractValue) -> Vec<u64> {
    if !value.possible_values.is_empty() {
        return value.possible_values.clone();
    }
    match (value.lo, value.hi) {
        (Some(lo), Some(hi)) if lo == hi => vec![lo],
        (Some(lo), Some(hi)) => vec![lo, hi],
        _ => Vec::new(),
    }
}

fn stride_for_values(values: &[u64]) -> u64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut stride = 0_u64;
    for pair in sorted.windows(2) {
        let delta = pair[1].saturating_sub(pair[0]);
        stride = if stride == 0 {
            delta
        } else {
            gcd(stride, delta)
        };
    }
    stride.max(1)
}

fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let next = left % right;
        left = right;
        right = next;
    }
    left
}

fn state_signature(state: &AbstractState) -> Vec<String> {
    state
        .regs
        .iter()
        .map(|(name, value)| format!("r:{name}:{}", value_signature(value)))
        .chain(
            state
                .stack
                .iter()
                .map(|(slot, value)| format!("s:{slot}:{}", value_signature(value))),
        )
        .collect()
}

fn value_signature(value: &AbstractValue) -> String {
    format!(
        "{}:{:?}:{:?}:{:?}:{:?}:{}:{}",
        value.kind,
        value.lo,
        value.hi,
        value.possible_values,
        value.target_va,
        value.region,
        value.stride
    )
}

fn instructions_by_block<'a>(
    ir: &'a [IrInstruction],
    cfg: &CfgRecord,
) -> BTreeMap<u64, Vec<&'a IrInstruction>> {
    let mut map: BTreeMap<u64, Vec<&IrInstruction>> = BTreeMap::new();
    for block in &cfg.blocks {
        let rows = ir
            .iter()
            .filter(|ins| block.start <= ins.address && ins.address < block.end)
            .collect::<Vec<_>>();
        map.insert(block.start, rows);
    }
    map
}

fn outgoing_edges_by_block<'a>(
    cfg: &'a CfgRecord,
) -> BTreeMap<u64, Vec<&'a crate::pe::EdgeRecord>> {
    let mut map: BTreeMap<u64, Vec<&crate::pe::EdgeRecord>> = BTreeMap::new();
    for edge in &cfg.edges {
        let Some(from_block) = block_for_cfg(cfg, edge.from) else {
            continue;
        };
        map.entry(from_block).or_default().push(edge);
    }
    for values in map.values_mut() {
        values.sort_by(|left, right| {
            left.to
                .cmp(&right.to)
                .then_with(|| left.edge_type.cmp(&right.edge_type))
        });
        values.dedup_by(|left, right| left.to == right.to && left.edge_type == right.edge_type);
    }
    map
}

fn predecessors_by_block(cfg: &CfgRecord) -> BTreeMap<u64, Vec<u64>> {
    let mut map: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for edge in &cfg.edges {
        let Some(from_block) = block_for_cfg(cfg, edge.from) else {
            continue;
        };
        map.entry(edge.to).or_default().push(from_block);
    }
    for values in map.values_mut() {
        values.sort_unstable();
        values.dedup();
    }
    map
}

fn entry_blocks(cfg: &CfgRecord, preds: &BTreeMap<u64, Vec<u64>>) -> Vec<u64> {
    let mut entries = cfg
        .blocks
        .iter()
        .filter_map(|block| {
            let is_entry = preds
                .get(&block.start)
                .map(|incoming| incoming.iter().all(|pred| *pred == block.start))
                .unwrap_or(true);
            is_entry.then_some(block.start)
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        if let Some(first) = cfg.blocks.first() {
            entries.push(first.start);
        }
    }
    entries
}

fn block_for_cfg(cfg: &CfgRecord, address: u64) -> Option<u64> {
    cfg.blocks
        .iter()
        .find(|block| block.start <= address && address < block.end)
        .map(|block| block.start)
}

fn value_for_instruction(
    ins: &IrInstruction,
    strings_by_va: &BTreeMap<u64, &StringRecord>,
    regs: &BTreeMap<String, AbstractValue>,
    stack: &BTreeMap<i64, AbstractValue>,
) -> Option<AbstractValue> {
    if ins.mnemonic == "xor" {
        if let (Some(write), Some(read)) = (&ins.write_reg, ins.read_regs.first()) {
            if write == read {
                return Some(constant(0, "medium", Vec::new()));
            }
        }
    }

    if matches!(ins.mnemonic.as_str(), "add" | "sub") {
        if let (Some(source), Some(imm)) = (
            ins.read_regs.first().and_then(|reg| regs.get(reg)).cloned(),
            ins.immediate,
        ) {
            return arithmetic(source, ins.mnemonic.as_str(), imm);
        }
    }

    if matches!(ins.mnemonic.as_str(), "shl" | "shr" | "sar") {
        if let (Some(source), Some(imm)) = (
            ins.read_regs.first().and_then(|reg| regs.get(reg)).cloned(),
            ins.immediate,
        ) {
            return shift(source, ins.mnemonic.as_str(), imm);
        }
    }

    if ins.mnemonic == "and" {
        if let Some(imm) = ins.immediate {
            return Some(AbstractValue {
                kind: "interval".to_string(),
                lo: Some(0),
                hi: Some(imm),
                stride: 1,
                value: None,
                target_va: None,
                evidence: Vec::new(),
                confidence: "low".to_string(),
                region: "integer".to_string(),
                expression: None,
                base: None,
                index: None,
                scale: 0,
                displacement: 0,
                possible_values: vec![0, imm],
            });
        }
    }

    if ins.mnemonic == "lea" && ins.rip_target.is_none() {
        if let Some(value) = pointer_expression(ins, regs, strings_by_va) {
            return Some(value);
        }
    }

    if let Some(value) = pointer_or_constant(ins.rip_target, strings_by_va) {
        return Some(value);
    }
    if matches!(
        ins.mnemonic.as_str(),
        "mov" | "movabs" | "movzx" | "movsxd" | "lea"
    ) {
        if let Some(value) = pointer_or_constant(ins.immediate, strings_by_va) {
            return Some(value);
        }
    }
    if ins.memory_read {
        if let Some(value) = ins.stack_slot.and_then(|slot| stack.get(&slot)).cloned() {
            return Some(value);
        }
    }
    ins.read_regs.first().and_then(|reg| regs.get(reg)).cloned()
}

fn pointer_or_constant(
    target: Option<u64>,
    strings_by_va: &BTreeMap<u64, &StringRecord>,
) -> Option<AbstractValue> {
    let target = target?;
    if let Some(string) = strings_by_va.get(&target) {
        return Some(AbstractValue {
            kind: "string_pointer".to_string(),
            lo: Some(target),
            hi: Some(target),
            stride: 1,
            value: Some(string.text.clone()),
            target_va: Some(string.va),
            evidence: Vec::new(),
            confidence: "high".to_string(),
            region: "string".to_string(),
            expression: None,
            base: None,
            index: None,
            scale: 0,
            displacement: 0,
            possible_values: vec![target],
        });
    }
    Some(constant(target, "medium", Vec::new()))
}

fn pointer_expression(
    ins: &IrInstruction,
    regs: &BTreeMap<String, AbstractValue>,
    strings_by_va: &BTreeMap<u64, &StringRecord>,
) -> Option<AbstractValue> {
    let base_reg = ins.memory_base.clone();
    let index_reg = ins.memory_index.clone();
    if base_reg.is_none() && index_reg.is_none() && ins.memory_displacement == 0 {
        return None;
    }
    let base_value = base_reg
        .as_ref()
        .and_then(|reg| regs.get(reg))
        .and_then(|value| value.lo);
    let index_value = index_reg
        .as_ref()
        .and_then(|reg| regs.get(reg))
        .and_then(|value| value.lo);
    let mut target = base_value.unwrap_or(0);
    if let Some(index) = index_value {
        target = target.wrapping_add(index.wrapping_mul(ins.memory_scale.max(1) as u64));
    }
    target = target.wrapping_add_signed(ins.memory_displacement);
    if target == 0 {
        return None;
    }
    let string = strings_by_va.get(&target);
    Some(AbstractValue {
        kind: "pointer_expression".to_string(),
        lo: Some(target),
        hi: Some(target),
        stride: 1,
        value: string
            .map(|row| row.text.clone())
            .or_else(|| Some(format!("0x{target:X}"))),
        target_va: Some(target),
        evidence: Vec::new(),
        confidence: if base_value.is_some() || index_value.is_some() {
            "medium".to_string()
        } else {
            "low".to_string()
        },
        region: if string.is_some() {
            "string".to_string()
        } else {
            "data".to_string()
        },
        expression: Some(format!(
            "{} + {}*{} {:+#x}",
            base_reg.clone().unwrap_or_else(|| "0".to_string()),
            index_reg.clone().unwrap_or_else(|| "0".to_string()),
            ins.memory_scale.max(1),
            ins.memory_displacement
        )),
        base: base_reg,
        index: index_reg,
        scale: ins.memory_scale.max(1),
        displacement: ins.memory_displacement,
        possible_values: vec![target],
    })
}

fn arithmetic(mut source: AbstractValue, op: &str, imm: u64) -> Option<AbstractValue> {
    let (Some(lo), Some(hi)) = (source.lo, source.hi) else {
        return None;
    };
    let (next_lo, next_hi) = if op == "sub" {
        (lo.wrapping_sub(imm), hi.wrapping_sub(imm))
    } else {
        (lo.wrapping_add(imm), hi.wrapping_add(imm))
    };
    source.lo = Some(next_lo);
    source.hi = Some(next_hi);
    source.value = if next_lo == next_hi {
        source.kind = "constant".to_string();
        Some(format!("0x{next_lo:X}"))
    } else {
        source.kind = "interval".to_string();
        None
    };
    source.confidence = "medium".to_string();
    source.possible_values = vec![next_lo, next_hi];
    Some(source)
}

fn shift(mut source: AbstractValue, op: &str, imm: u64) -> Option<AbstractValue> {
    let (Some(lo), Some(hi)) = (source.lo, source.hi) else {
        return None;
    };
    if imm >= 64 {
        return None;
    }
    let (next_lo, next_hi) = match op {
        "shl" => (lo.wrapping_shl(imm as u32), hi.wrapping_shl(imm as u32)),
        _ => (lo.wrapping_shr(imm as u32), hi.wrapping_shr(imm as u32)),
    };
    source.lo = Some(next_lo.min(next_hi));
    source.hi = Some(next_lo.max(next_hi));
    source.value = (source.lo == source.hi).then(|| format!("0x{:X}", source.lo.unwrap()));
    source.kind = if source.lo == source.hi {
        "constant".to_string()
    } else {
        "interval".to_string()
    };
    source.confidence = "medium".to_string();
    source.possible_values = vec![next_lo, next_hi];
    Some(source)
}

fn constant(value: u64, confidence: &str, evidence: Vec<u64>) -> AbstractValue {
    AbstractValue {
        kind: "constant".to_string(),
        lo: Some(value),
        hi: Some(value),
        stride: 1,
        value: Some(format!("0x{value:X}")),
        target_va: None,
        evidence,
        confidence: confidence.to_string(),
        region: "integer".to_string(),
        expression: None,
        base: None,
        index: None,
        scale: 0,
        displacement: 0,
        possible_values: vec![value],
    }
}

fn with_evidence(mut value: AbstractValue, address: u64) -> AbstractValue {
    if !value.evidence.contains(&address) {
        value.evidence.push(address);
    }
    value
}

fn record(
    function: u64,
    site_va: u64,
    location: String,
    value: &AbstractValue,
    index: usize,
) -> VsaValueRecord {
    VsaValueRecord {
        value_id: format!("vsa:{function:016X}:{site_va:016X}:{index:04X}"),
        function,
        site_va,
        location,
        kind: value.kind.clone(),
        lo: value.lo,
        hi: value.hi,
        stride: value.stride,
        value: value.value.clone(),
        target_va: value.target_va,
        evidence: value.evidence.clone(),
        confidence: value.confidence.clone(),
        region: value.region.clone(),
        expression: value.expression.clone(),
        base: value.base.clone(),
        index: value.index.clone(),
        scale: value.scale,
        displacement: value.displacement,
        possible_values: value.possible_values.clone(),
        work_budget_exhausted: false,
    }
}

fn cap_record(function: u64, site_va: u64, index: usize) -> VsaValueRecord {
    VsaValueRecord {
        value_id: format!("vsa:{function:016X}:{site_va:016X}:cap:{index:04X}"),
        function,
        site_va,
        location: "analysis_budget".to_string(),
        kind: "cap".to_string(),
        lo: None,
        hi: None,
        stride: 0,
        value: Some("work_budget_exhausted".to_string()),
        target_va: None,
        evidence: vec![site_va],
        confidence: "high".to_string(),
        region: "unknown".to_string(),
        expression: None,
        base: None,
        index: None,
        scale: 0,
        displacement: 0,
        possible_values: Vec::new(),
        work_budget_exhausted: true,
    }
}

fn loop_cap_record(function: u64, site_va: u64, index: usize) -> VsaValueRecord {
    VsaValueRecord {
        value_id: format!("vsa:{function:016X}:{site_va:016X}:loopcap:{index:04X}"),
        function,
        site_va,
        location: "analysis_budget".to_string(),
        kind: "cap".to_string(),
        lo: None,
        hi: None,
        stride: 0,
        value: Some("loop_widening_cap".to_string()),
        target_va: None,
        evidence: vec![site_va],
        confidence: "high".to_string(),
        region: "unknown".to_string(),
        expression: None,
        base: None,
        index: None,
        scale: 0,
        displacement: 0,
        possible_values: Vec::new(),
        work_budget_exhausted: true,
    }
}
