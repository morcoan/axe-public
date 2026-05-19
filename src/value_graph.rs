use crate::ir::IrInstruction;
use crate::pe::{FunctionRecord, StringRecord, ValueGraphRecord};
use crate::semantic_index::FunctionSemanticIndex;
use std::collections::BTreeMap;

#[derive(Clone)]
struct TrackedValue {
    inferred_type: String,
    value: Option<String>,
    target_va: Option<u64>,
    evidence: Vec<u64>,
    confidence: String,
}

pub fn build_value_graph(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    strings: &[StringRecord],
) -> Vec<ValueGraphRecord> {
    let strings_by_va: BTreeMap<u64, &StringRecord> =
        strings.iter().map(|row| (row.va, row)).collect();
    let mut rows = Vec::new();
    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        let mut regs: BTreeMap<String, TrackedValue> = BTreeMap::new();
        let mut stack: BTreeMap<i64, TrackedValue> = BTreeMap::new();
        for ins in &ir[slice.ir_range.clone()] {
            if ins.memory_write {
                if let Some(slot) = ins.stack_slot {
                    if let Some(value) = value_from_instruction(ins, &strings_by_va)
                        .or_else(|| copy_from_first_reg(ins, &regs))
                    {
                        stack.insert(slot, append_evidence(value, ins.address));
                        if let Some(row) = record_for(
                            function.start,
                            ins.address,
                            format!("stack[{slot:+}]"),
                            stack.get(&slot).unwrap(),
                            rows.len(),
                        ) {
                            rows.push(row);
                        }
                    }
                }
            }

            let Some(write_reg) = &ins.write_reg else {
                continue;
            };
            let next = value_from_instruction(ins, &strings_by_va)
                .or_else(|| stack_value(ins, &stack))
                .or_else(|| copy_from_first_reg(ins, &regs));
            if let Some(value) = next {
                let value = append_evidence(value, ins.address);
                regs.insert(write_reg.clone(), value);
                if let Some(row) = record_for(
                    function.start,
                    ins.address,
                    write_reg.clone(),
                    regs.get(write_reg).unwrap(),
                    rows.len(),
                ) {
                    rows.push(row);
                }
            } else if !matches!(ins.mnemonic.as_str(), "mov" | "lea" | "movzx" | "movsxd") {
                regs.remove(write_reg);
            }
        }
    }
    rows
}

fn value_from_instruction(
    ins: &IrInstruction,
    strings_by_va: &BTreeMap<u64, &StringRecord>,
) -> Option<TrackedValue> {
    if let Some(string) = ins
        .rip_target
        .and_then(|target| strings_by_va.get(&target).copied())
        .or_else(|| {
            ins.immediate
                .and_then(|target| strings_by_va.get(&target).copied())
        })
    {
        return Some(TrackedValue {
            inferred_type: "string_pointer".to_string(),
            value: Some(string.text.clone()),
            target_va: Some(string.va),
            evidence: Vec::new(),
            confidence: "high".to_string(),
        });
    }
    if ins.mnemonic == "xor" {
        if let (Some(write), Some(read)) = (&ins.write_reg, ins.read_regs.first()) {
            if write == read {
                return Some(TrackedValue {
                    inferred_type: "constant".to_string(),
                    value: Some("0x0".to_string()),
                    target_va: None,
                    evidence: Vec::new(),
                    confidence: "medium".to_string(),
                });
            }
        }
    }
    if let Some(immediate) = ins.immediate.filter(|_| {
        matches!(
            ins.mnemonic.as_str(),
            "mov" | "movabs" | "movzx" | "movsxd" | "lea"
        )
    }) {
        return Some(TrackedValue {
            inferred_type: "constant".to_string(),
            value: Some(format!("0x{immediate:X}")),
            target_va: None,
            evidence: Vec::new(),
            confidence: "medium".to_string(),
        });
    }
    None
}

fn stack_value(ins: &IrInstruction, stack: &BTreeMap<i64, TrackedValue>) -> Option<TrackedValue> {
    if !ins.memory_read {
        return None;
    }
    stack.get(&ins.stack_slot?).cloned()
}

fn copy_from_first_reg(
    ins: &IrInstruction,
    regs: &BTreeMap<String, TrackedValue>,
) -> Option<TrackedValue> {
    ins.read_regs.first().and_then(|reg| regs.get(reg)).cloned()
}

fn append_evidence(mut value: TrackedValue, address: u64) -> TrackedValue {
    if !value.evidence.contains(&address) {
        value.evidence.push(address);
    }
    value
}

fn record_for(
    function: u64,
    source_instruction: u64,
    location: String,
    value: &TrackedValue,
    index: usize,
) -> Option<ValueGraphRecord> {
    if value.value.is_none() && value.target_va.is_none() {
        return None;
    }
    Some(ValueGraphRecord {
        value_id: format!("value:{function:016X}:{source_instruction:016X}:{index:04X}"),
        function,
        source_instruction,
        location,
        inferred_type: value.inferred_type.clone(),
        value: value.value.clone(),
        target_va: value.target_va,
        evidence: value.evidence.clone(),
        confidence: value.confidence.clone(),
    })
}
