use crate::image::BinaryImage;
use crate::ir::IrInstruction;
use crate::pe::{FunctionRecord, JumpTableRecord, SecondPassTargetRecord, VsaValueRecord};
use crate::semantic_index::FunctionSemanticIndex;
use std::collections::{BTreeMap, BTreeSet};

#[allow(dead_code)]
pub struct ResolvedTable {
    pub kind: String,
    pub targets: Vec<u64>,
    pub entry_size: u32,
}

pub fn resolve_table_entries<F>(
    table_va: u64,
    data: &[u8],
    image_base: u64,
    is_executable: F,
    max_entries: usize,
) -> Option<ResolvedTable>
where
    F: Fn(u64) -> bool + Copy,
{
    resolve_absolute_entries(data, is_executable, max_entries)
        .map(|targets| ResolvedTable {
            kind: "absolute".to_string(),
            targets,
            entry_size: 8,
        })
        .or_else(|| {
            resolve_rva_entries(data, image_base, is_executable, max_entries).map(|targets| {
                ResolvedTable {
                    kind: "rva".to_string(),
                    targets,
                    entry_size: 4,
                }
            })
        })
        .or_else(|| {
            resolve_relative_entries(table_va, data, is_executable, max_entries).map(|targets| {
                ResolvedTable {
                    kind: "relative".to_string(),
                    targets,
                    entry_size: 4,
                }
            })
        })
}

pub fn build_jump_tables(
    image: &dyn BinaryImage,
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    vsa_values: &[VsaValueRecord],
    targets: &[SecondPassTargetRecord],
    budget_name: &str,
) -> Vec<JumpTableRecord> {
    let target_functions: BTreeSet<u64> = targets.iter().map(|row| row.function).collect();
    if target_functions.is_empty() {
        return Vec::new();
    }
    let max_entries = match budget_name {
        "max" => 4096,
        "high" => 512,
        _ => 128,
    };
    let values = index_values(vsa_values);
    let mut rows = Vec::new();

    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        if !target_functions.contains(&function.start) {
            continue;
        }
        for ins in &ir[slice.ir_range.clone()] {
            if !ins.is_jump || ins.direct_target.is_some() {
                continue;
            }
            let Some(table_va) = candidate_table_va(function.start, ins, &values) else {
                continue;
            };
            let Some(section) = image.section_for_va(table_va) else {
                continue;
            };
            let section_data = section.data(image.bytes());
            let offset = table_va.saturating_sub(section.va) as usize;
            if offset >= section_data.len() {
                continue;
            }
            let data = &section_data[offset..];
            let entry_limit = infer_switch_entry_limit(&ir[slice.ir_range.clone()], ins.address)
                .unwrap_or(max_entries)
                .min(max_entries);
            let resolved = resolve_table_entries(
                table_va,
                data,
                image.base(),
                |va| {
                    image
                        .section_for_va(va)
                        .is_some_and(|section| section.executable)
                },
                entry_limit,
            );
            if let Some(resolved) = resolved {
                rows.push(JumpTableRecord {
                    table_id: format!("jumptable:{:016X}:{:016X}", function.start, ins.address),
                    function: function.start,
                    jump_va: ins.address,
                    table_va: Some(table_va),
                    entry_size: resolved.entry_size,
                    targets: resolved.targets,
                    confidence: "medium".to_string(),
                    evidence: vec![ins.address, table_va],
                });
            }
        }
    }
    rows
}

fn resolve_absolute_entries<F>(
    data: &[u8],
    is_executable: F,
    max_entries: usize,
) -> Option<Vec<u64>>
where
    F: Fn(u64) -> bool + Copy,
{
    let mut targets = Vec::new();
    for chunk in data.chunks_exact(8).take(max_entries) {
        let target = u64::from_le_bytes(chunk.try_into().unwrap());
        if !is_executable(target) {
            break;
        }
        targets.push(target);
    }
    enough(targets)
}

fn resolve_rva_entries<F>(
    data: &[u8],
    image_base: u64,
    is_executable: F,
    max_entries: usize,
) -> Option<Vec<u64>>
where
    F: Fn(u64) -> bool + Copy,
{
    let mut targets = Vec::new();
    for chunk in data.chunks_exact(4).take(max_entries) {
        let rva = u32::from_le_bytes(chunk.try_into().unwrap()) as u64;
        let target = image_base + rva;
        if !is_executable(target) {
            break;
        }
        targets.push(target);
    }
    enough(targets)
}

fn resolve_relative_entries<F>(
    table_va: u64,
    data: &[u8],
    is_executable: F,
    max_entries: usize,
) -> Option<Vec<u64>>
where
    F: Fn(u64) -> bool + Copy,
{
    let mut targets = Vec::new();
    for chunk in data.chunks_exact(4).take(max_entries) {
        let delta = i32::from_le_bytes(chunk.try_into().unwrap()) as i64;
        let target = table_va.wrapping_add_signed(delta);
        if !is_executable(target) {
            break;
        }
        targets.push(target);
    }
    enough(targets)
}

fn enough(targets: Vec<u64>) -> Option<Vec<u64>> {
    (targets.len() >= 2).then_some(targets)
}

fn index_values(values: &[VsaValueRecord]) -> BTreeMap<(u64, String), Vec<&VsaValueRecord>> {
    let mut index: BTreeMap<(u64, String), Vec<&VsaValueRecord>> = BTreeMap::new();
    for value in values {
        index
            .entry((value.function, value.location.clone()))
            .or_default()
            .push(value);
    }
    index
}

fn candidate_table_va(
    function: u64,
    ins: &IrInstruction,
    values: &BTreeMap<(u64, String), Vec<&VsaValueRecord>>,
) -> Option<u64> {
    if let Some(target) = ins.rip_target {
        return Some(target);
    }
    if ins.memory_base.is_none()
        && ins.memory_displacement > 0
        && (ins.indirect_target_memory || ins.memory_read)
    {
        return Some(ins.memory_displacement as u64);
    }
    let base = ins
        .memory_base
        .as_ref()
        .and_then(|reg| latest_value(values, function, reg, ins.address))
        .and_then(|row| row.target_va.or(row.lo));
    let index_offset = ins
        .memory_index
        .as_ref()
        .and_then(|reg| latest_value(values, function, reg, ins.address))
        .and_then(|row| row.lo)
        .map(|value| value.wrapping_mul(ins.memory_scale.max(1) as u64))
        .unwrap_or(0);
    base.map(|base| {
        base.wrapping_add(index_offset)
            .wrapping_add_signed(ins.memory_displacement)
    })
}

fn infer_switch_entry_limit(ir: &[IrInstruction], jump_va: u64) -> Option<usize> {
    ir.iter()
        .rev()
        .filter(|ins| ins.address < jump_va)
        .take(12)
        .find_map(|ins| {
            if matches!(ins.mnemonic.as_str(), "cmp" | "sub" | "and") {
                let imm = ins.immediate?;
                if imm > 0 && imm <= 4096 {
                    return Some((imm as usize).saturating_add(1));
                }
            }
            None
        })
}

fn latest_value<'a>(
    values: &'a BTreeMap<(u64, String), Vec<&'a VsaValueRecord>>,
    function: u64,
    location: &str,
    before_or_at: u64,
) -> Option<&'a VsaValueRecord> {
    let rows = values.get(&(function, location.to_string()))?;
    let index = rows.partition_point(|row| row.site_va <= before_or_at);
    index.checked_sub(1).and_then(|idx| rows.get(idx).copied())
}
