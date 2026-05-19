use crate::image::BinaryImage;
use crate::ir::IrInstruction;
use crate::pe::{
    FunctionRecord, ResolvedCallRecord, RttiRecord, SecondPassTargetRecord, StringRecord,
    VTableRecord,
};
use crate::semantic_index::FunctionSemanticIndex;
use std::collections::{BTreeMap, BTreeSet};

#[allow(dead_code)]
pub struct ParsedMsvcCol {
    pub col_va: u64,
    pub type_descriptor_va: u64,
    pub class_descriptor_va: u64,
    pub class_name: Option<String>,
    pub class_attributes: u32,
    pub num_base_classes: u32,
    pub base_classes: Vec<String>,
}

pub fn recover_cpp(
    image: &dyn BinaryImage,
    strings: &[StringRecord],
) -> (Vec<VTableRecord>, Vec<RttiRecord>) {
    let rtti: Vec<RttiRecord> = strings
        .iter()
        .filter(|row| row.text.contains(".?AV") || row.text.contains(".?AU"))
        .map(|row| RttiRecord {
            va: row.va,
            rva: row.rva,
            text: row.text.clone(),
            section: row.section.clone(),
        })
        .collect();

    let base = image.base();
    let mut vtables = Vec::new();
    for section in image.sections() {
        if section.executable || section.data_size < 24 {
            continue;
        }
        let data = section.data(image.bytes());
        let mut offset = 0usize;
        while offset + 24 <= data.len() {
            let va = section.va + offset as u64;
            let mut methods = Vec::new();
            let mut cursor = offset;
            while cursor + 8 <= data.len() {
                let ptr = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap());
                if !image
                    .section_for_va(ptr)
                    .map(|s| s.executable)
                    .unwrap_or(false)
                {
                    break;
                }
                methods.push(ptr);
                cursor += 8;
            }
            if methods.len() >= 3 {
                let col = offset
                    .checked_sub(8)
                    .and_then(|before| data.get(before..before + 8))
                    .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
                    .and_then(|col_va| parse_msvc_col(image.bytes(), base, col_va));
                vtables.push(VTableRecord {
                    va,
                    rva: va - base,
                    section: section.name.clone(),
                    method_count: methods.len(),
                    methods: methods.into_iter().take(64).collect(),
                    probable_class: col
                        .as_ref()
                        .and_then(|row| row.class_name.clone())
                        .or_else(|| nearest_rtti(va, &rtti)),
                    col_va: col.as_ref().map(|row| row.col_va),
                    class_descriptor_va: col.as_ref().map(|row| row.class_descriptor_va),
                    base_classes: col
                        .as_ref()
                        .map(|row| row.base_classes.clone())
                        .unwrap_or_default(),
                    constructor_candidates: Vec::new(),
                    ownership_confidence: if col.is_some() { "high" } else { "low" }.to_string(),
                });
                offset = cursor;
            } else {
                offset += 8;
            }
        }
    }
    (vtables, rtti)
}

pub fn parse_msvc_col(bytes: &[u8], image_base: u64, col_va: u64) -> Option<ParsedMsvcCol> {
    let col_offset = col_va.checked_sub(image_base)? as usize;
    let col = bytes.get(col_offset..col_offset + 20)?;
    let signature = u32::from_le_bytes(col[0..4].try_into().unwrap());
    let type_descriptor_raw = u32::from_le_bytes(col[12..16].try_into().unwrap());
    let class_descriptor_raw = u32::from_le_bytes(col[16..20].try_into().unwrap());
    if signature > 1 || type_descriptor_raw == 0 || class_descriptor_raw == 0 {
        return None;
    }
    let type_descriptor_va = if signature == 1 {
        image_base + type_descriptor_raw as u64
    } else {
        type_descriptor_raw as u64
    };
    let class_descriptor_va = if signature == 1 {
        image_base + class_descriptor_raw as u64
    } else {
        class_descriptor_raw as u64
    };
    let class_name = read_type_descriptor_name(bytes, image_base, type_descriptor_va);
    let (class_attributes, num_base_classes, base_classes) =
        parse_class_hierarchy(bytes, image_base, signature, class_descriptor_va).unwrap_or((
            0,
            0,
            Vec::new(),
        ));
    Some(ParsedMsvcCol {
        col_va,
        type_descriptor_va,
        class_descriptor_va,
        class_name,
        class_attributes,
        num_base_classes,
        base_classes,
    })
}

pub fn refine_vtable_ownership(
    mut vtables: Vec<VTableRecord>,
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    targets: &[SecondPassTargetRecord],
) -> (Vec<VTableRecord>, usize) {
    let target_functions: BTreeSet<u64> = targets.iter().map(|row| row.function).collect();
    let vtable_vas: BTreeSet<u64> = vtables.iter().map(|row| row.va).collect();
    let mut refined = 0usize;
    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        if !target_functions.is_empty() && !target_functions.contains(&function.start) {
            continue;
        }
        for ins in &ir[slice.ir_range.clone()] {
            let possible_vtable = ins.immediate.or(ins.rip_target);
            let Some(vtable_va) = possible_vtable else {
                continue;
            };
            if !ins.memory_write || !vtable_vas.contains(&vtable_va) {
                continue;
            }
            if let Some(row) = vtables.iter_mut().find(|row| row.va == vtable_va) {
                if !row.constructor_candidates.contains(&function.start) {
                    row.constructor_candidates.push(function.start);
                    row.ownership_confidence = if row.col_va.is_some() {
                        "high".to_string()
                    } else {
                        "medium".to_string()
                    };
                    refined += 1;
                }
            }
        }
    }
    (vtables, refined)
}

pub fn resolve_virtual_calls(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    vtables: &[VTableRecord],
    targets: &[SecondPassTargetRecord],
) -> Vec<ResolvedCallRecord> {
    let target_functions: BTreeSet<u64> = targets.iter().map(|row| row.function).collect();
    let mut methods_by_slot: BTreeMap<usize, Vec<&VTableRecord>> = BTreeMap::new();
    for table in vtables {
        if table.methods.is_empty() {
            continue;
        }
        for slot in 0..table.methods.len().min(128) {
            methods_by_slot.entry(slot).or_default().push(table);
        }
    }

    let mut rows = Vec::new();
    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        if !target_functions.is_empty() && !target_functions.contains(&function.start) {
            continue;
        }
        let mut vtable_regs: BTreeMap<String, String> = BTreeMap::new();
        for ins in &ir[slice.ir_range.clone()] {
            if ins.memory_read
                && !ins.memory_write
                && ins.memory_displacement == 0
                && ins.memory_index.is_none()
            {
                if let (Some(write), Some(base)) = (&ins.write_reg, &ins.memory_base) {
                    vtable_regs.insert(write.clone(), base.clone());
                }
            }
            if !ins.is_call || !ins.indirect_target_memory {
                continue;
            }
            let Some(base) = &ins.memory_base else {
                continue;
            };
            if !vtable_regs.contains_key(base) {
                continue;
            }
            if ins.memory_displacement < 0 || ins.memory_displacement % 8 != 0 {
                continue;
            }
            let slot = (ins.memory_displacement / 8) as usize;
            let Some(candidates) = methods_by_slot.get(&slot) else {
                continue;
            };
            let owned: Vec<&VTableRecord> = candidates
                .iter()
                .copied()
                .filter(|row| row.ownership_confidence != "low")
                .collect();
            let candidate_set = if owned.is_empty() { candidates } else { &owned };
            if candidate_set.len() != 1 {
                let mut candidate_targets = candidate_set
                    .iter()
                    .filter_map(|row| row.methods.get(slot).copied())
                    .collect::<Vec<_>>();
                candidate_targets.sort_unstable();
                candidate_targets.dedup();
                let mut candidate_classes = candidate_set
                    .iter()
                    .map(|row| {
                        row.probable_class
                            .clone()
                            .unwrap_or_else(|| format!("vtable:{:016X}", row.va))
                    })
                    .collect::<Vec<_>>();
                candidate_classes.sort();
                candidate_classes.dedup();
                if !candidate_targets.is_empty() {
                    rows.push(ResolvedCallRecord {
                        caller: function.start,
                        callsite: ins.address,
                        original_callee: 0,
                        resolved_api: format!("virtual:ambiguous::slot_{slot}"),
                        wrapper_chain: Vec::new(),
                        chain_depth: 0,
                        confidence: "low".to_string(),
                        resolution_kind: Some("ambiguous_virtual_dispatch".to_string()),
                        class_id: None,
                        vtable_va: None,
                        vtable_slot: Some(slot),
                        target: None,
                        candidate_targets,
                        candidate_classes,
                    });
                }
                continue;
            }
            let table = candidate_set[0];
            let Some(target) = table.methods.get(slot).copied() else {
                continue;
            };
            let class_id = format!("class:{:016X}", table.va);
            let class_name = table.probable_class.as_deref().unwrap_or("unknown_class");
            rows.push(ResolvedCallRecord {
                caller: function.start,
                callsite: ins.address,
                original_callee: 0,
                resolved_api: format!("virtual:{class_name}::slot_{slot}"),
                wrapper_chain: Vec::new(),
                chain_depth: 0,
                confidence: if table.ownership_confidence == "high" {
                    "high".to_string()
                } else {
                    "medium".to_string()
                },
                resolution_kind: Some("virtual_dispatch".to_string()),
                class_id: Some(class_id),
                vtable_va: Some(table.va),
                vtable_slot: Some(slot),
                target: Some(target),
                candidate_targets: Vec::new(),
                candidate_classes: Vec::new(),
            });
        }
    }
    rows.sort_by(|left, right| {
        left.caller
            .cmp(&right.caller)
            .then_with(|| left.callsite.cmp(&right.callsite))
            .then_with(|| left.vtable_va.cmp(&right.vtable_va))
            .then_with(|| left.vtable_slot.cmp(&right.vtable_slot))
    });
    rows
}

pub fn read_type_descriptor_name(
    bytes: &[u8],
    image_base: u64,
    type_descriptor_va: u64,
) -> Option<String> {
    let start = type_descriptor_va.checked_sub(image_base)? as usize + 16;
    let mut end = start;
    while end < bytes.len() && bytes[end] != 0 {
        end += 1;
    }
    (end > start).then(|| String::from_utf8_lossy(&bytes[start..end]).to_string())
}

pub fn parse_class_hierarchy(
    bytes: &[u8],
    image_base: u64,
    signature: u32,
    class_descriptor_va: u64,
) -> Option<(u32, u32, Vec<String>)> {
    let offset = class_descriptor_va.checked_sub(image_base)? as usize;
    let chd = bytes.get(offset..offset + 16)?;
    let attributes = u32::from_le_bytes(chd[4..8].try_into().unwrap());
    let num_base_classes = u32::from_le_bytes(chd[8..12].try_into().unwrap());
    let base_array_raw = u32::from_le_bytes(chd[12..16].try_into().unwrap());
    if num_base_classes == 0 || num_base_classes > 256 || base_array_raw == 0 {
        return Some((attributes, num_base_classes, Vec::new()));
    }
    let base_array_va = rtti_ptr(image_base, signature, base_array_raw);
    let base_array_offset = base_array_va.checked_sub(image_base)? as usize;
    let mut names = Vec::new();
    for index in 0..num_base_classes.min(64) as usize {
        let entry = bytes.get(base_array_offset + index * 4..base_array_offset + index * 4 + 4)?;
        let bcd_raw = u32::from_le_bytes(entry.try_into().unwrap());
        if bcd_raw == 0 {
            continue;
        }
        let bcd_va = rtti_ptr(image_base, signature, bcd_raw);
        let bcd_offset = match bcd_va.checked_sub(image_base).map(|value| value as usize) {
            Some(offset) => offset,
            None => continue,
        };
        let Some(type_raw_bytes) = bytes.get(bcd_offset..bcd_offset + 4) else {
            continue;
        };
        let type_raw = u32::from_le_bytes(type_raw_bytes.try_into().unwrap());
        if type_raw == 0 {
            continue;
        }
        let type_va = rtti_ptr(image_base, signature, type_raw);
        if let Some(name) = read_type_descriptor_name(bytes, image_base, type_va) {
            names.push(name);
        }
    }
    names.sort();
    names.dedup();
    Some((attributes, num_base_classes, names))
}

fn rtti_ptr(image_base: u64, signature: u32, raw: u32) -> u64 {
    if signature == 1 {
        image_base + raw as u64
    } else {
        raw as u64
    }
}

fn nearest_rtti(va: u64, rtti: &[RttiRecord]) -> Option<String> {
    rtti.iter()
        .filter(|row| va >= row.va && va - row.va < 0x200)
        .last()
        .map(|row| row.text.clone())
}
