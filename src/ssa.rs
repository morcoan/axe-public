use crate::ir::IrInstruction;
use crate::pe::{
    CfgRecord, DataflowEdgeRecord, FunctionRecord, SecondPassTargetRecord, SsaValueRecord,
};
use crate::semantic_index::FunctionSemanticIndex;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

pub struct SsaBuildResult {
    pub values: Vec<SsaValueRecord>,
    pub dataflow_edges: Vec<DataflowEdgeRecord>,
    pub caps_hit: bool,
}

#[derive(Clone)]
struct CurrentDef {
    id: String,
    site_va: u64,
    storage: String,
}

#[allow(dead_code)]
pub fn build_ssa(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    cfg: &[CfgRecord],
    budget_name: &str,
) -> SsaBuildResult {
    build_ssa_inner(functions, semantic_index, ir, cfg, budget_name, None)
}

pub fn build_ssa_for_targets(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    cfg: &[CfgRecord],
    targets: &[SecondPassTargetRecord],
    budget_name: &str,
) -> SsaBuildResult {
    let selected = targets
        .iter()
        .map(|row| row.function)
        .collect::<BTreeSet<_>>();
    if selected.is_empty() {
        return SsaBuildResult {
            values: Vec::new(),
            dataflow_edges: Vec::new(),
            caps_hit: false,
        };
    }
    build_ssa_inner(
        functions,
        semantic_index,
        ir,
        cfg,
        budget_name,
        Some(&selected),
    )
}

fn build_ssa_inner(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    cfg: &[CfgRecord],
    budget_name: &str,
    selected_functions: Option<&BTreeSet<u64>>,
) -> SsaBuildResult {
    let per_function_cap = match budget_name {
        "max" => usize::MAX,
        "high" => 256,
        _ => 64,
    };
    let blocks_by_function: BTreeMap<u64, &CfgRecord> =
        cfg.iter().map(|row| (row.function, row)).collect();

    // Process functions in parallel — each slice is independent (SSA versions,
    // edges, caps are per-function). Then flatten into ordered output.
    let per_function: Vec<(Vec<SsaValueRecord>, Vec<DataflowEdgeRecord>, bool)> = semantic_index
        .slices
        .par_iter()
        .filter_map(|slice| {
            let function = functions.get(slice.function_index)?;
            if selected_functions.is_some_and(|selected| !selected.contains(&function.start)) {
                return None;
            }
            Some(process_function_slice(
                function,
                ir,
                slice,
                blocks_by_function.get(&function.start).copied(),
                per_function_cap,
            ))
        })
        .collect();

    let mut values = Vec::new();
    let mut edges = Vec::new();
    let mut caps_hit = false;
    for (vs, es, hit) in per_function {
        values.extend(vs);
        edges.extend(es);
        caps_hit |= hit;
    }

    SsaBuildResult {
        values,
        dataflow_edges: edges,
        caps_hit,
    }
}

fn process_function_slice(
    function: &FunctionRecord,
    ir: &[IrInstruction],
    slice: &crate::semantic_index::FunctionSemanticSlice,
    cfg_record: Option<&CfgRecord>,
    per_function_cap: usize,
) -> (Vec<SsaValueRecord>, Vec<DataflowEdgeRecord>, bool) {
    let mut values: Vec<SsaValueRecord> = Vec::new();
    let mut edges: Vec<DataflowEdgeRecord> = Vec::new();
    let mut caps_hit = false;
    let mut versions: BTreeMap<String, u32> = BTreeMap::new();
    let mut current: BTreeMap<String, CurrentDef> = BTreeMap::new();
    let mut out_defs_by_block: BTreeMap<u64, BTreeMap<String, CurrentDef>> = BTreeMap::new();
    let mut emitted_join_phis: BTreeSet<u64> = BTreeSet::new();
    let mut emitted = 0usize;
    let predecessors_by_join = predecessor_blocks_by_join(cfg_record);

    for ins in &ir[slice.ir_range.clone()] {
        if emitted >= per_function_cap {
            caps_hit = true;
            break;
        }
        let block = block_for(cfg_record, ins.address);
        if let Some(block) = block {
            if emitted_join_phis.insert(block) {
                if let Some(predecessors) = predecessors_by_join.get(&block) {
                    emitted += emit_join_phis(
                        function.start,
                        block,
                        predecessors,
                        &out_defs_by_block,
                        &mut current,
                        &mut versions,
                        &mut values,
                        &mut edges,
                        per_function_cap.saturating_sub(emitted),
                    );
                    if emitted >= per_function_cap {
                        caps_hit = true;
                        break;
                    }
                }
            }
        }
        let mut input_defs = Vec::new();
        for storage in read_storages(ins) {
            if let Some(def) = current.get(&storage) {
                input_defs.push(def.clone());
            }
        }

        if ins.memory_read {
            if let Some(def) = current.get("mem") {
                input_defs.push(def.clone());
            }
        }

        let writes = write_storages(ins);
        for (storage, kind, source) in writes {
            if emitted >= per_function_cap {
                caps_hit = true;
                break;
            }
            let value = new_value(
                function.start,
                block,
                ins.address,
                &storage,
                &kind,
                &source,
                constant_value(ins),
                &mut versions,
                &input_defs.iter().map(|row| row.site_va).collect::<Vec<_>>(),
                values.len(),
            );
            for def in &input_defs {
                edges.push(DataflowEdgeRecord {
                    edge_id: format!(
                        "df:{:016X}:{}:{}",
                        function.start,
                        edges.len(),
                        value.ssa_id
                    ),
                    function: function.start,
                    from_value: Some(def.id.clone()),
                    to_value: value.ssa_id.clone(),
                    from_va: Some(def.site_va),
                    to_va: value.site_va,
                    from_storage: Some(def.storage.clone()),
                    to_storage: storage.clone(),
                    edge_kind: if kind == "memory" {
                        "memory_store".to_string()
                    } else {
                        "use_def".to_string()
                    },
                    type_tag: None,
                    evidence: vec![def.site_va, value.site_va],
                });
            }
            current.insert(
                storage.clone(),
                CurrentDef {
                    id: value.ssa_id.clone(),
                    site_va: value.site_va,
                    storage,
                },
            );
            values.push(value);
            emitted += 1;
        }
        if let Some(block) = block {
            out_defs_by_block.insert(block, current.clone());
        }
    }

    (values, edges, caps_hit)
}

fn emit_join_phis(
    function: u64,
    block: u64,
    predecessors: &[u64],
    out_defs_by_block: &BTreeMap<u64, BTreeMap<String, CurrentDef>>,
    current: &mut BTreeMap<String, CurrentDef>,
    versions: &mut BTreeMap<String, u32>,
    values: &mut Vec<SsaValueRecord>,
    edges: &mut Vec<DataflowEdgeRecord>,
    remaining_cap: usize,
) -> usize {
    if remaining_cap == 0 {
        return 0;
    }
    let mut storages = BTreeSet::new();
    for predecessor in predecessors {
        if let Some(defs) = out_defs_by_block.get(predecessor) {
            storages.extend(defs.keys().cloned());
        }
    }

    let mut emitted = 0usize;
    for storage in storages {
        if emitted >= remaining_cap {
            break;
        }
        let mut incoming = Vec::new();
        let mut incoming_ids = BTreeSet::new();
        for predecessor in predecessors {
            let Some(def) = out_defs_by_block
                .get(predecessor)
                .and_then(|defs| defs.get(&storage))
                .cloned()
            else {
                continue;
            };
            incoming_ids.insert(def.id.clone());
            incoming.push(def);
        }
        if incoming.len() < 2 || incoming_ids.len() < 2 {
            continue;
        }
        let evidence = incoming.iter().map(|row| row.site_va).collect::<Vec<_>>();
        let value = new_value(
            function,
            Some(block),
            block,
            &storage,
            &kind_for_storage(&storage),
            "phi",
            None,
            versions,
            &evidence,
            values.len(),
        );
        for def in &incoming {
            edges.push(DataflowEdgeRecord {
                edge_id: format!("df:{function:016X}:{}:{}", edges.len(), value.ssa_id),
                function,
                from_value: Some(def.id.clone()),
                to_value: value.ssa_id.clone(),
                from_va: Some(def.site_va),
                to_va: value.site_va,
                from_storage: Some(def.storage.clone()),
                to_storage: storage.clone(),
                edge_kind: "phi".to_string(),
                type_tag: None,
                evidence: vec![def.site_va, value.site_va],
            });
        }
        current.insert(
            storage.clone(),
            CurrentDef {
                id: value.ssa_id.clone(),
                site_va: value.site_va,
                storage,
            },
        );
        values.push(value);
        emitted += 1;
    }
    emitted
}

fn new_value(
    function: u64,
    block: Option<u64>,
    site_va: u64,
    storage: &str,
    kind: &str,
    source: &str,
    value: Option<String>,
    versions: &mut BTreeMap<String, u32>,
    evidence: &[u64],
    index: usize,
) -> SsaValueRecord {
    let version = versions.entry(storage.to_string()).or_insert(0);
    *version += 1;
    let mut evidence_vas = evidence.to_vec();
    evidence_vas.push(site_va);
    evidence_vas.sort_unstable();
    evidence_vas.dedup();
    SsaValueRecord {
        ssa_id: format!("ssa:{function:016X}:{storage}:v{version}:{}", index),
        function,
        block,
        site_va,
        storage: storage.to_string(),
        version: *version,
        kind: kind.to_string(),
        source: source.to_string(),
        value,
        evidence: evidence_vas,
        confidence: if source == "phi" { "medium" } else { "high" }.to_string(),
    }
}

fn write_storages(ins: &IrInstruction) -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    if let Some(reg) = &ins.write_reg {
        rows.push((reg.clone(), "register".to_string(), ins.mnemonic.clone()));
    }
    if ins.memory_write {
        if let Some(slot) = ins.stack_slot {
            rows.push((
                format!("stack[{slot:+}]"),
                "stack_slot".to_string(),
                ins.mnemonic.clone(),
            ));
        }
        rows.push(("mem".to_string(), "memory".to_string(), "store".to_string()));
    }
    if matches!(
        ins.mnemonic.as_str(),
        "cmp" | "test" | "sub" | "add" | "and" | "or" | "xor"
    ) {
        for flag in ["zf", "sf", "of", "cf"] {
            rows.push((flag.to_string(), "flag".to_string(), ins.mnemonic.clone()));
        }
    }
    rows
}

fn read_storages(ins: &IrInstruction) -> Vec<String> {
    let mut rows: Vec<String> = ins.read_regs.clone();
    if ins.memory_read {
        if let Some(slot) = ins.stack_slot {
            rows.push(format!("stack[{slot:+}]"));
        }
    }
    rows.sort();
    rows.dedup();
    rows
}

fn constant_value(ins: &IrInstruction) -> Option<String> {
    if matches!(ins.mnemonic.as_str(), "mov" | "movabs" | "lea") {
        if let Some(target) = ins.rip_target.or(ins.immediate) {
            return Some(format!("0x{target:X}"));
        }
    }
    None
}

fn predecessor_blocks_by_join(cfg: Option<&CfgRecord>) -> BTreeMap<u64, Vec<u64>> {
    let Some(cfg) = cfg else {
        return BTreeMap::new();
    };
    let mut incoming: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for edge in &cfg.edges {
        let Some(predecessor_block) = block_for(Some(cfg), edge.from) else {
            continue;
        };
        incoming.entry(edge.to).or_default().push(predecessor_block);
    }
    incoming
        .into_iter()
        .filter_map(|(block, mut predecessors)| {
            predecessors.sort_unstable();
            predecessors.dedup();
            (predecessors.len() > 1).then_some((block, predecessors))
        })
        .collect()
}

fn block_for(cfg: Option<&CfgRecord>, address: u64) -> Option<u64> {
    cfg.and_then(|row| {
        row.blocks
            .iter()
            .find(|block| block.start <= address && address < block.end)
            .map(|block| block.start)
    })
}

fn kind_for_storage(storage: &str) -> String {
    if storage == "mem" {
        "memory".to_string()
    } else if storage.starts_with("stack[") {
        "stack_slot".to_string()
    } else if matches!(storage, "zf" | "sf" | "of" | "cf" | "pf" | "af") {
        "flag".to_string()
    } else {
        "register".to_string()
    }
}
