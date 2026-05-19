use crate::ir::IrInstruction;
use crate::pe::{CfgRecord, FunctionRecord, InstructionRecord, XrefRecord};
use serde::Serialize;
use std::ops::Range;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct FunctionSemanticSlice {
    pub function_index: usize,
    pub function_start: u64,
    pub function_end: u64,
    pub instruction_range: Range<usize>,
    pub ir_range: Range<usize>,
    pub xref_range: Range<usize>,
    pub cfg_index: Option<usize>,
    pub has_return: bool,
    pub overlaps_known_function: bool,
}

#[derive(Clone, Debug, Default)]
pub struct FunctionSemanticIndex {
    pub slices: Vec<FunctionSemanticSlice>,
}

impl FunctionSemanticIndex {
    pub fn build(
        functions: &[FunctionRecord],
        instructions: &[InstructionRecord],
        ir: &[IrInstruction],
        xrefs: &[XrefRecord],
        cfg: &[CfgRecord],
    ) -> Self {
        let instruction_addresses: Vec<u64> = instructions.iter().map(|row| row.address).collect();
        let ir_addresses: Vec<u64> = ir.iter().map(|row| row.address).collect();
        let xref_froms: Vec<u64> = xrefs.iter().map(|row| row.from).collect();
        let mut cfg_by_function = std::collections::BTreeMap::new();
        for (idx, row) in cfg.iter().enumerate() {
            cfg_by_function.insert(row.function, idx);
        }

        let mut slices = Vec::with_capacity(functions.len());
        for (idx, function) in functions.iter().enumerate() {
            let instruction_start =
                instruction_addresses.partition_point(|addr| *addr < function.start);
            let instruction_end =
                instruction_addresses.partition_point(|addr| *addr < function.end);
            let ir_start = ir_addresses.partition_point(|addr| *addr < function.start);
            let ir_end = ir_addresses.partition_point(|addr| *addr < function.end);
            let xref_start = xref_froms.partition_point(|addr| *addr < function.start);
            let xref_end = xref_froms.partition_point(|addr| *addr < function.end);
            let has_return = instructions[instruction_start..instruction_end]
                .iter()
                .any(|row| row.is_ret);
            let overlaps_previous = idx
                .checked_sub(1)
                .and_then(|prev| functions.get(prev))
                .is_some_and(|prev| prev.end > function.start);
            let overlaps_next = functions
                .get(idx + 1)
                .is_some_and(|next| next.start < function.end);

            slices.push(FunctionSemanticSlice {
                function_index: idx,
                function_start: function.start,
                function_end: function.end,
                instruction_range: instruction_start..instruction_end,
                ir_range: ir_start..ir_end,
                xref_range: xref_start..xref_end,
                cfg_index: cfg_by_function.get(&function.start).copied(),
                has_return,
                overlaps_known_function: overlaps_previous || overlaps_next,
            });
        }

        Self { slices }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SemanticBudget {
    pub name: String,
    pub heuristic_strings_per_call: usize,
    pub dossier_links_per_function: usize,
    pub dossier_summaries_per_function: usize,
    pub stack_store_slots_per_function: usize,
    pub api_hash_constants_per_function: usize,
    pub encoded_blob_hints: usize,
}

impl SemanticBudget {
    pub fn from_name(name: &str) -> Self {
        match name {
            "high" => Self {
                name: "high".to_string(),
                heuristic_strings_per_call: 12,
                dossier_links_per_function: 256,
                dossier_summaries_per_function: 6,
                stack_store_slots_per_function: 512,
                api_hash_constants_per_function: 32,
                encoded_blob_hints: 1024,
            },
            "max" => Self {
                name: "max".to_string(),
                heuristic_strings_per_call: usize::MAX,
                dossier_links_per_function: usize::MAX,
                dossier_summaries_per_function: 16,
                stack_store_slots_per_function: usize::MAX,
                api_hash_constants_per_function: usize::MAX,
                encoded_blob_hints: usize::MAX,
            },
            _ => Self {
                name: "normal".to_string(),
                heuristic_strings_per_call: 4,
                dossier_links_per_function: 64,
                dossier_summaries_per_function: 3,
                stack_store_slots_per_function: 256,
                api_hash_constants_per_function: 8,
                encoded_blob_hints: 256,
            },
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SemanticCounters {
    pub functions_semantically_scanned: usize,
    pub api_flows_proven: usize,
    pub api_flows_heuristic: usize,
    pub stack_strings_recovered: usize,
    pub api_hash_candidates: usize,
    pub encoded_blob_hints: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SemanticCapsHit {
    pub heuristic_api_flows: bool,
    pub dossier_links: bool,
    pub stack_store_slots: bool,
    pub api_hash_constants: bool,
    pub encoded_blob_hints: bool,
}

pub fn flow_id(function: u64, callsite: u64, index: usize) -> String {
    format!("flow:{function:016X}:{callsite:016X}:{index:04X}")
}

pub fn recovered_id(function: u64, kind: &str, index: usize) -> String {
    format!("recovered:{function:016X}:{kind}:{index:04X}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{FunctionRecord, InstructionRecord, XrefRecord};

    #[test]
    fn semantic_index_maps_function_local_slices() {
        let functions = vec![
            FunctionRecord {
                start: 0x1000,
                end: 0x1010,
                size: 0x10,
                source: "pdata".to_string(),
                calls: Vec::new(),
                calls_imports: Vec::new(),
                strings: Vec::new(),
                xrefs: 0,
            },
            FunctionRecord {
                start: 0x2000,
                end: 0x2010,
                size: 0x10,
                source: "call".to_string(),
                calls: Vec::new(),
                calls_imports: Vec::new(),
                strings: Vec::new(),
                xrefs: 0,
            },
        ];
        let instructions = vec![
            test_instruction(0x1000, false),
            test_instruction(0x1008, true),
            test_instruction(0x2000, false),
        ];
        let ir = vec![test_ir(0x1000), test_ir(0x1008), test_ir(0x2000)];
        let xrefs = vec![test_xref(0x1004), test_xref(0x2004)];
        let index = FunctionSemanticIndex::build(&functions, &instructions, &ir, &xrefs, &[]);

        assert_eq!(0..2, index.slices[0].instruction_range);
        assert_eq!(0..2, index.slices[0].ir_range);
        assert_eq!(0..1, index.slices[0].xref_range);
        assert!(index.slices[0].has_return);
        assert_eq!(2..3, index.slices[1].instruction_range);
        assert_eq!(1..2, index.slices[1].xref_range);
    }

    fn test_instruction(address: u64, is_ret: bool) -> InstructionRecord {
        InstructionRecord {
            address,
            size: 1,
            mnemonic: if is_ret { "ret" } else { "nop" }.to_string(),
            op_str: String::new(),
            section: ".text".to_string(),
            groups: Vec::new(),
            is_call: false,
            is_jump: false,
            is_ret,
            branch_target: None,
        }
    }

    fn test_ir(address: u64) -> IrInstruction {
        IrInstruction {
            address,
            size: 1,
            mnemonic: "nop".to_string(),
            write_reg: None,
            read_regs: Vec::new(),
            immediate: None,
            rip_target: None,
            stack_slot: None,
            memory_base: None,
            memory_index: None,
            memory_scale: 0,
            memory_displacement: 0,
            operand_width: 0,
            indirect_target_register: None,
            indirect_target_memory: false,
            memory_write: false,
            memory_read: false,
            direct_target: None,
            is_call: false,
            is_jump: false,
        }
    }

    fn test_xref(from: u64) -> XrefRecord {
        XrefRecord {
            kind: "code".to_string(),
            from,
            target: 0x3000,
            role: "call".to_string(),
            symbol: None,
            text: None,
            encoding: None,
            section: Some(".text".to_string()),
        }
    }
}
