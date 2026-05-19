use crate::pe::{BasicBlockRecord, CfgRecord, EdgeRecord, FunctionRecord, InstructionRecord};
use rustc_hash::FxHashMap;
use std::collections::BTreeSet;

pub fn build_cfg(
    functions: &[FunctionRecord],
    instructions: &[InstructionRecord],
) -> Vec<CfgRecord> {
    let by_va: FxHashMap<u64, &InstructionRecord> =
        instructions.iter().map(|row| (row.address, row)).collect();
    let mut addresses: Vec<u64> = by_va.keys().copied().collect();
    addresses.sort();
    let mut rows = Vec::new();
    for function in functions {
        let start_idx = addresses.partition_point(|addr| *addr < function.start);
        let end_idx = addresses.partition_point(|addr| *addr < function.end);
        let insns: Vec<&InstructionRecord> = addresses[start_idx..end_idx]
            .iter()
            .filter_map(|addr| by_va.get(addr).copied())
            .collect();
        if insns.is_empty() {
            continue;
        }
        let instruction_starts: BTreeSet<u64> = insns.iter().map(|ins| ins.address).collect();
        let mut starts = BTreeSet::new();
        let mut edges = Vec::new();
        starts.insert(function.start);
        for ins in &insns {
            let next_addr = ins.address + ins.size as u64;
            if let Some(target) = ins.branch_target {
                if function.start <= target && target < function.end {
                    starts.insert(target);
                    edges.push(EdgeRecord {
                        from: ins.address,
                        to: target,
                        edge_type: "branch".to_string(),
                    });
                }
            }
            if (ins.is_jump || ins.is_call) && instruction_starts.contains(&next_addr) {
                starts.insert(next_addr);
            }
            if ins.is_call && instruction_starts.contains(&next_addr) {
                edges.push(EdgeRecord {
                    from: ins.address,
                    to: next_addr,
                    edge_type: "fallthrough".to_string(),
                });
            } else if ins.is_jump
                && !ins.mnemonic.eq_ignore_ascii_case("jmp")
                && instruction_starts.contains(&next_addr)
            {
                edges.push(EdgeRecord {
                    from: ins.address,
                    to: next_addr,
                    edge_type: "fallthrough".to_string(),
                });
            }
        }
        let starts_vec: Vec<u64> = starts.into_iter().collect();
        let mut blocks = Vec::new();
        for (idx, start) in starts_vec.iter().copied().enumerate() {
            let following = starts_vec.get(idx + 1).copied().unwrap_or(function.end);
            let block_ins: Vec<&InstructionRecord> = insns
                .iter()
                .copied()
                .filter(|ins| start <= ins.address && ins.address < following)
                .collect();
            if let Some(last) = block_ins.last() {
                blocks.push(BasicBlockRecord {
                    start,
                    end: last.address + last.size as u64,
                    instruction_count: block_ins.len(),
                });
            }
        }
        rows.push(CfgRecord {
            function: function.start,
            blocks,
            edges,
        });
    }
    rows
}
