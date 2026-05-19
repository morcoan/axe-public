//! VSA-driven indirect call/jump resolution.
//!
//! Walks indirect-call and indirect-jump sites in IR, looks up the VSA value
//! for the indirect target register/memory at that site, and emits resolved
//! edge records when VSA has a concrete `target_va`. Complements
//! `jump_tables` (which handles switch tables) by resolving the simpler
//! "indirect through a constant pointer" case.

use crate::ir::IrInstruction;
use crate::pe::{FunctionRecord, ImportRecord, VsaValueRecord};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct ResolvedIndirectRecord {
    pub schema: &'static str,
    pub kind: &'static str, // "indirect_call" | "indirect_jump"
    pub function: u64,
    pub site_va: u64,
    pub target_va: u64,
    pub via: String, // "register=rax" | "memory=[rip+...]"
    pub resolved_symbol: Option<String>,
    pub confidence: &'static str, // "high" | "medium" | "low"
    pub evidence: Vec<u64>,
}

pub fn resolve_indirect(
    functions: &[FunctionRecord],
    ir: &[IrInstruction],
    vsa_values: &[VsaValueRecord],
    imports: &[ImportRecord],
) -> Vec<ResolvedIndirectRecord> {
    if ir.is_empty() {
        return Vec::new();
    }
    let imports_by_va: BTreeMap<u64, &ImportRecord> = imports.iter().map(|i| (i.va, i)).collect();

    // VSA records indexed by (function, site_va, location) — gives us
    // O(1) lookup at each indirect site.
    let mut vsa_by_site_reg: BTreeMap<(u64, u64, String), &VsaValueRecord> = BTreeMap::new();
    for v in vsa_values {
        if v.target_va.is_none() {
            continue;
        }
        // Don't overwrite a higher-confidence record at the same key.
        let key = (v.function, v.site_va, v.location.to_ascii_lowercase());
        match vsa_by_site_reg.get(&key) {
            Some(existing)
                if confidence_rank(&existing.confidence) >= confidence_rank(&v.confidence) => {}
            _ => {
                vsa_by_site_reg.insert(key, v);
            }
        }
    }

    let mut out = Vec::new();
    let function_of_ir: BTreeMap<u64, u64> = functions
        .iter()
        .flat_map(|f| {
            ir.iter()
                .filter(move |ins| ins.address >= f.start && ins.address < f.end)
                .map(move |ins| (ins.address, f.start))
        })
        .collect();

    for ins in ir {
        if !(ins.is_call || ins.is_jump) {
            continue;
        }
        // Already resolved as a direct target — skip.
        if ins.direct_target.is_some() || ins.rip_target.is_some() {
            continue;
        }
        let Some(&function) = function_of_ir.get(&ins.address) else {
            continue;
        };

        let (via, vsa) = if let Some(reg) = &ins.indirect_target_register {
            let key = (function, ins.address, reg.to_ascii_lowercase());
            (
                format!("register={}", reg),
                vsa_by_site_reg.get(&key).copied(),
            )
        } else if ins.indirect_target_memory {
            let mem_descriptor = describe_memory(ins);
            // Try the read register that holds the pointer first.
            let lookup = ins
                .memory_base
                .as_deref()
                .map(|reg| {
                    vsa_by_site_reg
                        .get(&(function, ins.address, reg.to_ascii_lowercase()))
                        .copied()
                })
                .flatten();
            (format!("memory={}", mem_descriptor), lookup)
        } else {
            continue;
        };

        let Some(vsa) = vsa else {
            continue;
        };
        let target = match vsa.target_va {
            Some(t) if t != 0 => t,
            _ => continue,
        };
        let confidence = match vsa.confidence.as_str() {
            "high" => "high",
            "medium" | "definite" => "medium",
            _ => "low",
        };
        let resolved_symbol = imports_by_va
            .get(&target)
            .map(|imp| imp.symbol.clone())
            .or_else(|| vsa.expression.clone());

        let mut evidence = vsa.evidence.clone();
        if !evidence.contains(&ins.address) {
            evidence.insert(0, ins.address);
        }

        out.push(ResolvedIndirectRecord {
            schema: "resolved_indirect/1",
            kind: if ins.is_call {
                "indirect_call"
            } else {
                "indirect_jump"
            },
            function,
            site_va: ins.address,
            target_va: target,
            via,
            resolved_symbol,
            confidence,
            evidence,
        });
    }

    out
}

fn confidence_rank(c: &str) -> u8 {
    match c {
        "high" | "definite" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn describe_memory(ins: &IrInstruction) -> String {
    let mut parts = Vec::new();
    if let Some(base) = &ins.memory_base {
        parts.push(base.clone());
    }
    if let Some(index) = &ins.memory_index {
        if ins.memory_scale > 1 {
            parts.push(format!("{}*{}", index, ins.memory_scale));
        } else {
            parts.push(index.clone());
        }
    }
    if ins.memory_displacement != 0 {
        if ins.memory_displacement > 0 {
            parts.push(format!("+0x{:X}", ins.memory_displacement));
        } else {
            parts.push(format!("-0x{:X}", -ins.memory_displacement));
        }
    }
    format!("[{}]", parts.join(""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::FunctionRecord;

    fn ir(addr: u64, indirect_reg: Option<&str>) -> IrInstruction {
        IrInstruction {
            address: addr,
            size: 3,
            mnemonic: "call".to_string(),
            write_reg: None,
            read_regs: Vec::new(),
            immediate: None,
            rip_target: None,
            stack_slot: None,
            memory_base: None,
            memory_index: None,
            memory_scale: 0,
            memory_displacement: 0,
            operand_width: 8,
            indirect_target_register: indirect_reg.map(|s| s.to_string()),
            indirect_target_memory: false,
            memory_write: false,
            memory_read: false,
            direct_target: None,
            is_call: true,
            is_jump: false,
        }
    }

    fn vsa(function: u64, site_va: u64, location: &str, target: u64) -> VsaValueRecord {
        VsaValueRecord {
            value_id: "v".to_string(),
            function,
            site_va,
            location: location.to_string(),
            kind: "concrete".to_string(),
            lo: Some(target),
            hi: Some(target),
            stride: 0,
            value: Some(format!("0x{:X}", target)),
            target_va: Some(target),
            evidence: vec![site_va],
            confidence: "high".to_string(),
            region: "global".to_string(),
            expression: None,
            base: None,
            index: None,
            scale: 0,
            displacement: 0,
            possible_values: Vec::new(),
            work_budget_exhausted: false,
        }
    }

    #[test]
    fn resolves_indirect_call_via_vsa_target_va() {
        let functions = vec![FunctionRecord {
            start: 0x1000,
            end: 0x1100,
            size: 0x100,
            source: "test".into(),
            calls: vec![],
            calls_imports: vec![],
            strings: vec![],
            xrefs: 0,
        }];
        let irs = vec![ir(0x1020, Some("rax"))];
        let vsas = vec![vsa(0x1000, 0x1020, "rax", 0x401000)];
        let imports = vec![ImportRecord {
            dll: "kernel32.dll".to_string(),
            name: "CreateFileW".to_string(),
            symbol: "kernel32.dll!CreateFileW".to_string(),
            va: 0x401000,
            rva: 0x1000,
            hint: None,
            categories: vec![],
        }];
        let result = resolve_indirect(&functions, &irs, &vsas, &imports);
        assert_eq!(1, result.len());
        let r = &result[0];
        assert_eq!(0x1020, r.site_va);
        assert_eq!(0x401000, r.target_va);
        assert_eq!("indirect_call", r.kind);
        assert_eq!(
            Some("kernel32.dll!CreateFileW".to_string()),
            r.resolved_symbol
        );
        assert_eq!("high", r.confidence);
    }

    #[test]
    fn skips_when_vsa_has_no_target_va() {
        let functions = vec![FunctionRecord {
            start: 0x1000,
            end: 0x1100,
            size: 0x100,
            source: "test".into(),
            calls: vec![],
            calls_imports: vec![],
            strings: vec![],
            xrefs: 0,
        }];
        let irs = vec![ir(0x1020, Some("rax"))];
        let mut vsa_record = vsa(0x1000, 0x1020, "rax", 0);
        vsa_record.target_va = None;
        let result = resolve_indirect(&functions, &irs, &[vsa_record], &[]);
        assert!(result.is_empty(), "should not emit when target_va is None");
    }

    #[test]
    fn skips_direct_calls() {
        let functions = vec![FunctionRecord {
            start: 0x1000,
            end: 0x1100,
            size: 0x100,
            source: "test".into(),
            calls: vec![],
            calls_imports: vec![],
            strings: vec![],
            xrefs: 0,
        }];
        let mut direct = ir(0x1020, None);
        direct.direct_target = Some(0x401000);
        let result = resolve_indirect(&functions, &[direct], &[], &[]);
        assert!(result.is_empty(), "direct calls should be skipped");
    }
}
