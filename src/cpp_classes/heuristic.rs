//! Heuristic C++ class layout reconstruction for binaries with no
//! RTTI and no debug info.
//!
//! Looks for constructor-shaped functions (write a vtable pointer to
//! `[this+0]`), then collects field-access constraints from the rest
//! of the function. Emits one [`ClassFact`] per discovered vftable
//! with [`ClaimSource::Heuristic`]-like sources
//! ([`ClaimSource::CtorDtorPattern`] and
//! [`ClaimSource::FieldAccessInference`]).
//!
//! Confidence is intentionally capped at 0.7 — see
//! [`ClaimSource::FieldAccessInference`]'s band.

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::cpp_classes::fact::{build_class_id, ClassFact, CppAbi, FieldFact, CLASS_SCHEMA};
use crate::facts::{Claim, ClaimSource, EvidenceRef};
use crate::ir::IrInstruction;
use crate::pe::FunctionRecord;
use crate::semantic_index::FunctionSemanticIndex;

const CTOR_SCORE: f32 = 0.65;
const FIELD_SCORE: f32 = 0.55;

#[derive(Clone, Debug)]
struct HeuristicConstraint {
    /// VA of the vtable pointer this ctor writes to `[rcx]`.
    vftable_va: u64,
    /// VA of the ctor function (evidence).
    ctor_va: u64,
    /// Field accesses `[rcx + offset]` observed in this ctor.
    fields: Vec<(i64, u32, u64)>, // (offset, width_bytes, access_site_va)
}

pub fn collect(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
) -> Vec<ClassFact> {
    let constraints = collect_constraints(functions, semantic_index, ir);
    merge_constraints_by_vftable(constraints)
}

fn collect_constraints(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
) -> Vec<HeuristicConstraint> {
    let mut out = Vec::new();
    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        let slice_ir = &ir[slice.ir_range.clone()];
        if let Some(constraint) = inspect_function(function.start, slice_ir) {
            out.push(constraint);
        }
    }
    out
}

fn inspect_function(ctor_va: u64, slice_ir: &[IrInstruction]) -> Option<HeuristicConstraint> {
    let vptr_write = slice_ir.iter().find(|ins| is_vptr_write(ins))?;
    let vftable_va = vptr_write_target(vptr_write)?;
    let fields = collect_field_accesses(slice_ir);
    Some(HeuristicConstraint {
        vftable_va,
        ctor_va,
        fields,
    })
}

/// A vptr write: `mov [rcx], reg` or `mov [rcx], imm` where the
/// destination has displacement 0. The source is a vtable pointer.
fn is_vptr_write(ins: &IrInstruction) -> bool {
    ins.mnemonic == "mov"
        && ins.memory_write
        && ins.memory_base.as_deref() == Some("rcx")
        && ins.memory_displacement == 0
        && ins.operand_width >= 4
}

fn vptr_write_target(ins: &IrInstruction) -> Option<u64> {
    ins.rip_target.or(ins.immediate)
}

/// Collect `[rcx + offset]` accesses where `offset > 0` (non-vptr).
fn collect_field_accesses(slice_ir: &[IrInstruction]) -> Vec<(i64, u32, u64)> {
    let mut accesses = Vec::new();
    for ins in slice_ir {
        if (ins.memory_read || ins.memory_write)
            && ins.memory_base.as_deref() == Some("rcx")
            && ins.memory_displacement > 0
            && ins.memory_displacement < 4096
            && ins.operand_width >= 1
            && ins.operand_width <= 16
        {
            accesses.push((ins.memory_displacement, ins.operand_width, ins.address));
        }
    }
    accesses
}

fn merge_constraints_by_vftable(constraints: Vec<HeuristicConstraint>) -> Vec<ClassFact> {
    // Group constraints by vftable_va so multiple ctors of the same
    // class merge into one fact with combined field evidence.
    let mut grouped: BTreeMap<u64, Vec<HeuristicConstraint>> = BTreeMap::new();
    for c in constraints {
        grouped.entry(c.vftable_va).or_default().push(c);
    }

    grouped
        .into_iter()
        .map(|(vftable_va, ctors)| build_one(vftable_va, &ctors))
        .collect()
}

fn build_one(vftable_va: u64, ctors: &[HeuristicConstraint]) -> ClassFact {
    // Field-merge: collapse overlapping offsets, keeping max width.
    let mut field_map: BTreeMap<i64, (u32, Vec<u64>)> = BTreeMap::new();
    for ctor in ctors {
        for &(offset, width, site_va) in &ctor.fields {
            let entry = field_map.entry(offset).or_insert((0, Vec::new()));
            entry.0 = entry.0.max(width);
            entry.1.push(site_va);
        }
    }
    let fields: Vec<FieldFact> = field_map
        .into_iter()
        .map(|(offset, (width, sites))| FieldFact {
            offset: offset as u64,
            size: Claim::new(width, ClaimSource::FieldAccessInference).with_score(FIELD_SCORE),
            name: None,
            type_guess: None,
            access_sites: sites,
        })
        .collect();

    let mut evidence: Vec<EvidenceRef> = ctors
        .iter()
        .map(|c| EvidenceRef::Instruction { va: c.ctor_va })
        .collect();
    evidence.push(EvidenceRef::RawAddr { va: vftable_va });

    let ctor_vas: Vec<u64> = ctors.iter().map(|c| c.ctor_va).collect();

    ClassFact {
        schema: CLASS_SCHEMA,
        class_id: build_class_id(None, Some(vftable_va)),
        demangled_name: None,
        mangled_name: None,
        size: None,
        abi: CppAbi::Unknown,
        vtables: Vec::new(),
        bases: Vec::new(),
        fields,
        methods: Vec::new(),
        constructors: ctor_vas,
        destructors: Vec::new(),
        claim: Claim::new((), ClaimSource::CtorDtorPattern)
            .with_score(CTOR_SCORE)
            .with_evidence(evidence),
        contributing_sources: vec![
            ClaimSource::CtorDtorPattern,
            ClaimSource::FieldAccessInference,
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ir(address: u64, mnemonic: &str) -> IrInstruction {
        IrInstruction {
            address,
            size: 4,
            mnemonic: mnemonic.to_string(),
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

    #[test]
    fn detects_vptr_write_with_rip_target() {
        let mut vptr_ins = ir(0x1000, "mov");
        vptr_ins.memory_write = true;
        vptr_ins.memory_base = Some("rcx".into());
        vptr_ins.memory_displacement = 0;
        vptr_ins.rip_target = Some(0x140020000);
        vptr_ins.operand_width = 8;
        assert!(is_vptr_write(&vptr_ins));
        assert_eq!(vptr_write_target(&vptr_ins), Some(0x140020000));
    }

    #[test]
    fn rejects_field_write_as_vptr() {
        let mut field_ins = ir(0x1000, "mov");
        field_ins.memory_write = true;
        field_ins.memory_base = Some("rcx".into());
        field_ins.memory_displacement = 0x28; // not vptr
        field_ins.operand_width = 4;
        assert!(!is_vptr_write(&field_ins));
    }

    #[test]
    fn collect_field_accesses_returns_non_vptr_only() {
        let mut vptr_ins = ir(0x1000, "mov");
        vptr_ins.memory_write = true;
        vptr_ins.memory_base = Some("rcx".into());
        vptr_ins.memory_displacement = 0;
        vptr_ins.rip_target = Some(0x140020000);
        vptr_ins.operand_width = 8;

        let mut field_ins = ir(0x1004, "mov");
        field_ins.memory_write = true;
        field_ins.memory_base = Some("rcx".into());
        field_ins.memory_displacement = 0x28;
        field_ins.operand_width = 4;

        let mut other_ins = ir(0x1008, "mov");
        other_ins.memory_read = true;
        other_ins.memory_base = Some("rdx".into()); // wrong base
        other_ins.memory_displacement = 0x10;
        other_ins.operand_width = 4;

        let fields = collect_field_accesses(&[vptr_ins, field_ins, other_ins]);
        assert_eq!(fields, vec![(0x28, 4, 0x1004)]);
    }

    #[test]
    fn merge_groups_ctors_by_vftable() {
        // Two ctors of the same class, each writing the same vftable
        // and touching different fields.
        let c1 = HeuristicConstraint {
            vftable_va: 0x140020000,
            ctor_va: 0x1500,
            fields: vec![(0x10, 4, 0x1504)],
        };
        let c2 = HeuristicConstraint {
            vftable_va: 0x140020000,
            ctor_va: 0x1600,
            fields: vec![(0x10, 8, 0x1604), (0x18, 4, 0x1608)],
        };
        let facts = merge_constraints_by_vftable(vec![c1, c2]);
        assert_eq!(facts.len(), 1, "same vftable -> one ClassFact");
        let f = &facts[0];
        assert_eq!(f.constructors.len(), 2);
        assert_eq!(f.fields.len(), 2);
        // Field at 0x10 should have width 8 (max of 4 and 8).
        let field_10 = f.fields.iter().find(|fld| fld.offset == 0x10).unwrap();
        assert_eq!(field_10.size.value, 8);
        // Both access sites recorded.
        assert_eq!(field_10.access_sites.len(), 2);
    }

    #[test]
    fn confidence_capped_below_high_band() {
        let c = HeuristicConstraint {
            vftable_va: 0x140020000,
            ctor_va: 0x1500,
            fields: Vec::new(),
        };
        let facts = merge_constraints_by_vftable(vec![c]);
        // Heuristic should never reach High band (>= 0.85).
        assert!(facts[0].claim.confidence.as_f32() < 0.85);
    }
}
