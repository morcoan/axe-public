//! Adjustor-thunk detection for MSVC multi-inheritance.
//!
//! A thunk is a tiny trampoline function that adjusts the `this`
//! pointer by a constant offset, then jumps to the real method. MSVC
//! emits one per virtual override that needs a different subobject
//! base. Pattern:
//!
//! ```text
//!     sub  rcx, <offset>     ; or: lea rcx, [rcx-<offset>]
//!     jmp  <real_method>
//! ```
//!
//! Detection is used by [`crate::cpp_classes::msvc_rtti`] to mark
//! vtable-slot functions as `is_thunk: true` and to record the
//! subobject offset on the [`crate::cpp_classes::fact::MethodFact`].

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::ir::IrInstruction;
use crate::pe::FunctionRecord;
use crate::semantic_index::FunctionSemanticIndex;

/// What an adjustor thunk reveals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdjustorInfo {
    /// The real method the thunk forwards to.
    pub real_target_va: u64,
    /// The byte offset applied to `this` (positive = thunk subtracts
    /// this many bytes from `rcx` before forwarding).
    pub offset: i64,
}

/// Build a map from `function_va → AdjustorInfo` covering every
/// function that matches the adjustor-thunk pattern.
pub fn detect_adjustor_thunks(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
) -> BTreeMap<u64, AdjustorInfo> {
    let mut map = BTreeMap::new();
    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        if function.end.saturating_sub(function.start) > 16 {
            continue;
        }
        let slice_ir = &ir[slice.ir_range.clone()];
        if let Some(info) = match_thunk_pattern(slice_ir) {
            map.insert(function.start, info);
        }
    }
    map
}

fn match_thunk_pattern(slice_ir: &[IrInstruction]) -> Option<AdjustorInfo> {
    if slice_ir.len() < 2 || slice_ir.len() > 4 {
        return None;
    }
    let adjust = &slice_ir[0];
    let branch = slice_ir
        .iter()
        .skip(1)
        .find(|i| i.is_jump && i.direct_target.is_some())?;

    let offset = match adjust.mnemonic.as_str() {
        "sub" if adjust.write_reg.as_deref() == Some("rcx") => adjust.immediate? as i64,
        "lea" if adjust.write_reg.as_deref() == Some("rcx") => {
            // lea rcx, [rcx - imm] → memory_base=rcx, memory_displacement=-imm.
            if adjust.memory_base.as_deref() != Some("rcx") {
                return None;
            }
            -adjust.memory_displacement
        }
        _ => return None,
    };

    if offset <= 0 || offset > 4096 {
        return None;
    }

    Some(AdjustorInfo {
        real_target_va: branch.direct_target?,
        offset,
    })
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
    fn detects_sub_jmp_pattern() {
        let mut sub_ins = ir(0x1000, "sub");
        sub_ins.write_reg = Some("rcx".into());
        sub_ins.immediate = Some(8);
        let mut jmp_ins = ir(0x1004, "jmp");
        jmp_ins.is_jump = true;
        jmp_ins.direct_target = Some(0x2000);

        let info = match_thunk_pattern(&[sub_ins, jmp_ins]);
        assert_eq!(
            info,
            Some(AdjustorInfo {
                real_target_va: 0x2000,
                offset: 8
            })
        );
    }

    #[test]
    fn detects_lea_jmp_pattern() {
        let mut lea_ins = ir(0x1000, "lea");
        lea_ins.write_reg = Some("rcx".into());
        lea_ins.memory_base = Some("rcx".into());
        lea_ins.memory_displacement = -16; // `lea rcx, [rcx-16]`
        let mut jmp_ins = ir(0x1004, "jmp");
        jmp_ins.is_jump = true;
        jmp_ins.direct_target = Some(0x2000);

        let info = match_thunk_pattern(&[lea_ins, jmp_ins]);
        assert_eq!(
            info,
            Some(AdjustorInfo {
                real_target_va: 0x2000,
                offset: 16
            })
        );
    }

    #[test]
    fn rejects_non_thunk_function() {
        let mut mov_ins = ir(0x1000, "mov");
        mov_ins.write_reg = Some("rcx".into());
        let mut ret_ins = ir(0x1004, "ret");
        assert!(match_thunk_pattern(&[mov_ins, ret_ins]).is_none());
    }

    #[test]
    fn rejects_oversized_offset() {
        let mut sub_ins = ir(0x1000, "sub");
        sub_ins.write_reg = Some("rcx".into());
        sub_ins.immediate = Some(100_000); // too large for a class subobject
        let mut jmp_ins = ir(0x1004, "jmp");
        jmp_ins.is_jump = true;
        jmp_ins.direct_target = Some(0x2000);
        assert!(match_thunk_pattern(&[sub_ins, jmp_ins]).is_none());
    }

    #[test]
    fn rejects_indirect_jump() {
        let mut sub_ins = ir(0x1000, "sub");
        sub_ins.write_reg = Some("rcx".into());
        sub_ins.immediate = Some(8);
        let mut jmp_ins = ir(0x1004, "jmp");
        jmp_ins.is_jump = true;
        jmp_ins.direct_target = None; // indirect
        assert!(match_thunk_pattern(&[sub_ins, jmp_ins]).is_none());
    }
}
