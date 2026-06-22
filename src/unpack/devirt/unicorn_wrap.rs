//! `unicorn-engine` adapter (opt-in via `unpack-emulation`).
//!
//! Wraps Unicorn so snapshot `RegionDescriptor`s can be mapped into the
//! emulator's address space, registers can be primed, and a bounded number
//! of instructions can be stepped from a chosen RIP. Used by the Themida
//! 2.x and 3.x handler-walking paths in `devirt/themida.rs` /
//! `devirt/themida3x.rs`.
//!
//! The standalone `step_n()` function below is retained for backward
//! compatibility with the original skeleton; real callers should construct
//! an `Emulator`, map regions / write bytes / set registers, then call
//! `Emulator::step_n`.

use crate::unpack::UnpackError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmulatorStepOutcome {
    /// Stepped successfully; the value is the number of bytes RIP advanced
    /// (NOT the number of instructions — for that we'd need an instruction
    /// hook). Distinguishes "made progress" from "halted at PC0".
    Stepped(u64),
    /// Reached a clean halt (ret with empty call stack, or hlt-equivalent).
    Halted,
    /// Faulted at the given virtual address (unmapped read/write, illegal
    /// instruction, division by zero, etc.).
    Faulted(u64),
}

// ---------------------------------------------------------------------------
// Live implementation (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "unpack-emulation")]
mod live {
    use super::{EmulatorStepOutcome, UnpackError};
    use unicorn_engine::{
        unicorn_const::{Arch, Mode, Prot},
        RegisterX86, Unicorn,
    };

    /// Owning wrapper around a Unicorn instance pre-configured for x86_64.
    /// Drops cleanly via Unicorn's own Drop impl.
    pub struct Emulator {
        uc: Unicorn<'static, ()>,
    }

    impl Emulator {
        /// Construct a fresh x86_64 emulator with no mapped regions and no
        /// register state. Caller must `map_region` + `write_bytes` + set
        /// any seed registers before calling `step_n`.
        pub fn new() -> Result<Self, UnpackError> {
            let uc = Unicorn::new(Arch::X86, Mode::MODE_64)
                .map_err(|e| UnpackError::Pipeline(format!("unicorn init: {:?}", e)))?;
            Ok(Self { uc })
        }

        /// Map a virtual-address range with the given protections. `perms`
        /// is a permissions string in the same compact format used by
        /// `RegionDescriptor.permissions` ("RWX" / "R-X" / "RW-" / ...).
        pub fn map_region(&mut self, va: u64, size: usize, perms: &str) -> Result<(), UnpackError> {
            let mut p = Prot::NONE;
            if perms.contains('R') {
                p |= Prot::READ;
            }
            if perms.contains('W') {
                p |= Prot::WRITE;
            }
            if perms.contains('X') {
                p |= Prot::EXEC;
            }
            // Unicorn requires page-aligned mappings (4 KiB). Round size up.
            let aligned_size = (size + 0xFFF) & !0xFFF;
            self.uc.mem_map(va, aligned_size as u64, p).map_err(|e| {
                UnpackError::Pipeline(format!("mem_map {:#x}+{:#x}: {:?}", va, aligned_size, e))
            })
        }

        /// Write raw bytes into a previously-mapped region.
        pub fn write_bytes(&mut self, va: u64, bytes: &[u8]) -> Result<(), UnpackError> {
            self.uc
                .mem_write(va, bytes)
                .map_err(|e| UnpackError::Pipeline(format!("mem_write {:#x}: {:?}", va, e)))
        }

        /// Set a register by lowercase name (`"rax"`, `"rip"`, `"rflags"`,
        /// etc.). Returns an error for unsupported names rather than
        /// silently no-opping.
        pub fn set_reg(&mut self, reg: &str, value: u64) -> Result<(), UnpackError> {
            let r = reg_id_from_name(reg)?;
            self.uc
                .reg_write(r, value)
                .map_err(|e| UnpackError::Pipeline(format!("reg_write {}: {:?}", reg, e)))
        }

        /// Read a register by lowercase name.
        pub fn get_reg(&self, reg: &str) -> Result<u64, UnpackError> {
            let r = reg_id_from_name(reg)?;
            self.uc
                .reg_read(r)
                .map_err(|e| UnpackError::Pipeline(format!("reg_read {}: {:?}", reg, e)))
        }

        /// Step up to `max_instructions` instructions starting at `start_va`.
        /// Returns `Stepped(advanced_bytes)` on success (counted instructions
        /// reached without fault), `Halted` if execution stopped cleanly at a
        /// recognized terminator (currently: emu_start returning Ok with RIP
        /// unchanged is treated as Halted), or `Faulted(rip)` on any unicorn
        /// error.
        pub fn step_n(
            &mut self,
            start_va: u64,
            max_instructions: u32,
        ) -> Result<EmulatorStepOutcome, UnpackError> {
            match self.uc.emu_start(start_va, 0, 0, max_instructions as usize) {
                Ok(()) => {
                    let after_pc = self.get_reg("rip").unwrap_or(start_va);
                    if after_pc == start_va {
                        Ok(EmulatorStepOutcome::Halted)
                    } else {
                        Ok(EmulatorStepOutcome::Stepped(
                            after_pc.saturating_sub(start_va),
                        ))
                    }
                }
                Err(_) => {
                    let fault_pc = self.get_reg("rip").unwrap_or(start_va);
                    Ok(EmulatorStepOutcome::Faulted(fault_pc))
                }
            }
        }
    }

    fn reg_id_from_name(name: &str) -> Result<RegisterX86, UnpackError> {
        let lower = name.to_ascii_lowercase();
        Ok(match lower.as_str() {
            "rax" => RegisterX86::RAX,
            "rbx" => RegisterX86::RBX,
            "rcx" => RegisterX86::RCX,
            "rdx" => RegisterX86::RDX,
            "rsi" => RegisterX86::RSI,
            "rdi" => RegisterX86::RDI,
            "rsp" => RegisterX86::RSP,
            "rbp" => RegisterX86::RBP,
            "r8" => RegisterX86::R8,
            "r9" => RegisterX86::R9,
            "r10" => RegisterX86::R10,
            "r11" => RegisterX86::R11,
            "r12" => RegisterX86::R12,
            "r13" => RegisterX86::R13,
            "r14" => RegisterX86::R14,
            "r15" => RegisterX86::R15,
            "rip" => RegisterX86::RIP,
            "rflags" | "eflags" => RegisterX86::EFLAGS,
            other => {
                return Err(UnpackError::Pipeline(format!(
                    "unknown register name: {}",
                    other
                )))
            }
        })
    }
}

#[cfg(feature = "unpack-emulation")]
pub use live::Emulator;

// ---------------------------------------------------------------------------
// Backward-compat shim
// ---------------------------------------------------------------------------

/// Legacy free-function entry point retained so the existing test in
/// `step_n_without_feature_errors_with_emulation_missing` keeps passing.
/// Real callers should construct an `Emulator` instead — see the live
/// implementation above.
pub fn step_n(_start_va: u64, _max_instructions: u32) -> Result<EmulatorStepOutcome, UnpackError> {
    #[cfg(not(feature = "unpack-emulation"))]
    return Err(UnpackError::EmulationFeatureMissing);
    #[cfg(feature = "unpack-emulation")]
    return Err(UnpackError::Pipeline(
        "unicorn_wrap::step_n: use Emulator::step_n on an initialized Emulator instead".into(),
    ));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(feature = "unpack-emulation"))]
    fn step_n_without_feature_errors_with_emulation_missing() {
        match step_n(0x140001000, 10) {
            Err(UnpackError::EmulationFeatureMissing) => {}
            other => panic!("expected EmulationFeatureMissing, got {:?}", other),
        }
    }

    /// B1 acceptance: identity_handler sled (`mov rax, rcx; mov rdx, rax;
    /// ret`) — after step_n, RAX must equal the RCX value we primed at the
    /// start. Validates: arena mapping, code write, register prime, step,
    /// register readback.
    #[test]
    #[cfg(feature = "unpack-emulation")]
    fn identity_handler_propagates_rcx_to_rax() {
        let base: u64 = 0x1000;
        let code: &[u8] = &[
            0x48, 0x89, 0xC8, // mov rax, rcx
            0x48, 0x89, 0xC2, // mov rdx, rax
            0xC3, // ret
        ];

        let mut emu = Emulator::new().expect("create emulator");
        emu.map_region(base, 0x1000, "RWX")
            .expect("map code region");
        // Stack — needed because `ret` reads the return address off the stack.
        // If the stack page isn't mapped, the ret faults. Map a small RW
        // arena and point rsp at the middle.
        emu.map_region(0x10000, 0x1000, "RW-")
            .expect("map stack region");
        emu.set_reg("rsp", 0x10800).expect("set rsp");
        emu.write_bytes(base, code).expect("write code");

        let seed_rcx: u64 = 0xDEADBEEF12345678;
        emu.set_reg("rcx", seed_rcx).expect("set rcx");
        emu.set_reg("rax", 0).expect("clear rax");

        let outcome = emu.step_n(base, 16).expect("step");
        // The ret reading from our zeroed stack will set PC = 0 and fault on
        // the next fetch — that's fine, we already executed the two movs.
        // Either Stepped(>=6) or Faulted is acceptable; the key check is the
        // register state after the two movs ran.
        match outcome {
            EmulatorStepOutcome::Stepped(_)
            | EmulatorStepOutcome::Faulted(_)
            | EmulatorStepOutcome::Halted => {}
        }

        let rax_after = emu.get_reg("rax").expect("read rax");
        assert_eq!(
            rax_after, seed_rcx,
            "rax should equal seeded rcx after `mov rax, rcx`"
        );
        let rdx_after = emu.get_reg("rdx").expect("read rdx");
        assert_eq!(
            rdx_after, seed_rcx,
            "rdx should equal rax after `mov rdx, rax`"
        );
    }

    /// Faults on unmapped code should return `Faulted`, not panic.
    #[test]
    #[cfg(feature = "unpack-emulation")]
    fn unmapped_code_returns_faulted() {
        let mut emu = Emulator::new().expect("create");
        // No mem_map call; emu_start on unmapped memory will fault.
        let outcome = emu.step_n(0x1000, 4).expect("step");
        match outcome {
            EmulatorStepOutcome::Faulted(_) => {}
            other => panic!("expected Faulted on unmapped code, got {:?}", other),
        }
    }
}
