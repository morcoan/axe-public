//! Per-register and per-memory-byte symbolic shadow state — Codex
//! finding 1 mitigation.
//!
//! Every supported instruction the [`shadow_emulator`](super::shadow_emulator)
//! steps through populates this state with [`NodeId`]s into the
//! [`ExprDag`](super::expr::ExprDag). Branch events emitted from the
//! shadow emulator carry NodeIds directly — that's what lets the SMT
//! backend reason about symbolic shifts, memory loads, multi-byte
//! reconstruction, and checksum arithmetic that the bounded solver
//! cannot touch.
//!
//! Unsupported instructions mark their destinations as `None`
//! (concretize-or-bail boundary). The fraction of `None`s in any
//! given solve is reported in `solves.jsonl::constraint_summary` so
//! consumers can see when concretization is dominating.

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::concolic::expr::NodeId;

/// Per-register symbolic state. `None` means "concrete" (no symbolic
/// expression bound to this register) — the read path falls back to
/// the concrete value tracked by the native emulator.
#[derive(Clone, Debug, Default)]
pub struct RegFile {
    pub rax: Option<NodeId>,
    pub rbx: Option<NodeId>,
    pub rcx: Option<NodeId>,
    pub rdx: Option<NodeId>,
    pub rsi: Option<NodeId>,
    pub rdi: Option<NodeId>,
    pub rsp: Option<NodeId>,
    pub rbp: Option<NodeId>,
    pub r8: Option<NodeId>,
    pub r9: Option<NodeId>,
    pub r10: Option<NodeId>,
    pub r11: Option<NodeId>,
    pub r12: Option<NodeId>,
    pub r13: Option<NodeId>,
    pub r14: Option<NodeId>,
    pub r15: Option<NodeId>,
}

impl RegFile {
    pub fn read(&self, reg: &str) -> Option<NodeId> {
        match reg {
            "rax" => self.rax,
            "rbx" => self.rbx,
            "rcx" => self.rcx,
            "rdx" => self.rdx,
            "rsi" => self.rsi,
            "rdi" => self.rdi,
            "rsp" => self.rsp,
            "rbp" => self.rbp,
            "r8" => self.r8,
            "r9" => self.r9,
            "r10" => self.r10,
            "r11" => self.r11,
            "r12" => self.r12,
            "r13" => self.r13,
            "r14" => self.r14,
            "r15" => self.r15,
            _ => None,
        }
    }

    pub fn write(&mut self, reg: &str, node: Option<NodeId>) {
        match reg {
            "rax" => self.rax = node,
            "rbx" => self.rbx = node,
            "rcx" => self.rcx = node,
            "rdx" => self.rdx = node,
            "rsi" => self.rsi = node,
            "rdi" => self.rdi = node,
            "rsp" => self.rsp = node,
            "rbp" => self.rbp = node,
            "r8" => self.r8 = node,
            "r9" => self.r9 = node,
            "r10" => self.r10 = node,
            "r11" => self.r11 = node,
            "r12" => self.r12 = node,
            "r13" => self.r13 = node,
            "r14" => self.r14 = node,
            "r15" => self.r15 = node,
            _ => {} // unknown reg name — silent no-op
        }
    }

    pub fn clear(&mut self, reg: &str) {
        self.write(reg, None);
    }

    /// Returns count of registers currently holding symbolic state.
    pub fn symbolic_count(&self) -> usize {
        [
            self.rax, self.rbx, self.rcx, self.rdx, self.rsi, self.rdi, self.rsp, self.rbp,
            self.r8, self.r9, self.r10, self.r11, self.r12, self.r13, self.r14, self.r15,
        ]
        .iter()
        .filter(|n| n.is_some())
        .count()
    }
}

/// Flag-register shadow state. We track ZF/SF/CF/OF symbolically when
/// the last flag-setting op had symbolic operands; otherwise `None`
/// (read falls back to the native emulator's concrete flags).
#[derive(Clone, Copy, Debug, Default)]
pub struct ShadowFlags {
    pub zf: Option<NodeId>,
    pub sf: Option<NodeId>,
    pub cf: Option<NodeId>,
    pub of: Option<NodeId>,
}

/// Per-byte-keyed symbolic memory plus an optional fallback array
/// for fully-symbolic-address regions.
///
/// Most loads and stores go through `byte_map` (concrete-addressed
/// shadow bytes); only loads/stores with symbolic addresses fall
/// through to `array_fallback` (a `Sort::Array { index_bits: 64,
/// value_bits: 8 }` node).
#[derive(Clone, Debug, Default)]
pub struct ShadowMemory {
    pub byte_map: BTreeMap<u64, NodeId>,
    pub array_fallback: Option<NodeId>,
}

impl ShadowMemory {
    pub fn read_byte(&self, addr: u64) -> Option<NodeId> {
        self.byte_map.get(&addr).copied()
    }

    pub fn write_byte(&mut self, addr: u64, node: Option<NodeId>) {
        match node {
            Some(n) => {
                self.byte_map.insert(addr, n);
            }
            None => {
                self.byte_map.remove(&addr);
            }
        }
    }

    pub fn clear(&mut self, addr: u64) {
        self.byte_map.remove(&addr);
    }

    /// Number of currently-symbolic bytes.
    pub fn symbolic_byte_count(&self) -> usize {
        self.byte_map.len()
    }
}

/// Top-level shadow state combining registers, flags, and memory.
#[derive(Clone, Debug, Default)]
pub struct ShadowState {
    pub regs: RegFile,
    pub flags: ShadowFlags,
    pub memory: ShadowMemory,
    /// Count of instructions that concretized (marked dest as None
    /// because we don't model the op). Reported in solves telemetry.
    pub concretization_events: u64,
}

impl ShadowState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Convenience: write a register, OR if value is `None`, clear it.
    pub fn write_reg(&mut self, reg: &str, node: Option<NodeId>) {
        if node.is_none() && self.regs.read(reg).is_some() {
            self.concretization_events += 1;
        }
        self.regs.write(reg, node);
    }

    pub fn read_reg(&self, reg: &str) -> Option<NodeId> {
        self.regs.read(reg)
    }

    pub fn write_byte(&mut self, addr: u64, node: Option<NodeId>) {
        if node.is_none() && self.memory.read_byte(addr).is_some() {
            self.concretization_events += 1;
        }
        self.memory.write_byte(addr, node);
    }

    pub fn read_byte(&self, addr: u64) -> Option<NodeId> {
        self.memory.read_byte(addr)
    }

    /// Aggregate metric: total symbolic state size (regs + flags + mem bytes).
    pub fn symbolic_size(&self) -> usize {
        self.regs.symbolic_count()
            + (self.flags.zf.is_some() as usize)
            + (self.flags.sf.is_some() as usize)
            + (self.flags.cf.is_some() as usize)
            + (self.flags.of.is_some() as usize)
            + self.memory.symbolic_byte_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regfile_read_write_roundtrip() {
        let mut r = RegFile::default();
        r.write("rax", Some(7));
        assert_eq!(r.read("rax"), Some(7));
        assert_eq!(r.read("rbx"), None);
    }

    #[test]
    fn regfile_clear_makes_concrete() {
        let mut r = RegFile::default();
        r.write("rcx", Some(42));
        r.clear("rcx");
        assert_eq!(r.read("rcx"), None);
    }

    #[test]
    fn regfile_unknown_reg_name_is_noop() {
        let mut r = RegFile::default();
        r.write("xmm0", Some(1)); // unknown — silently ignored
        assert_eq!(r.read("xmm0"), None);
    }

    #[test]
    fn regfile_symbolic_count_tracks_state() {
        let mut r = RegFile::default();
        assert_eq!(r.symbolic_count(), 0);
        r.write("rax", Some(1));
        r.write("rbx", Some(2));
        assert_eq!(r.symbolic_count(), 2);
        r.clear("rax");
        assert_eq!(r.symbolic_count(), 1);
    }

    #[test]
    fn memory_byte_roundtrip() {
        let mut m = ShadowMemory::default();
        m.write_byte(0x1000, Some(5));
        m.write_byte(0x1001, Some(6));
        assert_eq!(m.read_byte(0x1000), Some(5));
        assert_eq!(m.read_byte(0x1001), Some(6));
        assert_eq!(m.read_byte(0x1002), None);
        assert_eq!(m.symbolic_byte_count(), 2);
    }

    #[test]
    fn memory_write_none_removes_byte() {
        let mut m = ShadowMemory::default();
        m.write_byte(0x1000, Some(5));
        m.write_byte(0x1000, None);
        assert_eq!(m.read_byte(0x1000), None);
        assert_eq!(m.symbolic_byte_count(), 0);
    }

    #[test]
    fn shadow_state_tracks_concretization_events() {
        let mut s = ShadowState::new();
        s.write_reg("rax", Some(1));
        assert_eq!(s.concretization_events, 0);
        // Writing None to a previously-symbolic reg counts as concretization.
        s.write_reg("rax", None);
        assert_eq!(s.concretization_events, 1);
        // Writing None to an already-None reg does NOT count.
        s.write_reg("rbx", None);
        assert_eq!(s.concretization_events, 1);
    }

    #[test]
    fn shadow_state_size_aggregates_regs_flags_memory() {
        let mut s = ShadowState::new();
        s.write_reg("rcx", Some(1));
        s.flags.zf = Some(2);
        s.write_byte(0x1000, Some(3));
        s.write_byte(0x1001, Some(4));
        assert_eq!(s.symbolic_size(), 4); // 1 reg + 1 flag + 2 bytes
    }
}
