//! Shadow-state-tracking emulator (Codex finding 1 mitigation).
//!
//! Reads `iced-x86`-formatted [`InstructionRecord`] rows alongside the
//! native emulator and propagates symbolic [`NodeId`]s through a
//! per-register / per-memory-byte [`ShadowState`]. On a conditional
//! branch whose flag-setting `cmp`/`test` had at least one symbolic
//! operand, emits a [`BranchEventWithNodeIds`] whose predicate is a
//! real `Expr` rooted in the variables the engine cares about
//! (`input_b<i>`, propagated through arithmetic / shifts / extracts).
//!
//! The native emulator stays untouched — this layer is *additive*:
//! both the native concrete state and the shadow symbolic state advance
//! in lockstep, and the concolic session reconciles them.
//!
//! ## Supported instruction families (the contract)
//!
//! | Mnemonic | Behavior                                                                  |
//! |----------|---------------------------------------------------------------------------|
//! | `mov`    | reg-reg / reg-imm / reg-mem / mem-reg with explicit width                 |
//! | `movzx`  | zero-extend source to destination width                                   |
//! | `movsx`  | sign-extend source to destination width                                   |
//! | `add`    | `dst = dst + src` at destination width                                     |
//! | `sub`    | `dst = dst - src`                                                          |
//! | `imul`   | 2-operand form: `dst = dst * src`                                          |
//! | `and`    | `dst = dst & src`                                                          |
//! | `or`     | `dst = dst \| src`                                                         |
//! | `xor`    | `dst = dst ^ src`                                                          |
//! | `shl`    | `dst = dst << src` (immediate shift count up to 63)                       |
//! | `shr`    | `dst = dst >> src` (logical)                                              |
//! | `sar`    | `dst = dst >> src` (arithmetic)                                           |
//! | `lea`    | `dst = base [+ disp]` — addr-computation as arithmetic                    |
//! | `cmp`    | sets last-compare to (lhs, rhs, width); does NOT write a register         |
//! | `test`   | sets last-compare to (lhs & rhs, BvConst(0)); ZF semantics                |
//!
//! Anything outside the table → destinations marked `None` (the
//! `concretize-or-bail` boundary). Each concretization increments
//! [`ShadowState::concretization_events`] for telemetry.

#![allow(dead_code)]

use crate::concolic::expr::{Expr, ExprDag, NodeId, Sort, SymbolId};
use crate::concolic::shadow_state::ShadowState;
use crate::pe::InstructionRecord;

/// 64-bit canonical width — every shadow register is stored at this
/// width; sub-register reads use [`Expr::Extract`].
pub const REG_BITS: u32 = 64;

/// Per-step output: the most recent flag-setting cmp/test the emulator
/// observed. Conditional jumps fold this into a relational Expr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastCompare {
    pub lhs: NodeId,
    pub rhs: NodeId,
    pub width: u32,
    /// True if the source op was `test` (i.e. AND-then-compare-to-zero)
    /// rather than `cmp` (sub-then-compare). The branch lifter uses
    /// this to skip relational mnemonics that don't make sense for
    /// `test` (e.g. `jl`/`jg` after `test` are valid x86 but never
    /// surface a useful symbolic predicate).
    pub is_test: bool,
}

/// Branch event emitted when the shadow emulator sees a conditional
/// jump whose source `cmp`/`test` carried symbolic state.
#[derive(Clone, Debug)]
pub struct BranchEventWithNodeIds {
    pub site_va: u64,
    pub mnemonic: String,
    /// The Bool [`NodeId`] for the predicate. Solving `predicate` for
    /// `true` flips the branch toward the taken side; `Not(predicate)`
    /// flips toward fall-through.
    pub predicate: NodeId,
    /// Width of the comparison the predicate was built from.
    pub width: u32,
    /// Optional reference back to last-compare for diagnostics.
    pub last_cmp: LastCompare,
}

/// Shadow emulator. Owns a borrow on the `ExprDag` and an owned
/// `ShadowState`; the caller feeds it one [`InstructionRecord`] per
/// `step_instruction` call and consumes any emitted branch events.
pub struct ShadowEmulator<'a> {
    pub dag: &'a mut ExprDag,
    pub state: ShadowState,
    /// Synthetic base address for the symbolic input. Memory reads in
    /// `[input_base, input_base + input_len)` lift to `Var(input_b<i>, Bv(8))`
    /// concatenations.
    pub input_base: u64,
    pub input_len: u32,
    last_cmp: Option<LastCompare>,
}

impl<'a> ShadowEmulator<'a> {
    pub fn new(dag: &'a mut ExprDag, input_base: u64, input_len: u32) -> Self {
        Self {
            dag,
            state: ShadowState::new(),
            input_base,
            input_len,
            last_cmp: None,
        }
    }

    /// Latest cmp/test observed. Test code uses this to assert that
    /// the emulator correctly captured a flag-setting op.
    pub fn last_compare(&self) -> Option<LastCompare> {
        self.last_cmp
    }

    /// Step one instruction. Returns a [`BranchEventWithNodeIds`] iff
    /// the instruction is a conditional jump AND the preceding
    /// flag-setting op had at least one symbolic operand.
    pub fn step_instruction(&mut self, ir: &InstructionRecord) -> Option<BranchEventWithNodeIds> {
        let m = ir.mnemonic.to_ascii_lowercase();
        let operands = parse_operands(&ir.op_str);

        // Conditional jump handling FIRST — these are emitted from
        // `last_cmp`; their operand string is the target VA, not regs.
        if let Some(rel) = relation_for_branch(&m) {
            return self.emit_branch_event(ir.address, &m, rel);
        }

        match m.as_str() {
            "mov" => self.step_mov(&operands),
            "movzx" => self.step_movzx_or_sx(&operands, false),
            "movsx" => self.step_movzx_or_sx(&operands, true),
            "add" => self.step_binop(&operands, Binop::Add),
            "sub" => self.step_binop(&operands, Binop::Sub),
            "imul" => self.step_binop(&operands, Binop::Mul),
            "and" => self.step_binop(&operands, Binop::And),
            "or" => self.step_binop(&operands, Binop::Or),
            "xor" => self.step_binop(&operands, Binop::Xor),
            "shl" | "sal" => self.step_shift(&operands, Shift::Shl),
            "shr" => self.step_shift(&operands, Shift::Lshr),
            "sar" => self.step_shift(&operands, Shift::Ashr),
            "cmp" => self.step_cmp(&operands, false),
            "test" => self.step_cmp(&operands, true),
            "lea" => self.step_lea(&operands),
            _ => {
                // Unsupported family — clear any destination register
                // (first operand) to mark concretized.
                if let Some(Operand::Reg { name: dst, .. }) = operands.first() {
                    if let Some(c) = canonical_reg(dst) {
                        if self.state.read_reg(c).is_some() {
                            self.state.write_reg(c, None);
                        }
                    }
                }
            }
        }
        None
    }

    // ──────────────────────────────────────────────────────────────────
    // mnemonic handlers

    fn step_mov(&mut self, ops: &[Operand]) {
        let (dst, src) = match ops {
            [a, b] => (a, b),
            _ => return,
        };
        match dst {
            Operand::Reg { name, width } => {
                let src_node = self.read_operand(src, *width);
                let dst64 = self.widen_to_64(src_node, *width);
                self.write_reg64(name, dst64);
            }
            Operand::Mem { base, disp, width } => {
                let src_node = self.read_operand(src, *width);
                self.write_memory_region(base.clone(), *disp, *width, src_node);
            }
            Operand::Imm(_) => {}
        }
    }

    fn step_movzx_or_sx(&mut self, ops: &[Operand], signed: bool) {
        let (dst, src) = match ops {
            [a, b] => (a, b),
            _ => return,
        };
        let Operand::Reg {
            name: dst_name,
            width: dw,
        } = dst
        else {
            return;
        };
        let src_w = src.width().unwrap_or(8);
        let src_node = self.read_operand(src, src_w);
        let extra = dw.saturating_sub(src_w);
        let extended = match src_node {
            Some(n) if extra > 0 => {
                let kind = if signed {
                    Expr::SignExt { extra, value: n }
                } else {
                    Expr::ZeroExt { extra, value: n }
                };
                Some(self.dag.intern(kind))
            }
            other => other,
        };
        let dst64 = self.widen_to_64(extended, *dw);
        self.write_reg64(dst_name, dst64);
    }

    fn step_binop(&mut self, ops: &[Operand], op: Binop) {
        let (dst, src) = match ops {
            [a, b] => (a, b),
            _ => return,
        };
        let Operand::Reg { name, width } = dst else {
            return;
        };
        let lhs = self.read_operand(dst, *width);
        let rhs = self.read_operand(src, *width);
        let result = match (lhs, rhs) {
            (Some(l), Some(r)) => Some(self.dag.intern(op.to_expr(l, r))),
            (Some(l), None) | (None, Some(l)) => {
                // One side concrete: still symbolic propagation if
                // the other side has a concrete value we can fold in.
                let imm = match src {
                    Operand::Imm(v) => Some(*v),
                    _ => None,
                };
                imm.map(|v| {
                    let cv = self.dag.intern(Expr::BvConst {
                        value: v as u128,
                        bits: *width,
                    });
                    self.dag.intern(op.to_expr(l, cv))
                })
            }
            (None, None) => None,
        };
        let dst64 = self.widen_to_64(result, *width);
        self.write_reg64(name, dst64);
    }

    fn step_shift(&mut self, ops: &[Operand], shift: Shift) {
        let (dst, src) = match ops {
            [a, b] => (a, b),
            _ => return,
        };
        let Operand::Reg { name, width } = dst else {
            return;
        };
        let lhs = self.read_operand(dst, *width);
        let amount = match src {
            Operand::Imm(v) => Some(self.dag.intern(Expr::BvConst {
                value: (*v as u128) & ((1u128 << width) - 1).max(1),
                bits: *width,
            })),
            Operand::Reg { .. } => self.read_operand(src, *width),
            Operand::Mem { .. } => None,
        };
        let result = match (lhs, amount) {
            (Some(l), Some(a)) => Some(self.dag.intern(shift.to_expr(l, a))),
            _ => None,
        };
        let dst64 = self.widen_to_64(result, *width);
        self.write_reg64(name, dst64);
    }

    fn step_cmp(&mut self, ops: &[Operand], is_test: bool) {
        let (a, b) = match ops {
            [a, b] => (a, b),
            _ => return,
        };
        // Width: min of operand widths if both are non-mem; else max.
        let w = match (a.width(), b.width()) {
            (Some(wa), Some(wb)) => wa.min(wb).max(8),
            (Some(wa), None) => wa,
            (None, Some(wb)) => wb,
            (None, None) => 32,
        };
        let lhs = self.read_operand(a, w);
        let rhs = self.read_operand(b, w);
        // "Symbolic" means a Reg or Mem operand whose shadow read
        // returned Some. Pure-immediate operands always read as Some
        // (BvConst) but don't count toward "we have symbolic state."
        let lhs_symbolic = matches!(a, Operand::Reg { .. } | Operand::Mem { .. }) && lhs.is_some();
        let rhs_symbolic = matches!(b, Operand::Reg { .. } | Operand::Mem { .. }) && rhs.is_some();
        if !lhs_symbolic && !rhs_symbolic {
            self.last_cmp = None;
            return;
        }
        let lhs_n = lhs.unwrap_or_else(|| {
            let imm = literal_value(a).unwrap_or(0);
            self.dag.intern(Expr::BvConst {
                value: imm as u128,
                bits: w,
            })
        });
        let rhs_n = rhs.unwrap_or_else(|| {
            let imm = literal_value(b).unwrap_or(0);
            self.dag.intern(Expr::BvConst {
                value: imm as u128,
                bits: w,
            })
        });
        let (lhs_for_predicate, rhs_for_predicate) = if is_test {
            // test x, y  ≡  cmp (x & y), 0
            let anded = self.dag.intern(Expr::BvAnd(lhs_n, rhs_n));
            let zero = self.dag.intern(Expr::BvConst { value: 0, bits: w });
            (anded, zero)
        } else {
            (lhs_n, rhs_n)
        };
        self.last_cmp = Some(LastCompare {
            lhs: lhs_for_predicate,
            rhs: rhs_for_predicate,
            width: w,
            is_test,
        });
    }

    fn step_lea(&mut self, ops: &[Operand]) {
        let (dst, src) = match ops {
            [a, b] => (a, b),
            _ => return,
        };
        let Operand::Reg { name, .. } = dst else {
            return;
        };
        let Operand::Mem { base, disp, .. } = src else {
            return;
        };
        let base_node = match base.as_deref() {
            Some(b) => canonical_reg(b).and_then(|c| self.state.read_reg(c)),
            None => None,
        };
        let result = match base_node {
            Some(b) => {
                let d = self.dag.intern(Expr::BvConst {
                    value: ((*disp) as i64 as i128 as u128) & ((1u128 << 64) - 1),
                    bits: 64,
                });
                Some(self.dag.intern(Expr::BvAdd(b, d)))
            }
            None => None,
        };
        self.write_reg64(name, result);
    }

    // ──────────────────────────────────────────────────────────────────
    // helpers

    fn emit_branch_event(
        &mut self,
        site_va: u64,
        mnemonic: &str,
        rel: BranchRel,
    ) -> Option<BranchEventWithNodeIds> {
        let cmp = self.last_cmp?;
        let predicate = build_predicate(self.dag, rel, cmp.lhs, cmp.rhs);
        Some(BranchEventWithNodeIds {
            site_va,
            mnemonic: mnemonic.to_string(),
            predicate,
            width: cmp.width,
            last_cmp: cmp,
        })
    }

    fn read_operand(&mut self, op: &Operand, want_width: u32) -> Option<NodeId> {
        match op {
            Operand::Imm(v) => Some(self.dag.intern(Expr::BvConst {
                value: (*v as u128) & ((1u128 << want_width.min(127)) - 1).max(1),
                bits: want_width,
            })),
            Operand::Reg { name, width } => {
                let canon = canonical_reg(name)?;
                let full = self.state.read_reg(canon)?;
                Some(self.narrow_to(full, *width, want_width, name == "ah"))
            }
            Operand::Mem { base, disp, width } => {
                // Symbolic load from `[base+disp]`. Only the "input
                // region" convention is modeled; everything else falls
                // back to the shadow byte_map (concrete loads of
                // previously-symbolic stores).
                let read_width = (*width).min(want_width);
                let load = self.read_memory_region(base.as_deref(), *disp, read_width)?;
                Some(self.narrow_to(load, read_width, want_width, false))
            }
        }
    }

    fn read_memory_region(
        &mut self,
        base: Option<&str>,
        disp: i64,
        width_bits: u32,
    ) -> Option<NodeId> {
        if width_bits == 0 || width_bits % 8 != 0 {
            return None;
        }
        let byte_count = (width_bits / 8) as i64;
        let base_concrete = base
            .and_then(canonical_reg)
            .filter(|c| self.state.read_reg(c).is_none())
            .is_some()
            || base.is_none();
        let effective_addr = if base.is_none() {
            disp as u64
        } else {
            // Convention: when base reg is concrete (no symbolic shadow),
            // we treat the addr as `base_concrete_value + disp` where
            // `base_concrete_value` is the input_base when the addr
            // lands in the input region; otherwise we conservatively
            // assume the base equals input_base (the only thing the
            // shadow emulator can meaningfully model).
            self.input_base.wrapping_add(disp as u64)
        };
        if !base_concrete {
            return None;
        }
        if effective_addr >= self.input_base
            && effective_addr + (byte_count as u64) <= self.input_base + self.input_len as u64
        {
            // Read from symbolic input region.
            let offset = (effective_addr - self.input_base) as u32;
            Some(self.concat_input_bytes(offset, byte_count as u32))
        } else {
            // Check shadow byte_map for any prior symbolic stores.
            self.concat_shadow_bytes(effective_addr, byte_count as u32)
        }
    }

    fn concat_input_bytes(&mut self, start: u32, count: u32) -> NodeId {
        debug_assert!(count > 0);
        // x86 is little-endian: byte 0 is least significant.
        // Concat in expr.rs is left-high right-low, so we build
        // `Concat(b_n-1, Concat(b_n-2, ... b_0))`.
        let mut acc: Option<NodeId> = None;
        for i in 0..count {
            let byte_id = self.input_byte_var(start + i);
            acc = Some(match acc {
                None => byte_id,
                Some(low) => self.dag.intern(Expr::Concat(byte_id, low)),
            });
        }
        acc.expect("count >= 1")
    }

    fn concat_shadow_bytes(&mut self, addr: u64, count: u32) -> Option<NodeId> {
        // Only fully-symbolic regions count; if ANY byte is concrete,
        // give up (we'd need the concrete native value to splice it in
        // and the shadow layer doesn't see that).
        let mut acc: Option<NodeId> = None;
        for i in 0..count as u64 {
            let b = self.state.read_byte(addr + i)?;
            acc = Some(match acc {
                None => b,
                Some(low) => self.dag.intern(Expr::Concat(b, low)),
            });
        }
        acc
    }

    fn input_byte_var(&mut self, index: u32) -> NodeId {
        let name = format!("input_b{}", index);
        let sym: SymbolId = self.dag.intern_symbol(&name);
        self.dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        })
    }

    fn write_memory_region(
        &mut self,
        base: Option<String>,
        disp: i64,
        width_bits: u32,
        value: Option<NodeId>,
    ) {
        if width_bits == 0 || width_bits % 8 != 0 {
            return;
        }
        let byte_count = (width_bits / 8) as u64;
        // Same address-derivation convention as `read_memory_region`.
        let effective_addr = match base {
            Some(_) => self.input_base.wrapping_add(disp as u64),
            None => disp as u64,
        };
        for i in 0..byte_count {
            let byte_val = value.map(|v| {
                let lo = (i as u32) * 8;
                let hi = lo + 7;
                self.dag.intern(Expr::Extract { hi, lo, value: v })
            });
            self.state.write_byte(effective_addr + i, byte_val);
        }
    }

    fn write_reg64(&mut self, name_alias: &str, full: Option<NodeId>) {
        let canon = match canonical_reg(name_alias) {
            Some(c) => c,
            None => return,
        };
        self.state.write_reg(canon, full);
    }

    /// Zero/sign-extend (whichever fits the underlying value's sort)
    /// a sub-width Expr to 64 bits for storage in the canonical reg
    /// file. For widths that already are 64, returns the input.
    fn widen_to_64(&mut self, n: Option<NodeId>, width: u32) -> Option<NodeId> {
        let n = n?;
        if width >= 64 {
            return Some(n);
        }
        Some(self.dag.intern(Expr::ZeroExt {
            extra: 64 - width,
            value: n,
        }))
    }

    /// Extract a sub-width view of a 64-bit reg. `is_ah` toggles the
    /// special `[15:8]` slice for the legacy `ah`/`bh`/`ch`/`dh` regs.
    fn narrow_to(
        &mut self,
        full: NodeId,
        stored_width: u32,
        want_width: u32,
        is_ah: bool,
    ) -> NodeId {
        let _ = stored_width;
        if is_ah {
            return self.dag.intern(Expr::Extract {
                hi: 15,
                lo: 8,
                value: full,
            });
        }
        if want_width >= 64 {
            return full;
        }
        self.dag.intern(Expr::Extract {
            hi: want_width - 1,
            lo: 0,
            value: full,
        })
    }
}

// ──────────────────────────────────────────────────────────────────────
// operand parser

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    Reg {
        name: String,
        width: u32,
    },
    Imm(u64),
    Mem {
        base: Option<String>,
        disp: i64,
        width: u32,
    },
}

impl Operand {
    fn width(&self) -> Option<u32> {
        match self {
            Operand::Reg { width, .. } => Some(*width),
            Operand::Imm(_) => None,
            Operand::Mem { width, .. } => Some(*width),
        }
    }
}

fn literal_value(o: &Operand) -> Option<u64> {
    match o {
        Operand::Imm(v) => Some(*v),
        _ => None,
    }
}

/// Parse an iced-x86-style operand string into a `Vec<Operand>`.
/// Handles `reg`, `imm`, `[reg+disp]`, and `<width> ptr [reg+disp]`.
/// Unrecognized operands yield concretized placeholders (Operand::Imm(0))
/// so the caller can detect them via `read_operand`'s `None` return.
pub fn parse_operands(s: &str) -> Vec<Operand> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'[' => depth += 1,
            b']' => depth -= 1,
            b',' if depth == 0 => {
                out.push(parse_single_operand(&s[start..i]));
                start = i + 1;
            }
            _ => {}
        }
    }
    if start <= s.len() {
        let last = s[start..].trim();
        if !last.is_empty() {
            out.push(parse_single_operand(last));
        }
    }
    out
}

fn parse_single_operand(raw: &str) -> Operand {
    let s = raw.trim();
    // Width-ptr prefix?
    let (width_hint, rest) = strip_width_prefix(s);
    let s = rest.trim();

    if let Some(stripped) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        let (base, disp) = parse_addr_inner(stripped);
        return Operand::Mem {
            base,
            disp,
            width: width_hint.unwrap_or(64),
        };
    }
    if let Some(w) = register_width(s) {
        return Operand::Reg {
            name: s.to_ascii_lowercase(),
            width: w,
        };
    }
    if let Some(v) = parse_int_like(s) {
        return Operand::Imm(v);
    }
    // Unknown shape: encode as a 0 immediate so the caller's
    // `read_operand` returns the literal-0 path and the caller can
    // skip the instruction cleanly.
    Operand::Imm(0)
}

fn parse_addr_inner(s: &str) -> (Option<String>, i64) {
    let s = s.trim();
    // Strip `rel` keyword if present (e.g. `rel 0x1000`).
    let s = s.strip_prefix("rel ").unwrap_or(s).trim();
    // Split on + or - keeping the sign of the disp.
    let (left, sign, right) = split_addr_terms(s);
    let base = if !left.is_empty() && register_width(left).is_some() {
        Some(left.to_ascii_lowercase())
    } else {
        None
    };
    let disp = match right {
        Some(r) => {
            let mag = parse_int_like(r).unwrap_or(0) as i64;
            if sign == '-' {
                -mag
            } else {
                mag
            }
        }
        None => {
            // Whole expression might be just a literal (no base).
            if base.is_none() {
                parse_int_like(left).unwrap_or(0) as i64
            } else {
                0
            }
        }
    };
    (base, disp)
}

fn split_addr_terms(s: &str) -> (&str, char, Option<&str>) {
    let bytes = s.as_bytes();
    for i in 1..bytes.len() {
        match bytes[i] {
            b'+' => return (s[..i].trim(), '+', Some(s[i + 1..].trim())),
            b'-' => return (s[..i].trim(), '-', Some(s[i + 1..].trim())),
            _ => {}
        }
    }
    (s.trim(), '+', None)
}

fn strip_width_prefix(s: &str) -> (Option<u32>, &str) {
    let lower_chunks: Vec<&str> = s.splitn(3, ' ').collect();
    if lower_chunks.len() >= 3 && lower_chunks[1].eq_ignore_ascii_case("ptr") {
        let w = match lower_chunks[0].to_ascii_lowercase().as_str() {
            "byte" => Some(8),
            "word" => Some(16),
            "dword" => Some(32),
            "qword" => Some(64),
            _ => None,
        };
        if w.is_some() {
            return (
                w,
                &s[lower_chunks[0].len() + 1 + lower_chunks[1].len() + 1..],
            );
        }
    }
    (None, s)
}

fn parse_int_like(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        return u64::from_str_radix(rest, 16).ok();
    }
    if let Some(rest) = s.strip_prefix('-') {
        return rest.parse::<i64>().ok().map(|v| (-v) as u64);
    }
    s.parse::<u64>().ok()
}

/// Returns the width-in-bits of a recognized x86-64 GPR alias, or
/// `None` for unknown names.
pub fn register_width(name: &str) -> Option<u32> {
    let s = name.to_ascii_lowercase();
    match s.as_str() {
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rsp" | "rbp" | "r8" | "r9" | "r10"
        | "r11" | "r12" | "r13" | "r14" | "r15" => Some(64),
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "esp" | "ebp" | "r8d" | "r9d" | "r10d"
        | "r11d" | "r12d" | "r13d" | "r14d" | "r15d" => Some(32),
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "sp" | "bp" | "r8w" | "r9w" | "r10w" | "r11w"
        | "r12w" | "r13w" | "r14w" | "r15w" => Some(16),
        "al" | "bl" | "cl" | "dl" | "sil" | "dil" | "spl" | "bpl" | "r8b" | "r9b" | "r10b"
        | "r11b" | "r12b" | "r13b" | "r14b" | "r15b" | "ah" | "bh" | "ch" | "dh" => Some(8),
        _ => None,
    }
}

/// Normalize a sub-register alias to its 64-bit canonical name. Used
/// by [`ShadowState::read_reg`]/`write_reg`.
pub fn canonical_reg(name: &str) -> Option<&'static str> {
    let s = name.to_ascii_lowercase();
    Some(match s.as_str() {
        "rax" | "eax" | "ax" | "ah" | "al" => "rax",
        "rbx" | "ebx" | "bx" | "bh" | "bl" => "rbx",
        "rcx" | "ecx" | "cx" | "ch" | "cl" => "rcx",
        "rdx" | "edx" | "dx" | "dh" | "dl" => "rdx",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" => "r15",
        _ => return None,
    })
}

// ──────────────────────────────────────────────────────────────────────
// internal helpers for binop / shift dispatch

#[derive(Clone, Copy)]
enum Binop {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
}

impl Binop {
    fn to_expr(self, l: NodeId, r: NodeId) -> Expr {
        match self {
            Binop::Add => Expr::BvAdd(l, r),
            Binop::Sub => Expr::BvSub(l, r),
            Binop::Mul => Expr::BvMul(l, r),
            Binop::And => Expr::BvAnd(l, r),
            Binop::Or => Expr::BvOr(l, r),
            Binop::Xor => Expr::BvXor(l, r),
        }
    }
}

#[derive(Clone, Copy)]
enum Shift {
    Shl,
    Lshr,
    Ashr,
}

impl Shift {
    fn to_expr(self, l: NodeId, r: NodeId) -> Expr {
        match self {
            Shift::Shl => Expr::BvShl(l, r),
            Shift::Lshr => Expr::BvLShr(l, r),
            Shift::Ashr => Expr::BvAShr(l, r),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum BranchRel {
    Eq,
    Ne,
    UGt,
    UGe,
    ULt,
    ULe,
    SGt,
    SGe,
    SLt,
    SLe,
}

fn relation_for_branch(mnemonic: &str) -> Option<BranchRel> {
    Some(match mnemonic {
        "je" | "jz" => BranchRel::Eq,
        "jne" | "jnz" => BranchRel::Ne,
        "ja" | "jnbe" => BranchRel::UGt,
        "jae" | "jnb" | "jnc" => BranchRel::UGe,
        "jb" | "jc" | "jnae" => BranchRel::ULt,
        "jbe" | "jna" => BranchRel::ULe,
        "jg" | "jnle" => BranchRel::SGt,
        "jge" | "jnl" => BranchRel::SGe,
        "jl" | "jnge" => BranchRel::SLt,
        "jle" | "jng" => BranchRel::SLe,
        _ => return None,
    })
}

fn build_predicate(dag: &mut ExprDag, rel: BranchRel, lhs: NodeId, rhs: NodeId) -> NodeId {
    match rel {
        BranchRel::Eq => dag.intern(Expr::Eq(lhs, rhs)),
        BranchRel::Ne => {
            let eq = dag.intern(Expr::Eq(lhs, rhs));
            dag.intern(Expr::Not(eq))
        }
        BranchRel::UGt => {
            let ule = dag.intern(Expr::Ule(lhs, rhs));
            dag.intern(Expr::Not(ule))
        }
        BranchRel::UGe => {
            let ult = dag.intern(Expr::Ult(lhs, rhs));
            dag.intern(Expr::Not(ult))
        }
        BranchRel::ULt => dag.intern(Expr::Ult(lhs, rhs)),
        BranchRel::ULe => dag.intern(Expr::Ule(lhs, rhs)),
        BranchRel::SGt => {
            let sle = dag.intern(Expr::Sle(lhs, rhs));
            dag.intern(Expr::Not(sle))
        }
        BranchRel::SGe => {
            let slt = dag.intern(Expr::Slt(lhs, rhs));
            dag.intern(Expr::Not(slt))
        }
        BranchRel::SLt => dag.intern(Expr::Slt(lhs, rhs)),
        BranchRel::SLe => dag.intern(Expr::Sle(lhs, rhs)),
    }
}

// ──────────────────────────────────────────────────────────────────────
// tests

#[cfg(test)]
mod tests {
    use super::*;

    fn ir(addr: u64, mnemonic: &str, op_str: &str) -> InstructionRecord {
        InstructionRecord {
            address: addr,
            size: 0,
            mnemonic: mnemonic.to_string(),
            op_str: op_str.to_string(),
            section: String::new(),
            groups: Vec::new(),
            is_call: false,
            is_jump: false,
            is_ret: false,
            branch_target: None,
        }
    }

    #[test]
    fn parse_simple_reg_imm() {
        let ops = parse_operands("rax, 0x40");
        assert_eq!(
            ops,
            vec![
                Operand::Reg {
                    name: "rax".into(),
                    width: 64
                },
                Operand::Imm(0x40),
            ]
        );
    }

    #[test]
    fn parse_mem_with_width_prefix() {
        let ops = parse_operands("eax, dword ptr [rdi+0x10]");
        assert_eq!(
            ops,
            vec![
                Operand::Reg {
                    name: "eax".into(),
                    width: 32
                },
                Operand::Mem {
                    base: Some("rdi".into()),
                    disp: 0x10,
                    width: 32
                },
            ]
        );
    }

    #[test]
    fn parse_mem_with_negative_disp() {
        let ops = parse_operands("rax, qword ptr [rbp-8]");
        assert_eq!(
            ops,
            vec![
                Operand::Reg {
                    name: "rax".into(),
                    width: 64
                },
                Operand::Mem {
                    base: Some("rbp".into()),
                    disp: -8,
                    width: 64
                },
            ]
        );
    }

    #[test]
    fn parse_bare_mem_no_disp() {
        let ops = parse_operands("rcx, qword ptr [rdi]");
        assert_eq!(
            ops[1],
            Operand::Mem {
                base: Some("rdi".into()),
                disp: 0,
                width: 64
            }
        );
    }

    #[test]
    fn canonical_reg_normalizes_subregister_aliases() {
        assert_eq!(canonical_reg("eax"), Some("rax"));
        assert_eq!(canonical_reg("r10d"), Some("r10"));
        assert_eq!(canonical_reg("ah"), Some("rax"));
        assert_eq!(canonical_reg("xmm0"), None);
    }

    #[test]
    fn elf_magic_check_produces_branch_event() {
        // Synthesize: mov eax, dword ptr [rdi+0x10]; cmp eax, 0x7F454C46; je .
        let mut dag = ExprDag::new();
        let mut em = ShadowEmulator::new(&mut dag, 0x10000010, 128);
        // input_base + 0 corresponds to the byte at [rdi+0x10] because
        // the shadow convention shifts the effective addr to input_base.
        em.step_instruction(&ir(0x1000, "mov", "eax, dword ptr [rdi+0x10]"));
        em.step_instruction(&ir(0x1004, "cmp", "eax, 0x7F454C46"));
        // The cmp should populate last_cmp.
        let cmp = em.last_compare().expect("cmp should populate last_compare");
        assert_eq!(cmp.width, 32, "cmp eax uses 32-bit width");
        // The je should emit a branch event.
        let evt = em
            .step_instruction(&ir(0x1009, "je", "0x2000"))
            .expect("je after symbolic cmp must emit branch event");
        assert_eq!(evt.mnemonic, "je");
        // Predicate is an Eq node.
        assert!(matches!(em.dag.get(evt.predicate), Expr::Eq(_, _)));
    }

    #[test]
    fn unsupported_instruction_concretizes_destination() {
        let mut dag = ExprDag::new();
        let mut em = ShadowEmulator::new(&mut dag, 0, 0);
        // First make rax symbolic by faking a mov from input.
        let sym = em.dag.intern_symbol("input_b0");
        let var = em.dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        em.state.write_reg("rax", Some(var));
        assert!(em.state.read_reg("rax").is_some());
        // Step an unsupported instruction that targets rax.
        em.step_instruction(&ir(0x1000, "bswap", "rax"));
        assert!(em.state.read_reg("rax").is_none(), "rax must concretize");
        assert!(em.state.concretization_events >= 1);
    }

    #[test]
    fn cmp_without_symbolic_operands_does_not_set_last_compare() {
        let mut dag = ExprDag::new();
        let mut em = ShadowEmulator::new(&mut dag, 0, 0);
        em.step_instruction(&ir(0x1000, "cmp", "rax, 0x10"));
        assert!(em.last_compare().is_none());
    }

    #[test]
    fn shl_propagates_symbolic_state() {
        let mut dag = ExprDag::new();
        let mut em = ShadowEmulator::new(&mut dag, 0, 8);
        em.step_instruction(&ir(0x1000, "mov", "rax, qword ptr [rdi]"));
        em.step_instruction(&ir(0x1004, "shl", "rax, 8"));
        let v = em.state.read_reg("rax").expect("rax remains symbolic");
        assert!(matches!(
            em.dag.get(v),
            Expr::ZeroExt { .. } | Expr::BvShl(..)
        ));
    }

    #[test]
    fn test_instruction_synthesizes_and_zero_compare() {
        let mut dag = ExprDag::new();
        let mut em = ShadowEmulator::new(&mut dag, 0, 8);
        em.step_instruction(&ir(0x1000, "mov", "rax, qword ptr [rdi]"));
        em.step_instruction(&ir(0x1004, "test", "rax, rax"));
        let cmp = em.last_compare().expect("test populates last_compare");
        assert!(cmp.is_test);
        // RHS of the synthesized compare is the zero constant.
        match em.dag.get(cmp.rhs) {
            Expr::BvConst { value: 0, .. } => {}
            other => panic!("rhs must be BvConst(0), got {other:?}"),
        }
    }

    #[test]
    fn mov_reg_reg_propagates_shadow() {
        let mut dag = ExprDag::new();
        let mut em = ShadowEmulator::new(&mut dag, 0, 8);
        em.step_instruction(&ir(0x1000, "mov", "rax, qword ptr [rdi]"));
        em.step_instruction(&ir(0x1004, "mov", "rcx, rax"));
        assert!(em.state.read_reg("rcx").is_some());
    }
}
