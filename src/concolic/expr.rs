//! Canonical hash-consed `Expr` DAG for the symbolic IR.
//!
//! Independent of any specific SMT backend. The shadow emulator
//! (`src/concolic/shadow_emulator.rs`, step 4) interns Expr nodes per
//! register and memory byte; the SMT backends (`z3_backend.rs`,
//! `smt2_backend.rs`) lower them into Z3 ASTs.
//!
//! Discipline: **never silently coerce bit widths**. Every BV binop
//! requires matching operand widths; type-check via [`ExprDag::validate`]
//! before lowering or after any DAG mutation.

#![allow(dead_code)]

use std::collections::BTreeMap;

use rustc_hash::FxHashMap;

/// Index into [`ExprDag::nodes`]. `u32` keeps `Expr` cheap to hash.
pub type NodeId = u32;

/// Interned identifier for a variable name.
pub type SymbolId = u32;

/// Stable step-1 placeholder for the `Expr` variant set. Real
/// variants land in step 2; step 1 only needs the type to exist so
/// the module compiles.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Sort {
    Bool,
    Bv(u32),
    Array { index_bits: u32, value_bits: u32 },
}

/// Canonical symbolic-expression variants.
///
/// Step 1 ships the full enum so downstream modules compile against
/// the final shape. Validation rules live in [`ExprDag::validate`];
/// each variant's width semantics are documented inline.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Expr {
    /// `name` is a [`SymbolId`] interned in `ExprDag::symbols`.
    Var {
        name: SymbolId,
        sort: Sort,
    },
    BvConst {
        value: u128,
        bits: u32,
    },
    BoolConst(bool),

    Not(NodeId),
    And(Vec<NodeId>),
    Or(Vec<NodeId>),
    Eq(NodeId, NodeId),

    BvAdd(NodeId, NodeId),
    BvSub(NodeId, NodeId),
    BvMul(NodeId, NodeId),
    BvAnd(NodeId, NodeId),
    BvOr(NodeId, NodeId),
    BvXor(NodeId, NodeId),
    BvShl(NodeId, NodeId),
    BvLShr(NodeId, NodeId),
    BvAShr(NodeId, NodeId),

    Ult(NodeId, NodeId),
    Ule(NodeId, NodeId),
    Slt(NodeId, NodeId),
    Sle(NodeId, NodeId),

    Extract {
        hi: u32,
        lo: u32,
        value: NodeId,
    },
    Concat(NodeId, NodeId),
    ZeroExt {
        extra: u32,
        value: NodeId,
    },
    SignExt {
        extra: u32,
        value: NodeId,
    },

    Ite {
        cond: NodeId,
        then_id: NodeId,
        else_id: NodeId,
    },

    Load8 {
        mem: NodeId,
        addr: NodeId,
    },
    Store8 {
        mem: NodeId,
        addr: NodeId,
        value: NodeId,
    },
}

/// Type-error returned by [`ExprDag::validate`].
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TypeError {
    #[error("BV binop '{op}' operand width mismatch: lhs={lhs}, rhs={rhs}")]
    WidthMismatch {
        op: &'static str,
        lhs: u32,
        rhs: u32,
    },
    #[error("Extract bounds out of range: hi={hi}, lo={lo}, value width={width}")]
    BadExtractBounds { hi: u32, lo: u32, width: u32 },
    #[error("Sort mismatch on {op}: expected {expected:?}, got {got:?}")]
    SortMismatch {
        op: &'static str,
        expected: Sort,
        got: Sort,
    },
    #[error("Array value width must be 8, got {got}")]
    ArrayValueWidth { got: u32 },
    #[error("BvConst value 0x{value:x} does not fit in {bits} bits")]
    BvConstOverflow { value: u128, bits: u32 },
    #[error("invalid NodeId {0} (out of range)")]
    InvalidNodeId(NodeId),
}

/// Hash-consed Expr DAG.
///
/// Interning: identical sub-expressions get the same NodeId, so the
/// DAG is by construction structurally shared and the let-binding
/// pass in `smt2_emit.rs` (step 7) can detect shared subexpressions
/// via simple reference counting.
pub struct ExprDag {
    nodes: Vec<Expr>,
    index: FxHashMap<Expr, NodeId>,
    symbols: Vec<String>,
    symbol_index: FxHashMap<String, SymbolId>,
}

impl ExprDag {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            index: FxHashMap::default(),
            symbols: Vec::new(),
            symbol_index: FxHashMap::default(),
        }
    }

    /// Intern an `Expr`; returns the existing NodeId if the same
    /// expression has been seen before.
    pub fn intern(&mut self, e: Expr) -> NodeId {
        if let Some(&id) = self.index.get(&e) {
            return id;
        }
        let id = self.nodes.len() as NodeId;
        self.nodes.push(e.clone());
        self.index.insert(e, id);
        id
    }

    /// Intern a string symbol name. Returns the existing SymbolId
    /// if the name has been seen before.
    pub fn intern_symbol(&mut self, name: &str) -> SymbolId {
        if let Some(&id) = self.symbol_index.get(name) {
            return id;
        }
        let id = self.symbols.len() as SymbolId;
        self.symbols.push(name.to_string());
        self.symbol_index.insert(name.to_string(), id);
        id
    }

    pub fn get(&self, id: NodeId) -> &Expr {
        &self.nodes[id as usize]
    }

    pub fn try_get(&self, id: NodeId) -> Option<&Expr> {
        self.nodes.get(id as usize)
    }

    pub fn symbol_name(&self, id: SymbolId) -> &str {
        &self.symbols[id as usize]
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Compute the `Sort` of a node by walking the DAG. Returns
    /// `None` for invalid NodeIds. Does NOT validate consistency —
    /// use [`validate`] for that.
    pub fn sort_of(&self, id: NodeId) -> Option<Sort> {
        let e = self.try_get(id)?;
        Some(match e {
            Expr::Var { sort, .. } => *sort,
            Expr::BvConst { bits, .. } => Sort::Bv(*bits),
            Expr::BoolConst(_) => Sort::Bool,
            Expr::Not(_) | Expr::And(_) | Expr::Or(_) | Expr::Eq(..) => Sort::Bool,
            Expr::Ult(..) | Expr::Ule(..) | Expr::Slt(..) | Expr::Sle(..) => Sort::Bool,
            Expr::BvAdd(a, _)
            | Expr::BvSub(a, _)
            | Expr::BvMul(a, _)
            | Expr::BvAnd(a, _)
            | Expr::BvOr(a, _)
            | Expr::BvXor(a, _)
            | Expr::BvShl(a, _)
            | Expr::BvLShr(a, _)
            | Expr::BvAShr(a, _) => self.sort_of(*a)?,
            Expr::Extract { hi, lo, .. } => Sort::Bv(hi - lo + 1),
            Expr::Concat(a, b) => {
                let wa = bv_width(self.sort_of(*a)?)?;
                let wb = bv_width(self.sort_of(*b)?)?;
                Sort::Bv(wa + wb)
            }
            Expr::ZeroExt { extra, value } | Expr::SignExt { extra, value } => {
                let wv = bv_width(self.sort_of(*value)?)?;
                Sort::Bv(wv + extra)
            }
            Expr::Ite { then_id, .. } => self.sort_of(*then_id)?,
            Expr::Load8 { .. } => Sort::Bv(8),
            Expr::Store8 { mem, .. } => self.sort_of(*mem)?,
        })
    }

    /// Validate that every BV binop has matching operand widths,
    /// every `Extract` is in range, every `Concat` widths sum
    /// correctly, etc. Walks the DAG with a visited guard to avoid
    /// quadratic re-traversal of shared subexpressions.
    pub fn validate(&self, root: NodeId) -> Result<(), TypeError> {
        let mut visited: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
        self.validate_node(root, &mut visited)
    }

    fn validate_node(
        &self,
        id: NodeId,
        visited: &mut std::collections::HashSet<NodeId>,
    ) -> Result<(), TypeError> {
        if !visited.insert(id) {
            return Ok(());
        }
        let e = self.try_get(id).ok_or(TypeError::InvalidNodeId(id))?;
        match e {
            Expr::Var { .. } | Expr::BoolConst(_) => Ok(()),
            Expr::BvConst { value, bits } => {
                if *bits == 0 || *bits > 128 {
                    return Err(TypeError::BvConstOverflow {
                        value: *value,
                        bits: *bits,
                    });
                }
                if *bits < 128 && *value >= (1u128 << *bits) {
                    return Err(TypeError::BvConstOverflow {
                        value: *value,
                        bits: *bits,
                    });
                }
                Ok(())
            }
            Expr::Not(a) => {
                self.validate_node(*a, visited)?;
                self.expect_sort(*a, Sort::Bool, "not")
            }
            Expr::And(children) | Expr::Or(children) => {
                for &c in children {
                    self.validate_node(c, visited)?;
                    self.expect_sort(c, Sort::Bool, "and/or")?;
                }
                Ok(())
            }
            Expr::Eq(a, b) => {
                self.validate_node(*a, visited)?;
                self.validate_node(*b, visited)?;
                let sa = self.sort_of(*a).ok_or(TypeError::InvalidNodeId(*a))?;
                let sb = self.sort_of(*b).ok_or(TypeError::InvalidNodeId(*b))?;
                if sa != sb {
                    return Err(TypeError::SortMismatch {
                        op: "eq",
                        expected: sa,
                        got: sb,
                    });
                }
                Ok(())
            }
            Expr::BvAdd(a, b)
            | Expr::BvSub(a, b)
            | Expr::BvMul(a, b)
            | Expr::BvAnd(a, b)
            | Expr::BvOr(a, b)
            | Expr::BvXor(a, b)
            | Expr::BvShl(a, b)
            | Expr::BvLShr(a, b)
            | Expr::BvAShr(a, b) => {
                self.validate_node(*a, visited)?;
                self.validate_node(*b, visited)?;
                let wa = bv_width(self.sort_of(*a).ok_or(TypeError::InvalidNodeId(*a))?).ok_or(
                    TypeError::SortMismatch {
                        op: bv_op_name(e),
                        expected: Sort::Bv(0),
                        got: Sort::Bool,
                    },
                )?;
                let wb = bv_width(self.sort_of(*b).ok_or(TypeError::InvalidNodeId(*b))?).ok_or(
                    TypeError::SortMismatch {
                        op: bv_op_name(e),
                        expected: Sort::Bv(0),
                        got: Sort::Bool,
                    },
                )?;
                if wa != wb {
                    return Err(TypeError::WidthMismatch {
                        op: bv_op_name(e),
                        lhs: wa,
                        rhs: wb,
                    });
                }
                Ok(())
            }
            Expr::Ult(a, b) | Expr::Ule(a, b) | Expr::Slt(a, b) | Expr::Sle(a, b) => {
                self.validate_node(*a, visited)?;
                self.validate_node(*b, visited)?;
                let wa = bv_width(self.sort_of(*a).ok_or(TypeError::InvalidNodeId(*a))?).ok_or(
                    TypeError::SortMismatch {
                        op: "bv_cmp",
                        expected: Sort::Bv(0),
                        got: Sort::Bool,
                    },
                )?;
                let wb = bv_width(self.sort_of(*b).ok_or(TypeError::InvalidNodeId(*b))?).ok_or(
                    TypeError::SortMismatch {
                        op: "bv_cmp",
                        expected: Sort::Bv(0),
                        got: Sort::Bool,
                    },
                )?;
                if wa != wb {
                    return Err(TypeError::WidthMismatch {
                        op: "bv_cmp",
                        lhs: wa,
                        rhs: wb,
                    });
                }
                Ok(())
            }
            Expr::Extract { hi, lo, value } => {
                self.validate_node(*value, visited)?;
                let w = bv_width(
                    self.sort_of(*value)
                        .ok_or(TypeError::InvalidNodeId(*value))?,
                )
                .ok_or(TypeError::SortMismatch {
                    op: "extract",
                    expected: Sort::Bv(0),
                    got: Sort::Bool,
                })?;
                if hi < lo || *hi >= w {
                    return Err(TypeError::BadExtractBounds {
                        hi: *hi,
                        lo: *lo,
                        width: w,
                    });
                }
                Ok(())
            }
            Expr::Concat(a, b) => {
                self.validate_node(*a, visited)?;
                self.validate_node(*b, visited)?;
                // Both must be BVs; widths sum.
                bv_width(self.sort_of(*a).ok_or(TypeError::InvalidNodeId(*a))?).ok_or(
                    TypeError::SortMismatch {
                        op: "concat",
                        expected: Sort::Bv(0),
                        got: Sort::Bool,
                    },
                )?;
                bv_width(self.sort_of(*b).ok_or(TypeError::InvalidNodeId(*b))?).ok_or(
                    TypeError::SortMismatch {
                        op: "concat",
                        expected: Sort::Bv(0),
                        got: Sort::Bool,
                    },
                )?;
                Ok(())
            }
            Expr::ZeroExt { value, .. } | Expr::SignExt { value, .. } => {
                self.validate_node(*value, visited)?;
                bv_width(
                    self.sort_of(*value)
                        .ok_or(TypeError::InvalidNodeId(*value))?,
                )
                .ok_or(TypeError::SortMismatch {
                    op: "ext",
                    expected: Sort::Bv(0),
                    got: Sort::Bool,
                })?;
                Ok(())
            }
            Expr::Ite {
                cond,
                then_id,
                else_id,
            } => {
                self.validate_node(*cond, visited)?;
                self.validate_node(*then_id, visited)?;
                self.validate_node(*else_id, visited)?;
                self.expect_sort(*cond, Sort::Bool, "ite-cond")?;
                let st = self
                    .sort_of(*then_id)
                    .ok_or(TypeError::InvalidNodeId(*then_id))?;
                let se = self
                    .sort_of(*else_id)
                    .ok_or(TypeError::InvalidNodeId(*else_id))?;
                if st != se {
                    return Err(TypeError::SortMismatch {
                        op: "ite",
                        expected: st,
                        got: se,
                    });
                }
                Ok(())
            }
            Expr::Load8 { mem, addr } => {
                self.validate_node(*mem, visited)?;
                self.validate_node(*addr, visited)?;
                let sm = self.sort_of(*mem).ok_or(TypeError::InvalidNodeId(*mem))?;
                let Sort::Array { value_bits, .. } = sm else {
                    return Err(TypeError::SortMismatch {
                        op: "load8",
                        expected: Sort::Array {
                            index_bits: 64,
                            value_bits: 8,
                        },
                        got: sm,
                    });
                };
                if value_bits != 8 {
                    return Err(TypeError::ArrayValueWidth { got: value_bits });
                }
                Ok(())
            }
            Expr::Store8 { mem, addr, value } => {
                self.validate_node(*mem, visited)?;
                self.validate_node(*addr, visited)?;
                self.validate_node(*value, visited)?;
                let sm = self.sort_of(*mem).ok_or(TypeError::InvalidNodeId(*mem))?;
                let Sort::Array { value_bits, .. } = sm else {
                    return Err(TypeError::SortMismatch {
                        op: "store8",
                        expected: Sort::Array {
                            index_bits: 64,
                            value_bits: 8,
                        },
                        got: sm,
                    });
                };
                if value_bits != 8 {
                    return Err(TypeError::ArrayValueWidth { got: value_bits });
                }
                let sv = self
                    .sort_of(*value)
                    .ok_or(TypeError::InvalidNodeId(*value))?;
                if bv_width(sv) != Some(8) {
                    return Err(TypeError::SortMismatch {
                        op: "store8-value",
                        expected: Sort::Bv(8),
                        got: sv,
                    });
                }
                Ok(())
            }
        }
    }

    fn expect_sort(&self, id: NodeId, expected: Sort, op: &'static str) -> Result<(), TypeError> {
        let got = self.sort_of(id).ok_or(TypeError::InvalidNodeId(id))?;
        if got == expected {
            Ok(())
        } else {
            Err(TypeError::SortMismatch { op, expected, got })
        }
    }
}

impl Default for ExprDag {
    fn default() -> Self {
        Self::new()
    }
}

fn bv_width(s: Sort) -> Option<u32> {
    match s {
        Sort::Bv(w) => Some(w),
        _ => None,
    }
}

fn bv_op_name(e: &Expr) -> &'static str {
    match e {
        Expr::BvAdd(..) => "bvadd",
        Expr::BvSub(..) => "bvsub",
        Expr::BvMul(..) => "bvmul",
        Expr::BvAnd(..) => "bvand",
        Expr::BvOr(..) => "bvor",
        Expr::BvXor(..) => "bvxor",
        Expr::BvShl(..) => "bvshl",
        Expr::BvLShr(..) => "bvlshr",
        Expr::BvAShr(..) => "bvashr",
        _ => "bv_op",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_dedups() {
        let mut d = ExprDag::new();
        let a = d.intern(Expr::BvConst { value: 1, bits: 8 });
        let b = d.intern(Expr::BvConst { value: 1, bits: 8 });
        assert_eq!(a, b);
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn distinct_consts_get_distinct_ids() {
        let mut d = ExprDag::new();
        let a = d.intern(Expr::BvConst { value: 1, bits: 8 });
        let b = d.intern(Expr::BvConst { value: 2, bits: 8 });
        assert_ne!(a, b);
    }

    #[test]
    fn symbol_interning_dedups() {
        let mut d = ExprDag::new();
        let a = d.intern_symbol("input_b0");
        let b = d.intern_symbol("input_b0");
        let c = d.intern_symbol("input_b1");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(d.symbol_name(a), "input_b0");
    }

    #[test]
    fn sort_of_bv_const() {
        let mut d = ExprDag::new();
        let n = d.intern(Expr::BvConst {
            value: 0xff,
            bits: 8,
        });
        assert_eq!(d.sort_of(n), Some(Sort::Bv(8)));
    }

    #[test]
    fn sort_of_concat_sums_widths() {
        let mut d = ExprDag::new();
        let a = d.intern(Expr::BvConst {
            value: 0xab,
            bits: 8,
        });
        let b = d.intern(Expr::BvConst {
            value: 0xcd,
            bits: 16,
        });
        let cc = d.intern(Expr::Concat(a, b));
        assert_eq!(d.sort_of(cc), Some(Sort::Bv(24)));
    }

    #[test]
    fn sort_of_extract_uses_bound_range() {
        let mut d = ExprDag::new();
        let v = d.intern(Expr::BvConst {
            value: 0x1234_5678,
            bits: 32,
        });
        let ex = d.intern(Expr::Extract {
            hi: 15,
            lo: 0,
            value: v,
        });
        assert_eq!(d.sort_of(ex), Some(Sort::Bv(16)));
    }

    #[test]
    fn validate_accepts_matching_bv_widths() {
        let mut d = ExprDag::new();
        let a = d.intern(Expr::BvConst { value: 1, bits: 32 });
        let b = d.intern(Expr::BvConst { value: 2, bits: 32 });
        let add = d.intern(Expr::BvAdd(a, b));
        assert!(d.validate(add).is_ok());
    }

    #[test]
    fn validate_rejects_mismatched_bv_widths() {
        let mut d = ExprDag::new();
        let a = d.intern(Expr::BvConst { value: 1, bits: 32 });
        let b = d.intern(Expr::BvConst { value: 2, bits: 64 });
        let add = d.intern(Expr::BvAdd(a, b));
        let err = d.validate(add).unwrap_err();
        assert!(matches!(
            err,
            TypeError::WidthMismatch {
                op: "bvadd",
                lhs: 32,
                rhs: 64
            }
        ));
    }

    #[test]
    fn validate_rejects_out_of_range_extract() {
        let mut d = ExprDag::new();
        let v = d.intern(Expr::BvConst { value: 0, bits: 16 });
        let ex = d.intern(Expr::Extract {
            hi: 31,
            lo: 0,
            value: v,
        });
        let err = d.validate(ex).unwrap_err();
        assert!(matches!(
            err,
            TypeError::BadExtractBounds {
                hi: 31,
                lo: 0,
                width: 16
            }
        ));
    }

    #[test]
    fn validate_rejects_eq_with_sort_mismatch() {
        let mut d = ExprDag::new();
        let a = d.intern(Expr::BvConst { value: 1, bits: 8 });
        let b = d.intern(Expr::BoolConst(true));
        let eq = d.intern(Expr::Eq(a, b));
        let err = d.validate(eq).unwrap_err();
        assert!(matches!(err, TypeError::SortMismatch { op: "eq", .. }));
    }

    #[test]
    fn validate_rejects_overflowing_bv_const() {
        let mut d = ExprDag::new();
        let n = d.intern(Expr::BvConst {
            value: 0xff_ff,
            bits: 8,
        });
        let err = d.validate(n).unwrap_err();
        assert!(matches!(err, TypeError::BvConstOverflow { .. }));
    }

    #[test]
    fn validate_accepts_zero_ext() {
        let mut d = ExprDag::new();
        let v = d.intern(Expr::BvConst {
            value: 0xff,
            bits: 8,
        });
        let ze = d.intern(Expr::ZeroExt {
            extra: 24,
            value: v,
        });
        assert!(d.validate(ze).is_ok());
        assert_eq!(d.sort_of(ze), Some(Sort::Bv(32)));
    }

    /// Suppress an unused warning so the `BTreeMap` import (placeholder
    /// for future memory model) doesn't produce noise.
    #[test]
    fn placeholder_for_future_memory_model() {
        let _: BTreeMap<u64, NodeId> = BTreeMap::new();
    }
}
