//! Expr DAG → Z3 AST lowering (gated behind `concolic-z3-inproc`).
//!
//! This module exists only when the `concolic-z3-inproc` feature is
//! enabled. It needs the `z3` Rust crate (which in turn needs
//! libclang + Z3 headers at build time — see Cargo.toml for the
//! opt-in story).
//!
//! [`Z3Lowerer`] takes an [`ExprDag`] and produces Z3 ASTs
//! ([`LoweredAst`]) one NodeId at a time. It memoizes lowered
//! results so shared subexpressions are emitted once per query.
//!
//! Width discipline: every BV binop checks that its operands' widths
//! match. A mismatch returns
//! [`crate::concolic::backend::LoweringError::WidthMismatch`]
//! instead of silently widening — the Expr DAG's `validate` already
//! catches these at intern time, but the lowering belt-and-suspenders
//! check protects against future refactors.

#![cfg(feature = "concolic-z3-inproc")]
#![allow(dead_code)]

use std::collections::HashMap;

use z3::ast::{Ast, Bool, Dynamic, BV};
use z3::{Context, Sort as Z3Sort};

use crate::concolic::backend::LoweringError;
use crate::concolic::expr::{Expr, ExprDag, NodeId, Sort};

const BACKEND_NAME: &str = "z3_in_process";

/// A lowered Expr AST is either a `Bool<'ctx>` or a `BV<'ctx>`. We
/// don't currently lower arrays — `Load8`/`Store8` are flattened
/// to BV by the lowering rules below.
#[derive(Clone)]
pub enum LoweredAst<'ctx> {
    Bool(Bool<'ctx>),
    Bv(BV<'ctx>),
}

impl<'ctx> LoweredAst<'ctx> {
    pub fn as_bool(self) -> Result<Bool<'ctx>, LoweringError> {
        match self {
            LoweredAst::Bool(b) => Ok(b),
            LoweredAst::Bv(_) => Err(LoweringError::UnsupportedExpr {
                backend: BACKEND_NAME,
                detail: "expected Bool, got BV".into(),
            }),
        }
    }

    pub fn as_bv(self) -> Result<BV<'ctx>, LoweringError> {
        match self {
            LoweredAst::Bv(v) => Ok(v),
            LoweredAst::Bool(_) => Err(LoweringError::UnsupportedExpr {
                backend: BACKEND_NAME,
                detail: "expected BV, got Bool".into(),
            }),
        }
    }
}

/// Stateful lowerer: borrows the Z3 context for the duration of one
/// query. Memoizes Bool and BV results so a shared subexpression
/// (the whole point of hash-consing) lowers exactly once.
pub struct Z3Lowerer<'ctx> {
    ctx: &'ctx Context,
    bool_cache: HashMap<NodeId, Bool<'ctx>>,
    bv_cache: HashMap<NodeId, BV<'ctx>>,
}

impl<'ctx> Z3Lowerer<'ctx> {
    pub fn new(ctx: &'ctx Context) -> Self {
        Self {
            ctx,
            bool_cache: HashMap::new(),
            bv_cache: HashMap::new(),
        }
    }

    pub fn lower_bool(&mut self, dag: &ExprDag, id: NodeId) -> Result<Bool<'ctx>, LoweringError> {
        if let Some(b) = self.bool_cache.get(&id) {
            return Ok(b.clone());
        }
        let expr = dag.get(id);
        let result = match expr {
            Expr::BoolConst(b) => Bool::from_bool(self.ctx, *b),
            Expr::Var {
                name,
                sort: Sort::Bool,
            } => Bool::new_const(self.ctx, dag.symbol_name(*name)),
            Expr::Not(a) => self.lower_bool(dag, *a)?.not(),
            Expr::And(children) => {
                let asts: Vec<Bool<'ctx>> = children
                    .iter()
                    .map(|c| self.lower_bool(dag, *c))
                    .collect::<Result<_, _>>()?;
                let refs: Vec<&Bool<'ctx>> = asts.iter().collect();
                Bool::and(self.ctx, &refs)
            }
            Expr::Or(children) => {
                let asts: Vec<Bool<'ctx>> = children
                    .iter()
                    .map(|c| self.lower_bool(dag, *c))
                    .collect::<Result<_, _>>()?;
                let refs: Vec<&Bool<'ctx>> = asts.iter().collect();
                Bool::or(self.ctx, &refs)
            }
            Expr::Eq(a, b) => {
                let lhs = self.lower_dynamic(dag, *a)?;
                let rhs = self.lower_dynamic(dag, *b)?;
                lhs._eq(&rhs)
            }
            Expr::Ult(a, b) => {
                let l = self.lower_bv(dag, *a)?;
                let r = self.lower_bv(dag, *b)?;
                check_widths("bvult", &l, &r)?;
                l.bvult(&r)
            }
            Expr::Ule(a, b) => {
                let l = self.lower_bv(dag, *a)?;
                let r = self.lower_bv(dag, *b)?;
                check_widths("bvule", &l, &r)?;
                l.bvule(&r)
            }
            Expr::Slt(a, b) => {
                let l = self.lower_bv(dag, *a)?;
                let r = self.lower_bv(dag, *b)?;
                check_widths("bvslt", &l, &r)?;
                l.bvslt(&r)
            }
            Expr::Sle(a, b) => {
                let l = self.lower_bv(dag, *a)?;
                let r = self.lower_bv(dag, *b)?;
                check_widths("bvsle", &l, &r)?;
                l.bvsle(&r)
            }
            other => {
                return Err(LoweringError::UnsupportedExpr {
                    backend: BACKEND_NAME,
                    detail: format!("not a Bool kind: {other:?}"),
                });
            }
        };
        self.bool_cache.insert(id, result.clone());
        Ok(result)
    }

    pub fn lower_bv(&mut self, dag: &ExprDag, id: NodeId) -> Result<BV<'ctx>, LoweringError> {
        if let Some(v) = self.bv_cache.get(&id) {
            return Ok(v.clone());
        }
        let expr = dag.get(id);
        let result = match expr {
            Expr::BvConst { value, bits } => {
                if *bits <= 64 {
                    BV::from_u64(self.ctx, *value as u64, *bits)
                } else {
                    // Synthesize u128 via Concat of u64 halves.
                    let hi = ((*value >> 64) & 0xFFFF_FFFF_FFFF_FFFF) as u64;
                    let lo = (*value & 0xFFFF_FFFF_FFFF_FFFF) as u64;
                    let hi_bv = BV::from_u64(self.ctx, hi, bits - 64);
                    let lo_bv = BV::from_u64(self.ctx, lo, 64);
                    hi_bv.concat(&lo_bv)
                }
            }
            Expr::Var {
                name,
                sort: Sort::Bv(bits),
            } => BV::new_const(self.ctx, dag.symbol_name(*name), *bits),
            Expr::BvAdd(a, b) => self.bin_bv(dag, *a, *b, "bvadd", |l, r| l.bvadd(&r))?,
            Expr::BvSub(a, b) => self.bin_bv(dag, *a, *b, "bvsub", |l, r| l.bvsub(&r))?,
            Expr::BvMul(a, b) => self.bin_bv(dag, *a, *b, "bvmul", |l, r| l.bvmul(&r))?,
            Expr::BvAnd(a, b) => self.bin_bv(dag, *a, *b, "bvand", |l, r| l.bvand(&r))?,
            Expr::BvOr(a, b) => self.bin_bv(dag, *a, *b, "bvor", |l, r| l.bvor(&r))?,
            Expr::BvXor(a, b) => self.bin_bv(dag, *a, *b, "bvxor", |l, r| l.bvxor(&r))?,
            Expr::BvShl(a, b) => self.bin_bv(dag, *a, *b, "bvshl", |l, r| l.bvshl(&r))?,
            Expr::BvLShr(a, b) => self.bin_bv(dag, *a, *b, "bvlshr", |l, r| l.bvlshr(&r))?,
            Expr::BvAShr(a, b) => self.bin_bv(dag, *a, *b, "bvashr", |l, r| l.bvashr(&r))?,
            Expr::Concat(a, b) => {
                let l = self.lower_bv(dag, *a)?;
                let r = self.lower_bv(dag, *b)?;
                l.concat(&r)
            }
            Expr::Extract { hi, lo, value } => {
                let v = self.lower_bv(dag, *value)?;
                v.extract(*hi, *lo)
            }
            Expr::ZeroExt { extra, value } => {
                let v = self.lower_bv(dag, *value)?;
                v.zero_ext(*extra)
            }
            Expr::SignExt { extra, value } => {
                let v = self.lower_bv(dag, *value)?;
                v.sign_ext(*extra)
            }
            Expr::Ite {
                cond,
                then_id,
                else_id,
            } => {
                let c = self.lower_bool(dag, *cond)?;
                let t = self.lower_bv(dag, *then_id)?;
                let e = self.lower_bv(dag, *else_id)?;
                c.ite(&t, &e)
            }
            Expr::Load8 { mem: _, addr } => {
                // For v1 we flatten loads into a fresh per-address BV
                // constant — full ArrayEx lowering is out of scope. The
                // shadow emulator's `[input_base + i]` reads already
                // produce `Var(input_b<i>)` so this fallback only fires
                // on non-input loads (rare in well-instrumented runs).
                let addr_repr = format!("load8_at_{}", addr);
                BV::new_const(self.ctx, addr_repr, 8)
            }
            other => {
                return Err(LoweringError::UnsupportedExpr {
                    backend: BACKEND_NAME,
                    detail: format!("not a BV kind: {other:?}"),
                });
            }
        };
        self.bv_cache.insert(id, result.clone());
        Ok(result)
    }

    /// Lower as Dynamic — used by `Eq` which can compare either Bool
    /// or BV. Picks based on the DAG-declared Sort.
    fn lower_dynamic(&mut self, dag: &ExprDag, id: NodeId) -> Result<Dynamic<'ctx>, LoweringError> {
        match dag.sort_of(id) {
            Some(Sort::Bool) => Ok(Dynamic::from_ast(&self.lower_bool(dag, id)?)),
            Some(Sort::Bv(_)) => Ok(Dynamic::from_ast(&self.lower_bv(dag, id)?)),
            Some(Sort::Array { .. }) => Err(LoweringError::UnsupportedExpr {
                backend: BACKEND_NAME,
                detail: "array sort not lowerable to Dynamic".into(),
            }),
            None => Err(LoweringError::UnsupportedExpr {
                backend: BACKEND_NAME,
                detail: "node has no declared sort".into(),
            }),
        }
    }

    fn bin_bv<F>(
        &mut self,
        dag: &ExprDag,
        a: NodeId,
        b: NodeId,
        op_name: &'static str,
        mk: F,
    ) -> Result<BV<'ctx>, LoweringError>
    where
        F: FnOnce(BV<'ctx>, BV<'ctx>) -> BV<'ctx>,
    {
        let l = self.lower_bv(dag, a)?;
        let r = self.lower_bv(dag, b)?;
        check_widths(op_name, &l, &r)?;
        Ok(mk(l, r))
    }
}

fn check_widths<'ctx>(
    op: &'static str,
    lhs: &BV<'ctx>,
    rhs: &BV<'ctx>,
) -> Result<(), LoweringError> {
    let lhs_w = lhs.get_size();
    let rhs_w = rhs.get_size();
    if lhs_w != rhs_w {
        return Err(LoweringError::WidthMismatch {
            op,
            lhs: lhs_w,
            rhs: rhs_w,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use z3::Config;

    #[test]
    fn lowers_bv_const_to_z3_const() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut dag = ExprDag::new();
        let n = dag.intern(Expr::BvConst {
            value: 0x42,
            bits: 8,
        });
        let mut lowerer = Z3Lowerer::new(&ctx);
        let bv = lowerer.lower_bv(&dag, n).unwrap();
        assert_eq!(bv.get_size(), 8);
    }

    #[test]
    fn lowers_eq_var_const_to_bool() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c = dag.intern(Expr::BvConst {
            value: 0x42,
            bits: 8,
        });
        let eq = dag.intern(Expr::Eq(v, c));
        let mut lowerer = Z3Lowerer::new(&ctx);
        let _ = lowerer.lower_bool(&dag, eq).unwrap();
    }

    #[test]
    fn width_mismatch_returns_error() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut dag = ExprDag::new();
        let a = dag.intern(Expr::BvConst { value: 1, bits: 8 });
        let b = dag.intern(Expr::BvConst { value: 1, bits: 16 });
        // The DAG's intern is supposed to reject this, but if it
        // ever doesn't, the lowering check is the second line of
        // defense. Manually construct to bypass intern's validation:
        // build the Expr::BvAdd directly using a mismatched pair.
        // The DAG validation may reject; in that case we exercise
        // the lowering check via a width-mismatched BV pair built
        // outside the DAG. For this hermetic test, simply lower
        // both sides and call check_widths directly.
        let mut lowerer = Z3Lowerer::new(&ctx);
        let lhs = lowerer.lower_bv(&dag, a).unwrap();
        let rhs = lowerer.lower_bv(&dag, b).unwrap();
        let err = check_widths("bvadd", &lhs, &rhs);
        assert!(matches!(
            err,
            Err(LoweringError::WidthMismatch {
                op: "bvadd",
                lhs: 8,
                rhs: 16
            })
        ));
    }

    #[test]
    fn cache_returns_same_ast_for_same_node_id() {
        let cfg = Config::new();
        let ctx = Context::new(&cfg);
        let mut dag = ExprDag::new();
        let n = dag.intern(Expr::BvConst {
            value: 0x10,
            bits: 8,
        });
        let mut lowerer = Z3Lowerer::new(&ctx);
        let _a = lowerer.lower_bv(&dag, n).unwrap();
        let _b = lowerer.lower_bv(&dag, n).unwrap();
        // We can't compare Z3 ASTs for pointer equality, but the
        // bv_cache must now have exactly one entry.
        assert_eq!(lowerer.bv_cache.len(), 1);
    }
}
