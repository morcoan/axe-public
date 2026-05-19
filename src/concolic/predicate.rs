//! Fallback `BranchPredicate` → `Expr` lifter.
//!
//! Used when the [`shadow_emulator`](super::shadow_emulator) has no
//! NodeId for either operand of a branch — i.e., the branch's left
//! and right are register-name strings without symbolic shadow
//! state. This is the parity path with the existing bounded solver
//! (`src/symbolic_solver.rs`).
//!
//! The shadow emulator should produce real NodeId-bearing branches
//! most of the time once it's tracking enough instruction families;
//! this lifter is the floor that ensures concolic always at least
//! matches the bounded solver's reach.

#![allow(dead_code)]

use std::collections::HashMap;

use crate::concolic::expr::{Expr, ExprDag, NodeId, Sort, SymbolId};
use crate::native_emulator::BranchPredicate;

/// Symbol table mapping reg/var names to NodeIds in a session's DAG.
/// Reused across calls so the same `rax` reference becomes the same
/// NodeId.
#[derive(Default)]
pub struct SymbolTable {
    by_name: HashMap<String, NodeId>,
    width: u32,
}

impl SymbolTable {
    pub fn new(default_width: u32) -> Self {
        Self {
            by_name: HashMap::new(),
            width: default_width,
        }
    }

    pub fn fetch_or_define(&mut self, dag: &mut ExprDag, name: &str) -> NodeId {
        if let Some(&id) = self.by_name.get(name) {
            return id;
        }
        let sym: SymbolId = dag.intern_symbol(name);
        let id = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(self.width),
        });
        self.by_name.insert(name.to_string(), id);
        id
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum LiftError {
    #[error("unsupported branch mnemonic: {0}")]
    UnsupportedMnemonic(String),
    #[error("empty operand string in branch predicate")]
    EmptyOperand,
}

/// Lift a `BranchPredicate` into a Bool `Expr` NodeId.
///
/// Each operand is either:
/// - a numeric literal (`123`, `0x1f`, `-1`) → `Expr::BvConst`
/// - anything else → treated as a symbolic variable name and bound
///   via [`SymbolTable::fetch_or_define`]
pub fn lift_branch_predicate(
    pred: &BranchPredicate,
    dag: &mut ExprDag,
    table: &mut SymbolTable,
) -> Result<NodeId, LiftError> {
    if pred.left.is_empty() || pred.right.is_empty() {
        return Err(LiftError::EmptyOperand);
    }
    let lhs = operand_to_node(&pred.left, pred.left_value, dag, table);
    let rhs = operand_to_node(&pred.right, pred.right_value, dag, table);
    let rel = relation_for_branch(&pred.mnemonic)
        .ok_or_else(|| LiftError::UnsupportedMnemonic(pred.mnemonic.clone()))?;
    Ok(apply_relation(rel, lhs, rhs, dag))
}

fn operand_to_node(
    operand: &str,
    concrete: Option<u64>,
    dag: &mut ExprDag,
    table: &mut SymbolTable,
) -> NodeId {
    if let Ok(v) = parse_numeric(operand) {
        dag.intern(Expr::BvConst {
            value: v as u128,
            bits: table.width,
        })
    } else if let Some(v) = concrete {
        // Operand name didn't parse as a literal but we have a
        // concrete value from the emulator: use it.
        dag.intern(Expr::BvConst {
            value: v as u128,
            bits: table.width,
        })
    } else {
        table.fetch_or_define(dag, operand)
    }
}

fn parse_numeric(s: &str) -> Result<u64, std::num::ParseIntError> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(rest, 16)
    } else if let Some(rest) = s.strip_prefix('-') {
        rest.parse::<i64>().map(|v| -v as u64)
    } else {
        s.parse::<u64>()
    }
}

/// Mirror of `src/symbolic_solver.rs::relation_for_branch`. Returns
/// the SMT relation string for a recognized branch mnemonic.
fn relation_for_branch(mnemonic: &str) -> Option<&'static str> {
    let m = mnemonic.to_ascii_lowercase();
    match m.as_str() {
        "je" | "jz" => Some("="),
        "jne" | "jnz" => Some("!="),
        "ja" | "jnbe" => Some("u>"),
        "jae" | "jnb" => Some("u>="),
        "jb" | "jc" | "jnae" => Some("u<"),
        "jbe" | "jna" => Some("u<="),
        "jg" | "jnle" => Some("s>"),
        "jge" | "jnl" => Some("s>="),
        "jl" | "jnge" => Some("s<"),
        "jle" | "jng" => Some("s<="),
        _ => None,
    }
}

fn apply_relation(rel: &str, lhs: NodeId, rhs: NodeId, dag: &mut ExprDag) -> NodeId {
    match rel {
        "=" => dag.intern(Expr::Eq(lhs, rhs)),
        "!=" => {
            let eq = dag.intern(Expr::Eq(lhs, rhs));
            dag.intern(Expr::Not(eq))
        }
        "u<" => dag.intern(Expr::Ult(lhs, rhs)),
        "u<=" => dag.intern(Expr::Ule(lhs, rhs)),
        "u>" => {
            let le = dag.intern(Expr::Ule(lhs, rhs));
            dag.intern(Expr::Not(le))
        }
        "u>=" => {
            let lt = dag.intern(Expr::Ult(lhs, rhs));
            dag.intern(Expr::Not(lt))
        }
        "s<" => dag.intern(Expr::Slt(lhs, rhs)),
        "s<=" => dag.intern(Expr::Sle(lhs, rhs)),
        "s>" => {
            let le = dag.intern(Expr::Sle(lhs, rhs));
            dag.intern(Expr::Not(le))
        }
        "s>=" => {
            let lt = dag.intern(Expr::Slt(lhs, rhs));
            dag.intern(Expr::Not(lt))
        }
        _ => dag.intern(Expr::BoolConst(false)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_emulator::BranchPredicate;

    fn pred(
        mnemonic: &str,
        left: &str,
        right: &str,
        lv: Option<u64>,
        rv: Option<u64>,
    ) -> BranchPredicate {
        BranchPredicate {
            site_va: 0x1000,
            mnemonic: mnemonic.into(),
            left: left.into(),
            right: right.into(),
            predicate: format!("{left} {mnemonic} {right}"),
            left_value: lv,
            right_value: rv,
        }
    }

    #[test]
    fn lift_je_with_constant_rhs() {
        let mut dag = ExprDag::new();
        let mut table = SymbolTable::new(64);
        let p = pred("je", "rcx", "4", Some(0), Some(4));
        let nid = lift_branch_predicate(&p, &mut dag, &mut table).unwrap();
        // Should be Eq(rcx_var, BvConst 4).
        assert!(matches!(dag.get(nid), Expr::Eq(_, _)));
    }

    #[test]
    fn lift_jne_wraps_eq_in_not() {
        let mut dag = ExprDag::new();
        let mut table = SymbolTable::new(64);
        let p = pred("jne", "rcx", "rdx", None, None);
        let nid = lift_branch_predicate(&p, &mut dag, &mut table).unwrap();
        // Not(Eq(rcx_var, rdx_var)).
        assert!(matches!(dag.get(nid), Expr::Not(_)));
    }

    #[test]
    fn lift_unsupported_mnemonic_errors() {
        let mut dag = ExprDag::new();
        let mut table = SymbolTable::new(64);
        let p = pred("jecxz", "rcx", "0", None, Some(0));
        let err = lift_branch_predicate(&p, &mut dag, &mut table).unwrap_err();
        assert!(matches!(err, LiftError::UnsupportedMnemonic(_)));
    }

    #[test]
    fn parse_numeric_handles_hex_and_decimal() {
        assert_eq!(parse_numeric("0x1f").unwrap(), 31);
        assert_eq!(parse_numeric("0X10").unwrap(), 16);
        assert_eq!(parse_numeric("42").unwrap(), 42);
    }

    #[test]
    fn empty_operand_errors() {
        let mut dag = ExprDag::new();
        let mut table = SymbolTable::new(64);
        let p = pred("je", "", "0", None, None);
        let err = lift_branch_predicate(&p, &mut dag, &mut table).unwrap_err();
        assert!(matches!(err, LiftError::EmptyOperand));
    }

    #[test]
    fn lift_ja_uses_unsigned_compare() {
        let mut dag = ExprDag::new();
        let mut table = SymbolTable::new(64);
        let p = pred("ja", "rax", "10", None, Some(10));
        let nid = lift_branch_predicate(&p, &mut dag, &mut table).unwrap();
        // ja → u> → Not(Ule(...))
        assert!(matches!(dag.get(nid), Expr::Not(_)));
    }

    #[test]
    fn same_register_name_dedups_to_same_var() {
        let mut dag = ExprDag::new();
        let mut table = SymbolTable::new(64);
        let _ = lift_branch_predicate(&pred("je", "rcx", "0", None, None), &mut dag, &mut table);
        let _ = lift_branch_predicate(&pred("je", "rcx", "1", None, None), &mut dag, &mut table);
        // Both branches reference the SAME `rcx` Var NodeId.
        let count = dag.len();
        // We have: 1 Var(rcx), 1 BvConst(0), 1 Eq, 1 BvConst(1), 1 Eq → 5 unique nodes
        assert_eq!(count, 5);
    }
}
