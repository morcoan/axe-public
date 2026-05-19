//! [`PureRustFastSolver`] — the ladder's tier-1 fast path.
//!
//! Re-implements the same shape-matching the legacy
//! `src/symbolic_solver.rs` performed (untouched, by design) but at
//! the Expr DAG layer instead of `BranchPredicate` strings. The
//! contract is intentionally narrow: solve trivially-shaped queries
//! (Var-vs-constant comparison, optionally negated) so the ladder
//! avoids spinning up a Z3 context for branches that don't need it.
//!
//! Everything outside the narrow patterns returns
//! [`SolveStatus::Unknown`] with `reason: "unsupported_feature"` so
//! the ladder escalates to Z3. Because of the Codex finding 3 gate,
//! an `Unsat` from this tier is **not** authoritative — the ladder
//! re-runs the same query at tier 2/3 to confirm before any
//! branch-unreachable labeling.

#![allow(dead_code)]

use std::time::Instant;

use crate::concolic::backend::{BranchQuery, LoweringError, SmtBackend, SolveReport, SolveStatus};
use crate::concolic::expr::{Expr, ExprDag, NodeId};
use crate::concolic::smt2_emit::emit_query;

pub const BACKEND_NAME: &str = "pure_rust";

pub struct PureRustFastSolver;

impl PureRustFastSolver {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PureRustFastSolver {
    fn default() -> Self {
        Self::new()
    }
}

impl SmtBackend for PureRustFastSolver {
    fn solve_branch(&mut self, query: &BranchQuery, dag: &ExprDag) -> SolveReport {
        let started = Instant::now();
        let smt2 = self.dump_smt2(query, dag);
        let target = if query.want_taken {
            ResolvedTarget::Direct(query.target_branch)
        } else {
            ResolvedTarget::Negated(query.target_branch)
        };
        let outcome = solve_trivial(dag, target, query.input_bytes);
        let elapsed = started.elapsed().as_millis() as u64;
        match outcome {
            Ok(TrivialOutcome::Sat(model)) => SolveReport {
                status: SolveStatus::Sat,
                time_ms: elapsed,
                input_model: Some(model),
                smt2,
                reason: None,
                unsat_core: Vec::new(),
                unsat_assumptions_returned: false,
                backend: BACKEND_NAME,
            },
            Ok(TrivialOutcome::Unsat) => SolveReport {
                status: SolveStatus::Unsat,
                time_ms: elapsed,
                input_model: None,
                smt2,
                reason: Some("trivially_unsat".into()),
                unsat_core: Vec::new(),
                // Tier 1 never claims authoritative unreachability —
                // it lacks named-assumption support entirely. The
                // ladder re-runs at tier ≥ 3 to confirm.
                unsat_assumptions_returned: false,
                backend: BACKEND_NAME,
            },
            Err(reason) => SolveReport {
                status: SolveStatus::Unknown,
                time_ms: elapsed,
                input_model: None,
                smt2,
                reason: Some(reason),
                unsat_core: Vec::new(),
                unsat_assumptions_returned: false,
                backend: BACKEND_NAME,
            },
        }
    }

    fn dump_smt2(&self, query: &BranchQuery, dag: &ExprDag) -> String {
        emit_query(query, dag).smt2
    }

    fn name(&self) -> &'static str {
        BACKEND_NAME
    }
}

#[derive(Clone, Copy)]
enum ResolvedTarget {
    Direct(NodeId),
    Negated(NodeId),
}

enum TrivialOutcome {
    Sat(Vec<u8>),
    Unsat,
}

/// Match a trivial single-symbol-vs-constant pattern and synthesize
/// the input model that flips the branch. Returns `Err(reason)` if
/// the shape isn't one the fast solver handles.
fn solve_trivial(
    dag: &ExprDag,
    target: ResolvedTarget,
    input_bytes: u32,
) -> Result<TrivialOutcome, String> {
    let (node, negated) = match target {
        ResolvedTarget::Direct(n) => (n, false),
        ResolvedTarget::Negated(n) => (n, true),
    };
    let expr = dag
        .try_get(node)
        .ok_or_else(|| "invalid_node_id".to_string())?;

    // Strip an outer `Not` and treat as the inverse relation.
    let (expr, negated) = match expr {
        Expr::Not(inner) => (
            dag.try_get(*inner)
                .ok_or_else(|| "invalid_node_id".to_string())?,
            !negated,
        ),
        other => (other, negated),
    };

    let (rel, lhs, rhs) = match expr {
        Expr::Eq(a, b) => (Rel::Eq, *a, *b),
        Expr::Ult(a, b) => (Rel::Ult, *a, *b),
        Expr::Ule(a, b) => (Rel::Ule, *a, *b),
        Expr::Slt(a, b) => (Rel::Slt, *a, *b),
        Expr::Sle(a, b) => (Rel::Sle, *a, *b),
        _ => return Err("unsupported_feature".into()),
    };

    let rel = if negated { rel.invert() } else { rel };

    // Find which side is a Var that maps to a single input byte and
    // which is a BvConst. Anything else is `unsupported_feature`.
    let lhs_kind = classify_side(dag, lhs);
    let rhs_kind = classify_side(dag, rhs);

    let (byte_index, const_value, swapped) = match (&lhs_kind, &rhs_kind) {
        (SideKind::InputByte { index, width }, SideKind::Const { value, bits }) => {
            check_widths(*width, *bits)?.map(|_| (*index, *value, false))
        }
        (SideKind::Const { value, bits }, SideKind::InputByte { index, width }) => {
            check_widths(*bits, *width)?.map(|_| (*index, *value, true))
        }
        _ => return Err("unsupported_feature".into()),
    }
    .ok_or_else(|| "width_mismatch".to_string())?;

    if byte_index >= input_bytes {
        return Err("byte_index_out_of_range".into());
    }

    let satisfying = if swapped {
        flip_const_var(rel, const_value)
    } else {
        flip_var_const(rel, const_value)
    };

    match satisfying {
        Some(byte_val) => {
            let mut model = vec![0u8; input_bytes as usize];
            model[byte_index as usize] = byte_val;
            Ok(TrivialOutcome::Sat(model))
        }
        None => Ok(TrivialOutcome::Unsat),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Rel {
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
}

impl Rel {
    fn invert(self) -> Self {
        match self {
            Rel::Eq => Rel::Ne,
            Rel::Ne => Rel::Eq,
            Rel::Ult => Rel::Uge,
            Rel::Ule => Rel::Ugt,
            Rel::Ugt => Rel::Ule,
            Rel::Uge => Rel::Ult,
            Rel::Slt => Rel::Sge,
            Rel::Sle => Rel::Sgt,
            Rel::Sgt => Rel::Sle,
            Rel::Sge => Rel::Slt,
        }
    }
}

#[derive(Debug)]
enum SideKind {
    InputByte { index: u32, width: u32 },
    Const { value: u128, bits: u32 },
    Other,
}

fn classify_side(dag: &ExprDag, id: NodeId) -> SideKind {
    let Some(e) = dag.try_get(id) else {
        return SideKind::Other;
    };
    match e {
        Expr::Var { name, sort } => {
            let n = dag.symbol_name(*name);
            if let Some(idx) = parse_input_byte_var_name(n) {
                let width = match sort {
                    crate::concolic::expr::Sort::Bv(b) => *b,
                    _ => return SideKind::Other,
                };
                SideKind::InputByte { index: idx, width }
            } else {
                SideKind::Other
            }
        }
        Expr::BvConst { value, bits } => SideKind::Const {
            value: *value,
            bits: *bits,
        },
        // Allow `ZeroExt { value: Var(input_b<i>) }` to count as the
        // single-byte side — the shadow emulator emits these on
        // sub-register writes.
        Expr::ZeroExt { value, .. } | Expr::SignExt { value, .. } => {
            if let SideKind::InputByte { index, .. } = classify_side(dag, *value) {
                let outer_width = dag.sort_of(id).and_then(|s| match s {
                    crate::concolic::expr::Sort::Bv(b) => Some(b),
                    _ => None,
                });
                if let Some(w) = outer_width {
                    SideKind::InputByte { index, width: w }
                } else {
                    SideKind::Other
                }
            } else {
                SideKind::Other
            }
        }
        _ => SideKind::Other,
    }
}

fn parse_input_byte_var_name(s: &str) -> Option<u32> {
    s.strip_prefix("input_b")
        .and_then(|n| n.parse::<u32>().ok())
}

fn check_widths(var_width: u32, const_bits: u32) -> Result<Option<()>, String> {
    if var_width != const_bits {
        return Err("width_mismatch".into());
    }
    Ok(Some(()))
}

/// Find a single-byte value satisfying `var <rel> const`.
fn flip_var_const(rel: Rel, c: u128) -> Option<u8> {
    let c = (c & 0xff) as i32;
    match rel {
        Rel::Eq => u8::try_from(c).ok(),
        Rel::Ne => Some(if c == 0 { 1 } else { 0 }),
        Rel::Ult => (c.checked_sub(1)).and_then(|v| u8::try_from(v).ok()),
        Rel::Ule => u8::try_from(c).ok(),
        Rel::Ugt => u8::try_from(c + 1).ok(),
        Rel::Uge => u8::try_from(c).ok(),
        Rel::Slt => {
            let cs = c as i8;
            cs.checked_sub(1).map(|v| v as u8)
        }
        Rel::Sle => i8::try_from(c).ok().map(|v| v as u8),
        Rel::Sgt => (c as i8).checked_add(1).map(|v| v as u8),
        Rel::Sge => i8::try_from(c).ok().map(|v| v as u8),
    }
}

/// Find a value for `var` so that `const <rel> var` is true. (Mirror
/// case for swapped operands.)
fn flip_const_var(rel: Rel, c: u128) -> Option<u8> {
    let c = (c & 0xff) as i32;
    match rel {
        Rel::Eq => u8::try_from(c).ok(),
        Rel::Ne => Some(if c == 0 { 1 } else { 0 }),
        Rel::Ult => u8::try_from(c + 1).ok(),
        Rel::Ule => u8::try_from(c).ok(),
        Rel::Ugt => c.checked_sub(1).and_then(|v| u8::try_from(v).ok()),
        Rel::Uge => u8::try_from(c).ok(),
        Rel::Slt => (c as i8).checked_add(1).map(|v| v as u8),
        Rel::Sle => i8::try_from(c).ok().map(|v| v as u8),
        Rel::Sgt => (c as i8).checked_sub(1).map(|v| v as u8),
        Rel::Sge => i8::try_from(c).ok().map(|v| v as u8),
    }
}

// Marker so unused-import warnings don't fire when we add more
// surface area later.
#[allow(dead_code)]
fn _types_used(_: LoweringError) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concolic::backend::{BranchQuery, SolveStatus};
    use crate::concolic::expr::Sort;
    use std::time::Duration;

    fn input_byte(dag: &mut ExprDag, idx: u32, width: u32) -> NodeId {
        let sym = dag.intern_symbol(&format!("input_b{}", idx));
        dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(width),
        })
    }

    fn make_query(target: NodeId, want_taken: bool, input_bytes: u32) -> BranchQuery {
        BranchQuery {
            input_bytes,
            path_constraints: vec![],
            target_branch: target,
            want_taken,
            timeout: Duration::from_millis(10),
            prefer_logic: Some("QF_BV"),
        }
    }

    #[test]
    fn eq_var_const_returns_sat_with_byte_set() {
        let mut dag = ExprDag::new();
        let v = input_byte(&mut dag, 0, 8);
        let c = dag.intern(Expr::BvConst {
            value: 0x41,
            bits: 8,
        });
        let target = dag.intern(Expr::Eq(v, c));
        let mut solver = PureRustFastSolver::new();
        let report = solver.solve_branch(&make_query(target, true, 4), &dag);
        assert_eq!(report.status, SolveStatus::Sat);
        let model = report.input_model.expect("model populated");
        assert_eq!(model[0], 0x41);
        assert_eq!(model.len(), 4);
        assert_eq!(report.backend, "pure_rust");
    }

    #[test]
    fn ne_var_const_returns_sat_with_distinct_byte() {
        let mut dag = ExprDag::new();
        let v = input_byte(&mut dag, 2, 8);
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let eq = dag.intern(Expr::Eq(v, c));
        let target = dag.intern(Expr::Not(eq));
        let mut solver = PureRustFastSolver::new();
        let report = solver.solve_branch(&make_query(target, true, 4), &dag);
        assert_eq!(report.status, SolveStatus::Sat);
        assert_ne!(report.input_model.unwrap()[2], 0);
    }

    #[test]
    fn want_not_taken_inverts_relation() {
        let mut dag = ExprDag::new();
        let v = input_byte(&mut dag, 0, 8);
        let c = dag.intern(Expr::BvConst { value: 5, bits: 8 });
        let target = dag.intern(Expr::Eq(v, c));
        let mut solver = PureRustFastSolver::new();
        let report = solver.solve_branch(&make_query(target, false, 1), &dag);
        assert_eq!(report.status, SolveStatus::Sat);
        // The fast solver picked any byte != 5.
        assert_ne!(report.input_model.unwrap()[0], 5);
    }

    #[test]
    fn unsupported_shape_returns_unknown() {
        let mut dag = ExprDag::new();
        // Add two input bytes and compare them — pure_rust doesn't model this.
        let v1 = input_byte(&mut dag, 0, 8);
        let v2 = input_byte(&mut dag, 1, 8);
        let target = dag.intern(Expr::Eq(v1, v2));
        let mut solver = PureRustFastSolver::new();
        let report = solver.solve_branch(&make_query(target, true, 4), &dag);
        assert_eq!(report.status, SolveStatus::Unknown);
        assert_eq!(report.reason.as_deref(), Some("unsupported_feature"));
    }

    #[test]
    fn unsat_outcome_does_not_set_unreachable_flag() {
        let mut dag = ExprDag::new();
        // Eq(BvConst(5), BvConst(7)) — but our classifier requires a
        // Var on one side, so this falls into unsupported_feature.
        // Use Ult: var < 0 (always false in unsigned land).
        let v = input_byte(&mut dag, 0, 8);
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let target = dag.intern(Expr::Ult(v, c));
        let mut solver = PureRustFastSolver::new();
        let report = solver.solve_branch(&make_query(target, true, 1), &dag);
        assert_eq!(report.status, SolveStatus::Unsat);
        assert!(
            !report.unsat_assumptions_returned,
            "tier 1 never claims authoritative unreachability"
        );
        assert!(report.unsat_core.is_empty());
    }

    #[test]
    fn dump_smt2_is_always_available() {
        let mut dag = ExprDag::new();
        let v = input_byte(&mut dag, 0, 8);
        let c = dag.intern(Expr::BvConst {
            value: 0x40,
            bits: 8,
        });
        let target = dag.intern(Expr::Eq(v, c));
        let solver = PureRustFastSolver::new();
        let s = solver.dump_smt2(&make_query(target, true, 4), &dag);
        assert!(s.contains("(check-sat)"));
        assert!(s.contains("input_b0"));
    }

    #[test]
    fn zero_extend_of_input_byte_still_classifies() {
        let mut dag = ExprDag::new();
        let v = input_byte(&mut dag, 0, 8);
        let ze = dag.intern(Expr::ZeroExt {
            extra: 24,
            value: v,
        });
        let c = dag.intern(Expr::BvConst {
            value: 0x41,
            bits: 32,
        });
        let target = dag.intern(Expr::Eq(ze, c));
        let mut solver = PureRustFastSolver::new();
        let report = solver.solve_branch(&make_query(target, true, 4), &dag);
        assert_eq!(report.status, SolveStatus::Sat);
        assert_eq!(report.input_model.unwrap()[0], 0x41);
    }
}
