//! [`SolveLadder`] — the tiered cascade that picks which backend
//! gets each branch query.
//!
//! Five tiers (per the plan):
//! - **Tier 0** `ConstantFold` — a structural pre-pass over the DAG.
//!   No backend call. Reduces trivial `Eq(BvConst, BvConst)` to a
//!   constant Bool and short-circuits if the target is already
//!   forced.
//! - **Tier 1** `PureFast` — wraps [`super::pure_rust::PureRustFastSolver`].
//!   No timeout. Cheap; covers the bounded-solver-compatible shapes.
//! - **Tier 2** `Z3Quick` — Z3 in-process with a tight 250 ms budget
//!   and NO slicing. Catches "Z3 will just solve this in one shot."
//! - **Tier 3** `Z3SlicedAssumptions` — Z3 in-process with slicing +
//!   named `:named c_NN` assumptions + `(get-unsat-core)`. 1 s default.
//! - **Tier 4** `Z3External` — `z3 -smt2 -in` subprocess with slicing +
//!   named assumptions. 10 s default. Bare-`Unsat`-without-core
//!   downgraded by [`super::smt2_backend::parse_z3_response`] already.
//! - **Tier 5** `Unknown` — no backend; final fallthrough.
//!
//! **Authoritative-unreachable discipline (Codex finding 3)** — only
//! `Unsat` from tier ≥ 3 whose [`SolveReport::is_authoritative_unreachable`]
//! returns `true` may label a branch unreachable. Bare `Unsat` from
//! tiers 1–2 is treated as "re-escalate to confirm," not as proof.

#![allow(dead_code)]

use std::time::{Duration, Instant};

use serde::Serialize;

use crate::concolic::backend::{BranchQuery, SmtBackend, SolveReport, SolveStatus};
use crate::concolic::expr::{Expr, ExprDag, NodeId};
use crate::concolic::slicer::{backward_slice, ConstraintSlice};

/// Tier label attached to each [`LadderAttempt`] for telemetry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SolveTier {
    ConstantFold,
    PureFast,
    Z3Quick,
    Z3SlicedAssumptions,
    Z3External,
    Unknown,
}

impl SolveTier {
    /// `true` if this tier is *eligible* to authoritatively label a
    /// branch unreachable when its report meets the
    /// `is_authoritative_unreachable` bar.
    pub fn can_authoritatively_unreachable(self) -> bool {
        matches!(self, SolveTier::Z3SlicedAssumptions | SolveTier::Z3External)
    }

    pub fn label(self) -> &'static str {
        match self {
            SolveTier::ConstantFold => "constant_fold",
            SolveTier::PureFast => "pure_fast",
            SolveTier::Z3Quick => "z3_quick",
            SolveTier::Z3SlicedAssumptions => "z3_sliced_assumptions",
            SolveTier::Z3External => "z3_external",
            SolveTier::Unknown => "unknown",
        }
    }
}

/// One backend bound into the ladder with its tier metadata.
pub struct LadderBackend {
    pub tier: SolveTier,
    pub backend: Box<dyn SmtBackend>,
    pub slice: bool,
    pub timeout: Duration,
}

/// One row in the ladder's per-query attempt log.
#[derive(Clone, Debug, Serialize)]
pub struct LadderAttempt {
    pub tier: SolveTier,
    pub backend_name: &'static str,
    pub slice_size: usize,
    pub time_ms: u64,
    pub status: SolveStatus,
    pub reason: Option<String>,
    pub is_authoritative_unreachable: bool,
}

/// Full result of [`SolveLadder::solve`].
///
/// The final report is whichever attempt produced a `Sat` (preferred)
/// or the highest-tier authoritative `Unsat`, or the last attempt if
/// nothing of those landed.
#[derive(Debug)]
pub struct LadderOutcome {
    pub attempts: Vec<LadderAttempt>,
    pub winning_tier: SolveTier,
    pub final_report: SolveReport,
    pub branch_marked_unreachable: bool,
    pub total_time_ms: u64,
}

pub struct SolveLadder {
    backends: Vec<LadderBackend>,
}

impl SolveLadder {
    pub fn new(backends: Vec<LadderBackend>) -> Self {
        Self { backends }
    }

    /// Convenience: a default ladder with just tier 0 (const-fold)
    /// + tier 1 ([`super::pure_rust::PureRustFastSolver`]) + tier 4
    /// ([`super::smt2_backend::Z3ExternalSmt2Backend`]). The Z3
    /// in-process tiers (2 and 3) are added by callers when the
    /// `concolic-z3-inproc` feature is enabled.
    pub fn default_for_features() -> Self {
        let backends: Vec<LadderBackend> = vec![
            LadderBackend {
                tier: SolveTier::PureFast,
                backend: Box::new(crate::concolic::pure_rust::PureRustFastSolver::default()),
                slice: false,
                timeout: Duration::from_millis(0),
            },
            LadderBackend {
                tier: SolveTier::Z3External,
                backend: Box::new(
                    crate::concolic::smt2_backend::Z3ExternalSmt2Backend::with_defaults(),
                ),
                slice: true,
                timeout: Duration::from_millis(10_000),
            },
        ];
        Self::new(backends)
    }

    /// Run the ladder on `query`. Stops at the first `Sat` or the
    /// first authoritative `Unsat` from a tier ≥ 3.
    pub fn solve(&mut self, query: &BranchQuery, dag: &mut ExprDag) -> LadderOutcome {
        let started = Instant::now();
        let mut attempts: Vec<LadderAttempt> = Vec::new();
        let mut last_report: Option<(SolveTier, SolveReport, usize)> = None;
        let mut best_authoritative: Option<(SolveTier, SolveReport, usize)> = None;

        // Tier 0: constant fold.
        if let Some(cf) = constant_fold(query, dag) {
            attempts.push(LadderAttempt {
                tier: SolveTier::ConstantFold,
                backend_name: "constant_fold",
                slice_size: 0,
                time_ms: 0,
                status: cf.status,
                reason: cf.reason.clone(),
                is_authoritative_unreachable: false,
            });
            // Const-fold Sat: stop and return a zero-vector model.
            // Const-fold Unsat: seed `last_report` so it bubbles up
            // when no backend produces a Sat (but don't mark
            // unreachable — that's tier ≥ 3 only, Codex finding 3).
            match cf.status {
                SolveStatus::Sat => {
                    let total = started.elapsed().as_millis() as u64;
                    return LadderOutcome {
                        attempts,
                        winning_tier: SolveTier::ConstantFold,
                        final_report: cf,
                        branch_marked_unreachable: false,
                        total_time_ms: total,
                    };
                }
                SolveStatus::Unsat => {
                    last_report = Some((SolveTier::ConstantFold, cf, 0));
                }
                _ => {}
            }
        }

        for ladder_backend in &mut self.backends {
            // Maybe slice for this tier.
            let sub_query = if ladder_backend.slice {
                slice_query(query, dag, ladder_backend.timeout)
            } else {
                let mut q = query.clone();
                if ladder_backend.timeout > Duration::from_millis(0) {
                    q.timeout = ladder_backend.timeout;
                }
                (q, query.path_constraints.len())
            };
            let (effective_query, slice_size) = sub_query;

            let attempt_started = Instant::now();
            let report = ladder_backend.backend.solve_branch(&effective_query, dag);
            let _wall = attempt_started.elapsed();
            let authoritative = ladder_backend.tier.can_authoritatively_unreachable()
                && report.is_authoritative_unreachable();

            attempts.push(LadderAttempt {
                tier: ladder_backend.tier,
                backend_name: report.backend,
                slice_size,
                time_ms: report.time_ms,
                status: report.status,
                reason: report.reason.clone(),
                is_authoritative_unreachable: authoritative,
            });

            match report.status {
                SolveStatus::Sat => {
                    let total = started.elapsed().as_millis() as u64;
                    return LadderOutcome {
                        attempts,
                        winning_tier: ladder_backend.tier,
                        final_report: report,
                        branch_marked_unreachable: false,
                        total_time_ms: total,
                    };
                }
                SolveStatus::Unsat if authoritative => {
                    // Track but keep going to give later tiers a
                    // chance to find a model (in case the unsat was
                    // due to an over-aggressive slice). In practice
                    // the slicer is sound, so this is belt-and-suspenders.
                    best_authoritative = Some((ladder_backend.tier, report.clone(), slice_size));
                    last_report = Some((ladder_backend.tier, report, slice_size));
                }
                _ => {
                    last_report = Some((ladder_backend.tier, report, slice_size));
                }
            }
        }

        // No Sat anywhere. Prefer the authoritative-unreachable
        // report; otherwise return the last attempt.
        let total = started.elapsed().as_millis() as u64;
        if let Some((tier, report, _slice)) = best_authoritative {
            return LadderOutcome {
                attempts,
                winning_tier: tier,
                final_report: report,
                branch_marked_unreachable: true,
                total_time_ms: total,
            };
        }
        if let Some((tier, report, _slice)) = last_report {
            return LadderOutcome {
                attempts,
                winning_tier: tier,
                final_report: report,
                branch_marked_unreachable: false,
                total_time_ms: total,
            };
        }
        // No backends at all? Emit a stub.
        LadderOutcome {
            attempts,
            winning_tier: SolveTier::Unknown,
            final_report: SolveReport {
                status: SolveStatus::Unknown,
                time_ms: 0,
                input_model: None,
                smt2: String::new(),
                reason: Some("ladder_empty".into()),
                unsat_core: Vec::new(),
                unsat_assumptions_returned: false,
                backend: "ladder",
            },
            branch_marked_unreachable: false,
            total_time_ms: total,
        }
    }
}

/// Tier 0: try to fold the query's target branch (and the conjunction
/// of its path constraints) to a constant Bool without any backend
/// help. Returns:
/// - `Some(report{status: Sat, input_model: zero_vector, ...})` if
///   the constraint is trivially satisfiable for any input.
/// - `Some(report{status: Unsat, ...})` if the constraint is
///   structurally unsatisfiable.
/// - `None` if the query is non-trivial (need a backend).
fn constant_fold(query: &BranchQuery, dag: &ExprDag) -> Option<SolveReport> {
    // The target may be wrapped in want_taken=false; effectively assert
    // either `target` or `Not(target)`. If the target is a BoolConst,
    // the answer is immediate.
    let target_value = match dag.get(query.target_branch) {
        Expr::BoolConst(b) => *b,
        _ => return None,
    };
    let asserted_true = if query.want_taken {
        target_value
    } else {
        !target_value
    };
    if !asserted_true {
        return Some(SolveReport {
            status: SolveStatus::Unsat,
            time_ms: 0,
            input_model: None,
            smt2: String::new(),
            reason: Some("constant_fold_unsat".into()),
            unsat_core: Vec::new(),
            unsat_assumptions_returned: false,
            backend: "constant_fold",
        });
    }
    // The path constraints might still constrain things, but if they're
    // all BoolConst(true), the whole thing is satisfied trivially.
    for pc in &query.path_constraints {
        match dag.get(*pc) {
            Expr::BoolConst(true) => continue,
            _ => return None,
        }
    }
    Some(SolveReport {
        status: SolveStatus::Sat,
        time_ms: 0,
        input_model: Some(vec![0u8; query.input_bytes as usize]),
        smt2: String::new(),
        reason: None,
        unsat_core: Vec::new(),
        unsat_assumptions_returned: false,
        backend: "constant_fold",
    })
}

/// Reduce the query's path constraints to the slice reachable from
/// `target_branch`. Also caps the timeout for this tier.
fn slice_query(
    query: &BranchQuery,
    dag: &mut ExprDag,
    tier_timeout: Duration,
) -> (BranchQuery, usize) {
    let ConstraintSlice {
        constraints,
        variables: _,
        fixpoint_reached: _,
        iterations: _,
    } = backward_slice(dag, &query.path_constraints, query.target_branch);
    let mut q = query.clone();
    let slice_size = constraints.len();
    q.path_constraints = constraints;
    if tier_timeout > Duration::from_millis(0) {
        q.timeout = tier_timeout;
    }
    (q, slice_size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concolic::backend::{SmtBackend, SolveReport, SolveStatus};
    use crate::concolic::expr::{Expr, ExprDag, Sort};

    // Scripted backend that returns a queued sequence of reports.
    struct ScriptBackend {
        name: &'static str,
        script: Vec<SolveReport>,
    }
    impl ScriptBackend {
        fn new(name: &'static str, script: Vec<SolveReport>) -> Self {
            Self { name, script }
        }
        fn pop(&mut self) -> SolveReport {
            if self.script.is_empty() {
                return SolveReport {
                    status: SolveStatus::Unknown,
                    time_ms: 0,
                    input_model: None,
                    smt2: String::new(),
                    reason: Some("script_exhausted".into()),
                    unsat_core: Vec::new(),
                    unsat_assumptions_returned: false,
                    backend: "script",
                };
            }
            self.script.remove(0)
        }
    }
    impl SmtBackend for ScriptBackend {
        fn solve_branch(&mut self, _q: &BranchQuery, _d: &ExprDag) -> SolveReport {
            self.pop()
        }
        fn dump_smt2(&self, _q: &BranchQuery, _d: &ExprDag) -> String {
            String::new()
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn rep(status: SolveStatus, backend: &'static str) -> SolveReport {
        SolveReport {
            status,
            time_ms: 1,
            input_model: if status == SolveStatus::Sat {
                Some(vec![0xAB])
            } else {
                None
            },
            smt2: String::new(),
            reason: None,
            unsat_core: Vec::new(),
            unsat_assumptions_returned: false,
            backend,
        }
    }

    fn auth_unsat(backend: &'static str) -> SolveReport {
        let mut r = rep(SolveStatus::Unsat, backend);
        r.unsat_core = vec![1, 2];
        r.unsat_assumptions_returned = true;
        r
    }

    fn make_query(target: NodeId) -> BranchQuery {
        BranchQuery {
            input_bytes: 4,
            path_constraints: vec![],
            target_branch: target,
            want_taken: true,
            timeout: Duration::from_millis(100),
            prefer_logic: Some("QF_BV"),
        }
    }

    #[test]
    fn cascade_stops_at_first_sat() {
        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let target = dag.intern(Expr::Eq(v, c));

        // Tier 1 Unknown, Tier 2 Sat. Stops at tier 2.
        let mut ladder = SolveLadder::new(vec![
            LadderBackend {
                tier: SolveTier::PureFast,
                backend: Box::new(ScriptBackend::new(
                    "pure",
                    vec![rep(SolveStatus::Unknown, "pure")],
                )),
                slice: false,
                timeout: Duration::from_millis(0),
            },
            LadderBackend {
                tier: SolveTier::Z3Quick,
                backend: Box::new(ScriptBackend::new(
                    "z3q",
                    vec![rep(SolveStatus::Sat, "z3q")],
                )),
                slice: false,
                timeout: Duration::from_millis(250),
            },
            LadderBackend {
                tier: SolveTier::Z3SlicedAssumptions,
                backend: Box::new(ScriptBackend::new(
                    "z3s",
                    vec![rep(SolveStatus::Sat, "z3s")],
                )),
                slice: true,
                timeout: Duration::from_millis(1000),
            },
        ]);
        let outcome = ladder.solve(&make_query(target), &mut dag);
        assert_eq!(outcome.final_report.status, SolveStatus::Sat);
        assert_eq!(outcome.winning_tier, SolveTier::Z3Quick);
        // Tier 3 not invoked (attempts has 2: Pure + Z3Quick).
        // (Tier 0 const-fold doesn't fire on Eq(Var, Const).)
        assert_eq!(outcome.attempts.len(), 2);
        assert!(!outcome.branch_marked_unreachable);
    }

    #[test]
    fn tier_2_unsat_does_not_mark_unreachable() {
        // Codex finding 3: only tier ≥ 3 may mark unreachable.
        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let target = dag.intern(Expr::Eq(v, c));

        let mut ladder = SolveLadder::new(vec![LadderBackend {
            tier: SolveTier::Z3Quick,
            backend: Box::new(ScriptBackend::new("z3q", vec![auth_unsat("z3q")])),
            slice: false,
            timeout: Duration::from_millis(250),
        }]);
        let outcome = ladder.solve(&make_query(target), &mut dag);
        assert_eq!(outcome.final_report.status, SolveStatus::Unsat);
        assert!(
            !outcome.branch_marked_unreachable,
            "tier 2 Unsat MUST NOT mark unreachable"
        );
    }

    #[test]
    fn tier_3_auth_unsat_marks_unreachable() {
        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let target = dag.intern(Expr::Eq(v, c));

        let mut ladder = SolveLadder::new(vec![LadderBackend {
            tier: SolveTier::Z3SlicedAssumptions,
            backend: Box::new(ScriptBackend::new("z3s", vec![auth_unsat("z3s")])),
            slice: true,
            timeout: Duration::from_millis(1000),
        }]);
        let outcome = ladder.solve(&make_query(target), &mut dag);
        assert_eq!(outcome.final_report.status, SolveStatus::Unsat);
        assert!(outcome.branch_marked_unreachable);
    }

    #[test]
    fn tier_4_bare_unsat_without_core_does_not_mark_unreachable() {
        // External backend returns Unsat but unsat_assumptions_returned=false.
        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let target = dag.intern(Expr::Eq(v, c));

        let mut bare_unsat = rep(SolveStatus::Unsat, "z3e");
        bare_unsat.unsat_assumptions_returned = false;
        bare_unsat.unsat_core = vec![];

        let mut ladder = SolveLadder::new(vec![LadderBackend {
            tier: SolveTier::Z3External,
            backend: Box::new(ScriptBackend::new("z3e", vec![bare_unsat])),
            slice: true,
            timeout: Duration::from_millis(10_000),
        }]);
        let outcome = ladder.solve(&make_query(target), &mut dag);
        assert_eq!(outcome.final_report.status, SolveStatus::Unsat);
        assert!(
            !outcome.branch_marked_unreachable,
            "bare Unsat without core MUST NOT mark unreachable"
        );
    }

    #[test]
    fn constant_fold_on_true_target_returns_sat_immediately() {
        let mut dag = ExprDag::new();
        let target = dag.intern(Expr::BoolConst(true));
        let mut ladder = SolveLadder::new(vec![]);
        let outcome = ladder.solve(&make_query(target), &mut dag);
        assert_eq!(outcome.final_report.status, SolveStatus::Sat);
        assert_eq!(outcome.winning_tier, SolveTier::ConstantFold);
        assert!(outcome.final_report.input_model.is_some());
    }

    #[test]
    fn constant_fold_on_false_target_returns_unsat_but_not_unreachable() {
        let mut dag = ExprDag::new();
        let target = dag.intern(Expr::BoolConst(false));
        let mut ladder = SolveLadder::new(vec![]);
        let outcome = ladder.solve(&make_query(target), &mut dag);
        assert_eq!(outcome.final_report.status, SolveStatus::Unsat);
        // Const-fold isn't tier ≥ 3 → not authoritative.
        assert!(!outcome.branch_marked_unreachable);
    }

    #[test]
    fn cascade_returns_last_when_all_unknown() {
        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let target = dag.intern(Expr::Eq(v, c));

        let mut ladder = SolveLadder::new(vec![
            LadderBackend {
                tier: SolveTier::PureFast,
                backend: Box::new(ScriptBackend::new(
                    "pure",
                    vec![rep(SolveStatus::Unknown, "pure")],
                )),
                slice: false,
                timeout: Duration::from_millis(0),
            },
            LadderBackend {
                tier: SolveTier::Z3Quick,
                backend: Box::new(ScriptBackend::new(
                    "z3q",
                    vec![rep(SolveStatus::Timeout, "z3q")],
                )),
                slice: false,
                timeout: Duration::from_millis(250),
            },
        ]);
        let outcome = ladder.solve(&make_query(target), &mut dag);
        // No Sat, no authoritative Unsat — get the last report.
        assert_eq!(outcome.final_report.status, SolveStatus::Timeout);
        assert_eq!(outcome.attempts.len(), 2);
    }

    #[test]
    fn empty_ladder_yields_ladder_empty_unknown() {
        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let target = dag.intern(Expr::Eq(v, c));
        let mut ladder = SolveLadder::new(vec![]);
        let outcome = ladder.solve(&make_query(target), &mut dag);
        assert_eq!(outcome.final_report.status, SolveStatus::Unknown);
        assert_eq!(outcome.final_report.reason.as_deref(), Some("ladder_empty"));
    }
}
