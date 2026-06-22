//! Z3 in-process backend (gated behind `concolic-z3-inproc`).
//!
//! [`Z3InProcessBackend`] implements [`SmtBackend`] by:
//! 1. Constructing a fresh `Context` + `Solver` for the query.
//!    Per-query rebuild — the Rust `z3` crate's `BV<'ctx>` borrows
//!    `&Context`, and a long-lived ContextHolder cache would
//!    require `ouroboros` / `yoke` / unsafe. Profiling-driven
//!    optimization deferred.
//! 2. Lowering the query's `path_constraints` and `target_branch`
//!    via [`Z3Lowerer`] from `lowering.rs`.
//! 3. Adding each constraint as a *tracked assumption* (the Rust
//!    crate's `assert_and_track`), with a sidecar `Vec<(Bool, NodeId)>`
//!    so we can reverse-map the unsat-core back to NodeIds.
//! 4. Calling `solver.check_assumptions(&[…])`, classifying the
//!    result, and (for `Unsat`) extracting the core via
//!    `solver.get_unsat_core()`. Sets `unsat_assumptions_returned =
//!    true` iff the core is non-empty (the Codex finding 3 gate).
//!
//! Errors from lowering produce a `SolveReport` with
//! `status: SolveStatus::LoweringError` and the lowering-error string
//! in `reason` so the ladder can decide whether to escalate.

#![cfg(feature = "concolic-z3-inproc")]
#![allow(dead_code)]

use std::time::{Duration, Instant};

use z3::ast::{Ast, Bool};
use z3::{Config, Context, SatResult, Solver};

use crate::concolic::backend::{BranchQuery, SmtBackend, SolveReport, SolveStatus};
use crate::concolic::expr::{ExprDag, NodeId};
use crate::concolic::lowering::Z3Lowerer;
use crate::concolic::smt2_emit::emit_query;

pub const BACKEND_NAME: &str = "z3_in_process";

#[derive(Clone, Debug, Default)]
pub struct Z3InProcessConfig {
    /// Random seed for Z3's deterministic mode. `None` → don't set.
    pub random_seed: Option<u64>,
    /// Set `:model true` etc. Always sane defaults.
    pub want_models: bool,
    pub want_cores: bool,
}

pub struct Z3InProcessBackend {
    config: Z3InProcessConfig,
}

impl Z3InProcessBackend {
    pub fn new(config: Z3InProcessConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(Z3InProcessConfig {
            random_seed: None,
            want_models: true,
            want_cores: true,
        })
    }
}

impl SmtBackend for Z3InProcessBackend {
    fn solve_branch(&mut self, query: &BranchQuery, dag: &ExprDag) -> SolveReport {
        let smt2_dump = emit_query(query, dag).smt2;
        let started = Instant::now();

        let mut cfg = Config::new();
        if let Some(seed) = self.config.random_seed {
            cfg.set_param_value("smt.random_seed", &seed.to_string());
        }
        if self.config.want_models {
            cfg.set_model_generation(true);
        }
        if self.config.want_cores {
            cfg.set_proof_generation(false);
            // unsat-core via assumptions; no extra config needed.
        }

        let ctx = Context::new(&cfg);
        let solver = Solver::new(&ctx);
        if query.timeout > Duration::from_millis(0) {
            let timeout_ms = query.timeout.as_millis().min(u32::MAX as u128) as u32;
            let params = z3::Params::new(&ctx);
            // Rust crate exposes `params.set_u32("timeout", N)`.
            let mut p = params;
            p.set_u32("timeout", timeout_ms);
            solver.set_params(&p);
        }

        let mut lowerer = Z3Lowerer::new(&ctx);

        // Lower path constraints + the (possibly negated) target into
        // tracked assumptions. The sidecar `assumptions` is the
        // ordered list we pass to `check_assumptions`; we also keep a
        // mapping from each Bool's name → NodeId so we can reverse-
        // translate the unsat-core.
        let mut assumptions: Vec<Bool<'_>> = Vec::with_capacity(query.path_constraints.len() + 1);
        let mut assumption_to_node: Vec<NodeId> =
            Vec::with_capacity(query.path_constraints.len() + 1);
        for (i, pc) in query.path_constraints.iter().enumerate() {
            match lowerer.lower_bool(dag, *pc) {
                Ok(b) => {
                    let track = Bool::new_const(&ctx, format!("c_{i:02}"));
                    solver.assert_and_track(&b, &track);
                    assumptions.push(track);
                    assumption_to_node.push(*pc);
                }
                Err(e) => {
                    return SolveReport {
                        status: SolveStatus::LoweringError,
                        time_ms: started.elapsed().as_millis() as u64,
                        input_model: None,
                        smt2: smt2_dump,
                        reason: Some(format!("lowering path-constraint #{i}: {e}")),
                        unsat_core: Vec::new(),
                        unsat_assumptions_returned: false,
                        backend: BACKEND_NAME,
                    };
                }
            }
        }

        // Target branch.
        let target_lowered = match lowerer.lower_bool(dag, query.target_branch) {
            Ok(b) => {
                if query.want_taken {
                    b
                } else {
                    b.not()
                }
            }
            Err(e) => {
                return SolveReport {
                    status: SolveStatus::LoweringError,
                    time_ms: started.elapsed().as_millis() as u64,
                    input_model: None,
                    smt2: smt2_dump,
                    reason: Some(format!("lowering target: {e}")),
                    unsat_core: Vec::new(),
                    unsat_assumptions_returned: false,
                    backend: BACKEND_NAME,
                };
            }
        };
        let target_track = Bool::new_const(&ctx, "c_TGT");
        solver.assert_and_track(&target_lowered, &target_track);
        assumptions.push(target_track);
        assumption_to_node.push(query.target_branch);

        let check = solver.check_assumptions(&assumptions);
        let elapsed = started.elapsed();
        let time_ms = elapsed.as_millis() as u64;

        match check {
            SatResult::Sat => {
                let model = solver.get_model();
                let input_bytes = if let Some(m) = model {
                    let mut bytes = vec![0u8; query.input_bytes as usize];
                    for i in 0..query.input_bytes {
                        let name = format!("input_b{i}");
                        let var = z3::ast::BV::new_const(&ctx, name, 8);
                        if let Some(eval) = m.eval(&var, true) {
                            if let Some(v) = eval.as_u64() {
                                bytes[i as usize] = (v & 0xFF) as u8;
                            }
                        }
                    }
                    Some(bytes)
                } else {
                    None
                };
                SolveReport {
                    status: SolveStatus::Sat,
                    time_ms,
                    input_model: input_bytes,
                    smt2: smt2_dump,
                    reason: None,
                    unsat_core: Vec::new(),
                    unsat_assumptions_returned: false,
                    backend: BACKEND_NAME,
                }
            }
            SatResult::Unsat => {
                // Extract the unsat core. The Rust crate returns
                // Vec<Bool<'ctx>> for the named tracking constants
                // that were involved in the proof.
                let core_bools = solver.get_unsat_core();
                let mut unsat_core: Vec<NodeId> = Vec::new();
                for tracker in &core_bools {
                    // The tracker was named c_NN or c_TGT. Match by
                    // its string repr (the Z3 crate exposes `to_string`
                    // for ASTs via Display).
                    let tracker_str = format!("{tracker}");
                    for (i, ass) in assumptions.iter().enumerate() {
                        if format!("{ass}") == tracker_str {
                            unsat_core.push(assumption_to_node[i]);
                            break;
                        }
                    }
                }
                SolveReport {
                    status: SolveStatus::Unsat,
                    time_ms,
                    input_model: None,
                    smt2: smt2_dump,
                    reason: None,
                    unsat_core: unsat_core.clone(),
                    // Codex finding 3 gate: set true ONLY if we
                    // actually got a non-empty core back. Empty cores
                    // are bookkeeping noise and don't qualify as
                    // authoritative-unreachable evidence.
                    unsat_assumptions_returned: !unsat_core.is_empty(),
                    backend: BACKEND_NAME,
                }
            }
            SatResult::Unknown => {
                let reason = solver.get_reason_unknown();
                if reason.as_deref() == Some("timeout") || elapsed >= query.timeout {
                    SolveReport {
                        status: SolveStatus::Timeout,
                        time_ms,
                        input_model: None,
                        smt2: smt2_dump,
                        reason: Some("z3_in_process_timeout".into()),
                        unsat_core: Vec::new(),
                        unsat_assumptions_returned: false,
                        backend: BACKEND_NAME,
                    }
                } else {
                    SolveReport {
                        status: SolveStatus::Unknown,
                        time_ms,
                        input_model: None,
                        smt2: smt2_dump,
                        reason: reason.or_else(|| Some("z3_unknown".into())),
                        unsat_core: Vec::new(),
                        unsat_assumptions_returned: false,
                        backend: BACKEND_NAME,
                    }
                }
            }
        }
    }

    fn dump_smt2(&self, query: &BranchQuery, dag: &ExprDag) -> String {
        emit_query(query, dag).smt2
    }

    fn name(&self) -> &'static str {
        BACKEND_NAME
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concolic::expr::{Expr, Sort};

    #[test]
    fn solves_simple_byte_equality_constraint() {
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
        let target = dag.intern(Expr::Eq(v, c));
        let query = BranchQuery {
            input_bytes: 1,
            path_constraints: vec![],
            target_branch: target,
            want_taken: true,
            timeout: Duration::from_millis(1000),
            prefer_logic: Some("QF_BV"),
        };
        let mut backend = Z3InProcessBackend::with_defaults();
        let report = backend.solve_branch(&query, &dag);
        assert_eq!(report.status, SolveStatus::Sat);
        let model = report.input_model.unwrap();
        assert_eq!(model[0], 0x42);
    }

    #[test]
    fn unsat_constraint_returns_unsat_with_non_empty_core() {
        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c1 = dag.intern(Expr::BvConst {
            value: 0x01,
            bits: 8,
        });
        let c2 = dag.intern(Expr::BvConst {
            value: 0x02,
            bits: 8,
        });
        let eq1 = dag.intern(Expr::Eq(v, c1));
        let eq2 = dag.intern(Expr::Eq(v, c2));
        let query = BranchQuery {
            input_bytes: 1,
            path_constraints: vec![eq1, eq2],
            // Target is a tautology so the unsat comes from the
            // contradictory path constraints.
            target_branch: dag.intern(Expr::BoolConst(true)),
            want_taken: true,
            timeout: Duration::from_millis(1000),
            prefer_logic: Some("QF_BV"),
        };
        let mut backend = Z3InProcessBackend::with_defaults();
        let report = backend.solve_branch(&query, &dag);
        assert_eq!(report.status, SolveStatus::Unsat);
        assert!(
            report.unsat_assumptions_returned,
            "non-empty core must set the flag"
        );
        assert!(!report.unsat_core.is_empty());
        assert!(report.is_authoritative_unreachable());
    }
}
