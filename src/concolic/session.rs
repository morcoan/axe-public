//! End-to-end concolic session orchestrator.
//!
//! [`ConcolicSession`] owns the lifecycle of one concolic run: it
//! sets up the writers, drives the
//! [`super::scheduler::ConcolicScheduler`] pop loop, runs each
//! [`super::scheduler::FrontierItem`] through the
//! [`super::ladder::SolveLadder`], hands SAT models to the
//! [`super::validator::ModelValidator`], promotes confirmed-novelty
//! inputs through the [`super::fuzzer_bridge::CorpusBridge`], and
//! finalizes the per-artifact [`super::run_status::ConcolicRunStatusLedger`].
//!
//! Everything above is loosely coupled — the session is just the
//! glue. Replacing the executor, the ladder backend mix, or the
//! scheduler doesn't require touching this file (only its
//! constructor).

#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::concolic::backend::{BranchQuery, SolveStatus};
use crate::concolic::expr::ExprDag;
use crate::concolic::fuzzer_bridge::{CorpusBridge, PromoteOutcome};
use crate::concolic::ladder::SolveLadder;
use crate::concolic::llm_export::{
    BranchesWriter, ConstraintSummary, CoverageRecord, CoverageWriter, ExprsWriter, Smt2Writer,
    SolveBranch, SolveRecord, SolverSection, SolvesWriter, TracesWriter,
};
use crate::concolic::run_status::ConcolicRunStatusLedger;
use crate::concolic::scheduler::{ConcolicScheduler, FrontierItem};
use crate::concolic::validator::{ModelValidator, ValidationStatus};
use crate::concolic::{ConcolicError, ConcolicOptions, ConcolicReport};
use crate::fuzzer::corpus::FuzzCorpus;
use crate::fuzzer::coverage::CoverageMap;
use crate::fuzzer::executor::FuzzExecutor;

pub struct ConcolicSession {
    options: ConcolicOptions,
    out_dir: PathBuf,
    run_id: String,
    started_at_ms: u128,
    scheduler: ConcolicScheduler,
    ladder: SolveLadder,
    bridge: CorpusBridge,
}

impl ConcolicSession {
    /// Construct a session rooted at `out_dir`. Creates
    /// `out_dir/concolic/` lazily on first finalize.
    pub fn new(
        out_dir: PathBuf,
        options: ConcolicOptions,
        corpus: Arc<Mutex<FuzzCorpus>>,
        global_map: Arc<Mutex<CoverageMap>>,
    ) -> Self {
        let started_at_ms = now_ms();
        let run_id = format!("run-{started_at_ms:x}");
        Self {
            options,
            out_dir,
            run_id,
            started_at_ms,
            scheduler: ConcolicScheduler::new(),
            ladder: SolveLadder::default_for_features(),
            bridge: CorpusBridge::new(corpus, global_map),
        }
    }

    /// Construct a session with a custom-built ladder (lets tests
    /// inject scripted backends; lets future callers add Z3 tiers).
    pub fn with_ladder(
        out_dir: PathBuf,
        options: ConcolicOptions,
        corpus: Arc<Mutex<FuzzCorpus>>,
        global_map: Arc<Mutex<CoverageMap>>,
        ladder: SolveLadder,
    ) -> Self {
        let started_at_ms = now_ms();
        let run_id = format!("run-{started_at_ms:x}");
        Self {
            options,
            out_dir,
            run_id,
            started_at_ms,
            scheduler: ConcolicScheduler::new(),
            ladder,
            bridge: CorpusBridge::new(corpus, global_map),
        }
    }

    pub fn enqueue(&mut self, item: FrontierItem) {
        self.scheduler.enqueue(item);
    }

    pub fn pending(&self) -> usize {
        self.scheduler.len()
    }

    /// Run the loop until the scheduler is empty (or the time
    /// budget elapses). Returns the per-run summary; writes
    /// all artifacts + the ledger to disk.
    pub fn run_until_drained<E: FuzzExecutor>(
        mut self,
        executor: &mut E,
        dag: &mut ExprDag,
    ) -> Result<ConcolicReport, ConcolicError> {
        let concolic_dir = self.out_dir.join("concolic");
        std::fs::create_dir_all(&concolic_dir)?;
        let smt2_dir = concolic_dir.join("smt2");

        let mut solves_writer = SolvesWriter::create(&concolic_dir.join("solves.jsonl"))?;
        let mut exprs_writer = ExprsWriter::create(&concolic_dir.join("exprs.jsonl"))?;
        let mut branches_writer = BranchesWriter::create(&concolic_dir.join("branches.jsonl"))?;
        let mut traces_writer = TracesWriter::create(&concolic_dir.join("traces.jsonl"))?;
        let mut coverage_writer = CoverageWriter::create(&concolic_dir.join("coverage.jsonl"))?;
        let mut smt2_writer = Smt2Writer::create(&smt2_dir)?;
        let mut ledger =
            ConcolicRunStatusLedger::create(&self.out_dir, &self.run_id, self.started_at_ms);

        let mut report = ConcolicReport::default();
        report.run_id = self.run_id.clone();

        // Validator borrows the executor.
        let run_timeout = std::time::Duration::from_millis(self.options.z3_external_ms.max(1_000));

        let mut path_idx: u32 = 0;
        let start_wall = std::time::Instant::now();

        while let Some(item) = self.scheduler.next() {
            if let Some(budget) = self.options.time_budget {
                if start_wall.elapsed() >= budget {
                    break;
                }
            }
            path_idx = path_idx.saturating_add(1);

            let query = BranchQuery {
                input_bytes: item.input_bytes,
                path_constraints: item.path_constraints.clone(),
                target_branch: item.target_branch,
                want_taken: item.want_taken,
                timeout: run_timeout,
                prefer_logic: Some("QF_BV"),
            };

            let outcome = self.ladder.solve(&query, dag);
            report.solves_attempted += 1;

            // SMT-LIB dump (best-effort; cap may have been hit).
            let smt2_relative_path =
                match smt2_writer.dump(&outcome.final_report.smt2, path_idx, item.branch_index) {
                    Ok(p) => p,
                    Err(_) => None,
                };

            match outcome.final_report.status {
                SolveStatus::Sat => report.solves_sat += 1,
                SolveStatus::Unsat => report.solves_unsat += 1,
                SolveStatus::Unknown | SolveStatus::LoweringError => report.solves_unknown += 1,
                SolveStatus::Timeout => report.solves_timeout += 1,
            }

            // Validate + maybe promote.
            let mut model_validation_section = None;
            if let Some(model_bytes) = outcome.final_report.input_model.clone() {
                let snapshot: CoverageMap = {
                    let global_arc = self.bridge.coverage_merge();
                    let g = global_arc.lock().unwrap_or_else(|p| p.into_inner());
                    g.clone()
                };
                let mut validator = ModelValidator::new(executor, run_timeout);
                let validation = validator.validate(
                    &model_bytes,
                    item.branch_pc,
                    item.expected_flip_pc,
                    &snapshot,
                );
                model_validation_section =
                    Some(crate::concolic::llm_export::ModelValidationSection {
                        reexecuted: validation.reexecuted,
                        reached_target_pc: validation.reached_target_pc,
                        branch_flipped: validation.branch_flipped,
                        new_coverage: validation.new_coverage.is_interesting(),
                        crashed: validation.crashed,
                        status: status_label(validation.status),
                    });

                if matches!(validation.status, ValidationStatus::NewCrash) {
                    report.crashes_found += 1;
                }

                if matches!(validation.status, ValidationStatus::NewCoverageConfirmed) {
                    match self.bridge.promote_if_novel(
                        &model_bytes,
                        Some(&item.origin_seed_id),
                        &validation,
                        executor.map(),
                    ) {
                        Ok(PromoteOutcome::Promoted { model_id, novelty }) => {
                            report.models_promoted_to_corpus += 1;
                            let _ = coverage_writer.append(&CoverageRecord {
                                schema: "symtrace.coverage.v1",
                                ts_ms: now_ms() as u64,
                                source_solve_id: model_id,
                                new_edges: novelty.new_edges,
                                new_buckets: novelty.new_buckets,
                            });
                        }
                        Ok(_) => {}
                        Err(e) => {
                            ledger.mark_partial(
                                "solves.jsonl",
                                solves_writer.bytes_written(),
                                solves_writer.count() as u64,
                                &format!("promotion error: {e}"),
                            );
                        }
                    }
                }
            }

            let record = SolveRecord {
                schema: "symtrace.solve.v1",
                ts_ms: now_ms() as u64,
                run_id: self.run_id.clone(),
                path_id: item.path_id.clone(),
                branch: SolveBranch {
                    pc: format!("0x{:x}", item.branch_pc),
                    function: None,
                    edge_id: None,
                    depth: item.depth,
                    taken: item.want_taken,
                    requested: !item.want_taken,
                },
                constraint_summary: ConstraintSummary {
                    logic: "QF_BV",
                    num_constraints_total: item.path_constraints.len() as u32,
                    num_constraints_in_slice: item.path_constraints.len() as u32,
                    num_expr_nodes: item.expr_complexity,
                    input_bytes: item.input_bytes,
                    features: vec!["bitvector"],
                    unsupported_features: vec![],
                },
                solver: SolverSection {
                    tier_used: outcome.winning_tier.label(),
                    backend: outcome.final_report.backend,
                    status: status_label_for_solve(outcome.final_report.status),
                    time_ms: outcome.total_time_ms,
                    reason_unknown: outcome.final_report.reason.clone(),
                    unsat_core: outcome.final_report.unsat_core.clone(),
                    smt2_path: smt2_relative_path,
                },
                model: None,
                coverage: None,
                model_validation: model_validation_section,
            };
            solves_writer.append(&record)?;
        }

        // Finalize writers + record their final size in the ledger.
        let solves_bytes = solves_writer.bytes_written();
        let solves_count = solves_writer.count() as u64;
        let exprs_bytes = exprs_writer.bytes_written();
        let exprs_count = exprs_writer.count() as u64;
        let branches_bytes = branches_writer.bytes_written();
        let branches_count = branches_writer.count() as u64;
        let traces_bytes = traces_writer.bytes_written();
        let traces_count = traces_writer.count() as u64;
        let coverage_bytes = coverage_writer.bytes_written();
        let coverage_count = coverage_writer.count() as u64;
        let smt2_bytes = smt2_writer.bytes_written();
        let smt2_count = smt2_writer.written() as u64;

        let _ = solves_writer.finalize()?;
        let _ = exprs_writer.finalize()?;
        let _ = branches_writer.finalize()?;
        let _ = traces_writer.finalize()?;
        let _ = coverage_writer.finalize()?;

        ledger.mark_complete("solves.jsonl", solves_bytes, solves_count);
        ledger.mark_complete("exprs.jsonl", exprs_bytes, exprs_count);
        ledger.mark_complete("branches.jsonl", branches_bytes, branches_count);
        ledger.mark_complete("traces.jsonl", traces_bytes, traces_count);
        ledger.mark_complete("coverage.jsonl", coverage_bytes, coverage_count);
        ledger.mark_complete("smt2", smt2_bytes, smt2_count);

        let ledger_path = ledger.path().to_path_buf();
        ledger.finalize_atomic(now_ms())?;
        report.run_status_path = Some(ledger_path);

        Ok(report)
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn status_label(s: ValidationStatus) -> &'static str {
    match s {
        ValidationStatus::Valid => "valid",
        ValidationStatus::ModelMismatch => "model_mismatch",
        ValidationStatus::UnreachableInRealRun => "unreachable_in_real_run",
        ValidationStatus::NewCoverageConfirmed => "new_coverage_confirmed",
        ValidationStatus::NewCrash => "new_crash",
    }
}

fn status_label_for_solve(s: SolveStatus) -> &'static str {
    match s {
        SolveStatus::Sat => "sat",
        SolveStatus::Unsat => "unsat",
        SolveStatus::Unknown => "unknown",
        SolveStatus::Timeout => "timeout",
        SolveStatus::LoweringError => "lowering_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::concolic::backend::{SmtBackend, SolveReport};
    use crate::concolic::expr::{Expr, ExprDag, Sort};
    use crate::concolic::ladder::{LadderBackend, SolveTier};
    use crate::fuzzer::executor::{CrashInfo, ExecutionResult, ExitKind};
    use std::time::Duration;
    use tempfile::TempDir;

    // ───── stub backend ────────────────────────────────────────────
    struct ScriptBackend {
        next: SolveReport,
    }
    impl SmtBackend for ScriptBackend {
        fn solve_branch(&mut self, _q: &BranchQuery, _d: &ExprDag) -> SolveReport {
            self.next.clone()
        }
        fn dump_smt2(&self, _q: &BranchQuery, _d: &ExprDag) -> String {
            "(set-logic QF_BV)\n(check-sat)\n".to_string()
        }
        fn name(&self) -> &'static str {
            "script"
        }
    }

    // ───── stub executor ───────────────────────────────────────────
    struct StubExecutor {
        map: CoverageMap,
        edges: Vec<(u64, u64)>,
        exit: ExitKind,
    }
    impl StubExecutor {
        fn ok() -> Self {
            Self {
                map: CoverageMap::new(),
                edges: vec![(0x4000, 0x4010)],
                exit: ExitKind::Ok,
            }
        }
    }
    impl FuzzExecutor for StubExecutor {
        fn run(&mut self, _input: &[u8], _timeout: Duration) -> ExecutionResult {
            self.reset();
            for (f, t) in &self.edges {
                self.map.record_edge(*f, *t);
            }
            ExecutionResult {
                exit: self.exit,
                exec_us: 100,
                crash: if self.exit.is_crash_like() {
                    Some(CrashInfo::default())
                } else {
                    None
                },
                edges_observed: self.edges.len() as u64,
            }
        }
        fn reset(&mut self) {
            self.map.clear();
        }
        fn map(&self) -> &CoverageMap {
            &self.map
        }
    }

    fn sat_report(model: Vec<u8>) -> SolveReport {
        SolveReport {
            status: SolveStatus::Sat,
            time_ms: 1,
            input_model: Some(model),
            smt2: String::new(),
            reason: None,
            unsat_core: vec![],
            unsat_assumptions_returned: false,
            backend: "script",
        }
    }

    fn unknown_report() -> SolveReport {
        SolveReport {
            status: SolveStatus::Unknown,
            time_ms: 1,
            input_model: None,
            smt2: String::new(),
            reason: Some("test".into()),
            unsat_core: vec![],
            unsat_assumptions_returned: false,
            backend: "script",
        }
    }

    fn make_item_with_node(pc: u64, idx: u32, target: u32) -> FrontierItem {
        FrontierItem {
            path_id: format!("con:{pc:x}:{idx:04}"),
            branch_pc: pc,
            branch_index: idx,
            depth: 1,
            hit_count: 0,
            expr_complexity: 2,
            last_solver_ms: None,
            novelty_score: 0.5,
            origin_seed_id: "seed_root".into(),
            reachability_distance: 0,
            rhs_is_concrete: true,
            prior_timeouts: 0,
            target_branch: target,
            path_constraints: vec![],
            input_bytes: 2,
            want_taken: true,
            expected_flip_pc: Some(0x4010),
        }
    }

    #[test]
    fn drained_session_writes_all_jsonl_files_and_ledger() {
        let tmp = TempDir::new().unwrap();
        let corpus = Arc::new(Mutex::new(
            FuzzCorpus::open(&tmp.path().join("queue")).unwrap(),
        ));
        let global = Arc::new(Mutex::new(CoverageMap::new()));

        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let target = dag.intern(Expr::Eq(v, c));

        let mut ladder = SolveLadder::new(vec![LadderBackend {
            tier: SolveTier::PureFast,
            backend: Box::new(ScriptBackend {
                next: sat_report(vec![0u8, 0u8]),
            }),
            slice: false,
            timeout: Duration::from_millis(0),
        }]);

        let mut session = ConcolicSession::with_ladder(
            tmp.path().to_path_buf(),
            ConcolicOptions::default(),
            corpus,
            global,
            ladder,
        );
        session.enqueue(make_item_with_node(0x4000, 1, target));
        session.enqueue(make_item_with_node(0x4100, 1, target));
        let mut executor = StubExecutor::ok();
        let report = session.run_until_drained(&mut executor, &mut dag).unwrap();

        assert_eq!(report.solves_attempted, 2);
        assert_eq!(report.solves_sat, 2);
        assert!(tmp.path().join("concolic/solves.jsonl").exists());
        assert!(tmp.path().join("concolic/exprs.jsonl").exists());
        assert!(tmp.path().join("concolic/branches.jsonl").exists());
        assert!(tmp.path().join("concolic/traces.jsonl").exists());
        assert!(tmp.path().join("concolic/coverage.jsonl").exists());
        assert!(tmp.path().join("concolic/run_status.json").exists());
        // smt2 dir exists.
        assert!(tmp.path().join("concolic/smt2").exists());
        // run_status ledger path on the report.
        assert!(report.run_status_path.is_some());
    }

    #[test]
    fn session_with_unknown_results_marks_solves_unknown_in_report() {
        let tmp = TempDir::new().unwrap();
        let corpus = Arc::new(Mutex::new(
            FuzzCorpus::open(&tmp.path().join("queue")).unwrap(),
        ));
        let global = Arc::new(Mutex::new(CoverageMap::new()));
        let mut dag = ExprDag::new();
        let sym = dag.intern_symbol("input_b0");
        let v = dag.intern(Expr::Var {
            name: sym,
            sort: Sort::Bv(8),
        });
        let c = dag.intern(Expr::BvConst { value: 0, bits: 8 });
        let target = dag.intern(Expr::Eq(v, c));
        let ladder = SolveLadder::new(vec![LadderBackend {
            tier: SolveTier::PureFast,
            backend: Box::new(ScriptBackend {
                next: unknown_report(),
            }),
            slice: false,
            timeout: Duration::from_millis(0),
        }]);
        let mut session = ConcolicSession::with_ladder(
            tmp.path().to_path_buf(),
            ConcolicOptions::default(),
            corpus,
            global,
            ladder,
        );
        session.enqueue(make_item_with_node(0x4000, 1, target));
        let mut executor = StubExecutor::ok();
        let report = session.run_until_drained(&mut executor, &mut dag).unwrap();
        assert_eq!(report.solves_attempted, 1);
        assert_eq!(report.solves_unknown, 1);
        assert_eq!(report.models_promoted_to_corpus, 0);
    }

    #[test]
    fn empty_session_produces_zero_solves_but_still_finalizes_ledger() {
        let tmp = TempDir::new().unwrap();
        let corpus = Arc::new(Mutex::new(
            FuzzCorpus::open(&tmp.path().join("queue")).unwrap(),
        ));
        let global = Arc::new(Mutex::new(CoverageMap::new()));
        let session = ConcolicSession::new(
            tmp.path().to_path_buf(),
            ConcolicOptions::default(),
            corpus,
            global,
        );
        let mut dag = ExprDag::new();
        let mut executor = StubExecutor::ok();
        let report = session.run_until_drained(&mut executor, &mut dag).unwrap();
        assert_eq!(report.solves_attempted, 0);
        assert!(tmp.path().join("concolic/run_status.json").exists());
    }
}
