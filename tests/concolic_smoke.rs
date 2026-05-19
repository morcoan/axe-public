//! End-to-end concolic artifact pipeline test.
//!
//! Mirrors `tests/fuzzer_smoke.rs` but for the concolic engine.
//! Verifies:
//! - A drained [`ConcolicSession`] produces all 6 artifacts under
//!   `out/concolic/` (5 JSONL files + `smt2/` directory) and a
//!   `run_status.json` ledger.
//! - The manifest helper `concolic_artifact_index_entries` reads
//!   the ledger and produces the expected 7 [`ArtifactIndexRecord`]s
//!   (run_status.json + 6 artifacts).
//! - `recommended_reading_order` would put `concolic/run_status.json`
//!   first (validated structurally — the helper itself emits the
//!   run_status entry first).
//! - With `mode == "off"`, the helper returns an empty Vec.
//! - With a missing `run_status.json`, the helper returns an empty
//!   Vec (doesn't panic, doesn't poison the manifest).

#![cfg(feature = "concolic")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axe_core::concolic::backend::{BranchQuery, SmtBackend, SolveReport, SolveStatus};
use axe_core::concolic::expr::{Expr, ExprDag, Sort};
use axe_core::concolic::ladder::{LadderBackend, SolveLadder, SolveTier};
use axe_core::concolic::scheduler::FrontierItem;
use axe_core::concolic::session::ConcolicSession;
use axe_core::concolic::ConcolicOptions;
use axe_core::concolic_artifact_index_entries;
use axe_core::fuzzer::corpus::FuzzCorpus;
use axe_core::fuzzer::coverage::CoverageMap;
use axe_core::fuzzer::executor::{CrashInfo, ExecutionResult, ExitKind, FuzzExecutor};
use tempfile::TempDir;

/// Backend that always returns the same SAT report. Lets us drive
/// the session deterministically.
struct ConstSatBackend(SolveReport);
impl SmtBackend for ConstSatBackend {
    fn solve_branch(&mut self, _q: &BranchQuery, _d: &ExprDag) -> SolveReport {
        self.0.clone()
    }
    fn dump_smt2(&self, _q: &BranchQuery, _d: &ExprDag) -> String {
        "(set-logic QF_BV)\n(check-sat)\n".to_string()
    }
    fn name(&self) -> &'static str {
        "smoke_const"
    }
}

/// Executor that records a fixed set of edges on every run.
struct SmokeExecutor {
    map: CoverageMap,
    edges_per_run: Vec<(u64, u64)>,
}
impl SmokeExecutor {
    fn new(edges: Vec<(u64, u64)>) -> Self {
        Self {
            map: CoverageMap::new(),
            edges_per_run: edges,
        }
    }
}
impl FuzzExecutor for SmokeExecutor {
    fn run(&mut self, _input: &[u8], _timeout: Duration) -> ExecutionResult {
        self.reset();
        for (from, to) in &self.edges_per_run {
            self.map.record_edge(*from, *to);
        }
        ExecutionResult {
            exit: ExitKind::Ok,
            exec_us: 200,
            crash: None,
            edges_observed: self.edges_per_run.len() as u64,
        }
    }
    fn reset(&mut self) {
        self.map.clear();
    }
    fn map(&self) -> &CoverageMap {
        &self.map
    }
}

fn drive_session_and_check_artifacts(tmp: &TempDir, enqueue_n: usize) {
    let out_dir = tmp.path().to_path_buf();
    let queue_dir = out_dir.join("queue");
    let corpus = Arc::new(Mutex::new(FuzzCorpus::open(&queue_dir).unwrap()));
    let global = Arc::new(Mutex::new(CoverageMap::new()));

    let mut dag = ExprDag::new();
    let sym = dag.intern_symbol("input_b0");
    let v = dag.intern(Expr::Var {
        name: sym,
        sort: Sort::Bv(8),
    });
    let c = dag.intern(Expr::BvConst {
        value: 0x7F,
        bits: 8,
    });
    let target = dag.intern(Expr::Eq(v, c));

    let sat_report = SolveReport {
        status: SolveStatus::Sat,
        time_ms: 1,
        // 2-byte model — matches the FrontierItem.input_bytes below.
        input_model: Some(vec![0x7F, 0x00]),
        smt2: "(set-logic QF_BV)\n(check-sat)\n".to_string(),
        reason: None,
        unsat_core: vec![],
        unsat_assumptions_returned: false,
        backend: "smoke_const",
    };
    let ladder = SolveLadder::new(vec![LadderBackend {
        tier: SolveTier::PureFast,
        backend: Box::new(ConstSatBackend(sat_report)),
        slice: false,
        timeout: Duration::from_millis(0),
    }]);

    let mut session = ConcolicSession::with_ladder(
        out_dir.clone(),
        ConcolicOptions::default(),
        corpus,
        global,
        ladder,
    );

    for i in 0..enqueue_n {
        let pc = 0x4000 + (i as u64) * 0x100;
        session.enqueue(FrontierItem {
            path_id: format!("con:{pc:x}:{i:04}"),
            branch_pc: pc,
            branch_index: i as u32,
            depth: 1,
            hit_count: 0,
            expr_complexity: 2,
            last_solver_ms: None,
            novelty_score: 0.5,
            origin_seed_id: "seed_smoke".into(),
            reachability_distance: 0,
            rhs_is_concrete: true,
            prior_timeouts: 0,
            target_branch: target,
            path_constraints: vec![],
            input_bytes: 2,
            want_taken: true,
            expected_flip_pc: Some(pc + 4),
        });
    }

    // Each pc gets two fresh edges:
    // (a) a prev → branch_pc edge so reached_target_pc is true;
    // (b) a branch_pc → flip_pc edge so branch_flipped is true.
    // Together these drive the validator to NewCoverageConfirmed,
    // which triggers a corpus promotion (and a coverage.jsonl row).
    let edges: Vec<(u64, u64)> = (0..enqueue_n)
        .flat_map(|i| {
            let pc = 0x4000 + (i as u64) * 0x100;
            [(pc - 4, pc), (pc, pc + 4)]
        })
        .collect();
    let mut executor = SmokeExecutor::new(edges);
    let report = session.run_until_drained(&mut executor, &mut dag).unwrap();
    assert_eq!(report.solves_attempted as usize, enqueue_n);
    assert_eq!(report.solves_sat as usize, enqueue_n);

    // Artifact sanity.
    assert!(out_dir.join("concolic/solves.jsonl").exists());
    assert!(out_dir.join("concolic/exprs.jsonl").exists());
    assert!(out_dir.join("concolic/branches.jsonl").exists());
    assert!(out_dir.join("concolic/traces.jsonl").exists());
    assert!(out_dir.join("concolic/coverage.jsonl").exists());
    assert!(out_dir.join("concolic/smt2").is_dir());
    assert!(out_dir.join("concolic/run_status.json").exists());

    // The solves.jsonl should have one record per enqueued item.
    let raw = std::fs::read_to_string(out_dir.join("concolic/solves.jsonl")).unwrap();
    assert_eq!(raw.lines().count(), enqueue_n);
}

#[test]
fn end_to_end_session_writes_all_six_artifacts_and_ledger() {
    let tmp = TempDir::new().unwrap();
    drive_session_and_check_artifacts(&tmp, 3);
}

#[test]
fn empty_session_still_writes_ledger_and_all_empty_artifact_files() {
    let tmp = TempDir::new().unwrap();
    drive_session_and_check_artifacts(&tmp, 0);
    // Empty session: ledger present, jsonl files exist but empty.
    let raw = std::fs::read_to_string(tmp.path().join("concolic/solves.jsonl")).unwrap();
    assert!(raw.is_empty());
}

#[test]
fn concolic_artifact_index_entries_off_mode_returns_empty() {
    let tmp = TempDir::new().unwrap();
    // No ledger written yet.
    let entries = concolic_artifact_index_entries(&tmp.path().join("concolic"), "off");
    assert!(entries.is_empty());
}

#[test]
fn concolic_artifact_index_entries_missing_ledger_returns_empty() {
    let tmp = TempDir::new().unwrap();
    // mode != "off", but no ledger on disk.
    let entries = concolic_artifact_index_entries(&tmp.path().join("concolic"), "on");
    assert!(entries.is_empty());
}

#[test]
fn manifest_entries_registers_run_status_first_then_six_artifacts() {
    let tmp = TempDir::new().unwrap();
    drive_session_and_check_artifacts(&tmp, 2);
    let entries = concolic_artifact_index_entries(&tmp.path().join("concolic"), "on");
    // 7 entries: 1 run_status + 6 artifacts (smt2 + 5 jsonl).
    assert_eq!(
        entries.len(),
        7,
        "{:?}",
        entries.iter().map(|e| &e.path).collect::<Vec<_>>()
    );
    assert_eq!(entries[0].path, "concolic/run_status.json");
    assert_eq!(entries[0].kind, "concolic_run_status");

    // All 6 artifact kinds present.
    let kinds: std::collections::HashSet<&str> =
        entries.iter().skip(1).map(|e| e.kind.as_str()).collect();
    for expected in &[
        "concolic_solves",
        "concolic_exprs",
        "concolic_branches",
        "concolic_traces",
        "concolic_coverage",
        "concolic_smt2_dir",
    ] {
        assert!(kinds.contains(*expected), "missing kind {expected}");
    }
}

#[test]
fn promoted_model_records_appear_in_coverage_jsonl() {
    let tmp = TempDir::new().unwrap();
    drive_session_and_check_artifacts(&tmp, 1);
    let raw = std::fs::read_to_string(tmp.path().join("concolic/coverage.jsonl")).unwrap();
    // Each enqueued item triggers a SAT → validation → if novelty,
    // a CoverageRecord. SmokeExecutor records a fresh edge each
    // run, so we expect at least one promotion → one coverage record.
    assert!(
        !raw.is_empty(),
        "coverage.jsonl should record the promoted model"
    );
}

#[test]
fn _unused_imports_silencer() {
    let _ = CrashInfo::default();
}
