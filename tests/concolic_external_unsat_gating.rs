//! Codex finding 3 regression test.
//!
//! The earlier draft gave Tier 4 ([`Z3ExternalSmt2Backend`]) the
//! same branch-unreachable authority as Tier 3 (sliced + named
//! assumptions) despite the external backend's parser only
//! recognizing `sat`/`unsat`/`unknown` + model definitions.
//!
//! The fix: bare `Unsat` without a parsed `(get-unsat-core)` reply
//! is DOWNGRADED to [`SolveStatus::Unknown`] with
//! `reason: "external_unsat_without_core"`. Only `Unsat` accompanied
//! by a parseable core sets `unsat_assumptions_returned == true` and
//! qualifies as authoritative-unreachable evidence.
//!
//! This test exercises [`parse_z3_response`] directly (so we don't
//! need a live `z3` binary on PATH) with three mock stdout payloads:
//! - sat + model              → SolveStatus::Sat
//! - bare unsat (no core)     → SolveStatus::Unknown (downgraded)
//! - unsat + parseable core   → SolveStatus::Unsat + authoritative
//!
//! And then runs both through the
//! [`crate::concolic::ladder::SolveLadder`] to confirm the bare-
//! Unsat case does NOT mark a branch unreachable.

#![cfg(feature = "concolic")]

use std::time::Duration;

use axe_core::concolic::backend::{BranchQuery, SmtBackend, SolveReport, SolveStatus};
use axe_core::concolic::expr::{Expr, ExprDag, NodeId, Sort};
use axe_core::concolic::ladder::{LadderBackend, SolveLadder, SolveTier};
use axe_core::concolic::smt2_backend::{parse_z3_response, BACKEND_NAME};
use axe_core::concolic::smt2_emit::EmittedQuery;

fn small_dag_with_target() -> (ExprDag, NodeId) {
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
    (dag, target)
}

fn query_for(target: NodeId) -> BranchQuery {
    BranchQuery {
        input_bytes: 4,
        path_constraints: vec![],
        target_branch: target,
        want_taken: true,
        timeout: Duration::from_millis(500),
        prefer_logic: Some("QF_BV"),
    }
}

fn emitted_with_targets() -> EmittedQuery {
    EmittedQuery {
        smt2: "; mock\n(check-sat)\n(get-unsat-core)\n".into(),
        // Reverse-map table the backend uses to translate c_NN → NodeIds.
        name_map: vec![
            ("c_00".into(), 11),
            ("c_TGT".into(), 99),
            ("c_01".into(), 22),
        ],
    }
}

#[test]
fn parse_z3_response_bare_unsat_downgrades_to_unknown() {
    let (_dag, target) = small_dag_with_target();
    let stdout = "unsat\n"; // No core line — the smoking-gun shape.
    let report = parse_z3_response(
        stdout.into(),
        Duration::from_millis(5),
        emitted_with_targets(),
        &query_for(target),
    );
    assert_eq!(report.status, SolveStatus::Unknown);
    assert_eq!(
        report.reason.as_deref(),
        Some("external_unsat_without_core"),
        "bare unsat must surface the gating reason"
    );
    assert!(!report.unsat_assumptions_returned);
    assert!(!report.is_authoritative_unreachable());
    assert_eq!(report.backend, BACKEND_NAME);
}

#[test]
fn parse_z3_response_unsat_with_core_is_authoritative() {
    let (_dag, target) = small_dag_with_target();
    let stdout = "unsat\n(c_00 c_TGT)\n";
    let report = parse_z3_response(
        stdout.into(),
        Duration::from_millis(5),
        emitted_with_targets(),
        &query_for(target),
    );
    assert_eq!(report.status, SolveStatus::Unsat);
    assert!(
        report.unsat_assumptions_returned,
        "named core present → assumptions_returned must be true"
    );
    assert_eq!(report.unsat_core, vec![11, 99], "c_00→11, c_TGT→99");
    assert!(report.is_authoritative_unreachable());
}

#[test]
fn parse_z3_response_unsat_with_error_after_core_call_downgrades() {
    let (_dag, target) = small_dag_with_target();
    // Z3 returned unsat but failed to produce a core (rare but
    // possible if the solver settings didn't request cores).
    let stdout = "unsat\n(error \"core not available\")\n";
    let report = parse_z3_response(
        stdout.into(),
        Duration::from_millis(5),
        emitted_with_targets(),
        &query_for(target),
    );
    assert_eq!(
        report.status,
        SolveStatus::Unknown,
        "unsat + error means we don't have an authoritative answer"
    );
    assert!(!report.is_authoritative_unreachable());
}

#[test]
fn parse_z3_response_sat_with_model_populates_input_bytes() {
    let (_dag, target) = small_dag_with_target();
    let stdout = "sat\n\
        (define-fun input_b0 () (_ BitVec 8) #x42)\n\
        (define-fun input_b3 () (_ BitVec 8) #xff)\n";
    let report = parse_z3_response(
        stdout.into(),
        Duration::from_millis(5),
        emitted_with_targets(),
        &query_for(target),
    );
    assert_eq!(report.status, SolveStatus::Sat);
    let model = report.input_model.expect("sat must yield a model");
    assert_eq!(model[0], 0x42);
    assert_eq!(model[3], 0xff);
    // unfilled bytes default to 0
    assert_eq!(model[1], 0);
    assert_eq!(model[2], 0);
}

// ───── Scripted-backend ladder tests (the critical Codex finding 3 gate) ─────

/// Stub backend that returns a pre-canned SolveReport. Used to feed
/// the ladder a "bare unsat" report and verify it does NOT mark the
/// branch unreachable.
struct ScriptedBackend {
    report: SolveReport,
}
impl SmtBackend for ScriptedBackend {
    fn solve_branch(&mut self, _q: &BranchQuery, _d: &ExprDag) -> SolveReport {
        self.report.clone()
    }
    fn dump_smt2(&self, _q: &BranchQuery, _d: &ExprDag) -> String {
        String::new()
    }
    fn name(&self) -> &'static str {
        "scripted"
    }
}

fn bare_unsat_report() -> SolveReport {
    SolveReport {
        status: SolveStatus::Unsat,
        time_ms: 50,
        input_model: None,
        smt2: String::new(),
        // The downgrade reason mimics what parse_z3_response would
        // have set, but it doesn't matter — the ladder gates on
        // unsat_assumptions_returned and unsat_core, not on the
        // string.
        reason: Some("external_unsat_without_core".into()),
        unsat_core: vec![],
        unsat_assumptions_returned: false,
        backend: "scripted",
    }
}

fn auth_unsat_report() -> SolveReport {
    let mut r = bare_unsat_report();
    r.unsat_core = vec![11, 99];
    r.unsat_assumptions_returned = true;
    r.reason = None;
    r
}

#[test]
fn ladder_does_not_mark_unreachable_for_tier_4_bare_unsat() {
    let (mut dag, target) = small_dag_with_target();
    let mut ladder = SolveLadder::new(vec![LadderBackend {
        tier: SolveTier::Z3External,
        backend: Box::new(ScriptedBackend {
            report: bare_unsat_report(),
        }),
        slice: true,
        timeout: Duration::from_millis(10_000),
    }]);
    let outcome = ladder.solve(&query_for(target), &mut dag);
    assert_eq!(outcome.final_report.status, SolveStatus::Unsat);
    assert!(
        !outcome.branch_marked_unreachable,
        "Codex finding 3: bare-unsat MUST NOT mark unreachable"
    );
}

#[test]
fn ladder_marks_unreachable_for_tier_4_with_authoritative_unsat() {
    let (mut dag, target) = small_dag_with_target();
    let mut ladder = SolveLadder::new(vec![LadderBackend {
        tier: SolveTier::Z3External,
        backend: Box::new(ScriptedBackend {
            report: auth_unsat_report(),
        }),
        slice: true,
        timeout: Duration::from_millis(10_000),
    }]);
    let outcome = ladder.solve(&query_for(target), &mut dag);
    assert_eq!(outcome.final_report.status, SolveStatus::Unsat);
    assert!(
        outcome.branch_marked_unreachable,
        "tier 4 with parseable core → authoritative unreachable"
    );
}

#[test]
fn ladder_tier_2_unsat_with_core_still_not_unreachable() {
    // Even with a parseable core, tier ≤ 2 must not mark
    // unreachable. Codex's discipline is "only tier ≥ 3."
    let (mut dag, target) = small_dag_with_target();
    let mut ladder = SolveLadder::new(vec![LadderBackend {
        tier: SolveTier::Z3Quick,
        backend: Box::new(ScriptedBackend {
            report: auth_unsat_report(),
        }),
        slice: false,
        timeout: Duration::from_millis(250),
    }]);
    let outcome = ladder.solve(&query_for(target), &mut dag);
    assert_eq!(outcome.final_report.status, SolveStatus::Unsat);
    assert!(
        !outcome.branch_marked_unreachable,
        "tier 2 NEVER marks unreachable regardless of core"
    );
}
