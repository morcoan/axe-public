//! `SmtBackend` trait + query/report types shared by every solver
//! impl (`PureRustFastSolver`, `Z3InProcessBackend`,
//! `Z3ExternalSmt2Backend`).
//!
//! The trait deliberately holds no Z3 types — `dyn SmtBackend` is
//! the abstraction the ladder uses to cascade across tiers. Even
//! the Z3-feature-gated backends conform to this trait so callers
//! never need to know which backend produced a [`SolveReport`].

#![allow(dead_code)]

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::concolic::expr::{ExprDag, NodeId};

/// The query handed to a backend's `solve_branch` call.
#[derive(Clone, Debug)]
pub struct BranchQuery {
    /// Number of symbolic input bytes; backends pre-declare
    /// `input_b0`..`input_b<N-1>` as 8-bit BVs.
    pub input_bytes: u32,
    /// Path constraints (each a Bool NodeId in the DAG). The slicer
    /// (`src/concolic/slicer.rs`) reduces the full path down to only
    /// the constraints reachable from `target_branch`.
    pub path_constraints: Vec<NodeId>,
    /// The Bool NodeId for the branch we want to flip.
    pub target_branch: NodeId,
    /// `true` → assert `target_branch`; `false` → assert `Not(target_branch)`.
    pub want_taken: bool,
    /// Wall-clock cap. Ignored by backends that don't support it.
    pub timeout: Duration,
    /// Preferred SMT-LIB logic (e.g. `"QF_BV"`, `"QF_ABV"`). The
    /// backend MAY fall back to a more general logic if the preferred
    /// one isn't supported.
    pub prefer_logic: Option<&'static str>,
}

/// Coarse outcome of a single `solve_branch` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SolveStatus {
    /// Backend found a model. `SolveReport::input_model` populated.
    Sat,
    /// Backend proved the constraints are unsatisfiable.
    Unsat,
    /// Backend gave up without a definitive answer (no timeout).
    Unknown,
    /// Backend hit the wall-clock cap.
    Timeout,
    /// Lowering / parsing / protocol error. NOT a satisfiability answer.
    LoweringError,
}

/// One backend's verdict on one `BranchQuery`.
#[derive(Clone, Debug, Serialize)]
pub struct SolveReport {
    pub status: SolveStatus,
    pub time_ms: u64,
    /// Concrete input bytes from the model (when `status == Sat`).
    pub input_model: Option<Vec<u8>>,
    /// The SMT-LIB query text the backend received. Always populated
    /// so a failed solve can be replayed offline via
    /// `z3 -smt2 path.smt2`.
    pub smt2: String,
    /// Human-readable reason for non-Sat outcomes
    /// (e.g. `"timeout"`, `"unsupported_feature"`).
    pub reason: Option<String>,
    /// NodeIds of constraints in the unsat core, when the backend
    /// produced one. Empty otherwise.
    pub unsat_core: Vec<NodeId>,
    /// **Codex finding 3 enforcement**: `true` ONLY when the backend
    /// returned an `Unsat` outcome with named assumptions AND a
    /// non-empty `unsat_core` reverse-mapped to known NodeIds. The
    /// ladder uses this as the gate for labeling a branch
    /// authoritatively unreachable. Bare `Unsat` from a backend
    /// without core support has this set to `false`.
    pub unsat_assumptions_returned: bool,
    /// Which backend produced this report (e.g. `"pure_rust"`,
    /// `"z3_in_process"`, `"z3_external_smt2"`).
    pub backend: &'static str,
}

impl SolveReport {
    /// `true` if this report meets the authoritative-unreachable bar.
    /// See `SolveReport::unsat_assumptions_returned`.
    pub fn is_authoritative_unreachable(&self) -> bool {
        self.status == SolveStatus::Unsat
            && self.unsat_assumptions_returned
            && !self.unsat_core.is_empty()
    }
}

/// Error returned by lowering helpers (Expr DAG → backend AST).
#[derive(Clone, Debug, thiserror::Error)]
pub enum LoweringError {
    #[error("BV binop '{op}' width mismatch: lhs={lhs}, rhs={rhs}")]
    WidthMismatch {
        op: &'static str,
        lhs: u32,
        rhs: u32,
    },
    #[error("unsupported Expr variant for backend '{backend}': {detail}")]
    UnsupportedExpr {
        backend: &'static str,
        detail: String,
    },
    #[error("symbol '{name}' not bound during lowering")]
    UnboundSymbol { name: String },
    #[error("backend protocol error: {0}")]
    Protocol(String),
}

/// The common abstraction every SMT backend implements.
///
/// `&mut self` so backends that hold resettable state (Z3 `Solver`,
/// per-query `Context`) can reuse it across calls if they choose.
pub trait SmtBackend {
    /// Lower the query and run the backend. Always returns a
    /// `SolveReport` — even error paths produce one with
    /// `status: LoweringError` or `Unknown` and an explanatory
    /// `reason`.
    fn solve_branch(&mut self, query: &BranchQuery, dag: &ExprDag) -> SolveReport;

    /// Emit the SMT-LIB text the backend would solve. Always
    /// available — used to write `out/concolic/smt2/path_NNNN.smt2`
    /// files for offline replay regardless of solve outcome.
    fn dump_smt2(&self, query: &BranchQuery, dag: &ExprDag) -> String;

    /// Stable identifier for telemetry: `"pure_rust"`,
    /// `"z3_in_process"`, `"z3_external_smt2"`.
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_report(status: SolveStatus, backend: &'static str) -> SolveReport {
        SolveReport {
            status,
            time_ms: 0,
            input_model: None,
            smt2: String::new(),
            reason: None,
            unsat_core: Vec::new(),
            unsat_assumptions_returned: false,
            backend,
        }
    }

    #[test]
    fn authoritative_unreachable_requires_all_three_conditions() {
        let mut r = empty_report(SolveStatus::Unsat, "z3");
        // Unsat but no core: NOT authoritative.
        assert!(!r.is_authoritative_unreachable());

        // Unsat with core but flag false: NOT authoritative.
        r.unsat_core = vec![1, 2];
        assert!(!r.is_authoritative_unreachable());

        // Unsat with core AND flag true: authoritative.
        r.unsat_assumptions_returned = true;
        assert!(r.is_authoritative_unreachable());

        // Flip to Sat: NOT authoritative regardless.
        r.status = SolveStatus::Sat;
        assert!(!r.is_authoritative_unreachable());
    }

    #[test]
    fn empty_core_disqualifies_even_with_flag_set() {
        let mut r = empty_report(SolveStatus::Unsat, "z3");
        r.unsat_assumptions_returned = true;
        // Empty core (perhaps backend bug or trivial unsat): NOT authoritative.
        assert!(!r.is_authoritative_unreachable());
    }

    #[test]
    fn serde_roundtrip_status() {
        let s = serde_json::to_string(&SolveStatus::Sat).unwrap();
        assert_eq!(s, "\"sat\"");
        let back: SolveStatus = serde_json::from_str(&s).unwrap();
        assert_eq!(back, SolveStatus::Sat);
    }
}
