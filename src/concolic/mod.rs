//! Hybrid concolic executor with Z3 SMT backend.
//!
//! Layered on top of the existing bounded `src/symbolic_solver.rs`
//! (which stays untouched). The new engine maintains a canonical
//! hash-consed [`expr::ExprDag`] of symbolic constraints, lowers
//! them through a stable [`backend::SmtBackend`] trait, and
//! re-executes Z3-produced models to confirm coverage before
//! promoting them to the fuzzer corpus.
//!
//! Three architectural choices to flag at the module root — each
//! addresses a Codex adversarial-review finding on this plan:
//!
//! 1. **Shadow-state-tracking emulator** (`shadow_state` +
//!    `shadow_emulator`, steps 3-4) propagates `Expr` NodeIds per
//!    register and per memory byte through every supported
//!    instruction. Branch events carry NodeIds, not strings — that's
//!    what lets the engine recover symbolic shifts, memory loads,
//!    multi-byte reconstruction, and checksum arithmetic.
//!
//! 2. **Transactional promotion** in
//!    `fuzzer_bridge::CorpusBridge::promote_if_novel` (step 18):
//!    `classify_against_snapshot` (read-only) → `staging::stage`
//!    (durable) → `corpus.add` (durable) → `merge_into_global`
//!    (mutates shared map LAST). Any failure short-circuits without
//!    polluting the fuzzer's coverage view.
//!
//! 3. **Authoritative branch-unreachable discipline** in
//!    `ladder::SolveLadder` (step 13): ONLY tier ≥ 3 `Unsat` with
//!    `unsat_assumptions_returned == true` AND a non-empty `unsat_core`
//!    may label a branch unreachable. Bare `Unsat` from the external
//!    backend without a parsed core is downgraded to `Unknown`.

#![allow(dead_code)]

pub mod backend;
pub mod expr;
pub mod fuzzer_bridge;
pub mod ladder;
pub mod llm_export;
#[cfg(feature = "concolic-z3-inproc")]
pub mod lowering;
pub mod predicate;
pub mod pure_rust;
pub mod run_status;
pub mod scheduler;
pub mod session;
pub mod shadow_emulator;
pub mod shadow_state;
pub mod slicer;
pub mod smt2_backend;
pub mod smt2_emit;
pub mod validator;
#[cfg(feature = "concolic-z3-inproc")]
pub mod z3_backend;

use std::path::PathBuf;
use std::time::Duration;

/// Top-level options for a concolic session.
#[derive(Clone, Debug)]
pub struct ConcolicOptions {
    pub time_budget: Option<Duration>,
    pub max_input_len: usize,
    pub seed: u64,
    pub z3_quick_ms: u64,
    pub z3_sliced_ms: u64,
    pub z3_external_ms: u64,
    pub user_targets: Vec<String>,
    pub max_promotions_per_solve: usize,
    pub out_dir: Option<PathBuf>,
}

impl Default for ConcolicOptions {
    fn default() -> Self {
        Self {
            time_budget: None,
            max_input_len: 4096,
            seed: 0,
            z3_quick_ms: 250,
            z3_sliced_ms: 1_000,
            z3_external_ms: 10_000,
            user_targets: Vec::new(),
            max_promotions_per_solve: 1,
            out_dir: None,
        }
    }
}

/// Caller-visible summary from [`run_concolic_session`].
#[derive(Clone, Debug, Default)]
pub struct ConcolicReport {
    pub run_id: String,
    pub solves_attempted: u64,
    pub solves_sat: u64,
    pub solves_unsat: u64,
    pub solves_unknown: u64,
    pub solves_timeout: u64,
    pub models_promoted_to_corpus: u64,
    pub crashes_found: u64,
    pub run_status_path: Option<PathBuf>,
}

/// Error type for concolic operations.
#[derive(Debug, thiserror::Error)]
pub enum ConcolicError {
    #[error("concolic engine is not implemented yet (step 1 skeleton)")]
    NotImplemented,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("type error in symbolic IR: {0}")]
    TypeError(String),
}

/// Run a concolic session. Step 1 ships a stub that returns
/// `Ok(ConcolicReport::default())` so callers (`portable.rs`) can
/// `#[cfg]`-gate the call site once the CLI flag is wired in step 20.
/// Real work lands in step 19 (`session.rs`).
pub fn run_concolic_session(_options: &ConcolicOptions) -> Result<ConcolicReport, ConcolicError> {
    Ok(ConcolicReport::default())
}
