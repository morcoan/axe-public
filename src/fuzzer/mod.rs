//! Coverage-guided fuzzer with LLM-friendly telemetry.
//!
//! See plan `~/.claude/plans/implement-the-right-design-rippling-acorn.md`
//! for the full architecture and 18-step build order. Step 1 (this file)
//! lands only the module skeleton and public type vocabulary; subsequent
//! steps implement the per-subsystem modules and wire them up to a
//! working fuzz session.
//!
//! Two architectural decisions deserve calling out at the module root,
//! because they shape how the rest of the tree fits together — both
//! came out of the Codex adversarial review of this plan:
//!
//! 1. **Per-artifact atomic finalization**: every artifact this fuzzer
//!    emits (`events.ndjson`, `findings.jsonl`, `corpus.sqlite`,
//!    `frontier.md`, `summary.json`) is written via
//!    [`atomic_write`](atomic_write) — temp-write + fsync + rename —
//!    and its status is recorded in [`run_status`](run_status). The
//!    `analysis_manifest.json` integration reads `run_status.json` and
//!    only advertises artifacts whose status is `complete`. This means
//!    a fuzz run that dies mid-finalize cannot lie about what's on
//!    disk: the manifest reflects the real state, with `status:
//!    "partial"` markers when applicable.
//!
//! 2. **Crash-authoritative emulator**: [`InProcessExecutor`] (added in
//!    step 17) is the high-throughput coverage path, but it explicitly
//!    has **no crash trust**. A crash detected by InProcess triggers an
//!    immediate replay under [`EmulatorExecutor`] (which cannot itself
//!    crash — it's an interpreter returning `Result`), and the
//!    EmulatorExecutor replay is what owns the `Finding` write. Every
//!    candidate input is persisted via [`staging`](staging) before
//!    execution so a parent-process crash can recover the lost input
//!    on the next session via `staging::recover_orphans`.

#![allow(dead_code)]

pub mod atomic_write;
pub mod corpus;
pub mod coverage;
pub mod crash;
pub mod executor;
pub mod harness;
pub mod llm_export;
pub mod mutators;
pub mod reachability;
pub mod run_status;
pub mod scheduler;
pub mod session;
pub mod sqlite_db;
pub mod staging;
pub mod symbols;
pub mod targets;

use std::path::PathBuf;
use std::time::Duration;

/// Top-level options for a fuzz session. Built from CLI flags
/// (`--fuzz-engine coverage --fuzz-backend ...`) in step 15.
#[derive(Clone, Debug)]
pub struct FuzzOptions {
    pub backend: FuzzBackend,
    pub iterations: usize,
    pub time_budget: Option<Duration>,
    pub max_input_len: usize,
    pub seed: u64,
    pub corpus_dir: Option<PathBuf>,
    pub dict_path: Option<PathBuf>,
    pub user_targets: Vec<String>,
}

impl Default for FuzzOptions {
    fn default() -> Self {
        Self {
            backend: FuzzBackend::Emulator,
            iterations: 0,
            time_budget: None,
            max_input_len: 4096,
            seed: 0,
            corpus_dir: None,
            dict_path: None,
            user_targets: Vec::new(),
        }
    }
}

/// Which executor backend drives the fuzz loop.
///
/// - [`Emulator`](FuzzBackend::Emulator): wraps the in-tree
///   `crate::native_emulator` interpreter. Crash-authoritative (cannot
///   itself crash) and works on binary-only targets that axe-core
///   already analyzes. Slower than InProcess (~100–1000 exec/s).
/// - [`InProcess`](FuzzBackend::InProcess): LibAFL + SanitizerCoverage
///   in-process Rust harness execution. Fast (~100k exec/s) but
///   crash-unsafe — a SIGSEGV kills the writers. Use only when speed
///   matters more than crash trust.
/// - [`Hybrid`](FuzzBackend::Hybrid): InProcess for coverage growth,
///   EmulatorExecutor for crash replay + persistence. Best of both;
///   added in step 18.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuzzBackend {
    InProcess,
    Emulator,
    Hybrid,
}

/// Outcome summary from [`run_fuzz_session`]. The full per-iteration
/// stream goes to `out/fuzzer/events.ndjson`; this struct is the
/// caller-visible top-of-funnel summary.
#[derive(Clone, Debug, Default)]
pub struct FuzzReport {
    pub run_id: String,
    pub iterations: u64,
    pub edges_covered: u64,
    pub unique_crashes: u32,
    pub unique_hangs: u32,
    pub frontier_path: Option<PathBuf>,
}

/// Input contract for `run_fuzz_session`. Aggregates references to the
/// analyzer's already-produced records so the fuzzer doesn't re-analyze
/// the binary. The struct is intentionally empty at step 1 — fields are
/// added in step 8 (session.rs) when the loop actually consumes them.
#[derive(Default)]
pub struct FuzzerInput<'a> {
    pub out_dir: Option<&'a std::path::Path>,
    pub opts: FuzzOptions,
}

/// Run a coverage-guided fuzz session.
///
/// Step 1 ships a stub that returns `Ok(FuzzReport::default())` without
/// doing any work — the function exists so `pe.rs` can `#[cfg]`-gate
/// the call site once the CLI flag is wired in step 15. Real work
/// lands in step 8 (minimal loop) and is filled out through step 18.
pub fn run_fuzz_session(_input: &FuzzerInput<'_>) -> Result<FuzzReport, FuzzerError> {
    Ok(FuzzReport::default())
}

/// Error type for fuzzer operations. Held intentionally narrow at step
/// 1; per-subsystem error variants are added as their owning modules
/// land (e.g. `Executor`, `Corpus`, `Crash`, `RunStatus`).
#[derive(Debug, thiserror::Error)]
pub enum FuzzerError {
    #[error("fuzzer is not implemented yet (step 1 skeleton)")]
    NotImplemented,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}
