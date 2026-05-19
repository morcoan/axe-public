//! Aurora — generic unpacker + anti-anti-VM for axe-core.
//!
//! Takes a packed PE, executes it under controlled instrumentation
//! with anti-anti-VM and anti-debug countermeasures, traces the
//! unpacking stub via guard pages + API breakpoints, identifies the
//! Original Entry Point (OEP) via 4-signal corroboration (entropy
//! drop + execute-from-newly-allocated + function prologue scan +
//! IAT-call pattern), and dumps the unpacked memory regions as an
//! **analyzable snapshot** consumed by `PEImage::from_snapshot()`
//! back into axe-core's existing static + vuln-discovery pipeline.
//!
//! # Scope
//!
//! - **Snapshot-only output.** PE reconstruction (rebuilt IAT,
//!   fixed relocations, realigned sections, patched headers) is an
//!   explicit non-goal. The snapshot is read by the parallel
//!   constructor `PEImage::from_snapshot()` (Step 5) and analyzed by
//!   the existing pipeline — no claim of re-runnability.
//! - **Windows-only at runtime.** The module compiles on all
//!   platforms (so the wire types and helpers participate in
//!   cross-platform tests), but `run_unpack()` returns
//!   `UnpackError::UnsupportedPlatform` on non-Windows hosts. The
//!   live debugger loop, hooks, and snapshot capture are gated
//!   `#[cfg(windows)]` at the module level inside this crate.
//! - **No BYOVD.** Kernel-driver mode (opt-in `unpack-driver`
//!   feature) requires Windows test-signing mode enabled or a
//!   user-supplied EV-signed `aurora_drv.sys` build. The plan
//!   never references, recommends, or assists in loading a
//!   third-party signed driver under false pretenses.
//! - **Honest capability tiers.** Findings produced by Aurora
//!   carry a `confidence_tier` derived from the protector class:
//!   `high` for UPX/MPRESS/PECompact/ASPack/NsPack, `medium` for
//!   simple custom stubs, `best_effort` for legacy VMProtect /
//!   Themida (≤2.x). Modern VMProtect (3.x+), modern Themida
//!   (3.x+), and Denuvo are explicit non-goals.
//!
//! See `docs/unpack-capabilities.md` (written at Step 61) for the
//! full per-packer reliability matrix and per-anti-debug-surface
//! coverage.

pub mod anti_debug;
pub mod api_intercept;
pub mod breakpoints;
pub mod containment;
pub mod debug_loop;
pub mod devirt;
pub mod disasm_snapshot;
pub mod driver;
pub mod entropy_curve;
pub mod guard_pages;
pub mod hooks;
pub mod memory_map;
pub mod oep_detector;
pub mod packer_dispatch;
pub mod process_control;
pub mod region_buffer;
pub mod session;
pub mod snapshot;
pub mod snapshot_capture;
pub mod unpack_run_status;
pub mod whp;
pub mod write_log;

use std::path::PathBuf;

/// Aurora session configuration. Constructed by the CLI from
/// `--unpack-*` flags (Step 58) and passed to `run_unpack()`.
#[derive(Clone, Debug)]
pub struct UnpackOptions {
    /// `Off` is the default — `run_unpack()` returns `Skipped`
    /// without spawning the target. `On` runs the full pipeline.
    pub mode: UnpackMode,
    /// Which execution tracer to use. Default `Debug` works in any
    /// virt layer (including VMware/VBox). `Whp` requires the
    /// `unpack-whp` feature AND Hyper-V enabled on the host (which
    /// blocks VMware/VBox from using VT-x). `Driver` requires the
    /// `unpack-driver` feature AND test-signing mode. `Auto`
    /// negotiates the best available at startup.
    pub tracer_mode: TracerMode,
    /// Wall-clock kill-switch (default 60s). Crash containment
    /// preempt #8 from the plan.
    pub timeout_secs: u64,
    /// Instruction-count budget tracked via periodic `Rip` deltas
    /// (default 100M). Caps runaway execution.
    pub instr_budget: u64,
    /// Output directory. Defaults to `out/unpack/` relative to
    /// caller's working dir. Holds `unpack_provenance.json`,
    /// `run_status.json`, jsonl logs, and `regions/region_NN.bin`.
    pub out_dir: PathBuf,
    /// When `true`, the anti-anti-VM + anti-debug hook scaffolding
    /// is NOT installed before `ResumeThread`. Used for fixtures
    /// that want to observe what the target does without
    /// suppression. Default `false` (hooks installed).
    pub hooks_disable: bool,
    /// Opt-in: enable `src/unpack/devirt/` (legacy VMProtect /
    /// Themida handler-stepping). Requires `unpack-emulation`
    /// feature. Produces `best_effort` tier findings only.
    pub include_devirt: bool,
}

impl Default for UnpackOptions {
    fn default() -> Self {
        Self {
            mode: UnpackMode::Off,
            tracer_mode: TracerMode::Debug,
            timeout_secs: 60,
            instr_budget: 100_000_000,
            out_dir: PathBuf::from("out").join("unpack"),
            hooks_disable: false,
            include_devirt: false,
        }
    }
}

/// Top-level on/off switch for the Aurora session. Maps to
/// `--unpack {off,on}` on the CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnpackMode {
    Off,
    On,
}

/// Which execution tracer drives the unpacking. Maps to
/// `--unpack-tracer {debug,whp,driver,auto}` on the CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TracerMode {
    /// Windows debug API (`WaitForDebugEvent` + INT3/HW BPs +
    /// `PAGE_GUARD` memory tracing). Works in any virt layer.
    /// The default; always available when the `unpack` feature
    /// is enabled on Windows.
    Debug,
    /// Windows Hypervisor Platform — guest-mode binary execution
    /// with EPT violations replacing software guard pages, and
    /// CPUID/RDTSC normalization for stealth. Requires
    /// `unpack-whp` feature AND Hyper-V enabled on the host.
    Whp,
    /// Kernel-driver mode — VM-artifact hiding at the syscall
    /// layer (process enumeration, registry reads, device opens).
    /// Requires `unpack-driver` feature AND test-signing mode
    /// or user-EV-signed `aurora_drv.sys`.
    Driver,
    /// Pick the best available tracer at startup based on
    /// detected host capabilities (Hyper-V presence,
    /// test-signing state). Falls back to `Debug` if no
    /// higher tracer is usable.
    Auto,
}

/// Result of an Aurora session. Returned by `run_unpack()`.
#[derive(Clone, Debug)]
pub struct UnpackReport {
    pub outcome: UnpackOutcome,
    /// Path to the emitted `unpack_provenance.json`, when present.
    /// `None` for `Skipped` / pre-emit `Failed`.
    pub snapshot_path: Option<PathBuf>,
    /// Number of memory regions captured to `regions/region_NN.bin`.
    pub regions_dumped: usize,
    /// Highest OEP-candidate corroboration score across the run
    /// (range `0.0..=1.0`). `0.0` when no OEP was detected.
    pub top_oep_confidence: f64,
}

/// Coarse outcome classification used by the run-status ledger
/// and by callers deciding whether to chain `axe-core`'s static
/// re-analysis on top of the snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnpackOutcome {
    /// Full pipeline ran: spawn → debug → memory trace → OEP
    /// detected → snapshot emitted → manifest finalized.
    Complete,
    /// Some artifacts emitted but the run was truncated (timeout
    /// or instr-budget hit). Snapshot may be incomplete; OEP may
    /// be a best-guess candidate rather than confirmed.
    Partial,
    /// `UnpackMode::Off`, or platform unsupported. No work done.
    Skipped,
    /// Hard failure before any artifact landed (target failed to
    /// spawn, debugger attach refused, etc.).
    Failed,
}

/// Errors surfaced from an Aurora session. Most variants are
/// added in later steps as the live debugger loop, hooks, WHP
/// tracer, and driver mode are implemented.
#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    #[error("Aurora is Windows-only; this build is running on a non-Windows host")]
    UnsupportedPlatform,
    #[error("input binary not found: {0}")]
    InputNotFound(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unpack-whp feature requested but not compiled in")]
    WhpFeatureMissing,
    #[error("unpack-driver feature requested but not compiled in")]
    DriverFeatureMissing,
    #[error("unpack-emulation feature requested but not compiled in")]
    EmulationFeatureMissing,
    /// Reserved for richer failures emitted from later steps
    /// (e.g. `process_control.rs`, `debug_loop.rs`). Keeps the
    /// `match` exhaustive without forcing premature variant
    /// definitions.
    #[error("unpack pipeline error: {0}")]
    Pipeline(String),
}

/// Aurora entry point. Stub until `session.rs` lands at Step 54.
///
/// Today this returns:
/// - `Skipped` when `options.mode == Off` (default), regardless
///   of platform.
/// - `UnsupportedPlatform` on non-Windows hosts when mode is `On`.
/// - `Complete` with empty report on Windows hosts when mode is
///   `On` — a placeholder until the real pipeline lands.
///
/// At Step 54, this dispatches to:
/// - `session::run_debug_mode(...)` for `TracerMode::Debug`
/// - `session::run_whp_mode(...)` for `TracerMode::Whp` (gated
///   `unpack-whp`; returns `WhpFeatureMissing` otherwise)
/// - `session::run_driver_mode(...)` for `TracerMode::Driver`
///   (gated `unpack-driver`; returns `DriverFeatureMissing`
///   otherwise)
/// - `session::resolve_auto(...)` for `TracerMode::Auto` (picks
///   the best available based on host capability probe)
pub fn run_unpack(
    input_path: &std::path::Path,
    options: &UnpackOptions,
) -> Result<UnpackReport, UnpackError> {
    if matches!(options.mode, UnpackMode::Off) {
        return Ok(UnpackReport {
            outcome: UnpackOutcome::Skipped,
            snapshot_path: None,
            regions_dumped: 0,
            top_oep_confidence: 0.0,
        });
    }

    if !input_path.exists() {
        return Err(UnpackError::InputNotFound(input_path.display().to_string()));
    }

    #[cfg(not(windows))]
    {
        let _ = (input_path, options);
        Err(UnpackError::UnsupportedPlatform)
    }
    #[cfg(windows)]
    {
        let _ = (input_path, options);
        Ok(UnpackReport {
            outcome: UnpackOutcome::Complete,
            snapshot_path: None,
            regions_dumped: 0,
            top_oep_confidence: 0.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_mode_is_off() {
        assert_eq!(UnpackOptions::default().mode, UnpackMode::Off);
    }

    #[test]
    fn default_options_tracer_is_debug() {
        assert_eq!(UnpackOptions::default().tracer_mode, TracerMode::Debug);
    }

    #[test]
    fn default_options_timeout_is_60_seconds() {
        assert_eq!(UnpackOptions::default().timeout_secs, 60);
    }

    #[test]
    fn default_options_instr_budget_is_100m() {
        assert_eq!(UnpackOptions::default().instr_budget, 100_000_000);
    }

    #[test]
    fn run_unpack_with_default_options_returns_skipped() {
        let report = run_unpack(
            std::path::Path::new("/nonexistent"),
            &UnpackOptions::default(),
        )
        .expect("Off mode must not error even on missing input");
        assert_eq!(report.outcome, UnpackOutcome::Skipped);
        assert!(report.snapshot_path.is_none());
        assert_eq!(report.regions_dumped, 0);
        assert_eq!(report.top_oep_confidence, 0.0);
    }

    #[test]
    fn run_unpack_on_returns_input_not_found_for_missing_file() {
        let opts = UnpackOptions {
            mode: UnpackMode::On,
            ..UnpackOptions::default()
        };
        let err = run_unpack(std::path::Path::new("/definitely/does/not/exist"), &opts)
            .expect_err("missing input must surface InputNotFound, not silently succeed");
        match err {
            UnpackError::InputNotFound(_) => {}
            other => panic!("expected InputNotFound, got {:?}", other),
        }
    }
}
