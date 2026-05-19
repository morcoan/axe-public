//! Dynamic-trace pipeline (Windows ETW v1).
//!
//! See plan `~/.claude/plans/implement-the-right-design-rippling-acorn.md`
//! for the full 21-step build order. This module ships the OS-agnostic
//! core + a Windows-only ETW collector behind two feature flags:
//!
//! - `dynamic-trace` (default off): schema, SQLite store, behavior-fact
//!   detectors, LLM evidence-pack emitters. Standalone on every platform.
//!   Does NOT imply `fuzzer` — shared utilities (`atomic_write`,
//!   `run_status` types) were extracted to feature-neutral modules in
//!   Step 2 (Codex finding 1 fix).
//! - `dynamic-trace-etw` (Windows, off by default): adds the
//!   `FerrisEtwCollector` impl plus a capability probe that gates
//!   target spawn on actual ETW provider startup (Codex finding 4 fix).
//!
//! Three architectural commitments to flag here — each addresses a
//! Codex adversarial-review finding on this plan:
//!
//! 1. **Strict loss policy** ([`LossPolicy`]). Any
//!    `events_dropped > 0` forces `outcome: "partial"` (default), or
//!    `failed`, depending on policy. Behavior facts carry an
//!    `uncertainty` annotation when emitted from a lossy stream; the
//!    evidence pack refuses to emit negative claims (e.g. "no network
//!    activity") when loss occurred. Codex finding 3 fix.
//! 2. **Detector ↔ provider coverage matrix.** v1 ships only
//!    detectors whose evidence the fixed kernel-provider bundle
//!    (file, registry, network, DNS, process, image-load) can supply.
//!    `code_injection`, LSASS access, and process-enumeration require
//!    the `Microsoft-Windows-Kernel-Object` handle provider; they are
//!    explicitly cut from v1 and tracked for v1.1. Codex finding 2 fix.
//! 3. **TraceCollector trait + provider validation spike** (lands in
//!    Step 7). The collector boundary is a trait so a raw-`windows`
//!    contingency can swap in if `ferrisetw` proves insufficient for
//!    any single provider. Codex finding 5 fix.
//!
//! # v1 operational contract
//!
//! - **Requires Administrator on Windows.** Kernel ETW providers
//!   (`EVENT_TRACE_FLAG_FILE_IO` et al.) need
//!   `SeSystemProfilePrivilege`, which is only present on elevated
//!   tokens. The [`session::run`] orchestrator calls
//!   [`privilege::capability_probe`] BEFORE spawning the target; on
//!   failure it writes `RunOutcome::Failed` with the verbatim Win32
//!   error and does NOT spawn anything.
//! - **Fixed kernel provider bundle** (see
//!   [`ProviderKind::v1_default_bundle`]): file, registry, network,
//!   DNS, process, image-load. The probe planner is deferred to v2.
//! - **Six v1 detectors** (see
//!   `behavior_facts::extract_facts`): `persistence`,
//!   `defense_evasion`, `exfil_staging`, `discovery`,
//!   `service_creation`, `browser_credential_access`. The cut
//!   detectors (`code_injection`, `lsass_credential_access`,
//!   `process_enumeration`) are listed in
//!   [`behavior_facts::V1_1_PLANNED_DETECTORS`].
//!
//! # Running the ETW smoke test
//!
//! The dedicated end-to-end test lives in
//! `tests/dynamic_trace_etw_smoke.rs` and is gated behind both
//! `#[cfg(all(windows, feature = "dynamic-trace-etw"))]` AND
//! `#[ignore]` so CI without admin doesn't false-fail. Run it from
//! an **Administrator** shell:
//!
//! ```text
//! cargo test --features dynamic-trace-etw -- \
//!     --ignored dynamic_trace_etw_smoke --test-threads=1
//! ```
//!
//! `--test-threads=1` is required: each test acquires a private ETW
//! session slot, and the system-logger budget is small.
//!
//! The per-provider validation spike (Step 7,
//! `tests/dynamic_trace_provider_probe.rs`) uses the same invocation
//! pattern but a different test name filter.
//!
//! # v2 roadmap
//!
//! - **Linux Aya/eBPF collector.** Implements [`collector::TraceCollector`]
//!   for kprobe/uprobe/tracepoint events. Schema is already
//!   OS-agnostic — only [`etw`] needs a sibling [`crate::dynamic_trace`]
//!   module.
//! - **Per-frame symbolication.** v1 only resolves `module:offset`.
//!   v1.1 adds raw-`windows` stack walking + `dbghelp` SymFromAddr.
//! - **Object handle provider.** Unlocks the cut detectors via a
//!   separate `EnableTraceEx2` enable alongside the SystemTraceProvider
//!   session.
//! - **Probe planner.** Selects providers from static analysis
//!   (existing `ApiFlowRecord`s + import table + strings).
//! - **DuckDB / Parquet store.** Drop-in replacement for SQLite when
//!   trace volume or query patterns demand columnar.

#![allow(dead_code)]

pub mod behavior_facts;
pub mod collector;
pub mod dyn_run_status;
#[cfg(all(windows, feature = "dynamic-trace-etw"))]
pub mod etw;
pub mod event;
pub mod llm_pack;
pub mod normalize;
pub mod privilege;
pub mod session;
pub mod store;
pub mod symbolicate;

use std::path::PathBuf;
use std::time::Duration;

/// Top-level options for a dynamic-trace session. Populated from CLI
/// flags in Step 16 (`--dynamic-trace-*` flag family).
#[derive(Clone, Debug)]
pub struct DynamicTraceOptions {
    /// Output directory root. The session writes
    /// `<out_dir>/{events.ndjson,entity_graph.json,behavior_facts.jsonl,
    /// behavior_fact_union.jsonl,evidence_pack.json,trace.sqlite,
    /// run_status.json}`.
    pub out_dir: PathBuf,
    /// Wall-clock cap. `None` means "run until target exits or Ctrl-C."
    pub duration: Option<Duration>,
    /// Target specification — see [`TargetSpec`].
    pub target: TargetSpec,
    /// Which ETW provider classes to subscribe. v1 default is the
    /// fixed bundle [`ProviderKind::v1_default_bundle`].
    pub providers: Vec<ProviderKind>,
    /// What to do when the ETW callback fills the consumer channel and
    /// events get dropped. See [`LossPolicy`]. v1 default: `Partial`.
    pub loss_policy: LossPolicy,
    /// Deterministic-mode RNG seed (used in offline JSONL-replay tests).
    pub seed: u64,
}

impl Default for DynamicTraceOptions {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("out/dynamic_trace"),
            duration: Some(Duration::from_secs(30)),
            target: TargetSpec::None,
            providers: ProviderKind::v1_default_bundle(),
            loss_policy: LossPolicy::Partial,
            seed: 0,
        }
    }
}

/// Which process to capture.
#[derive(Clone, Debug, Default)]
pub enum TargetSpec {
    /// No target — for tests / dry runs of the manifest pipeline.
    #[default]
    None,
    /// Attach to an already-running PID.
    Pid(u32),
    /// Spawn the given exe (via `CREATE_SUSPENDED`, then `ResumeThread`
    /// after the collector is live).
    Spawn { exe: PathBuf, args: Vec<String> },
}

/// Six v1 provider classes. Each maps to one or more
/// `EVENT_TRACE_FLAG_*` bits on the SystemTraceProvider session, OR a
/// separate `EnableTraceEx2` enable for the Object provider in v1.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderKind {
    File,
    Registry,
    Network,
    Dns,
    Process,
    ImageLoad,
}

impl ProviderKind {
    /// The fixed v1 bundle. v1.1 adds `Object` (handle events) to
    /// unlock `code_injection`, LSASS access, and process-enumeration
    /// detectors.
    pub fn v1_default_bundle() -> Vec<Self> {
        vec![
            Self::File,
            Self::Registry,
            Self::Network,
            Self::Dns,
            Self::Process,
            Self::ImageLoad,
        ]
    }

    pub fn as_csv_token(&self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Registry => "registry",
            Self::Network => "network",
            Self::Dns => "dns",
            Self::Process => "process",
            Self::ImageLoad => "image_load",
        }
    }

    pub fn from_csv_token(s: &str) -> Option<Self> {
        match s {
            "file" => Some(Self::File),
            "registry" => Some(Self::Registry),
            "network" => Some(Self::Network),
            "dns" => Some(Self::Dns),
            "process" => Some(Self::Process),
            "image_load" => Some(Self::ImageLoad),
            _ => None,
        }
    }
}

/// What to do when the bounded consumer channel fills and events get
/// dropped. **Codex finding 3 fix.**
///
/// A forensic tool that quietly emits `outcome: "complete"` while
/// having silently dropped events is worse than useless — it actively
/// misleads downstream LLM consumers. Default `Partial` makes the loss
/// visible without aborting the run; `Fail` is for high-stakes runs
/// where any drop should be treated as a session failure; `Warn`
/// keeps `Complete` outcome but stamps `run_meta.events_dropped` and
/// per-fact uncertainty (the lowest-friction mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum LossPolicy {
    /// `events_dropped > 0` → emit warning to events stream but keep
    /// `outcome: "complete"`. Behavior facts still carry an
    /// `uncertainty` annotation.
    Warn,
    /// `events_dropped > 0` → force `outcome: "partial"` regardless of
    /// per-artifact status. (Default.)
    #[default]
    Partial,
    /// `events_dropped > 0` → force `outcome: "failed"`.
    Fail,
}

impl LossPolicy {
    pub fn from_csv_token(s: &str) -> Option<Self> {
        match s {
            "warn" => Some(Self::Warn),
            "partial" => Some(Self::Partial),
            "fail" => Some(Self::Fail),
            _ => None,
        }
    }
}

/// Caller-visible summary from [`run_dynamic_trace_session`].
#[derive(Clone, Debug, Default)]
pub struct DynamicTraceReport {
    pub run_id: String,
    pub events_emitted: u64,
    pub events_dropped: u64,
    pub behavior_facts_count: u64,
    pub run_status_path: Option<PathBuf>,
}

/// Error type for dynamic-trace operations. Held intentionally narrow
/// here; per-subsystem error variants are added as their owning
/// modules land.
#[derive(Debug, thiserror::Error)]
pub enum DynamicTraceError {
    #[error("dynamic-trace session is not implemented yet (step 3 skeleton)")]
    NotImplemented,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("capability probe failed: {0}")]
    CapabilityProbe(String),
    #[error("collector failed: {0}")]
    Collector(String),
    #[error("target spawn failed: {0}")]
    TargetSpawn(String),
}

/// Run a dynamic-trace session. Delegates to [`session::run`] which
/// is OS-aware: on Windows + `dynamic-trace-etw` it runs the full
/// pipeline; otherwise it writes a `Failed` ledger so the manifest
/// has something to advertise.
pub fn run_dynamic_trace_session(
    options: &DynamicTraceOptions,
) -> Result<DynamicTraceReport, DynamicTraceError> {
    session::run(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_use_v1_bundle_and_partial_loss_policy() {
        let opts = DynamicTraceOptions::default();
        assert_eq!(opts.providers.len(), 6);
        assert!(opts.providers.contains(&ProviderKind::File));
        assert!(opts.providers.contains(&ProviderKind::Network));
        assert!(opts.providers.contains(&ProviderKind::ImageLoad));
        assert_eq!(opts.loss_policy, LossPolicy::Partial);
    }

    #[test]
    fn session_without_target_writes_run_status_and_returns_report() {
        // After Step 17 this is no longer a stub: the orchestrator
        // runs (or fails fast on the unsupported branch) and writes
        // a ledger. The report still has zero emits without a target.
        let tmp = tempfile::TempDir::new().unwrap();
        let opts = DynamicTraceOptions {
            out_dir: tmp.path().to_path_buf(),
            duration: Some(Duration::from_millis(50)),
            ..Default::default()
        };
        let result = run_dynamic_trace_session(&opts);
        // On non-Windows / no-ETW build: returns Ok with Failed ledger.
        // On Windows + ETW + not-elevated: returns Err.
        match result {
            Ok(report) => {
                assert_eq!(report.events_emitted, 0);
                assert!(report.run_status_path.is_some());
            }
            Err(_) => {
                // Capability probe failed (e.g. not elevated). Ledger
                // should still exist.
                assert!(tmp.path().join("run_status.json").exists());
            }
        }
    }

    #[test]
    fn provider_kind_csv_roundtrip() {
        for p in ProviderKind::v1_default_bundle() {
            let s = p.as_csv_token();
            assert_eq!(ProviderKind::from_csv_token(s), Some(p));
        }
        assert!(ProviderKind::from_csv_token("object").is_none());
    }

    #[test]
    fn loss_policy_csv_parse_rejects_unknown() {
        assert_eq!(LossPolicy::from_csv_token("warn"), Some(LossPolicy::Warn));
        assert_eq!(
            LossPolicy::from_csv_token("partial"),
            Some(LossPolicy::Partial)
        );
        assert_eq!(LossPolicy::from_csv_token("fail"), Some(LossPolicy::Fail));
        assert!(LossPolicy::from_csv_token("strict").is_none());
    }
}
