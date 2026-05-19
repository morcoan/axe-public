//! Vulnerability-discovery pipeline (v1.0 static-only; v1.1 adds
//! dynamic confirmation, harness synthesis, analyst, lifetime).
//!
//! See `~/.claude/plans/implement-the-right-design-rippling-acorn.md`
//! for the full 36-step build order (v1.0 = Steps 0-24, v1.1 = Steps
//! 25-36). v1.0 ships standalone with its own end-to-end smoke at
//! Step 24; v1.1 is gated by real-binary calibration documented in
//! `docs/vuln-calibration.md`.
//!
//! Three architectural commitments to flag at the module root — each
//! addresses a Codex round-1 adversarial-review finding on the plan:
//!
//! 1. **Per-chain dynamic-evidence attribution** (v1.1
//!    `dynamic_evidence.rs`, Codex finding 1). Aggregate
//!    `FuzzReport` fields and "a trace event in this process" cannot
//!    prove a candidate chain — they add ZERO confidence. Only
//!    `DynamicEvidence` records with `chain_id` + `sink_pc` matching
//!    the chain count toward scoring.
//! 2. **Skeleton-by-default harnesses** (v1.1 `harness_synth.rs`,
//!    Codex finding 2). Binary-only PE entries ALWAYS get Skeleton.
//!    The `Runnable` tier requires a source-available registered
//!    `fn(&[u8])` harness AND an end-to-end verification PASS proving
//!    the harness reaches the intended sink.
//! 3. **Lifetime templates opt-in only** (v1.1 `templates/lifetime.rs`,
//!    Codex finding 3). UAF and double-free are gated at compile time
//!    AND at runtime (`--vuln-include-lifetime`). They emit to a
//!    separate `lifetime_candidates.jsonl` artifact and are EXCLUDED
//!    from the default `evidence_bundle.json` top-N selection.
//!
//! Plus one in-place fix from Codex round 1 finding 4: v1.0 Step 7
//! refactors `src/portable.rs::dangerous_api` into a projection over
//! `crate::vuln::sinks::SinkCatalog` — single source of truth for the
//! sink list.

#![allow(dead_code)]

pub mod alias;
pub mod bug_class;
pub mod call_summaries;
#[cfg(feature = "vuln-discovery-concolic")]
pub mod concolic_query;
pub mod confirmation;
pub mod controlled_confirm;
pub mod dominator;
pub mod dynamic_attempt;
pub mod dynamic_evidence;
pub mod dynamic_orchestrator;
pub mod finding;
#[cfg(feature = "vuln-discovery-fuzz")]
pub mod fuzz_bridge;
pub mod graph;
pub mod graph_builder;
pub mod guards;
pub mod harness_synth;
pub mod harness_verify;
pub mod llm_analyst;
pub mod llm_pack;
pub mod proof_packet;
pub mod query;
pub mod ranges;
pub mod reachability;
pub mod scoring;
pub mod session;
pub mod sinks;
pub mod sources;
pub mod taint;
pub mod templates;
#[cfg(feature = "vuln-discovery-trace")]
pub mod trace_join;
pub mod vuln_run_status;

use std::path::PathBuf;
use std::time::Duration;

use crate::vuln::dynamic_evidence::DynamicEvidence;

/// v1.1 harness-tier-emission selector. CLI flag
/// `--vuln-harness-tier {skeleton,both}` maps to this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarnessTierMode {
    /// Emit only `.skeleton.md` files; never write `.runnable.rs`.
    /// Default; honors Codex finding 2 strictly.
    SkeletonOnly,
    /// Emit `.skeleton.md` always; also write `.runnable.rs` for
    /// harnesses whose tier has been promoted to Runnable (i.e.,
    /// `verify_runnable` PASSED). Binary-only PE entries stay
    /// Skeleton regardless of this mode.
    Both,
}

impl Default for HarnessTierMode {
    fn default() -> Self {
        Self::SkeletonOnly
    }
}

/// Top-level options for a vuln-discovery session.
#[derive(Clone, Debug)]
pub struct VulnOptions {
    /// Output directory. Session writes `findings.jsonl`,
    /// `chain_graph.json`, `evidence_bundle.json`, `findings.sqlite`,
    /// `run_status.json` (v1.0) plus harness/suggestion/lifetime
    /// artifacts in v1.1.
    pub out_dir: PathBuf,
    /// Comma-separated template selector. `"all"` = full registry
    /// (12 templates in v1.0; +2 lifetime in v1.1 if include_lifetime).
    pub templates: String,
    /// Drop chains with `confidence.score < this` from manifest.
    pub confidence_threshold: f32,
    /// Wall-clock cap. `None` = no time budget.
    pub time_budget: Option<Duration>,
    /// Deterministic-mode RNG seed.
    pub seed: u64,
    /// v1.1: opt-in to lifetime templates (UAF, double-free). Always
    /// `false` in v1.0. When `true`, lifetime templates emit to a
    /// separate `lifetime_candidates.jsonl` (NOT `findings.jsonl`).
    pub include_lifetime: bool,
    /// v1.1: master switch. When `false`, the session emits the v1.0
    /// 4-artifact set (findings, chain_graph, evidence_bundle,
    /// findings.sqlite) plus the run_status ledger, with NO v1.1
    /// additions — keeps v1.0 callers' wire-shape byte-identical.
    /// When `true`, the session ALSO synthesizes harnesses, emits
    /// patch / test suggestions, optionally emits
    /// `lifetime_candidates.jsonl`, re-scores findings with
    /// `dynamic_evidence`, and uses the v1.1 evidence-bundle shape
    /// (which excludes lifetime from top-N).
    pub enable_v1_1: bool,
    /// v1.1: harness-tier emission mode.
    pub harness_tier: HarnessTierMode,
    /// v1.1: pre-collected dynamic-evidence records, typically
    /// produced by Steps 27-29 (fuzz_bridge, trace_join,
    /// concolic_query) BEFORE this session runs. The session
    /// aggregates per-chain via `confirmation::aggregate_for_chain`
    /// (Step 30) and re-scores findings via `score_chain_v1_1`
    /// (Step 32). Empty in v1.0 mode.
    pub dynamic_evidence: Vec<DynamicEvidence>,
    /// Runtime-requested dynamic source selector from
    /// `--vuln-dynamic-confirmation`. The session uses this to emit
    /// explicit per-chain unavailable evidence records when the user
    /// requested dynamic confirmation but no source produced evidence.
    pub dynamic_confirmation_sources: String,
}

impl Default for VulnOptions {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("out/vuln"),
            templates: "all".to_string(),
            confidence_threshold: 0.45,
            time_budget: None,
            seed: 0,
            include_lifetime: false,
            enable_v1_1: false,
            harness_tier: HarnessTierMode::SkeletonOnly,
            dynamic_evidence: Vec::new(),
            dynamic_confirmation_sources: "off".to_string(),
        }
    }
}

/// Caller-visible summary from [`run_vuln_discovery`].
#[derive(Clone, Debug, Default)]
pub struct VulnReport {
    pub run_id: String,
    pub chains_discovered: u64,
    pub chains_above_threshold: u64,
    pub findings_emitted: u64,
    pub templates_loaded: u32,
    pub run_status_path: Option<PathBuf>,
}

/// Error type for vuln-discovery operations.
#[derive(Debug, thiserror::Error)]
pub enum VulnError {
    #[error("vuln-discovery is not implemented yet (step 1 skeleton)")]
    NotImplemented,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("graph build error: {0}")]
    GraphBuild(String),
    #[error("template error: {0}")]
    Template(String),
}

/// Run a vuln-discovery session with empty inputs (no-op). The
/// real entry point is [`session::run`] which takes
/// [`session::VulnInputs`] populated from the caller's existing
/// analysis records.
pub fn run_vuln_discovery(options: &VulnOptions) -> Result<VulnReport, VulnError> {
    session::run(options, &session::VulnInputs::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options_use_all_templates_and_threshold_0_45() {
        let opts = VulnOptions::default();
        assert_eq!(opts.templates, "all");
        assert!((opts.confidence_threshold - 0.45).abs() < f32::EPSILON);
        // Lifetime templates are NEVER default-on in v1.0 — Codex finding 3.
        assert!(!opts.include_lifetime);
    }

    #[test]
    fn run_with_empty_inputs_writes_run_status_with_zero_chains() {
        // Step 1 originally returned a stub; Step 24 wired the real
        // session. The session writes a run_status file even with
        // empty inputs (the analyzer still emits "no findings" + a
        // ledger so consumers can distinguish "feature off" from
        // "ran but found nothing").
        let tmp = tempfile::TempDir::new().unwrap();
        let opts = VulnOptions {
            out_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let report = run_vuln_discovery(&opts).unwrap();
        assert_eq!(report.chains_discovered, 0);
        assert_eq!(report.findings_emitted, 0);
        assert!(report.run_status_path.is_some());
        assert!(tmp.path().join("run_status.json").exists());
    }
}
