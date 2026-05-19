//! Dynamic-trace run-status ledger.
//!
//! Wraps the relocated shared types in `crate::run_status` with this
//! subsystem's own schema constant and the loss-policy override
//! introduced as Codex finding 3's complete fix:
//!
//! `finalize_atomic` consults [`crate::dynamic_trace::LossPolicy`]:
//! - `Warn`  → keep derived outcome unchanged (Complete possible).
//! - `Partial` (default) → if `events_dropped > 0`, force `Partial`.
//! - `Fail` → if `events_dropped > 0`, force `Failed`.
//!
//! The `run_meta` section records the exact drop count, the provider
//! bundle, and the capability-probe outcome so consumers can audit
//! why the outcome is what it is.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::atomic_write::write_atomic;
use crate::dynamic_trace::LossPolicy;
use crate::run_status::{
    derive_outcome, ArtifactStatus, ArtifactStatusEntry, RunOutcome, RunStatus,
};

pub const RUN_STATUS_SCHEMA: &str = "dynamic_trace_run_status/1";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunMeta {
    pub events_dropped: u64,
    pub providers: Vec<String>,
    pub loss_policy: String,
    pub capability_probe: Option<serde_json::Value>,
}

/// Wire shape returned by [`read_dynamic_trace_run_status`]. The
/// on-disk JSON has all the [`RunStatus`] fields at the top level
/// PLUS a sibling `run_meta` object. We deserialize by reading
/// `run_meta` separately and then RunStatus from the remaining
/// fields — avoids `#[serde(flatten)]` round-trip issues with
/// `BTreeMap`.
#[derive(Clone, Debug)]
pub struct DynamicTraceRunStatus {
    pub base: RunStatus,
    pub run_meta: RunMeta,
}

pub struct DynamicTraceRunStatusLedger {
    path: PathBuf,
    status: RunStatus,
    run_meta: RunMeta,
    loss_policy: LossPolicy,
}

impl DynamicTraceRunStatusLedger {
    pub fn create(
        out_dir: &Path,
        run_id: &str,
        started_at_ms: u128,
        loss_policy: LossPolicy,
    ) -> Self {
        let path = out_dir.join("run_status.json");
        let status = RunStatus::new(RUN_STATUS_SCHEMA, run_id, started_at_ms);
        let run_meta = RunMeta {
            events_dropped: 0,
            providers: Vec::new(),
            loss_policy: match loss_policy {
                LossPolicy::Warn => "warn".into(),
                LossPolicy::Partial => "partial".into(),
                LossPolicy::Fail => "fail".into(),
            },
            capability_probe: None,
        };
        Self {
            path,
            status,
            run_meta,
            loss_policy,
        }
    }

    pub fn mark(&mut self, name: &str, entry: ArtifactStatusEntry) {
        self.status.artifacts.insert(name.to_string(), entry);
    }

    pub fn mark_complete(&mut self, name: &str, bytes: u64, records: u64) {
        self.mark(name, ArtifactStatusEntry::complete(bytes, records));
    }

    pub fn mark_partial(&mut self, name: &str, bytes: u64, records: u64, reason: &str) {
        self.mark(name, ArtifactStatusEntry::partial(bytes, records, reason));
    }

    pub fn mark_failed(&mut self, name: &str, reason: &str) {
        self.mark(name, ArtifactStatusEntry::failed(reason));
    }

    pub fn mark_skipped(&mut self, name: &str, reason: &str) {
        self.mark(name, ArtifactStatusEntry::skipped(reason));
    }

    pub fn set_error(&mut self, msg: &str) {
        self.status.error = Some(msg.to_string());
    }

    pub fn set_events_dropped(&mut self, n: u64) {
        self.run_meta.events_dropped = n;
    }

    pub fn set_providers(&mut self, providers: Vec<String>) {
        self.run_meta.providers = providers;
    }

    pub fn set_capability_probe(&mut self, value: serde_json::Value) {
        self.run_meta.capability_probe = Some(value);
    }

    pub fn artifact(&self, name: &str) -> Option<&ArtifactStatusEntry> {
        self.status.artifacts.get(name)
    }

    pub fn artifacts(&self) -> &BTreeMap<String, ArtifactStatusEntry> {
        &self.status.artifacts
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn status(&self) -> &RunStatus {
        &self.status
    }

    pub fn run_meta(&self) -> &RunMeta {
        &self.run_meta
    }

    /// Compute the outcome (applying loss-policy override), stamp
    /// completion time, and atomically write the ledger.
    pub fn finalize_atomic(mut self, completed_at_ms: u128) -> io::Result<()> {
        self.status.completed_at_ms = Some(completed_at_ms);

        let base_outcome = derive_outcome(&self.status);
        let final_outcome =
            apply_loss_policy(base_outcome, self.loss_policy, self.run_meta.events_dropped);
        self.status.outcome = final_outcome;

        // Build the on-disk wire shape: RunStatus fields at top
        // level + sibling `run_meta` object.
        let mut base_value = serde_json::to_value(&self.status).map_err(io::Error::other)?;
        let run_meta_value = serde_json::to_value(&self.run_meta).map_err(io::Error::other)?;
        if let Some(obj) = base_value.as_object_mut() {
            obj.insert("run_meta".to_string(), run_meta_value);
        }
        let bytes = serde_json::to_vec_pretty(&base_value).map_err(io::Error::other)?;
        write_atomic(&self.path, &bytes)
    }
}

/// Apply Codex finding 3 fix: a forensic tool can't claim Complete
/// when events were dropped. The orchestrator sets the policy via
/// `--dynamic-trace-loss-policy`.
pub fn apply_loss_policy(
    derived: RunOutcome,
    policy: LossPolicy,
    events_dropped: u64,
) -> RunOutcome {
    if events_dropped == 0 {
        return derived;
    }
    match policy {
        LossPolicy::Warn => derived,
        LossPolicy::Partial => match derived {
            RunOutcome::Failed => RunOutcome::Failed,
            _ => RunOutcome::Partial,
        },
        LossPolicy::Fail => RunOutcome::Failed,
    }
}

/// Read an existing dynamic-trace `run_status.json`. Returns the
/// extended shape with `run_meta`. Falls back to `None` on any
/// I/O or parse error (caller treats as "did not finish cleanly").
pub fn read_dynamic_trace_run_status(path: &Path) -> Option<DynamicTraceRunStatus> {
    let bytes = std::fs::read(path).ok()?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let run_meta_value = value
        .as_object_mut()
        .and_then(|obj| obj.remove("run_meta"))
        .unwrap_or(serde_json::Value::Null);
    let base: RunStatus = serde_json::from_value(value).ok()?;
    let run_meta: RunMeta = serde_json::from_value(run_meta_value).unwrap_or_default();
    Some(DynamicTraceRunStatus { base, run_meta })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn schema_is_dynamic_trace_specific() {
        let tmp = TempDir::new().unwrap();
        let ledger =
            DynamicTraceRunStatusLedger::create(tmp.path(), "run-abc", 1000, LossPolicy::Partial);
        assert_eq!(ledger.status().schema, RUN_STATUS_SCHEMA);
        assert_ne!(ledger.status().schema, "fuzzer_run_status/1");
        assert_ne!(ledger.status().schema, "concolic_run_status/1");
    }

    #[test]
    fn all_complete_outcome_is_complete_with_zero_drops() {
        let tmp = TempDir::new().unwrap();
        let mut ledger =
            DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Partial);
        ledger.mark_complete("events.ndjson", 1, 1);
        ledger.finalize_atomic(1000).unwrap();
        let parsed = read_dynamic_trace_run_status(&tmp.path().join("run_status.json")).unwrap();
        assert_eq!(parsed.base.outcome, RunOutcome::Complete);
    }

    #[test]
    fn loss_policy_partial_forces_partial_outcome_when_dropped_gt_zero() {
        // All artifacts Complete, but events_dropped > 0 + Partial policy
        // → outcome MUST be forced to Partial (Codex finding 3).
        let tmp = TempDir::new().unwrap();
        let mut ledger =
            DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Partial);
        ledger.mark_complete("events.ndjson", 1, 1);
        ledger.set_events_dropped(42);
        ledger.finalize_atomic(1000).unwrap();
        let parsed = read_dynamic_trace_run_status(&tmp.path().join("run_status.json")).unwrap();
        assert_eq!(parsed.base.outcome, RunOutcome::Partial);
        assert_eq!(parsed.run_meta.events_dropped, 42);
    }

    #[test]
    fn loss_policy_fail_forces_failed_outcome_when_dropped_gt_zero() {
        let tmp = TempDir::new().unwrap();
        let mut ledger = DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Fail);
        ledger.mark_complete("events.ndjson", 1, 1);
        ledger.set_events_dropped(1);
        ledger.finalize_atomic(1000).unwrap();
        let parsed = read_dynamic_trace_run_status(&tmp.path().join("run_status.json")).unwrap();
        assert_eq!(parsed.base.outcome, RunOutcome::Failed);
    }

    #[test]
    fn loss_policy_warn_keeps_complete_outcome_when_dropped_gt_zero() {
        let tmp = TempDir::new().unwrap();
        let mut ledger = DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Warn);
        ledger.mark_complete("events.ndjson", 1, 1);
        ledger.set_events_dropped(7);
        ledger.finalize_atomic(1000).unwrap();
        let parsed = read_dynamic_trace_run_status(&tmp.path().join("run_status.json")).unwrap();
        assert_eq!(parsed.base.outcome, RunOutcome::Complete);
        assert_eq!(parsed.run_meta.events_dropped, 7);
    }

    #[test]
    fn run_meta_captures_providers_and_capability_probe() {
        let tmp = TempDir::new().unwrap();
        let mut ledger =
            DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Partial);
        ledger.mark_complete("events.ndjson", 1, 1);
        ledger.set_providers(vec!["file".into(), "registry".into()]);
        ledger.set_capability_probe(serde_json::json!({
            "elevated": true,
            "se_system_profile": "enabled",
            "probe_session": "ok_46ms"
        }));
        ledger.finalize_atomic(1000).unwrap();
        let parsed = read_dynamic_trace_run_status(&tmp.path().join("run_status.json")).unwrap();
        assert_eq!(parsed.run_meta.providers.len(), 2);
        assert!(parsed.run_meta.capability_probe.is_some());
    }

    #[test]
    fn apply_loss_policy_with_zero_drops_is_noop() {
        for outcome in [
            RunOutcome::Complete,
            RunOutcome::Partial,
            RunOutcome::Failed,
        ] {
            for policy in [LossPolicy::Warn, LossPolicy::Partial, LossPolicy::Fail] {
                assert_eq!(apply_loss_policy(outcome, policy, 0), outcome);
            }
        }
    }

    #[test]
    fn ledger_idempotent_last_write_wins() {
        let tmp = TempDir::new().unwrap();
        let mut ledger =
            DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Partial);
        ledger.mark_partial("events.ndjson", 0, 0, "first attempt");
        ledger.mark_complete("events.ndjson", 1024, 8);
        let entry = ledger.artifact("events.ndjson").unwrap();
        assert_eq!(entry.status, ArtifactStatus::Complete);
        assert_eq!(entry.bytes, 1024);
    }

    #[test]
    fn read_returns_none_for_missing_file() {
        let tmp = TempDir::new().unwrap();
        assert!(read_dynamic_trace_run_status(&tmp.path().join("missing.json")).is_none());
    }
}
