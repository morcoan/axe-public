//! Per-artifact status ledger types — feature-neutral.
//!
//! Originally landed in `src/fuzzer/run_status.rs`. The reusable type
//! vocabulary (`ArtifactStatus`, `ArtifactStatusEntry`, `RunOutcome`,
//! `RunStatus`, `derive_outcome`, `read_run_status`) was relocated
//! here in Step 2 of the dynamic-trace plan (Codex finding 1 fix) so
//! three subsystems — `fuzzer`, `concolic`, `dynamic-trace` — can
//! share one source of truth for what "Complete" / "Partial" /
//! "Failed" mean. Each subsystem defines its own schema string
//! constant and its own concrete ledger struct (which knows where the
//! `run_status.json` lives on disk).
//!
//! The fuzzer subsystem re-exports these types from
//! `src/fuzzer/run_status.rs` for back-compat: every existing call
//! site continues to work unchanged.
//!
//! `RunStatus::outcome` is computed by [`derive_outcome`]:
//! - all `Complete` → `Complete`
//! - any `Failed` or `Partial` → `Partial`
//! - mix of `Complete` + `Skipped` → `Partial`
//! - no artifacts at all → `Failed`
//!
//! Subsystems may layer their own rules on top of `derive_outcome`
//! (e.g. dynamic-trace forces `Partial` when `events_dropped > 0`
//! regardless of per-artifact status — Codex finding 3 fix).

#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    Complete,
    Partial,
    Failed,
    Skipped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOutcome {
    /// All artifacts reported `Complete`.
    Complete,
    /// Some `Complete`, some `Failed`/`Skipped`.
    Partial,
    /// Run aborted; ledger written from a panic handler or Ctrl-C
    /// path. Artifacts may exist with truncated content.
    Failed,
}

/// Per-artifact ledger row. `bytes` and `records` are best-effort
/// (writers report what they wrote at finalize time).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactStatusEntry {
    pub status: ArtifactStatus,
    pub bytes: u64,
    pub records: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ArtifactStatusEntry {
    pub fn complete(bytes: u64, records: u64) -> Self {
        Self {
            status: ArtifactStatus::Complete,
            bytes,
            records,
            error: None,
        }
    }
    pub fn partial(bytes: u64, records: u64, reason: &str) -> Self {
        Self {
            status: ArtifactStatus::Partial,
            bytes,
            records,
            error: Some(reason.into()),
        }
    }
    pub fn failed(reason: &str) -> Self {
        Self {
            status: ArtifactStatus::Failed,
            bytes: 0,
            records: 0,
            error: Some(reason.into()),
        }
    }
    pub fn skipped(reason: &str) -> Self {
        Self {
            status: ArtifactStatus::Skipped,
            bytes: 0,
            records: 0,
            error: Some(reason.into()),
        }
    }
}

/// The full run_status.json wire shape. The `schema` field is filled
/// in by the subsystem-specific ledger using its own
/// `RUN_STATUS_SCHEMA` constant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunStatus {
    pub schema: String,
    pub run_id: String,
    pub started_at_ms: u128,
    pub completed_at_ms: Option<u128>,
    pub outcome: RunOutcome,
    pub artifacts: BTreeMap<String, ArtifactStatusEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl RunStatus {
    /// Build an in-progress `RunStatus` with the given schema string.
    /// Outcome starts pessimistic (`Failed`) and is overwritten by
    /// `derive_outcome` at finalize time.
    pub fn new(schema: &str, run_id: &str, started_at_ms: u128) -> Self {
        Self {
            schema: schema.to_string(),
            run_id: run_id.to_string(),
            started_at_ms,
            completed_at_ms: None,
            outcome: RunOutcome::Failed,
            artifacts: BTreeMap::new(),
            error: None,
        }
    }
}

/// Compute the run outcome from per-artifact statuses. See module
/// docs for the rule set.
pub fn derive_outcome(s: &RunStatus) -> RunOutcome {
    if s.artifacts.is_empty() {
        return RunOutcome::Failed;
    }
    let mut any_failed = false;
    let mut any_skipped = false;
    let mut any_complete = false;
    let mut any_partial = false;
    for entry in s.artifacts.values() {
        match entry.status {
            ArtifactStatus::Complete => any_complete = true,
            ArtifactStatus::Partial => any_partial = true,
            ArtifactStatus::Failed => any_failed = true,
            ArtifactStatus::Skipped => any_skipped = true,
        }
    }
    if any_failed || any_partial {
        RunOutcome::Partial
    } else if any_skipped && any_complete {
        RunOutcome::Partial
    } else if any_complete {
        RunOutcome::Complete
    } else {
        RunOutcome::Failed
    }
}

/// Read an existing `run_status.json` from disk. Used by manifest
/// integrations to gate artifact registration on per-artifact
/// `Complete` status. Returns `None` if the file is missing or
/// unparseable — the manifest layer handles those cases as "the run
/// did not finish cleanly enough to advertise its artifacts."
pub fn read_run_status(path: &std::path::Path) -> Option<RunStatus> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SCHEMA: &str = "test_run_status/1";

    #[test]
    fn empty_ledger_outcome_is_failed() {
        let s = RunStatus::new(TEST_SCHEMA, "r1", 1);
        assert_eq!(derive_outcome(&s), RunOutcome::Failed);
    }

    #[test]
    fn all_complete_outcome_is_complete() {
        let mut s = RunStatus::new(TEST_SCHEMA, "r1", 1);
        s.artifacts
            .insert("a".into(), ArtifactStatusEntry::complete(100, 5));
        s.artifacts
            .insert("b".into(), ArtifactStatusEntry::complete(200, 10));
        assert_eq!(derive_outcome(&s), RunOutcome::Complete);
    }

    #[test]
    fn complete_plus_failed_is_partial() {
        let mut s = RunStatus::new(TEST_SCHEMA, "r1", 1);
        s.artifacts
            .insert("a".into(), ArtifactStatusEntry::complete(100, 5));
        s.artifacts
            .insert("b".into(), ArtifactStatusEntry::failed("io"));
        assert_eq!(derive_outcome(&s), RunOutcome::Partial);
    }

    #[test]
    fn complete_plus_skipped_is_partial() {
        let mut s = RunStatus::new(TEST_SCHEMA, "r1", 1);
        s.artifacts
            .insert("a".into(), ArtifactStatusEntry::complete(100, 5));
        s.artifacts
            .insert("b".into(), ArtifactStatusEntry::skipped("not requested"));
        assert_eq!(derive_outcome(&s), RunOutcome::Partial);
    }

    #[test]
    fn read_run_status_returns_none_for_missing_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("nope.json");
        assert!(read_run_status(&path).is_none());
    }

    #[test]
    fn read_run_status_returns_none_for_corrupt_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("bad.json");
        std::fs::write(&path, b"not json at all").unwrap();
        assert!(read_run_status(&path).is_none());
    }
}
