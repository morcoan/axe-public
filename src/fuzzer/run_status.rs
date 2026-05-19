//! Fuzzer run-status ledger — Codex finding 1 enforcement.
//!
//! `out/fuzzer/run_status.json` records the finalization state of
//! every fuzzer artifact so the analyzer's `analysis_manifest.json`
//! integration can register ONLY artifacts whose status is
//! `Complete`. Partial/failed/skipped artifacts either get a `status:
//! "partial"` field on their manifest entry or are omitted entirely.
//!
//! The reusable type vocabulary (`ArtifactStatus`,
//! `ArtifactStatusEntry`, `RunOutcome`, `RunStatus`, `derive_outcome`,
//! `read_run_status`) moved to `crate::run_status` in Step 2 of the
//! dynamic-trace plan and is re-exported below for back-compat. This
//! module retains the fuzzer-specific bits: the `RUN_STATUS_SCHEMA`
//! constant and the `RunStatusLedger` struct (which hardcodes the
//! `out/fuzzer/run_status.json` path).
//!
//! The ledger is written via [`crate::atomic_write`] so a partial
//! write never lies about state. `finalize_atomic` is the commit
//! point — drop without finalize leaves the prior version of
//! `run_status.json` (or none at all) on disk.

#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};

pub use crate::run_status::{
    derive_outcome, read_run_status, ArtifactStatus, ArtifactStatusEntry, RunOutcome, RunStatus,
};

use crate::atomic_write::write_atomic;

pub const RUN_STATUS_SCHEMA: &str = "fuzzer_run_status/1";

/// Mutable handle for incrementally marking artifact statuses across
/// the session, then atomically writing the final ledger to
/// `<out_dir>/fuzzer/run_status.json`.
pub struct RunStatusLedger {
    path: PathBuf,
    status: RunStatus,
}

impl RunStatusLedger {
    pub fn create(out_dir: &Path, run_id: &str, started_at_ms: u128) -> Self {
        let path = out_dir.join("fuzzer").join("run_status.json");
        Self {
            path,
            status: RunStatus::new(RUN_STATUS_SCHEMA, run_id, started_at_ms),
        }
    }

    /// Record an artifact's status. Idempotent — last write wins.
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

    pub fn artifact(&self, name: &str) -> Option<&ArtifactStatusEntry> {
        self.status.artifacts.get(name)
    }

    /// Compute outcome, stamp completion time, and atomically write
    /// the ledger.
    pub fn finalize_atomic(mut self, completed_at_ms: u128) -> io::Result<()> {
        self.status.completed_at_ms = Some(completed_at_ms);
        self.status.outcome = derive_outcome(&self.status);
        let bytes = serde_json::to_vec_pretty(&self.status).map_err(io::Error::other)?;
        write_atomic(&self.path, &bytes)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn status(&self) -> &RunStatus {
        &self.status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn finalize_writes_atomic_and_parses_back() {
        let tmp = TempDir::new().unwrap();
        let mut ledger = RunStatusLedger::create(tmp.path(), "run-abc", 1000);
        ledger.mark_complete("events.ndjson", 1024, 8);
        ledger.mark_complete("findings.jsonl", 256, 2);
        ledger.mark_skipped("corpus.sqlite", "feature off");
        ledger.finalize_atomic(2000).unwrap();

        let path = tmp.path().join("fuzzer").join("run_status.json");
        assert!(path.exists());
        let s = read_run_status(&path).unwrap();
        assert_eq!(s.schema, RUN_STATUS_SCHEMA);
        assert_eq!(s.run_id, "run-abc");
        assert_eq!(s.outcome, RunOutcome::Partial); // skip + complete = partial
        assert_eq!(s.artifacts.len(), 3);
        assert_eq!(
            s.artifacts["events.ndjson"].status,
            ArtifactStatus::Complete
        );
        assert_eq!(s.artifacts["corpus.sqlite"].status, ArtifactStatus::Skipped);
        assert_eq!(s.completed_at_ms, Some(2000));
    }

    #[test]
    fn ledger_mark_is_idempotent_with_last_write_wins() {
        let tmp = TempDir::new().unwrap();
        let mut ledger = RunStatusLedger::create(tmp.path(), "r", 0);
        ledger.mark_partial("x", 0, 0, "first attempt");
        ledger.mark_complete("x", 1024, 8);
        let entry = ledger.artifact("x").unwrap();
        assert_eq!(entry.status, ArtifactStatus::Complete);
        assert_eq!(entry.bytes, 1024);
    }
}
