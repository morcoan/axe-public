//! `out/concolic/run_status.json` — per-artifact finalization ledger
//! for the concolic session.
//!
//! Schema: `"concolic_run_status/1"` (distinct from the fuzzer's
//! `"fuzzer_run_status/1"`). Otherwise byte-identical wire shape; we
//! reuse the fuzzer's [`ArtifactStatus`], [`ArtifactStatusEntry`],
//! and [`RunOutcome`] types so the analyzer's manifest integration
//! can use the same `read_run_status` parser for both.
//!
//! Why two ledgers instead of one shared ledger: concolic and fuzzer
//! run independently (often in different processes). A single ledger
//! would race on the atomic-write commit. Two distinct files,
//! distinct schemas, distinct directories — manifest readers
//! `read_run_status(out/fuzzer/run_status.json)` and
//! `read_run_status(out/concolic/run_status.json)` separately.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::fuzzer::atomic_write::write_atomic;
use crate::fuzzer::run_status::{
    read_run_status as fuzzer_read_run_status, ArtifactStatus, ArtifactStatusEntry, RunOutcome,
    RunStatus,
};

pub const RUN_STATUS_SCHEMA: &str = "concolic_run_status/1";

pub struct ConcolicRunStatusLedger {
    path: PathBuf,
    status: RunStatus,
}

impl ConcolicRunStatusLedger {
    /// Construct a ledger that will write to
    /// `out_dir/concolic/run_status.json` when finalized.
    pub fn create(out_dir: &Path, run_id: &str, started_at_ms: u128) -> Self {
        let path = out_dir.join("concolic").join("run_status.json");
        // RunStatus::new now takes the schema directly (Step 2 of the
        // dynamic-trace plan moved the shared types to crate::run_status
        // and added the schema parameter).
        let status = RunStatus::new(RUN_STATUS_SCHEMA, run_id, started_at_ms);
        Self { path, status }
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

    /// Stamp completion + derive outcome + atomic-write to disk.
    pub fn finalize_atomic(mut self, completed_at_ms: u128) -> io::Result<()> {
        self.status.completed_at_ms = Some(completed_at_ms);
        self.status.outcome = derive_outcome(&self.status);
        let bytes = serde_json::to_vec_pretty(&self.status).map_err(io::Error::other)?;
        write_atomic(&self.path, &bytes)
    }
}

/// Re-export for the manifest integration in `llm_artifacts.rs`. The
/// manifest layer uses one reader; the schema string discrimination
/// happens at the caller.
pub fn read_run_status(path: &Path) -> Option<RunStatus> {
    fuzzer_read_run_status(path)
}

/// Mirror of [`crate::fuzzer::run_status::derive_outcome`] logic.
/// The fuzzer keeps it crate-private; rather than make it pub there,
/// we inline the (one-screen) match here so the concolic side has a
/// stable contract on outcome derivation.
fn derive_outcome(s: &RunStatus) -> RunOutcome {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn ledger_writes_to_concolic_subdir_with_concolic_schema() {
        let tmp = TempDir::new().unwrap();
        let mut ledger = ConcolicRunStatusLedger::create(tmp.path(), "run-c", 1000);
        ledger.mark_complete("solves.jsonl", 1024, 4);
        ledger.finalize_atomic(2000).unwrap();

        let path = tmp.path().join("concolic").join("run_status.json");
        assert!(
            path.exists(),
            "ledger writes to out_dir/concolic/run_status.json"
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(
            raw.contains("\"schema\": \"concolic_run_status/1\""),
            "uses concolic schema (raw: {raw})"
        );
    }

    #[test]
    fn ledger_mark_is_idempotent_last_write_wins() {
        let tmp = TempDir::new().unwrap();
        let mut ledger = ConcolicRunStatusLedger::create(tmp.path(), "r", 0);
        ledger.mark_partial("solves.jsonl", 0, 0, "starting");
        ledger.mark_complete("solves.jsonl", 1024, 5);
        let entry = ledger.artifact("solves.jsonl").unwrap();
        assert_eq!(entry.status, ArtifactStatus::Complete);
        assert_eq!(entry.bytes, 1024);
        assert_eq!(entry.records, 5);
    }

    #[test]
    fn all_complete_outcome_is_complete() {
        let mut s = RunStatus::new(RUN_STATUS_SCHEMA, "r", 0);
        s.artifacts
            .insert("solves.jsonl".into(), ArtifactStatusEntry::complete(100, 5));
        s.artifacts
            .insert("exprs.jsonl".into(), ArtifactStatusEntry::complete(200, 10));
        assert_eq!(derive_outcome(&s), RunOutcome::Complete);
    }

    #[test]
    fn empty_outcome_is_failed() {
        let mut s = RunStatus::new(RUN_STATUS_SCHEMA, "r", 0);
        assert_eq!(derive_outcome(&s), RunOutcome::Failed);
    }

    #[test]
    fn complete_plus_failed_is_partial() {
        let mut s = RunStatus::new(RUN_STATUS_SCHEMA, "r", 0);
        s.artifacts
            .insert("solves.jsonl".into(), ArtifactStatusEntry::complete(100, 5));
        s.artifacts
            .insert("smt2".into(), ArtifactStatusEntry::failed("io"));
        assert_eq!(derive_outcome(&s), RunOutcome::Partial);
    }

    #[test]
    fn complete_plus_skipped_is_partial() {
        let mut s = RunStatus::new(RUN_STATUS_SCHEMA, "r", 0);
        s.artifacts
            .insert("solves.jsonl".into(), ArtifactStatusEntry::complete(100, 5));
        s.artifacts
            .insert("traces.jsonl".into(), ArtifactStatusEntry::skipped("off"));
        assert_eq!(derive_outcome(&s), RunOutcome::Partial);
    }

    #[test]
    fn read_run_status_returns_none_for_missing_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("concolic").join("run_status.json");
        assert!(read_run_status(&path).is_none());
    }

    #[test]
    fn end_to_end_finalize_then_read_back() {
        let tmp = TempDir::new().unwrap();
        let mut ledger = ConcolicRunStatusLedger::create(tmp.path(), "run-c", 1000);
        ledger.mark_complete("solves.jsonl", 1024, 4);
        ledger.mark_complete("exprs.jsonl", 256, 12);
        ledger.mark_skipped("traces.jsonl", "feature off");
        ledger.finalize_atomic(2000).unwrap();

        let path = tmp.path().join("concolic").join("run_status.json");
        let s = read_run_status(&path).unwrap();
        assert_eq!(s.schema, "concolic_run_status/1");
        assert_eq!(s.run_id, "run-c");
        assert_eq!(s.outcome, RunOutcome::Partial);
        assert_eq!(s.completed_at_ms, Some(2000));
        assert_eq!(s.artifacts.len(), 3);
    }
}
