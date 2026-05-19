//! Vuln-discovery run-status ledger.
//!
//! Same pattern as `fuzzer/run_status.rs`, `concolic/run_status.rs`,
//! and `dynamic_trace/dyn_run_status.rs`: each subsystem wraps the
//! shared `crate::run_status` types with its own schema string and
//! per-artifact gating.

#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::atomic_write::write_atomic;
use crate::run_status::{
    derive_outcome, ArtifactStatus, ArtifactStatusEntry, RunOutcome, RunStatus,
};

pub const RUN_STATUS_SCHEMA: &str = "vuln_discovery_run_status/1";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunMeta {
    pub phase: String,
    pub templates_loaded: u32,
    pub chains_discovered: u64,
    pub chains_above_threshold: u64,
    pub scoring_calibrated: bool,
}

#[derive(Clone, Debug)]
pub struct VulnRunStatus {
    pub base: RunStatus,
    pub run_meta: RunMeta,
}

pub struct VulnRunStatusLedger {
    path: PathBuf,
    status: RunStatus,
    run_meta: RunMeta,
}

impl VulnRunStatusLedger {
    pub fn create(out_dir: &Path, run_id: &str, started_at_ms: u128) -> Self {
        let path = out_dir.join("run_status.json");
        let status = RunStatus::new(RUN_STATUS_SCHEMA, run_id, started_at_ms);
        Self {
            path,
            status,
            run_meta: RunMeta {
                phase: "v1.0_static".into(),
                templates_loaded: 0,
                chains_discovered: 0,
                chains_above_threshold: 0,
                scoring_calibrated: false,
            },
        }
    }

    pub fn mark(&mut self, name: &str, entry: ArtifactStatusEntry) {
        self.status.artifacts.insert(name.to_string(), entry);
    }

    pub fn mark_complete(&mut self, name: &str, bytes: u64, records: u64) {
        self.mark(name, ArtifactStatusEntry::complete(bytes, records));
    }

    pub fn mark_failed(&mut self, name: &str, reason: &str) {
        self.mark(name, ArtifactStatusEntry::failed(reason));
    }

    pub fn mark_skipped(&mut self, name: &str, reason: &str) {
        self.mark(name, ArtifactStatusEntry::skipped(reason));
    }

    pub fn set_run_meta(&mut self, run_meta: RunMeta) {
        self.run_meta = run_meta;
    }

    pub fn artifacts(&self) -> &std::collections::BTreeMap<String, ArtifactStatusEntry> {
        &self.status.artifacts
    }

    pub fn finalize_atomic(mut self, completed_at_ms: u128) -> io::Result<()> {
        self.status.completed_at_ms = Some(completed_at_ms);
        self.status.outcome = derive_outcome(&self.status);
        let mut value = serde_json::to_value(&self.status).map_err(io::Error::other)?;
        let rm = serde_json::to_value(&self.run_meta).map_err(io::Error::other)?;
        if let Some(obj) = value.as_object_mut() {
            obj.insert("run_meta".to_string(), rm);
        }
        let bytes = serde_json::to_vec_pretty(&value).map_err(io::Error::other)?;
        write_atomic(&self.path, &bytes)
    }
}

pub fn read_vuln_run_status(path: &Path) -> Option<VulnRunStatus> {
    let bytes = std::fs::read(path).ok()?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let rm = value
        .as_object_mut()
        .and_then(|o| o.remove("run_meta"))
        .unwrap_or(serde_json::Value::Null);
    let base: RunStatus = serde_json::from_value(value).ok()?;
    let run_meta: RunMeta = serde_json::from_value(rm).unwrap_or_default();
    Some(VulnRunStatus { base, run_meta })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn schema_is_vuln_discovery_specific() {
        let tmp = TempDir::new().unwrap();
        let ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
        assert_eq!(ledger.status.schema, RUN_STATUS_SCHEMA);
    }

    #[test]
    fn finalize_writes_atomic_and_round_trips() {
        let tmp = TempDir::new().unwrap();
        let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 100);
        ledger.mark_complete("findings.jsonl", 1024, 5);
        ledger.mark_complete("chain_graph.json", 256, 1);
        ledger.set_run_meta(RunMeta {
            phase: "v1.0_static".into(),
            templates_loaded: 12,
            chains_discovered: 47,
            chains_above_threshold: 12,
            scoring_calibrated: false,
        });
        ledger.finalize_atomic(200).unwrap();
        let parsed = read_vuln_run_status(&tmp.path().join("run_status.json")).unwrap();
        assert_eq!(parsed.base.outcome, RunOutcome::Complete);
        assert_eq!(parsed.run_meta.templates_loaded, 12);
        assert_eq!(parsed.run_meta.chains_above_threshold, 12);
        assert!(!parsed.run_meta.scoring_calibrated);
    }

    #[test]
    fn failed_artifact_makes_outcome_partial() {
        let tmp = TempDir::new().unwrap();
        let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
        ledger.mark_complete("findings.jsonl", 1, 1);
        ledger.mark_failed("chain_graph.json", "disk full");
        ledger.finalize_atomic(100).unwrap();
        let parsed = read_vuln_run_status(&tmp.path().join("run_status.json")).unwrap();
        assert_eq!(parsed.base.outcome, RunOutcome::Partial);
    }

    #[test]
    fn read_returns_none_for_missing_file() {
        let tmp = TempDir::new().unwrap();
        assert!(read_vuln_run_status(&tmp.path().join("nope.json")).is_none());
    }

    #[test]
    fn artifact_status_uses_complete_when_all_complete() {
        let tmp = TempDir::new().unwrap();
        let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
        ledger.mark_complete("findings.jsonl", 1, 1);
        ledger.finalize_atomic(100).unwrap();
        let parsed = read_vuln_run_status(&tmp.path().join("run_status.json")).unwrap();
        assert_eq!(parsed.base.outcome, RunOutcome::Complete);
        assert_eq!(
            parsed.base.artifacts["findings.jsonl"].status,
            ArtifactStatus::Complete
        );
    }
}
