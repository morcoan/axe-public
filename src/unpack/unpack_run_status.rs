//! Aurora-specific ledger wrapping `crate::run_status`.
//!
//! Each Aurora session emits `out/unpack/run_status.json` with
//! schema `unpack_run_status/1`. The wire shape is the standard
//! `RunStatus` (which the manifest helper at
//! `llm_artifacts::unpack_artifact_index_entries` reads via
//! `read_run_status`) plus an Aurora-specific `run_meta` block
//! that carries non-artifact-status context: the tracer mode used,
//! how many hooks installed, whether WHP/driver were active, the
//! top OEP confidence reached, and how many regions dumped.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::atomic_write::write_atomic;
use crate::run_status::{derive_outcome, ArtifactStatusEntry, RunStatus};

/// Pinned schema string for the Aurora run ledger.
pub const UNPACK_RUN_STATUS_SCHEMA: &str = "unpack_run_status/1";

/// Aurora-specific context carried alongside the standard
/// `RunStatus` fields. Mirrors the `run_meta` block in the wire
/// shape documented in the plan.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnpackRunMeta {
    pub tracer_mode: String,
    pub user_mode_hooks: u32,
    pub anti_debug_hooks: u32,
    pub whp_used: bool,
    pub driver_used: bool,
    pub oep_top_confidence: f64,
    pub regions_dumped: u32,
}

impl Default for UnpackRunMeta {
    fn default() -> Self {
        Self {
            tracer_mode: "debug".to_string(),
            user_mode_hooks: 0,
            anti_debug_hooks: 0,
            whp_used: false,
            driver_used: false,
            oep_top_confidence: 0.0,
            regions_dumped: 0,
        }
    }
}

/// The full on-disk shape: `RunStatus` fields flattened in, plus
/// the Aurora-specific `run_meta` block.
#[derive(Clone, Debug, Serialize)]
struct OnDiskShape<'a> {
    #[serde(flatten)]
    base: &'a RunStatus,
    run_meta: &'a UnpackRunMeta,
}

/// Build a fresh `RunStatus` keyed to the Aurora schema. The
/// caller adds artifacts to `status.artifacts` as they land and
/// calls `finalize()` to compute the outcome + write the file.
pub fn new_status(run_id: &str, started_at_ms: u128) -> RunStatus {
    RunStatus::new(UNPACK_RUN_STATUS_SCHEMA, run_id, started_at_ms)
}

/// Finalize and write `run_status.json` to `<out_dir>/run_status.json`.
/// Computes the outcome via `derive_outcome` (standard rules) and
/// stamps `completed_at_ms`. Caller-supplied `run_meta` is
/// serialized alongside the `RunStatus` fields under the
/// `run_meta` key.
pub fn finalize(
    out_dir: &Path,
    mut status: RunStatus,
    run_meta: &UnpackRunMeta,
    completed_at_ms: u128,
) -> std::io::Result<()> {
    status.outcome = derive_outcome(&status);
    status.completed_at_ms = Some(completed_at_ms);
    let shape = OnDiskShape {
        base: &status,
        run_meta,
    };
    let bytes = serde_json::to_vec_pretty(&shape)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let path = out_dir.join("run_status.json");
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_atomic(&path, &bytes)
}

/// Register an artifact in the ledger. Convenience over the raw
/// `BTreeMap::insert` so callers consistently spell the artifact
/// names ("unpack_provenance.json", "entropy_curve.jsonl", …)
/// the manifest helper expects.
pub fn record_artifact(
    artifacts: &mut BTreeMap<String, ArtifactStatusEntry>,
    name: &str,
    entry: ArtifactStatusEntry,
) {
    artifacts.insert(name.to_string(), entry);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run_status::RunOutcome;

    #[test]
    fn schema_string_is_pinned() {
        assert_eq!(UNPACK_RUN_STATUS_SCHEMA, "unpack_run_status/1");
    }

    #[test]
    fn new_status_uses_aurora_schema() {
        let s = new_status("blake3:abc", 1000);
        assert_eq!(s.schema, "unpack_run_status/1");
        assert_eq!(s.run_id, "blake3:abc");
        assert_eq!(s.started_at_ms, 1000);
        assert_eq!(s.outcome, RunOutcome::Failed); // pessimistic until finalized
        assert!(s.artifacts.is_empty());
    }

    #[test]
    fn default_run_meta_is_neutral() {
        let m = UnpackRunMeta::default();
        assert_eq!(m.tracer_mode, "debug");
        assert!(!m.whp_used);
        assert!(!m.driver_used);
        assert_eq!(m.oep_top_confidence, 0.0);
        assert_eq!(m.regions_dumped, 0);
    }

    #[test]
    fn finalize_writes_complete_outcome_when_all_artifacts_complete() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut status = new_status("r", 100);
        record_artifact(
            &mut status.artifacts,
            "unpack_provenance.json",
            ArtifactStatusEntry::complete(1024, 1),
        );
        record_artifact(
            &mut status.artifacts,
            "regions/region_00.bin",
            ArtifactStatusEntry::complete(4096, 0),
        );
        let meta = UnpackRunMeta {
            tracer_mode: "debug".into(),
            regions_dumped: 1,
            oep_top_confidence: 1.0,
            ..Default::default()
        };
        finalize(tmp.path(), status, &meta, 200).expect("write");

        let json = std::fs::read_to_string(tmp.path().join("run_status.json")).expect("read back");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["schema"], "unpack_run_status/1");
        assert_eq!(v["outcome"], "complete");
        assert_eq!(v["completed_at_ms"], 200);
        assert_eq!(v["run_meta"]["regions_dumped"], 1);
        assert_eq!(v["run_meta"]["oep_top_confidence"], 1.0);
        assert!(v["artifacts"]["unpack_provenance.json"].is_object());
    }

    #[test]
    fn finalize_writes_partial_outcome_when_one_artifact_failed() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut status = new_status("r", 100);
        record_artifact(
            &mut status.artifacts,
            "unpack_provenance.json",
            ArtifactStatusEntry::complete(1024, 1),
        );
        record_artifact(
            &mut status.artifacts,
            "regions/region_00.bin",
            ArtifactStatusEntry::failed("io: target died before dump"),
        );
        finalize(tmp.path(), status, &UnpackRunMeta::default(), 200).expect("write");
        let json = std::fs::read_to_string(tmp.path().join("run_status.json")).expect("read back");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["outcome"], "partial");
        assert_eq!(v["artifacts"]["regions/region_00.bin"]["status"], "failed");
    }

    #[test]
    fn finalize_writes_failed_outcome_when_no_artifacts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let status = new_status("r", 100);
        finalize(tmp.path(), status, &UnpackRunMeta::default(), 200).expect("write");
        let json = std::fs::read_to_string(tmp.path().join("run_status.json")).expect("read back");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["outcome"], "failed");
    }

    #[test]
    fn run_meta_serializes_as_nested_object() {
        let tmp = tempfile::TempDir::new().unwrap();
        let status = new_status("r", 100);
        let meta = UnpackRunMeta {
            tracer_mode: "whp".into(),
            user_mode_hooks: 5,
            anti_debug_hooks: 4,
            whp_used: true,
            driver_used: false,
            oep_top_confidence: 0.75,
            regions_dumped: 3,
        };
        finalize(tmp.path(), status, &meta, 200).expect("write");
        let json = std::fs::read_to_string(tmp.path().join("run_status.json")).expect("read back");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let rm = &v["run_meta"];
        assert_eq!(rm["tracer_mode"], "whp");
        assert_eq!(rm["user_mode_hooks"], 5);
        assert_eq!(rm["anti_debug_hooks"], 4);
        assert_eq!(rm["whp_used"], true);
        assert_eq!(rm["regions_dumped"], 3);
    }
}
