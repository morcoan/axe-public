//! Step 60 — manifest helper discipline.
//!
//! Verifies `unpack_artifact_index_entries` returns the right
//! count of entries per (mode, ledger state) combo.

#![cfg(feature = "unpack")]

use std::collections::BTreeMap;

use axe_core::unpack_artifact_index_entries;

fn write_ledger(dir: &std::path::Path, entries: BTreeMap<&str, (&str, u64)>) {
    use serde_json::json;
    let mut artifacts = serde_json::Map::new();
    for (name, (status, bytes)) in entries {
        artifacts.insert(
            name.to_string(),
            json!({
                "status": status,
                "bytes": bytes,
                "records": 0,
            }),
        );
    }
    let ledger = json!({
        "schema": "unpack_run_status/1",
        "run_id": "test",
        "started_at_ms": 0,
        "completed_at_ms": 1,
        "outcome": "complete",
        "artifacts": artifacts,
    });
    std::fs::write(
        dir.join("run_status.json"),
        serde_json::to_vec_pretty(&ledger).unwrap(),
    )
    .unwrap();
}

#[test]
fn mode_off_returns_zero_entries() {
    let tmp = tempfile::TempDir::new().unwrap();
    let entries = unpack_artifact_index_entries(tmp.path(), "off");
    assert!(entries.is_empty());
}

#[test]
fn missing_ledger_returns_zero_entries() {
    let tmp = tempfile::TempDir::new().unwrap();
    let entries = unpack_artifact_index_entries(tmp.path(), "on");
    assert!(entries.is_empty());
}

#[test]
fn all_complete_artifacts_show_as_entries_plus_run_status() {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut e = BTreeMap::new();
    e.insert("unpack_provenance.json", ("complete", 1024u64));
    e.insert("regions/region_00.bin", ("complete", 4096u64));
    e.insert("entropy_curve.jsonl", ("complete", 256u64));
    write_ledger(tmp.path(), e);
    let entries = unpack_artifact_index_entries(tmp.path(), "on");
    // 3 artifacts + 1 run_status = 4 entries
    assert_eq!(entries.len(), 4);
    // run_status is first
    assert_eq!(entries[0].kind, "unpack_run_status");
}

#[test]
fn failed_artifact_is_omitted_without_dropping_ledger() {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut e = BTreeMap::new();
    e.insert("unpack_provenance.json", ("complete", 1024u64));
    e.insert("regions/region_00.bin", ("failed", 0u64));
    write_ledger(tmp.path(), e);
    let entries = unpack_artifact_index_entries(tmp.path(), "on");
    // 1 complete artifact + 1 run_status (failed one omitted) = 2
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|e| e.kind != "unpack_region_blob"));
}

#[test]
fn region_blob_kind_recognized_from_path_prefix() {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut e = BTreeMap::new();
    e.insert("regions/region_07.bin", ("complete", 4096u64));
    write_ledger(tmp.path(), e);
    let entries = unpack_artifact_index_entries(tmp.path(), "on");
    let region = entries
        .iter()
        .find(|e| e.path == "unpack/regions/region_07.bin")
        .expect("region must be listed");
    assert_eq!(region.kind, "unpack_region_blob");
}

#[test]
fn entropy_curve_and_oep_candidates_have_dedicated_kinds() {
    let tmp = tempfile::TempDir::new().unwrap();
    let mut e = BTreeMap::new();
    e.insert("entropy_curve.jsonl", ("complete", 1u64));
    e.insert("oep_candidates.jsonl", ("complete", 1u64));
    e.insert("guard_page_log.jsonl", ("complete", 1u64));
    write_ledger(tmp.path(), e);
    let entries = unpack_artifact_index_entries(tmp.path(), "on");
    assert!(entries.iter().any(|e| e.kind == "unpack_entropy_curve"));
    assert!(entries.iter().any(|e| e.kind == "unpack_oep_candidates"));
    assert!(entries.iter().any(|e| e.kind == "unpack_guard_page_log"));
}
