//! Manifest-integration tests for vuln-discovery v1.0.
//!
//! Exercises the gating discipline:
//! - `mode == "off"` → 0 entries
//! - Missing run_status.json → 0 entries
//! - All Complete → 5 entries (1 ledger + 4 artifacts) w/ run_status first
//! - Any Failed → that artifact omitted, ledger still registered
//! - Any Partial → that artifact registered w/ `status: "partial"`

#![cfg(feature = "vuln-discovery")]

use axe_core::run_status::{ArtifactStatusEntry, RunOutcome};
use axe_core::vuln::vuln_run_status::{read_vuln_run_status, VulnRunStatusLedger};
use axe_core::vuln_artifact_index_entries;
use tempfile::TempDir;

fn mark_all_complete(ledger: &mut VulnRunStatusLedger) {
    ledger.mark_complete("findings.jsonl", 1024, 5);
    ledger.mark_complete("chain_graph.json", 256, 1);
    ledger.mark_complete("evidence_bundle.json", 512, 1);
    ledger.mark_complete("findings.sqlite", 4096, 5);
}

#[test]
fn mode_off_returns_zero_entries() {
    let tmp = TempDir::new().unwrap();
    assert!(vuln_artifact_index_entries(tmp.path(), "off").is_empty());
}

#[test]
fn missing_ledger_returns_zero_entries() {
    let tmp = TempDir::new().unwrap();
    assert!(vuln_artifact_index_entries(tmp.path(), "on").is_empty());
}

#[test]
fn all_complete_returns_five_entries_with_run_status_first() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
    mark_all_complete(&mut ledger);
    ledger.finalize_atomic(100).unwrap();
    let entries = vuln_artifact_index_entries(tmp.path(), "on");
    assert_eq!(entries.len(), 5);
    assert_eq!(entries[0].path, "vuln/run_status.json");
    assert_eq!(entries[0].kind, "vuln_run_status");
    for e in &entries {
        assert!(e.status.is_none(), "{} should have no status field", e.path);
    }
}

#[test]
fn failed_artifact_is_omitted_but_ledger_remains() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
    ledger.mark_complete("findings.jsonl", 1024, 5);
    ledger.mark_failed("chain_graph.json", "disk full");
    ledger.mark_complete("evidence_bundle.json", 512, 1);
    ledger.mark_complete("findings.sqlite", 4096, 5);
    ledger.finalize_atomic(100).unwrap();
    let entries = vuln_artifact_index_entries(tmp.path(), "on");
    // 4 entries: ledger + 3 Complete (chain_graph.json Failed → omitted).
    assert_eq!(entries.len(), 4);
    assert!(!entries.iter().any(|e| e.path == "vuln/chain_graph.json"));
    assert!(entries.iter().any(|e| e.path == "vuln/run_status.json"));
}

#[test]
fn partial_artifact_registers_with_partial_status_field() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
    ledger.mark_complete("findings.jsonl", 1024, 5);
    ledger.mark(
        "chain_graph.json",
        ArtifactStatusEntry::partial(128, 0, "truncated mid-write"),
    );
    ledger.mark_complete("evidence_bundle.json", 512, 1);
    ledger.mark_complete("findings.sqlite", 4096, 5);
    ledger.finalize_atomic(100).unwrap();
    let entries = vuln_artifact_index_entries(tmp.path(), "on");
    let cg = entries
        .iter()
        .find(|e| e.path == "vuln/chain_graph.json")
        .expect("partial chain_graph.json should be registered");
    assert_eq!(cg.status.as_deref(), Some("partial"));
}

#[test]
fn ledger_outcome_is_complete_when_all_artifacts_complete() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
    mark_all_complete(&mut ledger);
    ledger.finalize_atomic(100).unwrap();
    let parsed = read_vuln_run_status(&tmp.path().join("run_status.json")).unwrap();
    assert_eq!(parsed.base.outcome, RunOutcome::Complete);
    assert_eq!(parsed.run_meta.phase, "v1.0_static");
    assert!(!parsed.run_meta.scoring_calibrated);
}

// =====================================================================
// v1.1 manifest tests (Step 35) — verifies entry counts across the
// feature combinations the plan calls out:
//  - v1.0 only         → 5 entries (1 ledger + 4 v1.0 artifacts)
//  - v1.0 + v1.1 full  → 9 entries (1 ledger + 4 v1.0 + 4 v1.1 artifacts)
// =====================================================================

fn mark_v1_1_artifacts_complete(ledger: &mut VulnRunStatusLedger) {
    ledger.mark_complete("harnesses", 1024, 7);
    ledger.mark_complete("patch_suggestions.jsonl", 4096, 7);
    ledger.mark_complete("test_suggestions.jsonl", 4096, 7);
    ledger.mark_complete("lifetime_candidates.jsonl", 512, 2);
}

#[test]
fn v1_1_full_registers_nine_entries() {
    // Plan validation: "9 entries when all features on (4 v1.0 + 4 v1.1 + run_status)".
    let tmp = TempDir::new().unwrap();
    let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
    mark_all_complete(&mut ledger);
    mark_v1_1_artifacts_complete(&mut ledger);
    ledger.finalize_atomic(100).unwrap();
    let entries = vuln_artifact_index_entries(tmp.path(), "on");
    assert_eq!(
        entries.len(),
        9,
        "expected 9 entries (1 ledger + 4 v1.0 + 4 v1.1); got {} entries: {:?}",
        entries.len(),
        entries.iter().map(|e| &e.path).collect::<Vec<_>>()
    );
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    // v1.1 artifact kinds must all appear.
    assert!(kinds.contains(&"vuln_harnesses_dir"));
    assert!(kinds.contains(&"vuln_patch_suggestions"));
    assert!(kinds.contains(&"vuln_test_suggestions"));
    assert!(kinds.contains(&"vuln_lifetime_candidates"));
}

#[test]
fn v1_1_lifetime_only_registers_six_entries() {
    // v1.0 + lifetime_candidates.jsonl (no patches/tests/harnesses).
    let tmp = TempDir::new().unwrap();
    let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
    mark_all_complete(&mut ledger);
    ledger.mark_complete("lifetime_candidates.jsonl", 512, 2);
    ledger.finalize_atomic(100).unwrap();
    let entries = vuln_artifact_index_entries(tmp.path(), "on");
    assert_eq!(entries.len(), 6);
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"vuln_lifetime_candidates"));
    assert!(!kinds.contains(&"vuln_harnesses_dir"));
}

#[test]
fn v1_1_harnesses_only_registers_six_entries() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
    mark_all_complete(&mut ledger);
    ledger.mark_complete("harnesses", 1024, 7);
    ledger.finalize_atomic(100).unwrap();
    let entries = vuln_artifact_index_entries(tmp.path(), "on");
    assert_eq!(entries.len(), 6);
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"vuln_harnesses_dir"));
    assert!(!kinds.contains(&"vuln_lifetime_candidates"));
    assert!(!kinds.contains(&"vuln_patch_suggestions"));
}

#[test]
fn v1_1_failed_artifact_is_omitted_without_dropping_ledger() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
    mark_all_complete(&mut ledger);
    ledger.mark_complete("harnesses", 1024, 7);
    ledger.mark_failed("lifetime_candidates.jsonl", "permissions");
    ledger.mark_complete("patch_suggestions.jsonl", 4096, 7);
    ledger.mark_complete("test_suggestions.jsonl", 4096, 7);
    ledger.finalize_atomic(100).unwrap();
    let entries = vuln_artifact_index_entries(tmp.path(), "on");
    // 1 ledger + 4 v1.0 + (4 v1.1 − 1 failed) = 8 entries.
    assert_eq!(entries.len(), 8);
    assert!(!entries
        .iter()
        .any(|e| e.path == "vuln/lifetime_candidates.jsonl"));
    // The ledger and the other v1.1 artifacts are still present.
    assert!(entries.iter().any(|e| e.kind == "vuln_run_status"));
    assert!(entries.iter().any(|e| e.kind == "vuln_harnesses_dir"));
}

#[test]
fn v1_1_artifact_descriptions_mention_codex_findings() {
    // Self-documenting: the v1.1 wire-shape descriptions remind the
    // LLM consumer of the Codex-finding invariants the artifacts
    // enforce. Catch accidental description deletion.
    let tmp = TempDir::new().unwrap();
    let mut ledger = VulnRunStatusLedger::create(tmp.path(), "r", 0);
    mark_all_complete(&mut ledger);
    mark_v1_1_artifacts_complete(&mut ledger);
    ledger.finalize_atomic(100).unwrap();
    let entries = vuln_artifact_index_entries(tmp.path(), "on");
    let harness_desc = entries
        .iter()
        .find(|e| e.kind == "vuln_harnesses_dir")
        .unwrap();
    assert!(harness_desc.description.contains("Codex finding 2"));
    let lifetime_desc = entries
        .iter()
        .find(|e| e.kind == "vuln_lifetime_candidates")
        .unwrap();
    assert!(lifetime_desc.description.contains("Codex finding 3"));
    let bundle_desc = entries
        .iter()
        .find(|e| e.kind == "vuln_evidence_bundle")
        .unwrap();
    assert!(bundle_desc.description.contains("Codex finding 3"));
}
