//! Manifest-integration tests for the dynamic-trace pipeline.
//!
//! Exercises the gating discipline:
//! - `mode == "off"` → 0 entries
//! - missing run_status.json → 0 entries (run didn't finish cleanly)
//! - all Complete → 7 entries (1 ledger + 6 artifacts)
//! - any Failed → that artifact omitted; ledger still registered
//! - any Partial → that artifact registered with `status: "partial"`
//! - loss_policy=Partial + events_dropped > 0 → outcome forced Partial
//! - loss_policy=Warn + events_dropped > 0 → outcome stays Complete

#![cfg(feature = "dynamic-trace")]

use axe_core::dynamic_trace::dyn_run_status::{
    read_dynamic_trace_run_status, DynamicTraceRunStatusLedger,
};
use axe_core::dynamic_trace::LossPolicy;
use axe_core::dynamic_trace_artifact_index_entries;
use axe_core::run_status::RunOutcome;
use tempfile::TempDir;

fn mark_all_complete(ledger: &mut DynamicTraceRunStatusLedger) {
    ledger.mark_complete("events.ndjson", 1, 1);
    ledger.mark_complete("entity_graph.json", 1, 1);
    ledger.mark_complete("behavior_facts.jsonl", 1, 1);
    ledger.mark_complete("behavior_fact_union.jsonl", 1, 1);
    ledger.mark_complete("evidence_pack.json", 1, 1);
    ledger.mark_complete("trace.sqlite", 1, 1);
}

#[test]
fn mode_off_returns_zero_entries() {
    let tmp = TempDir::new().unwrap();
    let entries = dynamic_trace_artifact_index_entries(tmp.path(), "off");
    assert!(entries.is_empty());
}

#[test]
fn missing_ledger_returns_zero_entries() {
    let tmp = TempDir::new().unwrap();
    let entries = dynamic_trace_artifact_index_entries(tmp.path(), "on");
    assert!(entries.is_empty());
}

#[test]
fn all_complete_returns_seven_entries_with_run_status_first() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Partial);
    mark_all_complete(&mut ledger);
    ledger.finalize_atomic(1000).unwrap();

    let entries = dynamic_trace_artifact_index_entries(tmp.path(), "on");
    assert_eq!(entries.len(), 7);
    assert_eq!(entries[0].path, "dynamic_trace/run_status.json");
    assert_eq!(entries[0].kind, "dynamic_trace_run_status");
    // None of the entries should carry a "partial" status when all
    // artifacts are Complete.
    for e in &entries {
        assert!(e.status.is_none(), "{} should have no status", e.path);
    }
}

#[test]
fn failed_artifact_is_omitted_from_manifest() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Partial);
    ledger.mark_complete("events.ndjson", 1, 1);
    ledger.mark_complete("entity_graph.json", 1, 1);
    ledger.mark_failed("behavior_facts.jsonl", "disk full");
    ledger.mark_complete("behavior_fact_union.jsonl", 1, 1);
    ledger.mark_complete("evidence_pack.json", 1, 1);
    ledger.mark_complete("trace.sqlite", 1, 1);
    ledger.finalize_atomic(1000).unwrap();

    let entries = dynamic_trace_artifact_index_entries(tmp.path(), "on");
    // 6 entries: ledger + 5 Complete (behavior_facts.jsonl Failed → omitted).
    assert_eq!(entries.len(), 6);
    assert!(!entries
        .iter()
        .any(|e| e.path == "dynamic_trace/behavior_facts.jsonl"));
    assert!(entries
        .iter()
        .any(|e| e.path == "dynamic_trace/evidence_pack.json"));
}

#[test]
fn partial_artifact_registers_with_partial_status_field() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Partial);
    ledger.mark_complete("events.ndjson", 1, 1);
    ledger.mark_partial("entity_graph.json", 1, 1, "truncated mid-write");
    ledger.mark_complete("behavior_facts.jsonl", 1, 1);
    ledger.mark_complete("behavior_fact_union.jsonl", 1, 1);
    ledger.mark_complete("evidence_pack.json", 1, 1);
    ledger.mark_complete("trace.sqlite", 1, 1);
    ledger.finalize_atomic(1000).unwrap();

    let entries = dynamic_trace_artifact_index_entries(tmp.path(), "on");
    let entity_graph = entries
        .iter()
        .find(|e| e.path == "dynamic_trace/entity_graph.json")
        .expect("partial entity_graph.json should be registered");
    assert_eq!(entity_graph.status.as_deref(), Some("partial"));
}

#[test]
fn loss_policy_partial_with_drops_forces_partial_outcome_in_ledger() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Partial);
    mark_all_complete(&mut ledger);
    ledger.set_events_dropped(42);
    ledger.finalize_atomic(1000).unwrap();
    let parsed = read_dynamic_trace_run_status(&tmp.path().join("run_status.json")).unwrap();
    // Codex finding 3: complete artifacts + dropped events → Partial.
    assert_eq!(parsed.base.outcome, RunOutcome::Partial);
    // Manifest still registers all 7 entries even though outcome is Partial.
    let entries = dynamic_trace_artifact_index_entries(tmp.path(), "on");
    assert_eq!(entries.len(), 7);
}

#[test]
fn loss_policy_warn_with_drops_keeps_complete_outcome_in_ledger() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Warn);
    mark_all_complete(&mut ledger);
    ledger.set_events_dropped(42);
    ledger.finalize_atomic(1000).unwrap();
    let parsed = read_dynamic_trace_run_status(&tmp.path().join("run_status.json")).unwrap();
    assert_eq!(parsed.base.outcome, RunOutcome::Complete);
    assert_eq!(parsed.run_meta.events_dropped, 42);
}

#[test]
fn run_meta_capability_probe_round_trips() {
    let tmp = TempDir::new().unwrap();
    let mut ledger = DynamicTraceRunStatusLedger::create(tmp.path(), "r", 0, LossPolicy::Partial);
    mark_all_complete(&mut ledger);
    ledger.set_capability_probe(serde_json::json!({
        "elevated": true,
        "se_system_profile": "enabled",
        "probe_session": "ok_46ms"
    }));
    ledger.finalize_atomic(1000).unwrap();
    let parsed = read_dynamic_trace_run_status(&tmp.path().join("run_status.json")).unwrap();
    let probe = parsed.run_meta.capability_probe.unwrap();
    assert_eq!(probe["elevated"], true);
    assert_eq!(probe["se_system_profile"], "enabled");
}
