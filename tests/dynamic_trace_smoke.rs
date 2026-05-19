//! OS-agnostic end-to-end smoke test for the dynamic-trace pipeline.
//!
//! Runs on Linux, macOS, and Windows — no ETW required. Exercises
//! the full data path JSONL → schema → store → behavior facts → LLM
//! pack, plus the loss-policy + run-status discipline.

#![cfg(feature = "dynamic-trace")]

use std::fs;

use axe_core::dynamic_trace::behavior_facts::{extract_facts, LossMeta};
use axe_core::dynamic_trace::dyn_run_status::{
    read_dynamic_trace_run_status, DynamicTraceRunStatusLedger,
};
use axe_core::dynamic_trace::event::{EventSource, HostOs, TraceEvent};
use axe_core::dynamic_trace::llm_pack::{emit_all, PackInputs, StaticFactView};
use axe_core::dynamic_trace::normalize::{normalize_jsonl, EventIdCounter, NormalizeContext};
use axe_core::dynamic_trace::store::{TraceEventWriter, TraceStore};
use axe_core::dynamic_trace::{LossPolicy, ProviderKind};
use axe_core::dynamic_trace_artifact_index_entries;
use axe_core::run_status::RunOutcome;
use serde_json::json;
use tempfile::TempDir;

fn synth_events() -> Vec<serde_json::Value> {
    vec![
        // process.start of cmd.exe
        json!({
            "ts_ns": 100,
            "pid": 4210,
            "tid": 4214,
            "event_type": "process.start",
            "subject": {"kind": "process", "id": "proc:4210@t", "name": "cmd.exe"},
            "process_image": "C:\\Windows\\System32\\cmd.exe",
            "args": {"image": "C:\\Windows\\System32\\cmd.exe"}
        }),
        // image.load of ntdll.dll
        json!({
            "ts_ns": 110,
            "pid": 4210,
            "tid": 4214,
            "event_type": "image.load",
            "subject": {"kind": "process", "id": "proc:4210@t"},
            "object":  {"kind": "module",  "id": "mod:ntdll.dll", "name": "ntdll.dll"},
            "args": {"image_base": 140700000, "image_size": 1572864}
        }),
        // file.write to user temp (exfil_staging detector wants this + network)
        json!({
            "ts_ns": 200,
            "pid": 4210,
            "tid": 4214,
            "event_type": "file.write",
            "subject": {"kind": "process", "id": "proc:4210@t"},
            "object":  {"kind": "file",    "id": "file:C:\\Users\\u\\AppData\\Local\\Temp\\stage.bin"},
            "args": {"bytes": 4096}
        }),
        // network.connect (pairs with above for exfil_staging)
        json!({
            "ts_ns": 300,
            "pid": 4210,
            "tid": 4214,
            "event_type": "network.connect",
            "subject": {"kind": "process", "id": "proc:4210@t"},
            "object":  {"kind": "socket",  "id": "sock:0:0->1.2.3.4:443"}
        }),
        // registry.write to Run key (persistence)
        json!({
            "ts_ns": 400,
            "pid": 4210,
            "tid": 4214,
            "event_type": "registry.write",
            "subject": {"kind": "process", "id": "proc:4210@t"},
            "object":  {"kind": "registry", "id": "reg:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil"}
        }),
        // registry.write to Defender (defense_evasion)
        json!({
            "ts_ns": 500,
            "pid": 4210,
            "tid": 4214,
            "event_type": "registry.write",
            "subject": {"kind": "process", "id": "proc:4210@t"},
            "object":  {"kind": "registry", "id": "reg:HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware"}
        }),
        // file.read of browser Login Data (browser_credential_access)
        json!({
            "ts_ns": 600,
            "pid": 4210,
            "tid": 4214,
            "event_type": "file.read",
            "subject": {"kind": "process", "id": "proc:4210@t"},
            "object":  {"kind": "file",    "id": "file:C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"}
        }),
        // process.start of whoami.exe (discovery)
        json!({
            "ts_ns": 700,
            "pid": 4220,
            "tid": 4224,
            "event_type": "process.start",
            "subject": {"kind": "process", "id": "proc:4220@t", "name": "whoami.exe"},
            "process_image": "C:\\Windows\\System32\\whoami.exe",
            "args": {"image": "C:\\Windows\\System32\\whoami.exe"}
        }),
    ]
}

fn normalize_all(values: &[serde_json::Value], ctx: &NormalizeContext) -> Vec<TraceEvent> {
    values
        .iter()
        .filter_map(|v| normalize_jsonl(v, ctx))
        .collect()
}

#[test]
fn end_to_end_pipeline_produces_all_artifacts() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();
    let run_id = "blake3:smoke";

    let ctx = NormalizeContext {
        run_id: run_id.into(),
        host_os: HostOs::Windows,
        source: EventSource::Jsonl,
        counter: EventIdCounter::new(),
        plan: axe_core::dynamic_trace::collector::ProviderPlan::for_target(
            ProviderKind::v1_default_bundle(),
            None,
        ),
    };

    // 1. JSONL → canonical events
    let events = normalize_all(&synth_events(), &ctx);
    assert_eq!(events.len(), 8);

    // 2. Persist to store + ndjson writer
    let store_path = out.join("trace.sqlite");
    let mut store = TraceStore::open(&store_path).unwrap();
    let mut writer = TraceEventWriter::create(&out.join("events.ndjson")).unwrap();
    for ev in &events {
        store.insert_event(ev).unwrap();
        writer.append(ev).unwrap();
    }
    let ndjson_bytes = writer.finalize().unwrap();
    assert!(ndjson_bytes > 0);
    assert_eq!(store.count_events().unwrap(), 8);

    // 3. Behavior facts
    let loss = LossMeta::default();
    let facts = extract_facts(run_id, &events, &loss);
    assert!(
        !facts.is_empty(),
        "expected at least one fact from synth events"
    );
    // The synth set deliberately exercises 4 detectors:
    // persistence, defense_evasion, exfil_staging, discovery,
    // browser_credential_access. We don't assert exact count because
    // service_creation isn't in the synth set.
    let categories: std::collections::HashSet<_> =
        facts.iter().map(|f| f.category.as_str()).collect();
    for required in [
        "persistence",
        "defense_evasion",
        "exfil_staging",
        "discovery",
        "browser_credential_access",
    ] {
        assert!(
            categories.contains(required),
            "missing detector category: {required}; got {categories:?}"
        );
    }

    // 4. LLM pack → 4 artifacts
    let pack_inputs = PackInputs {
        run_id,
        duration_ms: 700,
        target_image: Some("cmd.exe"),
        target_pid: Some(4210),
        target_hash: Some("blake3:abc"),
        symbolication_miss_rate: 0.0,
    };
    let static_facts: Vec<StaticFactView> = Vec::new();
    let sizes = emit_all(
        out,
        &pack_inputs,
        &events,
        &static_facts,
        &facts,
        &loss,
        Some(&store),
    )
    .unwrap();
    assert!(sizes.entity_graph > 0);
    assert!(sizes.behavior_facts > 0);
    assert!(sizes.behavior_fact_union > 0);
    assert!(sizes.evidence_pack > 0);
    for name in [
        "entity_graph.json",
        "behavior_facts.jsonl",
        "behavior_fact_union.jsonl",
        "evidence_pack.json",
    ] {
        assert!(out.join(name).exists(), "missing {name}");
    }

    // 5. Run status ledger + manifest entries
    let mut ledger = DynamicTraceRunStatusLedger::create(out, run_id, 1000, LossPolicy::Partial);
    ledger.set_providers(vec!["file".into(), "registry".into()]);
    ledger.mark_complete("events.ndjson", ndjson_bytes, events.len() as u64);
    ledger.mark_complete("entity_graph.json", sizes.entity_graph, events.len() as u64);
    ledger.mark_complete(
        "behavior_facts.jsonl",
        sizes.behavior_facts,
        facts.len() as u64,
    );
    ledger.mark_complete(
        "behavior_fact_union.jsonl",
        sizes.behavior_fact_union,
        facts.len() as u64,
    );
    ledger.mark_complete("evidence_pack.json", sizes.evidence_pack, 1);
    ledger.mark_complete(
        "trace.sqlite",
        fs::metadata(&store_path).unwrap().len(),
        events.len() as u64,
    );
    ledger.finalize_atomic(2000).unwrap();

    let parsed = read_dynamic_trace_run_status(&out.join("run_status.json")).unwrap();
    assert_eq!(parsed.base.outcome, RunOutcome::Complete);
    assert_eq!(parsed.run_meta.events_dropped, 0);

    // 6. Manifest helper sees all 7 entries (6 artifacts + run_status).
    let entries = dynamic_trace_artifact_index_entries(out, "on");
    assert_eq!(entries.len(), 7);
    assert_eq!(entries[0].path, "dynamic_trace/run_status.json");
    let kinds: std::collections::HashSet<_> = entries.iter().map(|e| e.kind.as_str()).collect();
    for required in [
        "dynamic_trace_run_status",
        "dynamic_trace_events",
        "dynamic_trace_entity_graph",
        "dynamic_trace_behavior_facts",
        "dynamic_trace_behavior_fact_union",
        "dynamic_trace_evidence_pack",
        "dynamic_trace_store",
    ] {
        assert!(
            kinds.contains(required),
            "missing manifest kind: {required}"
        );
    }
}

#[test]
fn lossy_run_forces_partial_outcome_under_default_policy() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();
    let run_id = "blake3:lossy";

    let ctx = NormalizeContext {
        run_id: run_id.into(),
        host_os: HostOs::Windows,
        source: EventSource::Jsonl,
        counter: EventIdCounter::new(),
        plan: axe_core::dynamic_trace::collector::ProviderPlan::for_target(
            ProviderKind::v1_default_bundle(),
            None,
        ),
    };
    let events = normalize_all(&synth_events(), &ctx);

    // All artifacts go through Complete, but we report 42 dropped events.
    let mut ledger = DynamicTraceRunStatusLedger::create(out, run_id, 1000, LossPolicy::Partial);
    ledger.mark_complete("events.ndjson", 1024, events.len() as u64);
    ledger.set_events_dropped(42);
    ledger.finalize_atomic(2000).unwrap();

    let parsed = read_dynamic_trace_run_status(&out.join("run_status.json")).unwrap();
    // Codex finding 3 fix: Complete forced to Partial under loss.
    assert_eq!(parsed.base.outcome, RunOutcome::Partial);
    assert_eq!(parsed.run_meta.events_dropped, 42);

    // Behavior facts produced from a lossy stream get uncertainty stamps.
    let loss = LossMeta { events_dropped: 42 };
    let facts = extract_facts(run_id, &events, &loss);
    for fact in &facts {
        assert!(
            fact.uncertainty
                .as_deref()
                .map(|s| s.contains("dropped"))
                .unwrap_or(false),
            "lossy fact {} missing uncertainty stamp",
            fact.fact_id
        );
    }
}

#[test]
fn manifest_helper_off_mode_returns_empty() {
    let tmp = TempDir::new().unwrap();
    let entries = dynamic_trace_artifact_index_entries(tmp.path(), "off");
    assert!(entries.is_empty());
}

#[test]
fn manifest_helper_no_ledger_returns_empty() {
    let tmp = TempDir::new().unwrap();
    let entries = dynamic_trace_artifact_index_entries(tmp.path(), "on");
    assert!(entries.is_empty());
}
