//! End-to-end fuzzer artifact pipeline test.
//!
//! Verifies the full Codex-finding-driven discipline:
//! - All 5 fuzzer artifacts (`events.ndjson`, `findings.jsonl`,
//!   `corpus.sqlite`, `frontier.md`, `summary.json`) are written to
//!   `out/fuzzer/` via atomic-write or fsync-on-flush.
//! - The `run_status.json` ledger records per-artifact completion
//!   state.
//! - The manifest helper `fuzzer_artifact_index_entries` reads the
//!   ledger and produces correct `ArtifactIndexRecord`s — only
//!   registers `Complete`/`Partial` artifacts (Codex finding 1).
//! - A simulated mid-run failure produces a `Partial` outcome and
//!   the manifest reflects the truth.

#![cfg(feature = "fuzzer")]

use axe_core::fuzzer::llm_export::{
    EdgeLabel, Event, EventKind, EventWriter, FaultSymbol, Finding, FindingKind, FindingWriter,
    FrontierRenderer, SessionSnapshot, SummaryWriter, TargetReachability, EVENT_SCHEMA,
    FINDING_SCHEMA,
};
use axe_core::fuzzer::run_status::{read_run_status, ArtifactStatus, RunOutcome, RunStatusLedger};
use axe_core::fuzzer::sqlite_db::{CorpusDb, InputRow};
use axe_core::fuzzer_artifact_index_entries;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn sample_event(idx: usize) -> Event {
    Event {
        schema: EVENT_SCHEMA.to_string(),
        ts_ms: now_ms(),
        kind: EventKind::InterestingInput,
        input_id: format!("blake3-{:016x}", idx),
        parent_id: if idx == 0 {
            None
        } else {
            Some(format!("blake3-{:016x}", idx - 1))
        },
        exec_us: 100 + idx as u64 * 10,
        depth: idx as u32,
        coverage_hash: format!("xxh3-{idx:08x}"),
        new_edges: vec![EdgeLabel {
            from: 0x1000 + (idx as u64) * 0x10,
            to: 0x1010 + (idx as u64) * 0x10,
        }],
        new_edge_symbols: vec![format!("parse_step_{idx}")],
        closest_target: None,
        frontier_count: 2,
        mutator: Some("havoc".into()),
    }
}

fn sample_finding(idx: usize) -> Finding {
    Finding {
        schema: FINDING_SCHEMA.to_string(),
        finding_id: format!("crash-{idx:04}"),
        input_id: format!("blake3-{:016x}", 1000 + idx),
        kind: FindingKind::Crash,
        classification: "heap-buffer-overflow".into(),
        signal: Some(11),
        fault_pc: Some(0x140030120),
        fault_symbol: Some(FaultSymbol {
            function: Some("decode_payload".into()),
            demangled: Some("decode_payload".into()),
            source_file: Some("src/parser.rs".into()),
            line: Some(142),
        }),
        dedup_hash: format!("dedup-{idx}"),
        reproducer_path: format!("out/fuzzer/crashes/dedup-{idx}/input.bin"),
        target_id: Some("target-vuln-1".into()),
        distance_at_crash: Some(0),
    }
}

fn sample_snapshot(run_id: &str) -> SessionSnapshot {
    SessionSnapshot {
        run_id: run_id.into(),
        started_at_ms: now_ms().saturating_sub(60_000),
        now_ms: now_ms(),
        total_execs: 1024,
        corpus_size: 8,
        unique_crashes: 2,
        unique_hangs: 0,
        edges_covered: 184,
        edges_total_estimated: 1000,
        top_targets: vec![TargetReachability {
            target_id: "target-vuln-1".into(),
            name: Some("parser::unsafe_decode".into()),
            priority: 0.95,
            min_distance: Some(3),
            reached: false,
        }],
        recent_crash_summaries: Vec::new(),
    }
}

#[test]
fn happy_path_produces_all_five_artifacts_and_complete_ledger() {
    let tmp = TempDir::new().unwrap();
    let out_dir = tmp.path();
    let fuzzer_dir = out_dir.join("fuzzer");
    std::fs::create_dir_all(&fuzzer_dir).unwrap();

    let run_id = "smoke-run-1";
    let mut ledger = RunStatusLedger::create(out_dir, run_id, now_ms());

    // 1. Events.
    let mut events = EventWriter::create(&fuzzer_dir.join("events.ndjson")).unwrap();
    for i in 0..5 {
        events.append(&sample_event(i)).unwrap();
    }
    let event_count = events.count();
    let event_bytes = events.finalize().unwrap();
    ledger.mark_complete("events.ndjson", event_bytes, event_count as u64);

    // 2. Findings.
    let mut findings = FindingWriter::create(&fuzzer_dir.join("findings.jsonl")).unwrap();
    findings.append(&sample_finding(1)).unwrap();
    findings.append(&sample_finding(2)).unwrap();
    let finding_count = findings.count();
    let finding_bytes = findings.finalize().unwrap();
    ledger.mark_complete("findings.jsonl", finding_bytes, finding_count as u64);

    // 3. Corpus SQLite.
    let mut db = CorpusDb::open(&fuzzer_dir.join("corpus.sqlite")).unwrap();
    db.record_input_batch(&[InputRow {
        id: "blake3-aaa".into(),
        parent_id: None,
        path: "queue/blake3-aaa".into(),
        len: 32,
        exec_us: 100,
        depth: 0,
        coverage_hash: 0x1234,
        bitmap_size: 5,
        favored: false,
        times_fuzzed: 0,
        created_at_ms: 1_700_000_000_000,
    }])
    .unwrap();
    let db_bytes = db.finalize().unwrap();
    ledger.mark_complete("corpus.sqlite", db_bytes, 1);

    // 4. Frontier.
    let mut frontier = FrontierRenderer::create(&fuzzer_dir.join("frontier.md"));
    let snapshot = sample_snapshot(run_id);
    let frontier_bytes = frontier.render_now(&snapshot).unwrap();
    ledger.mark_complete("frontier.md", frontier_bytes, 1);

    // 5. Summary.
    let summary = SummaryWriter::create(&fuzzer_dir.join("summary.json"));
    let summary_bytes = summary.write(&snapshot).unwrap();
    ledger.mark_complete("summary.json", summary_bytes, 1);

    // 6. Ledger finalize.
    ledger.finalize_atomic(now_ms()).unwrap();

    // ── Assertions ──────────────────────────────────────────

    // All 6 files exist (5 artifacts + run_status.json).
    for name in [
        "events.ndjson",
        "findings.jsonl",
        "corpus.sqlite",
        "frontier.md",
        "summary.json",
        "run_status.json",
    ] {
        let p = fuzzer_dir.join(name);
        assert!(p.is_file(), "missing artifact: {p:?}");
        assert!(
            std::fs::metadata(&p).unwrap().len() > 0,
            "empty artifact: {p:?}"
        );
    }

    // Ledger parses + outcome is Complete.
    let status = read_run_status(&fuzzer_dir.join("run_status.json")).unwrap();
    assert_eq!(status.outcome, RunOutcome::Complete);
    assert_eq!(status.artifacts.len(), 5);
    for (_, entry) in &status.artifacts {
        assert_eq!(entry.status, ArtifactStatus::Complete);
    }

    // Manifest helper produces all 6 entries (5 artifacts + ledger itself).
    let entries = fuzzer_artifact_index_entries(&fuzzer_dir, "execute");
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    for expected in [
        "fuzzer/run_status.json",
        "fuzzer/events.ndjson",
        "fuzzer/findings.jsonl",
        "fuzzer/corpus.sqlite",
        "fuzzer/frontier.md",
        "fuzzer/summary.json",
    ] {
        assert!(
            paths.contains(&expected),
            "missing manifest entry: {expected}"
        );
    }
    // No entry has status: "partial" — all Complete.
    for e in &entries {
        assert!(e.status.is_none(), "{} got status {:?}", e.path, e.status);
    }
}

#[test]
fn partial_run_marks_failed_artifacts_correctly() {
    let tmp = TempDir::new().unwrap();
    let out_dir = tmp.path();
    let fuzzer_dir = out_dir.join("fuzzer");
    std::fs::create_dir_all(&fuzzer_dir).unwrap();

    let mut ledger = RunStatusLedger::create(out_dir, "partial-run", now_ms());

    // Events: complete.
    let mut events = EventWriter::create(&fuzzer_dir.join("events.ndjson")).unwrap();
    events.append(&sample_event(0)).unwrap();
    let bytes = events.finalize().unwrap();
    ledger.mark_complete("events.ndjson", bytes, 1);

    // Corpus: simulate failure (don't write anything; mark Failed).
    ledger.mark_failed("corpus.sqlite", "rusqlite open failed: disk full");

    // Summary: skipped.
    ledger.mark_skipped("summary.json", "fast smoke run; skipped");

    // Findings: partial — we wrote some bytes but didn't reach end.
    ledger.mark_partial("findings.jsonl", 256, 1, "writer dropped mid-flush");

    // Frontier: complete.
    let frontier = FrontierRenderer::create(&fuzzer_dir.join("frontier.md"));
    let _ = frontier; // path exists in ledger marker; we don't render
                      // Mark complete with zero bytes/records since we skipped the render
                      // (the test verifies the ledger respects the mark verbatim).
    ledger.mark_complete("frontier.md", 0, 0);

    ledger.finalize_atomic(now_ms()).unwrap();

    let status = read_run_status(&fuzzer_dir.join("run_status.json")).unwrap();
    assert_eq!(status.outcome, RunOutcome::Partial);

    // Manifest gating: Failed and Skipped artifacts are OMITTED;
    // Partial gets status: "partial".
    let entries = fuzzer_artifact_index_entries(&fuzzer_dir, "execute");
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains(&"fuzzer/events.ndjson"));
    assert!(paths.contains(&"fuzzer/findings.jsonl"));
    assert!(paths.contains(&"fuzzer/frontier.md"));
    assert!(paths.contains(&"fuzzer/run_status.json"));
    assert!(
        !paths.contains(&"fuzzer/corpus.sqlite"),
        "Failed artifact must be omitted from manifest"
    );
    assert!(
        !paths.contains(&"fuzzer/summary.json"),
        "Skipped artifact must be omitted from manifest"
    );

    // findings.jsonl entry has status: "partial".
    let findings_entry = entries
        .iter()
        .find(|e| e.path == "fuzzer/findings.jsonl")
        .unwrap();
    assert_eq!(findings_entry.status.as_deref(), Some("partial"));

    // events.ndjson is Complete → status is None (serializes-skip).
    let events_entry = entries
        .iter()
        .find(|e| e.path == "fuzzer/events.ndjson")
        .unwrap();
    assert!(events_entry.status.is_none());
}

#[test]
fn manifest_helper_omits_everything_when_mode_is_off() {
    let tmp = TempDir::new().unwrap();
    let fuzzer_dir = tmp.path().join("fuzzer");
    std::fs::create_dir_all(&fuzzer_dir).unwrap();

    // Even a complete ledger gets ignored when fuzz_mode is off.
    let mut ledger = RunStatusLedger::create(tmp.path(), "x", 0);
    ledger.mark_complete("events.ndjson", 10, 1);
    ledger.finalize_atomic(1).unwrap();

    let entries = fuzzer_artifact_index_entries(&fuzzer_dir, "off");
    assert!(
        entries.is_empty(),
        "fuzz_mode=off must produce no fuzzer entries"
    );
}

#[test]
fn manifest_helper_returns_empty_when_ledger_missing() {
    let tmp = TempDir::new().unwrap();
    let fuzzer_dir = tmp.path().join("fuzzer");
    std::fs::create_dir_all(&fuzzer_dir).unwrap();
    // No run_status.json written.

    let entries = fuzzer_artifact_index_entries(&fuzzer_dir, "execute");
    assert!(
        entries.is_empty(),
        "missing ledger means we cannot trust any fuzzer artifact"
    );
}

#[test]
fn manifest_helper_returns_empty_when_ledger_corrupt() {
    let tmp = TempDir::new().unwrap();
    let fuzzer_dir = tmp.path().join("fuzzer");
    std::fs::create_dir_all(&fuzzer_dir).unwrap();
    std::fs::write(fuzzer_dir.join("run_status.json"), b"not json").unwrap();

    let entries = fuzzer_artifact_index_entries(&fuzzer_dir, "execute");
    assert!(
        entries.is_empty(),
        "corrupt ledger must NOT poison the manifest"
    );
}
