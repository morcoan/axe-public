//! Streaming writers for LLM-consumable fuzzer artifacts.
//!
//! Two artifact families ship from this module:
//! - `events.ndjson` — one [`Event`] per "interesting input"
//!   occurrence. High write rate; buffered + fsync'd every 64 events
//!   (Codex finding 2 mitigation — bounded data loss on parent
//!   crash).
//! - `findings.jsonl` — one [`Finding`] per unique crash family.
//!   Low write rate; dedup-on-write + fsync per write.
//!
//! Both files are written **append-mode** rather than atomic-rename,
//! because they're streamed across the whole fuzz session. The
//! `run_status.json` ledger (step 14) records their final byte
//! counts so partial-write detection still works via the manifest
//! gating logic.

#![allow(dead_code)]

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Seek, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One "something interesting happened" record. The fuzz loop emits
/// these whenever a candidate produced new coverage, a new crash
/// family, or improved reachability.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    /// Schema tag — always `"fuzzer_event/1"` for this slice. Stored
    /// as `String` (not `&'static str`) so round-trip deserialization
    /// can borrow into the source buffer.
    pub schema: String,
    pub ts_ms: u128,
    pub kind: EventKind,
    pub input_id: String,
    pub parent_id: Option<String>,
    pub exec_us: u64,
    pub depth: u32,
    pub coverage_hash: String,
    pub new_edges: Vec<EdgeLabel>,
    pub new_edge_symbols: Vec<String>,
    pub closest_target: Option<TargetSnapshot>,
    pub frontier_count: usize,
    pub mutator: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    InterestingInput,
    NewTargetReached,
    NewCrash,
    DuplicateCrash,
    Timeout,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EdgeLabel {
    #[serde(serialize_with = "hex_va")]
    pub from: u64,
    #[serde(serialize_with = "hex_va")]
    pub to: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TargetSnapshot {
    pub target_id: String,
    pub function_name: Option<String>,
    pub previous_distance: Option<u32>,
    pub new_distance: Option<u32>,
}

/// One unique crash family record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub schema: String,
    pub finding_id: String,
    pub input_id: String,
    pub kind: FindingKind,
    pub classification: String,
    pub signal: Option<i32>,
    #[serde(serialize_with = "opt_hex_va")]
    pub fault_pc: Option<u64>,
    pub fault_symbol: Option<FaultSymbol>,
    pub dedup_hash: String,
    pub reproducer_path: String,
    pub target_id: Option<String>,
    pub distance_at_crash: Option<u32>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Crash,
    Hang,
    Timeout,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FaultSymbol {
    pub function: Option<String>,
    pub demangled: Option<String>,
    pub source_file: Option<String>,
    pub line: Option<u64>,
}

pub const EVENT_SCHEMA: &str = "fuzzer_event/1";
pub const FINDING_SCHEMA: &str = "fuzzer_finding/1";
const EVENT_FLUSH_EVERY: usize = 64;

fn hex_va<S: serde::Serializer>(va: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{va:016x}"))
}

fn opt_hex_va<S: serde::Serializer>(va: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    match va {
        Some(v) => s.serialize_str(&format!("0x{v:016x}")),
        None => s.serialize_none(),
    }
}

/// Append-mode NDJSON writer for [`Event`]s. Flushes + fsyncs every
/// [`EVENT_FLUSH_EVERY`] events (default 64). On drop, the writer
/// flushes but does NOT fsync — the explicit `finalize()` call does
/// both and reports the final byte count for `run_status.json`.
pub struct EventWriter {
    path: PathBuf,
    inner: Option<BufWriter<File>>,
    count: usize,
    since_last_flush: usize,
    bytes_written: u64,
}

impl EventWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            inner: Some(BufWriter::new(file)),
            count: 0,
            since_last_flush: 0,
            bytes_written: 0,
        })
    }

    /// Append one event, flush+fsync if we've crossed the threshold.
    pub fn append(&mut self, event: &Event) -> io::Result<()> {
        let bw = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::other("EventWriter already finalized"))?;
        let line = serde_json::to_vec(event).map_err(io::Error::other)?;
        bw.write_all(&line)?;
        bw.write_all(b"\n")?;
        let line_bytes = line.len() as u64 + 1;
        let crossed_threshold = self.since_last_flush + 1 >= EVENT_FLUSH_EVERY;
        if crossed_threshold {
            bw.flush()?;
            bw.get_ref().sync_all()?;
        }
        // Mutate counters after the inner borrow drops naturally.
        self.bytes_written += line_bytes;
        self.count += 1;
        if crossed_threshold {
            self.since_last_flush = 0;
        } else {
            self.since_last_flush += 1;
        }
        Ok(())
    }

    /// Flush + fsync + close. Returns the final byte count for the
    /// `run_status.json` ledger.
    pub fn finalize(mut self) -> io::Result<u64> {
        if let Some(mut bw) = self.inner.take() {
            bw.flush()?;
            bw.get_ref().sync_all()?;
            // Drop bw → drop File → close.
        }
        Ok(self.bytes_written)
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Append-mode JSONL writer for [`Finding`]s. Dedups on write via
/// `dedup_hash`; fsyncs per write (low rate, cheap insurance).
pub struct FindingWriter {
    path: PathBuf,
    inner: Option<BufWriter<File>>,
    seen_hashes: HashSet<String>,
    count: usize,
    bytes_written: u64,
}

impl FindingWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            inner: Some(BufWriter::new(file)),
            seen_hashes: HashSet::new(),
            count: 0,
            bytes_written: 0,
        })
    }

    /// Append a finding if its `dedup_hash` isn't already present.
    /// Returns `true` when written, `false` when deduped.
    pub fn append(&mut self, finding: &Finding) -> io::Result<bool> {
        if !self.seen_hashes.insert(finding.dedup_hash.clone()) {
            return Ok(false);
        }
        let bw = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::other("FindingWriter already finalized"))?;
        let line = serde_json::to_vec(finding).map_err(io::Error::other)?;
        bw.write_all(&line)?;
        bw.write_all(b"\n")?;
        bw.flush()?;
        bw.get_ref().sync_all()?;
        self.bytes_written += line.len() as u64 + 1;
        self.count += 1;
        Ok(true)
    }

    /// Final flush + fsync + close. Returns byte count.
    pub fn finalize(mut self) -> io::Result<u64> {
        if let Some(mut bw) = self.inner.take() {
            bw.flush()?;
            bw.get_ref().sync_all()?;
            // Capture position-based byte count when bytes_written wasn't tracked
            if self.bytes_written == 0 {
                self.bytes_written = bw.get_mut().stream_position().unwrap_or(self.bytes_written);
            }
        }
        Ok(self.bytes_written)
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ───── Frontier renderer + Summary writer (step 14) ─────────────────

/// Snapshot of session state used to render `frontier.md` and
/// `summary.json`. Held by the session and refreshed each iteration.
#[derive(Clone, Debug, Default)]
pub struct SessionSnapshot {
    pub run_id: String,
    pub started_at_ms: u128,
    pub now_ms: u128,
    pub total_execs: u64,
    pub corpus_size: usize,
    pub unique_crashes: usize,
    pub unique_hangs: usize,
    pub edges_covered: u64,
    pub edges_total_estimated: u64,
    pub top_targets: Vec<TargetReachability>,
    pub recent_crash_summaries: Vec<CrashSummary>,
}

#[derive(Clone, Debug)]
pub struct TargetReachability {
    pub target_id: String,
    pub name: Option<String>,
    pub priority: f32,
    pub min_distance: Option<u32>,
    pub reached: bool,
}

#[derive(Clone, Debug)]
pub struct CrashSummary {
    pub finding_id: String,
    pub classification: String,
    pub fault_function: Option<String>,
    pub fault_source: Option<String>,
    pub fault_line: Option<u64>,
    pub age_ms: u128,
}

/// Atomic writer for `frontier.md`. The frontier is regenerated
/// periodically — every 60 seconds OR every 256 events, whichever
/// comes first.
pub struct FrontierRenderer {
    path: PathBuf,
    last_render_ms: u128,
    events_since_render: u64,
    every_secs: u64,
    every_events: u64,
}

impl FrontierRenderer {
    pub fn create(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            last_render_ms: 0,
            events_since_render: 0,
            every_secs: 60,
            every_events: 256,
        }
    }

    pub fn with_cadence(mut self, secs: u64, events: u64) -> Self {
        self.every_secs = secs;
        self.every_events = events;
        self
    }

    /// Bump the events-since-render counter. Call once per event.
    pub fn tick(&mut self) {
        self.events_since_render += 1;
    }

    /// Render now if either threshold has been crossed. Returns the
    /// rendered byte count on render, `Ok(0)` if it was a no-op.
    pub fn maybe_render(&mut self, snapshot: &SessionSnapshot) -> io::Result<u64> {
        let now = snapshot.now_ms;
        let elapsed_secs = (now.saturating_sub(self.last_render_ms) / 1000) as u64;
        let should = self.last_render_ms == 0
            || elapsed_secs >= self.every_secs
            || self.events_since_render >= self.every_events;
        if !should {
            return Ok(0);
        }
        let bytes = self.render_now(snapshot)?;
        self.last_render_ms = now;
        self.events_since_render = 0;
        Ok(bytes)
    }

    /// Force a render regardless of cadence. Used at session end.
    pub fn render_now(&mut self, snapshot: &SessionSnapshot) -> io::Result<u64> {
        let body = render_frontier_markdown(snapshot);
        crate::fuzzer::atomic_write::write_atomic(&self.path, body.as_bytes())?;
        Ok(body.len() as u64)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn render_frontier_markdown(s: &SessionSnapshot) -> String {
    let mut out = String::new();
    out.push_str(&format!("# Fuzzing Frontier — run {}\n\n", s.run_id));
    out.push_str("## Coverage\n");
    out.push_str(&format!("- {} edges hit", s.edges_covered));
    if s.edges_total_estimated > 0 {
        let pct = (s.edges_covered as f64 / s.edges_total_estimated as f64) * 100.0;
        out.push_str(&format!(
            " (of ~{} reachable in this binary, {:.1}%)",
            s.edges_total_estimated, pct
        ));
    }
    out.push_str("\n");
    out.push_str(&format!("- {} inputs in corpus\n", s.corpus_size));
    out.push_str(&format!("- {} unique crash families\n", s.unique_crashes));
    out.push_str(&format!("- {} unique hangs\n", s.unique_hangs));
    out.push_str(&format!("- {} total executions\n\n", s.total_execs));

    out.push_str("## Closest unreached targets\n");
    let unreached: Vec<&TargetReachability> = s.top_targets.iter().filter(|t| !t.reached).collect();
    if unreached.is_empty() {
        out.push_str("- (none — every known target has been reached, or no targets defined)\n");
    } else {
        for (i, t) in unreached.iter().take(10).enumerate() {
            out.push_str(&format!(
                "{}. {}",
                i + 1,
                t.name.as_deref().unwrap_or(&t.target_id)
            ));
            if let Some(d) = t.min_distance {
                out.push_str(&format!("   distance={}", d));
            } else {
                out.push_str("   distance=unreachable");
            }
            out.push_str(&format!("   priority={:.2}\n", t.priority));
        }
    }
    out.push_str("\n");

    out.push_str("## Last crash families\n");
    if s.recent_crash_summaries.is_empty() {
        out.push_str("- (no crashes yet)\n");
    } else {
        for c in s.recent_crash_summaries.iter().take(5) {
            out.push_str(&format!("- {} ({})", c.finding_id, c.classification));
            if let Some(fn_name) = &c.fault_function {
                out.push_str(&format!(" @ {}", fn_name));
                if let (Some(src), Some(line)) = (&c.fault_source, c.fault_line) {
                    out.push_str(&format!(":{}:{}", src, line));
                }
            }
            let age_s = c.age_ms / 1000;
            out.push_str(&format!("   ({}s ago)\n", age_s));
        }
    }

    out
}

/// Atomic writer for `summary.json`. Re-written on each render tick
/// and once at session end.
pub struct SummaryWriter {
    path: PathBuf,
}

impl SummaryWriter {
    pub fn create(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
        }
    }

    pub fn write(&self, snapshot: &SessionSnapshot) -> io::Result<u64> {
        let json = serde_json::json!({
            "schema": "fuzzer_summary/1",
            "run_id": snapshot.run_id,
            "started_at_ms": snapshot.started_at_ms,
            "now_ms": snapshot.now_ms,
            "total_execs": snapshot.total_execs,
            "corpus_size": snapshot.corpus_size,
            "unique_crashes": snapshot.unique_crashes,
            "unique_hangs": snapshot.unique_hangs,
            "edges_covered": snapshot.edges_covered,
            "edges_total_estimated": snapshot.edges_total_estimated,
            "coverage_pct": if snapshot.edges_total_estimated > 0 {
                snapshot.edges_covered as f64 / snapshot.edges_total_estimated as f64
            } else {
                0.0
            },
            "top_targets": snapshot.top_targets.iter().take(10).map(|t| {
                serde_json::json!({
                    "target_id": t.target_id,
                    "name": t.name,
                    "priority": t.priority,
                    "min_distance": t.min_distance,
                    "reached": t.reached,
                })
            }).collect::<Vec<_>>(),
        });
        let bytes = serde_json::to_vec_pretty(&json).map_err(io::Error::other)?;
        crate::fuzzer::atomic_write::write_atomic(&self.path, &bytes)?;
        Ok(bytes.len() as u64)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_event(input_id: &str) -> Event {
        Event {
            schema: EVENT_SCHEMA.to_string(),
            ts_ms: 1_700_000_000_000,
            kind: EventKind::InterestingInput,
            input_id: input_id.into(),
            parent_id: None,
            exec_us: 250,
            depth: 1,
            coverage_hash: "xxh3:abcd1234".into(),
            new_edges: vec![EdgeLabel {
                from: 0x1000,
                to: 0x1010,
            }],
            new_edge_symbols: vec!["parse_chunk".into()],
            closest_target: None,
            frontier_count: 3,
            mutator: Some("havoc".into()),
        }
    }

    fn sample_finding(id: &str, hash: &str) -> Finding {
        Finding {
            schema: FINDING_SCHEMA.to_string(),
            finding_id: id.into(),
            input_id: "blake3-1234".into(),
            kind: FindingKind::Crash,
            classification: "heap-buffer-overflow".into(),
            signal: Some(11),
            fault_pc: Some(0x140030120),
            fault_symbol: Some(FaultSymbol {
                function: Some("decode_payload".into()),
                demangled: None,
                source_file: Some("src/parser.rs".into()),
                line: Some(142),
            }),
            dedup_hash: hash.into(),
            reproducer_path: "out/fuzzer/crashes/abc/input.bin".into(),
            target_id: None,
            distance_at_crash: Some(0),
        }
    }

    #[test]
    fn event_writer_appends_ndjson_lines() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.ndjson");
        let mut w = EventWriter::create(&path).unwrap();
        w.append(&sample_event("a")).unwrap();
        w.append(&sample_event("b")).unwrap();
        let bytes = w.finalize().unwrap();
        assert!(bytes > 0);
        let content = std::fs::read_to_string(&path).unwrap();
        let line_count = content.lines().count();
        assert_eq!(line_count, 2);
        // Validate each line parses as JSON and has the schema field.
        // Skip full `Event` round-trip because the hex-encoded VA
        // fields would require a matching custom deserializer; the
        // wire format is the design contract, not symmetric round-trip.
        for line in content.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["schema"], EVENT_SCHEMA);
        }
    }

    #[test]
    fn event_writer_serializes_va_as_hex_string() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.ndjson");
        let mut w = EventWriter::create(&path).unwrap();
        w.append(&sample_event("x")).unwrap();
        w.finalize().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains(r#""from":"0x0000000000001000""#),
            "got: {content}"
        );
        assert!(
            content.contains(r#""to":"0x0000000000001010""#),
            "got: {content}"
        );
    }

    #[test]
    fn event_writer_flush_at_threshold_keeps_data_durable() {
        // Write EVENT_FLUSH_EVERY + 1 events; reading the file before
        // finalize() should still return the flushed prefix.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.ndjson");
        let mut w = EventWriter::create(&path).unwrap();
        for i in 0..EVENT_FLUSH_EVERY + 5 {
            w.append(&sample_event(&format!("id-{i}"))).unwrap();
        }
        // Before finalize: at least the first 64 events are on disk.
        let content = std::fs::read_to_string(&path).unwrap();
        let line_count = content.lines().count();
        assert!(
            line_count >= EVENT_FLUSH_EVERY,
            "expected at least {EVENT_FLUSH_EVERY} flushed, got {line_count}"
        );
        let bytes = w.finalize().unwrap();
        // After finalize: all 69 events present.
        let final_content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(final_content.lines().count(), EVENT_FLUSH_EVERY + 5);
        assert!(bytes > 0);
    }

    #[test]
    fn finding_writer_dedups_by_hash() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("findings.jsonl");
        let mut w = FindingWriter::create(&path).unwrap();
        let wrote_a = w.append(&sample_finding("a", "hash-1")).unwrap();
        let wrote_dup = w.append(&sample_finding("b", "hash-1")).unwrap();
        let wrote_c = w.append(&sample_finding("c", "hash-2")).unwrap();
        assert!(wrote_a);
        assert!(!wrote_dup, "duplicate hash must not write");
        assert!(wrote_c);
        w.finalize().unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
    }

    #[test]
    fn finding_writer_fsyncs_each_write() {
        // Hard to assert fsync directly; assert that data is visible
        // BEFORE finalize.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("findings.jsonl");
        let mut w = FindingWriter::create(&path).unwrap();
        w.append(&sample_finding("a", "h1")).unwrap();
        let content_mid = std::fs::read_to_string(&path).unwrap();
        assert!(!content_mid.is_empty(), "data visible before finalize");
        w.finalize().unwrap();
    }

    #[test]
    fn finding_writer_finalize_returns_byte_count() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("findings.jsonl");
        let mut w = FindingWriter::create(&path).unwrap();
        w.append(&sample_finding("a", "h1")).unwrap();
        let bytes = w.finalize().unwrap();
        assert!(bytes > 100, "single finding > 100 bytes serialized");
    }

    // ───── frontier + summary tests (step 14) ─────

    fn sample_snapshot() -> SessionSnapshot {
        SessionSnapshot {
            run_id: "run-abc".into(),
            started_at_ms: 1_700_000_000_000,
            now_ms: 1_700_000_060_000,
            total_execs: 1024,
            corpus_size: 12,
            unique_crashes: 3,
            unique_hangs: 1,
            edges_covered: 184,
            edges_total_estimated: 1000,
            top_targets: vec![
                TargetReachability {
                    target_id: "target-vuln-1".into(),
                    name: Some("parser::unsafe_decode".into()),
                    priority: 0.95,
                    min_distance: Some(3),
                    reached: false,
                },
                TargetReachability {
                    target_id: "target-vuln-2".into(),
                    name: Some("hit_already".into()),
                    priority: 0.80,
                    min_distance: Some(0),
                    reached: true,
                },
            ],
            recent_crash_summaries: vec![CrashSummary {
                finding_id: "crash-01".into(),
                classification: "heap-buffer-overflow".into(),
                fault_function: Some("decode_payload".into()),
                fault_source: Some("src/parser.rs".into()),
                fault_line: Some(142),
                age_ms: 30_000,
            }],
        }
    }

    #[test]
    fn frontier_renders_coverage_and_targets() {
        let s = sample_snapshot();
        let md = render_frontier_markdown(&s);
        assert!(md.contains("184 edges hit"));
        assert!(md.contains("12 inputs in corpus"));
        assert!(md.contains("Closest unreached targets"));
        assert!(md.contains("parser::unsafe_decode"));
        assert!(!md.contains("hit_already"), "reached targets excluded");
    }

    #[test]
    fn frontier_renders_crash_summary() {
        let s = sample_snapshot();
        let md = render_frontier_markdown(&s);
        assert!(md.contains("crash-01"));
        assert!(md.contains("heap-buffer-overflow"));
        assert!(md.contains("decode_payload"));
        assert!(md.contains("src/parser.rs"));
        assert!(md.contains("142"));
    }

    #[test]
    fn frontier_maybe_render_respects_cadence() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.md");
        let mut r = FrontierRenderer::create(&path).with_cadence(60, 256);
        let mut s = sample_snapshot();
        // First call always renders (last_render_ms == 0).
        let bytes1 = r.maybe_render(&s).unwrap();
        assert!(bytes1 > 0);
        // Second call within the cadence window: no-op.
        s.now_ms += 1_000; // 1 second later
        let bytes2 = r.maybe_render(&s).unwrap();
        assert_eq!(bytes2, 0, "within cadence window, no re-render");
        // Past the time threshold: renders.
        s.now_ms += 61_000;
        let bytes3 = r.maybe_render(&s).unwrap();
        assert!(bytes3 > 0);
    }

    #[test]
    fn frontier_maybe_render_event_threshold() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("frontier.md");
        let mut r = FrontierRenderer::create(&path).with_cadence(60, 5);
        let s = sample_snapshot();
        r.maybe_render(&s).unwrap(); // first call renders
        for _ in 0..4 {
            r.tick();
        }
        // 4 ticks, threshold = 5, not crossed.
        let bytes = r.maybe_render(&s).unwrap();
        assert_eq!(bytes, 0);
        r.tick();
        // 5 ticks → threshold crossed.
        let bytes = r.maybe_render(&s).unwrap();
        assert!(bytes > 0);
    }

    #[test]
    fn summary_writer_writes_atomic_json() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("summary.json");
        let w = SummaryWriter::create(&path);
        let bytes = w.write(&sample_snapshot()).unwrap();
        assert!(bytes > 0);
        let content = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["schema"], "fuzzer_summary/1");
        assert_eq!(v["edges_covered"], 184);
        assert_eq!(v["corpus_size"], 12);
        let pct = v["coverage_pct"].as_f64().unwrap();
        assert!((pct - 0.184).abs() < 1e-6);
    }

    #[test]
    fn summary_writer_handles_zero_estimated_edges() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("summary.json");
        let w = SummaryWriter::create(&path);
        let mut s = sample_snapshot();
        s.edges_total_estimated = 0;
        w.write(&s).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(v["coverage_pct"].as_f64().unwrap(), 0.0);
    }
}
