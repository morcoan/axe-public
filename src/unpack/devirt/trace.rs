//! `devirt_trace.jsonl` schema + writer.
//!
//! The stable on-disk contract emitted by `devirt/themida.rs` (2.x) and
//! `devirt/themida3x.rs` (3.x, capped to `best_effort` per the plan).
//! Phase B2 of the devirt workstream defines the schema BEFORE any
//! protector-specific stepper writes a byte, so the 2.x and 3.x emitters
//! produce mergeable output that `PEImage::from_snapshot()` can ingest.
//!
//! Format: one JSON object per line, UTF-8, LF endings. First record is the
//! header (`"kind":"header"`), then zero or more step records
//! (`"kind":"step"`), then a single footer (`"kind":"footer"`). The writer
//! flushes every 256 records to bound memory under long traces and rejects
//! any footer whose tier disagrees with the header's `cap_reason` (defense
//! in depth for the Themida 3.x 0.40 confidence cap — see B5).
//!
//! All addresses and register values are rendered as lowercase `"0x..."`
//! strings to match the existing `RegionDescriptor.va_base` style at
//! `src/unpack/snapshot.rs:113-147`. Memory-write lists are capped at 16
//! per step; overflow sets `notes: "writes_truncated"`.

use crate::unpack::UnpackError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_MEM_WRITES_PER_STEP: usize = 16;
const FLUSH_EVERY: usize = 256;

/// First record in every `devirt_trace.jsonl`. Carries protector identity,
/// timestamp, emulator backend identifier, and the cap-reason for tiers
/// that are intentionally capped (e.g., `"themida_3x_partial"` for the
/// best-effort 3.x path).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceHeader {
    pub kind: String, // always "header"
    pub schema_version: u32,
    pub protector: String,
    pub protector_version_guess: String,
    pub trace_started_unix_ms: u64,
    pub emulator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap_reason: Option<String>,
}

/// One emulated step. `handler_idx` is `None` for non-dispatcher steps (e.g.,
/// the 3.x stepper's pre-amble anti-emulation guard). `regs` is a flat
/// map keyed by lowercase register name; values are `"0x..."` strings.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepRecord {
    pub kind: String, // always "step"
    pub step_idx: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handler_idx: Option<u32>,
    pub rip: String,
    pub opcode_bytes: String,
    pub opcode_mnemonic: String,
    pub regs: BTreeMap<String, String>,
    pub mem_writes: Vec<MemWrite>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemWrite {
    pub va: String,
    pub size: u32,
    pub value_hex: String,
}

/// Final record. `outcome` is one of `"oep_reached"`, `"halted"`,
/// `"truncated"`, `"crash"`. `confidence_tier` is the `tier_for_score`
/// result for `confidence_score`; the writer asserts the pair is
/// consistent with the header's `cap_reason`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceFooter {
    pub kind: String, // always "footer"
    pub steps_total: u32,
    pub outcome: String,
    pub truncated: bool,
    pub confidence_score: f64,
    pub confidence_tier: String,
}

/// Streaming writer for `devirt_trace.jsonl`. Constructed with a path under
/// the snapshot directory; flushes every `FLUSH_EVERY` records. After all
/// step records are written, call `finalize(footer)` to write the footer
/// and close the file.
pub struct TraceWriter {
    path: PathBuf,
    writer: BufWriter<File>,
    header_cap_reason: Option<String>,
    header_version_guess: String,
    records_since_flush: usize,
    steps_emitted: u32,
}

impl TraceWriter {
    /// Open a new trace file and write the header. `path` must be inside the
    /// snapshot directory — the caller (`session.rs`) enforces this; the
    /// writer doesn't double-check to keep the API simple.
    pub fn create(path: PathBuf, header: TraceHeader) -> Result<Self, UnpackError> {
        let header_cap_reason = header.cap_reason.clone();
        let header_version_guess = header.protector_version_guess.clone();
        let file = File::create(&path).map_err(|e| {
            UnpackError::Pipeline(format!("devirt_trace.jsonl create {:?}: {}", path, e))
        })?;
        let mut writer = BufWriter::new(file);
        write_record(&mut writer, &header, &path)?;
        Ok(Self {
            path,
            writer,
            header_cap_reason,
            header_version_guess,
            records_since_flush: 1,
            steps_emitted: 0,
        })
    }

    /// Append one step record. Records are buffered; the BufWriter flushes
    /// every `FLUSH_EVERY` records and on `finalize`.
    pub fn append_step(&mut self, mut step: StepRecord) -> Result<(), UnpackError> {
        if step.mem_writes.len() > MAX_MEM_WRITES_PER_STEP {
            step.mem_writes.truncate(MAX_MEM_WRITES_PER_STEP);
            step.notes = Some("writes_truncated".to_string());
        }
        // Enforce monotonic step_idx — defensive against caller bugs.
        if step.step_idx != self.steps_emitted {
            return Err(UnpackError::Pipeline(format!(
                "devirt_trace.jsonl: step_idx out of order (expected {}, got {})",
                self.steps_emitted, step.step_idx
            )));
        }
        write_record(&mut self.writer, &step, &self.path)?;
        self.steps_emitted += 1;
        self.records_since_flush += 1;
        if self.records_since_flush >= FLUSH_EVERY {
            self.writer
                .flush()
                .map_err(|e| UnpackError::Pipeline(format!("devirt_trace.jsonl flush: {}", e)))?;
            self.records_since_flush = 0;
        }
        Ok(())
    }

    /// Write the footer and close the file. Validates the
    /// header.cap_reason ↔ footer.confidence_tier invariant so a Themida
    /// 3.x partial trace can't accidentally claim `"high"` / `"medium"`
    /// confidence (this is the second of the two defense-in-depth
    /// enforcement points called out by Phase B5's plan).
    pub fn finalize(mut self, footer: TraceFooter) -> Result<PathBuf, UnpackError> {
        // Defense-in-depth: if the header marked this trace as the capped
        // 3.x tier, the footer MUST emit `"best_effort"`. Reject any other
        // tier to prevent accidental over-claim.
        if self.header_cap_reason.as_deref() == Some("themida_3x_partial")
            && footer.confidence_tier != "best_effort"
        {
            return Err(UnpackError::Pipeline(format!(
                "devirt_trace.jsonl: header cap_reason='themida_3x_partial' \
                 requires footer tier='best_effort', got '{}'",
                footer.confidence_tier
            )));
        }
        // The header's protector_version_guess and the cap_reason should also
        // line up — if the header claims "3.x" but cap_reason is None, that's
        // a producer bug (the cap should always apply for 3.x).
        if self.header_version_guess == "3.x"
            && self.header_cap_reason.is_none()
            && footer.confidence_tier != "best_effort"
        {
            return Err(UnpackError::Pipeline(
                "devirt_trace.jsonl: 3.x protector_version_guess requires \
                 either cap_reason set or footer tier 'best_effort'"
                    .into(),
            ));
        }
        write_record(&mut self.writer, &footer, &self.path)?;
        self.writer
            .flush()
            .map_err(|e| UnpackError::Pipeline(format!("devirt_trace.jsonl final flush: {}", e)))?;
        Ok(self.path)
    }
}

fn write_record<W: Write, T: Serialize>(
    writer: &mut W,
    record: &T,
    path: &Path,
) -> Result<(), UnpackError> {
    let json = serde_json::to_string(record).map_err(|e| {
        UnpackError::Pipeline(format!("devirt_trace.jsonl serialize {:?}: {}", path, e))
    })?;
    writeln!(writer, "{}", json)
        .map_err(|e| UnpackError::Pipeline(format!("devirt_trace.jsonl write {:?}: {}", path, e)))
}

/// Helper: render a u64 as the schema's `"0x..."` lowercase string.
pub fn hex_u64(v: u64) -> String {
    format!("0x{:x}", v)
}

/// Helper: render raw bytes as a lowercase hex string with no separators.
/// Matches the schema's `opcode_bytes` format.
pub fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_header(version_guess: &str, cap_reason: Option<&str>) -> TraceHeader {
        TraceHeader {
            kind: "header".to_string(),
            schema_version: SCHEMA_VERSION,
            protector: "themida-legacy".to_string(),
            protector_version_guess: version_guess.to_string(),
            trace_started_unix_ms: 1_747_600_000_000,
            emulator: "unicorn-2".to_string(),
            cap_reason: cap_reason.map(|s| s.to_string()),
        }
    }

    fn sample_step(step_idx: u32, handler_idx: Option<u32>) -> StepRecord {
        let mut regs = BTreeMap::new();
        for (k, v) in [
            ("rax", 0x0_u64),
            ("rcx", 0x140005000),
            ("rdx", 0x0),
            ("rip", 0x140001000 + (step_idx as u64) * 3),
        ] {
            regs.insert(k.to_string(), hex_u64(v));
        }
        StepRecord {
            kind: "step".to_string(),
            step_idx,
            handler_idx,
            rip: hex_u64(0x140001000 + (step_idx as u64) * 3),
            opcode_bytes: "488b4108".to_string(),
            opcode_mnemonic: "mov rax, [rcx+8]".to_string(),
            regs,
            mem_writes: vec![],
            notes: None,
        }
    }

    fn parse_jsonl(content: &str) -> Vec<serde_json::Value> {
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("each line is JSON"))
            .collect()
    }

    /// B2 acceptance: round-trip 100 synthetic records, validate each line
    /// parses, assert step_idx is monotonic.
    #[test]
    fn roundtrip_100_records_monotonic_step_idx() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("devirt_trace.jsonl");
        let mut writer = TraceWriter::create(path.clone(), sample_header("2.x", None)).unwrap();
        for i in 0..100u32 {
            writer.append_step(sample_step(i, Some(i / 10))).unwrap();
        }
        let footer = TraceFooter {
            kind: "footer".to_string(),
            steps_total: 100,
            outcome: "halted".to_string(),
            truncated: false,
            confidence_score: 0.62,
            confidence_tier: "medium".to_string(),
        };
        writer.finalize(footer).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let records = parse_jsonl(&content);
        assert_eq!(records.len(), 102, "header + 100 steps + footer");
        assert_eq!(records[0]["kind"], "header");
        assert_eq!(records[101]["kind"], "footer");
        let mut last_idx: i64 = -1;
        for r in &records[1..=100] {
            assert_eq!(r["kind"], "step");
            let idx = r["step_idx"].as_i64().unwrap();
            assert!(
                idx > last_idx,
                "step_idx must be monotonic (was {}, got {})",
                last_idx,
                idx
            );
            last_idx = idx;
        }
    }

    /// Out-of-order step_idx is rejected — caller-bug protection.
    #[test]
    fn rejects_nonmonotonic_step_idx() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("devirt_trace.jsonl");
        let mut writer = TraceWriter::create(path, sample_header("2.x", None)).unwrap();
        writer.append_step(sample_step(0, None)).unwrap();
        let err = writer.append_step(sample_step(2, None)).unwrap_err();
        match err {
            UnpackError::Pipeline(msg) => assert!(msg.contains("step_idx out of order"), "{}", msg),
            other => panic!("expected Pipeline error, got {:?}", other),
        }
    }

    /// Cap enforcement: 3.x cap_reason header + non-best_effort footer is
    /// rejected. Defense in depth for Phase B5's 0.40 confidence cap.
    #[test]
    fn rejects_3x_cap_with_non_best_effort_footer() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("devirt_trace.jsonl");
        let writer =
            TraceWriter::create(path, sample_header("3.x", Some("themida_3x_partial"))).unwrap();
        let footer = TraceFooter {
            kind: "footer".to_string(),
            steps_total: 0,
            outcome: "truncated".to_string(),
            truncated: true,
            confidence_score: 0.99, // pretending the producer mis-scored
            confidence_tier: "high".to_string(),
        };
        let err = writer.finalize(footer).unwrap_err();
        match err {
            UnpackError::Pipeline(msg) => assert!(
                msg.contains("themida_3x_partial") && msg.contains("best_effort"),
                "{}",
                msg
            ),
            other => panic!("expected Pipeline error, got {:?}", other),
        }
    }

    /// 3.x version_guess WITHOUT explicit cap_reason AND with a non-best_effort
    /// footer is also rejected — protects against the case where a producer
    /// forgot to set cap_reason but still emitted a 3.x trace.
    #[test]
    fn rejects_3x_version_without_cap_reason_at_high_tier() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("devirt_trace.jsonl");
        let writer = TraceWriter::create(path, sample_header("3.x", None)).unwrap();
        let footer = TraceFooter {
            kind: "footer".to_string(),
            steps_total: 0,
            outcome: "truncated".to_string(),
            truncated: true,
            confidence_score: 0.55,
            confidence_tier: "medium".to_string(),
        };
        let err = writer.finalize(footer).unwrap_err();
        match err {
            UnpackError::Pipeline(msg) => assert!(msg.contains("3.x"), "{}", msg),
            other => panic!("expected Pipeline error, got {:?}", other),
        }
    }

    /// 2.x can ship any tier (no cap) — sanity check.
    #[test]
    fn allows_2x_at_any_tier() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("devirt_trace.jsonl");
        let writer = TraceWriter::create(path, sample_header("2.x", None)).unwrap();
        let footer = TraceFooter {
            kind: "footer".to_string(),
            steps_total: 0,
            outcome: "halted".to_string(),
            truncated: false,
            confidence_score: 0.85,
            confidence_tier: "high".to_string(),
        };
        writer.finalize(footer).expect("2.x at high tier is fine");
    }

    /// mem_writes capping at 16 per step.
    #[test]
    fn caps_mem_writes_at_sixteen() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("devirt_trace.jsonl");
        let mut writer = TraceWriter::create(path.clone(), sample_header("2.x", None)).unwrap();
        let mut step = sample_step(0, None);
        step.mem_writes = (0..30)
            .map(|i| MemWrite {
                va: hex_u64(0x14ffff00 + i),
                size: 8,
                value_hex: "0000000000000000".to_string(),
            })
            .collect();
        writer.append_step(step).unwrap();
        writer
            .finalize(TraceFooter {
                kind: "footer".to_string(),
                steps_total: 1,
                outcome: "halted".to_string(),
                truncated: false,
                confidence_score: 0.5,
                confidence_tier: "medium".to_string(),
            })
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let records = parse_jsonl(&content);
        let step = &records[1];
        assert_eq!(
            step["mem_writes"].as_array().unwrap().len(),
            MAX_MEM_WRITES_PER_STEP,
            "mem_writes should be truncated to {}",
            MAX_MEM_WRITES_PER_STEP
        );
        assert_eq!(step["notes"], "writes_truncated");
    }
}
