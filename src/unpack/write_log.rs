//! Per-page write trace. Records guard-page violations as they
//! land in the debug loop, caps memory via a bounded ring
//! buffer, and emits `out/unpack/guard_page_log.jsonl` at
//! finalize.
//!
//! # Why bounded
//!
//! A pathological target (or a deliberately noisy packer) can
//! generate millions of writes during unpacking. Aurora caps
//! the log at `max_entries` (default 100k) and tracks
//! `dropped_count` so the snapshot's `uncertainties` field can
//! warn the LLM consumer when the log was truncated.
//!
//! # Drop policy
//!
//! Drop-oldest (FIFO). The reasoning: unpacking algorithms
//! typically write the decoded payload bytes LAST, so the most
//! recent entries are the most informative. If an analyst wants
//! the entire trace, they raise `max_entries`.

use std::collections::VecDeque;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::atomic_write::write_atomic;
use crate::unpack::guard_pages::GuardAccessKind;

const DEFAULT_MAX_ENTRIES: usize = 100_000;

/// One entry per guard-page violation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WriteLogEntry {
    /// Milliseconds since the Aurora session started.
    pub ts_ms: u64,
    /// Instruction pointer of the faulting instruction (in the
    /// target's address space).
    pub faulting_pc: String,
    /// Target VA that was accessed.
    pub target_va: String,
    /// Read / Write / Execute / Other. Mirrors
    /// `GuardAccessKind` from `guard_pages.rs`.
    pub access: String,
    /// ID of the captured region this VA falls inside, or
    /// `None` if the snapshot capture hasn't run yet / the
    /// faulting VA falls outside any captured region.
    pub region_id: Option<u32>,
}

/// Bounded ring buffer of write-log entries.
pub struct WriteLog {
    entries: VecDeque<WriteLogEntry>,
    max_entries: usize,
    dropped_count: u64,
}

impl WriteLog {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_ENTRIES)
    }

    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_entries.min(4096)),
            max_entries,
            dropped_count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped_count
    }

    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Append a new entry. When the buffer is at `max_entries`,
    /// pops the oldest (FIFO) and increments `dropped_count`.
    pub fn record(&mut self, entry: WriteLogEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
            self.dropped_count += 1;
        }
        self.entries.push_back(entry);
    }

    /// Convenience: build an entry from primitive fields and
    /// record it.
    pub fn record_access(
        &mut self,
        ts_ms: u64,
        faulting_pc: u64,
        target_va: u64,
        access: GuardAccessKind,
        region_id: Option<u32>,
    ) {
        self.record(WriteLogEntry {
            ts_ms,
            faulting_pc: format!("0x{:016x}", faulting_pc),
            target_va: format!("0x{:016x}", target_va),
            access: access_kind_str(access).to_string(),
            region_id,
        });
    }

    /// Atomically write the log as JSONL (one entry per line).
    /// Returns the number of bytes written.
    pub fn emit_jsonl(&self, path: &Path) -> std::io::Result<u64> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut buf: Vec<u8> = Vec::with_capacity(self.entries.len() * 96);
        for e in &self.entries {
            let line = serde_json::to_string(e)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
        }
        write_atomic(path, &buf)?;
        Ok(buf.len() as u64)
    }

    /// Iterator over current entries — convenient for tests +
    /// downstream consumers that want to fold into the snapshot
    /// manifest.
    pub fn iter(&self) -> impl Iterator<Item = &WriteLogEntry> {
        self.entries.iter()
    }
}

impl Default for WriteLog {
    fn default() -> Self {
        Self::new()
    }
}

fn access_kind_str(k: GuardAccessKind) -> &'static str {
    match k {
        GuardAccessKind::Read => "read",
        GuardAccessKind::Write => "write",
        GuardAccessKind::Execute => "execute",
        GuardAccessKind::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_log_is_empty() {
        let log = WriteLog::new();
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
        assert_eq!(log.dropped_count(), 0);
    }

    #[test]
    fn record_grows_until_cap_then_drops_oldest() {
        let mut log = WriteLog::with_capacity(3);
        log.record_access(0, 0x1000, 0x2000, GuardAccessKind::Write, Some(0));
        log.record_access(1, 0x1001, 0x2001, GuardAccessKind::Write, Some(0));
        log.record_access(2, 0x1002, 0x2002, GuardAccessKind::Write, Some(0));
        assert_eq!(log.len(), 3);
        assert_eq!(log.dropped_count(), 0);

        log.record_access(3, 0x1003, 0x2003, GuardAccessKind::Write, Some(0));
        assert_eq!(log.len(), 3, "cap holds");
        assert_eq!(log.dropped_count(), 1);

        // FIFO: oldest (ts_ms=0) should be gone.
        let earliest = log.iter().next().unwrap();
        assert_eq!(earliest.ts_ms, 1);
    }

    #[test]
    fn record_formats_addresses_with_16_hex_digits() {
        let mut log = WriteLog::new();
        log.record_access(42, 0x140001234, 0x140005678, GuardAccessKind::Read, Some(7));
        let e = log.iter().next().unwrap();
        assert_eq!(e.faulting_pc, "0x0000000140001234");
        assert_eq!(e.target_va, "0x0000000140005678");
        assert_eq!(e.access, "read");
        assert_eq!(e.region_id, Some(7));
    }

    #[test]
    fn access_kinds_serialize_to_lowercase_strings() {
        assert_eq!(access_kind_str(GuardAccessKind::Read), "read");
        assert_eq!(access_kind_str(GuardAccessKind::Write), "write");
        assert_eq!(access_kind_str(GuardAccessKind::Execute), "execute");
        assert_eq!(access_kind_str(GuardAccessKind::Other), "other");
    }

    #[test]
    fn emit_jsonl_round_trips_via_serde() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("guard_page_log.jsonl");
        let mut log = WriteLog::new();
        for i in 0..5 {
            log.record_access(
                i,
                0x1000 + i,
                0x2000 + i,
                GuardAccessKind::Write,
                Some(i as u32),
            );
        }
        let bytes_written = log.emit_jsonl(&path).expect("emit");
        assert!(bytes_written > 0);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 5);
        for (i, line) in text.lines().enumerate() {
            let e: WriteLogEntry = serde_json::from_str(line).unwrap();
            assert_eq!(e.ts_ms, i as u64);
        }
    }

    #[test]
    fn emit_jsonl_creates_parent_directory() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("nested").join("dir").join("log.jsonl");
        let log = WriteLog::new();
        log.emit_jsonl(&path).expect("emit creates parent");
        assert!(path.exists());
    }

    #[test]
    fn empty_log_emit_writes_empty_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("empty.jsonl");
        let log = WriteLog::new();
        let written = log.emit_jsonl(&path).expect("emit");
        assert_eq!(written, 0);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.is_empty());
    }

    #[test]
    fn dropped_count_accumulates_past_cap() {
        let mut log = WriteLog::with_capacity(2);
        for i in 0..10 {
            log.record_access(i, i, i, GuardAccessKind::Write, None);
        }
        assert_eq!(log.len(), 2);
        assert_eq!(log.dropped_count(), 8);
    }
}
