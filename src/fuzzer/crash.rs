//! Crash signature derivation + deduplication.
//!
//! AFL's classic "is this crash unique?" test is fragile when used
//! alone — fault addresses get reused across distinct bugs, and
//! stack hashes can over- or under-cluster. The signature here
//! combines three signals:
//!
//! 1. **Crash kind**: coarse class string from the executor
//!    (`"emulator_oob"`, `"heap-buffer-overflow"`, `"low_fidelity"`,
//!    `"budget_cap"`, …). Different kinds never dedupe together.
//! 2. **Signal number** when present (POSIX in-process backend
//!    populates this; emulator path leaves it `None`).
//! 3. **Normalized top frames** — top N PCs from the trace, sorted
//!    deterministically so reordering within a function group
//!    doesn't change the hash.
//!
//! BLAKE3 hash of `(kind || signal_bytes || sorted_top_frame_bytes)`
//! gives a 32-byte [`CrashSignature`]. Hex-encoded, it becomes the
//! `crashes/<sig>/` subdirectory under the fuzzer output dir.
//!
//! [`CrashDb::dedup_and_store`] returns `Some(sig)` for newly-seen
//! crashes and `None` for duplicates — the caller only emits a
//! `Finding` for new signatures.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use crate::fuzzer::atomic_write::write_atomic;
use crate::fuzzer::executor::{CrashInfo, ExitKind};

/// 32-byte BLAKE3 hash identifying a crash family.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CrashSignature(pub [u8; 32]);

impl CrashSignature {
    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

/// Per-family entry in the dedup database.
#[derive(Clone, Debug)]
pub struct CrashEntry {
    pub signature: CrashSignature,
    pub count: u32,
    pub first_input_id: String,
    pub first_seen_at_ms: u128,
}

/// In-memory dedup database + on-disk `crashes/<sig>/` layout.
pub struct CrashDb {
    seen: HashMap<CrashSignature, CrashEntry>,
    crashes_dir: PathBuf,
}

impl CrashDb {
    /// Open (or create) the crashes directory under the fuzzer's
    /// output dir. Loads no state from disk on open — the in-memory
    /// dedup table starts empty each session (matches AFL semantics).
    pub fn open(crashes_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(crashes_dir)?;
        Ok(Self {
            seen: HashMap::new(),
            crashes_dir: crashes_dir.to_path_buf(),
        })
    }

    /// Store a new crash if its signature hasn't been seen this
    /// session. Returns `Some(sig)` when a new family was recorded
    /// (and the caller should emit a `Finding`), or `None` for a
    /// duplicate (count incremented in place).
    pub fn dedup_and_store(
        &mut self,
        input_id: &str,
        input_bytes: &[u8],
        info: &CrashInfo,
    ) -> io::Result<Option<CrashSignature>> {
        let signature = signature_for(info);
        if let Some(entry) = self.seen.get_mut(&signature) {
            entry.count += 1;
            return Ok(None);
        }
        self.persist_crash(&signature, input_id, input_bytes, info)?;
        let entry = CrashEntry {
            signature,
            count: 1,
            first_input_id: input_id.to_string(),
            first_seen_at_ms: now_ms(),
        };
        self.seen.insert(signature, entry);
        Ok(Some(signature))
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn get(&self, sig: &CrashSignature) -> Option<&CrashEntry> {
        self.seen.get(sig)
    }

    pub fn iter(&self) -> impl Iterator<Item = &CrashEntry> {
        self.seen.values()
    }

    pub fn crashes_dir(&self) -> &Path {
        &self.crashes_dir
    }

    fn persist_crash(
        &self,
        signature: &CrashSignature,
        input_id: &str,
        input_bytes: &[u8],
        info: &CrashInfo,
    ) -> io::Result<()> {
        let sig_dir = self.crashes_dir.join(signature.to_hex());
        std::fs::create_dir_all(&sig_dir)?;
        write_atomic(&sig_dir.join("input.bin"), input_bytes)?;
        let info_json =
            serde_json::to_vec_pretty(&info_to_json(input_id, info)).map_err(io::Error::other)?;
        write_atomic(&sig_dir.join("info.json"), &info_json)?;
        Ok(())
    }
}

/// Derive a [`CrashSignature`] from a [`CrashInfo`]. Kind + signal +
/// sorted top-frame PCs feed BLAKE3.
pub fn signature_for(info: &CrashInfo) -> CrashSignature {
    let mut hasher = blake3::Hasher::new();
    hasher.update(info.kind.as_bytes());
    hasher.update(b"|");
    if let Some(sig) = info.signal {
        hasher.update(&sig.to_le_bytes());
    }
    hasher.update(b"|");
    let mut frames = info.top_frames.clone();
    frames.sort_unstable(); // canonical order; tolerates trace-order noise
    for f in &frames {
        hasher.update(&f.to_le_bytes());
    }
    hasher.update(b"|");
    if let Some(s) = &info.sanitizer_type {
        hasher.update(s.as_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    CrashSignature(out)
}

/// Helper for the `pe.rs` integration: a crash-like exit needs both
/// classification AND a `CrashInfo`. This wraps the boundary check
/// `exit.is_crash_like() || exit == Timeout` so callers don't have
/// to re-implement the rule.
pub fn should_dedupe(exit: ExitKind) -> bool {
    exit.is_crash_like() || exit == ExitKind::Timeout
}

fn info_to_json(input_id: &str, info: &CrashInfo) -> serde_json::Value {
    serde_json::json!({
        "schema": "fuzzer_crash_info/1",
        "input_id": input_id,
        "kind": info.kind,
        "signal": info.signal,
        "fault_pc": info.fault_pc.map(|v| format!("0x{v:016x}")),
        "top_frames": info.top_frames.iter().map(|v| format!("0x{v:016x}")).collect::<Vec<_>>(),
        "sanitizer_type": info.sanitizer_type,
    })
}

fn now_ms() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn info(kind: &str, signal: Option<i32>, frames: &[u64]) -> CrashInfo {
        CrashInfo {
            kind: kind.into(),
            signal,
            fault_pc: frames.first().copied(),
            top_frames: frames.to_vec(),
            sanitizer_type: None,
        }
    }

    #[test]
    fn signature_is_stable_for_same_inputs() {
        let a = signature_for(&info("oob", Some(11), &[0x1000, 0x1010, 0x1020]));
        let b = signature_for(&info("oob", Some(11), &[0x1000, 0x1010, 0x1020]));
        assert_eq!(a, b);
    }

    #[test]
    fn signature_invariant_under_frame_reordering() {
        // Same set of frames, different order → same signature
        // (the deterministic sort normalizes).
        let a = signature_for(&info("oob", Some(11), &[0x1000, 0x1010, 0x1020]));
        let b = signature_for(&info("oob", Some(11), &[0x1020, 0x1000, 0x1010]));
        assert_eq!(a, b, "frame order must not affect signature");
    }

    #[test]
    fn signature_differs_on_kind() {
        let a = signature_for(&info("heap-buffer-overflow", None, &[0x1000]));
        let b = signature_for(&info("stack-overflow", None, &[0x1000]));
        assert_ne!(a, b);
    }

    #[test]
    fn signature_differs_on_signal() {
        let a = signature_for(&info("crash", Some(11), &[0x1000]));
        let b = signature_for(&info("crash", Some(6), &[0x1000]));
        assert_ne!(a, b);
    }

    #[test]
    fn signature_differs_on_top_frames() {
        let a = signature_for(&info("crash", None, &[0x1000, 0x1010]));
        let b = signature_for(&info("crash", None, &[0x2000, 0x2010]));
        assert_ne!(a, b);
    }

    #[test]
    fn signature_hex_is_64_chars() {
        let sig = signature_for(&info("any", None, &[0x1000]));
        let hex = sig.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn dedup_stores_new_and_skips_repeat() {
        let tmp = TempDir::new().unwrap();
        let mut db = CrashDb::open(&tmp.path().join("crashes")).unwrap();
        let i = info("oob", Some(11), &[0x1000, 0x1010]);

        let first = db.dedup_and_store("input-a", b"input bytes", &i).unwrap();
        assert!(first.is_some(), "first crash recorded");
        assert_eq!(db.len(), 1);

        let second = db
            .dedup_and_store("input-b", b"different bytes", &i)
            .unwrap();
        assert!(second.is_none(), "same signature is a duplicate");
        assert_eq!(db.len(), 1, "no new family added");
        assert_eq!(db.iter().next().unwrap().count, 2, "count incremented");
    }

    #[test]
    fn dedup_persists_input_and_info_to_disk() {
        let tmp = TempDir::new().unwrap();
        let crashes_dir = tmp.path().join("crashes");
        let mut db = CrashDb::open(&crashes_dir).unwrap();
        let i = info("crash", Some(11), &[0xdead_beef]);
        let sig = db
            .dedup_and_store("input-xyz", b"the bytes", &i)
            .unwrap()
            .unwrap();

        let sig_dir = crashes_dir.join(sig.to_hex());
        assert!(sig_dir.join("input.bin").exists());
        assert!(sig_dir.join("info.json").exists());
        assert_eq!(
            std::fs::read(sig_dir.join("input.bin")).unwrap(),
            b"the bytes"
        );

        let info_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(sig_dir.join("info.json")).unwrap()).unwrap();
        assert_eq!(info_json["kind"], "crash");
        assert_eq!(info_json["signal"], 11);
        assert_eq!(info_json["input_id"], "input-xyz");
    }

    #[test]
    fn dedup_distinct_families_get_distinct_dirs() {
        let tmp = TempDir::new().unwrap();
        let crashes_dir = tmp.path().join("crashes");
        let mut db = CrashDb::open(&crashes_dir).unwrap();
        let i1 = info("heap-buffer-overflow", Some(11), &[0x1000]);
        let i2 = info("stack-overflow", Some(11), &[0x1000]);
        let s1 = db.dedup_and_store("a", b"a", &i1).unwrap().unwrap();
        let s2 = db.dedup_and_store("b", b"b", &i2).unwrap().unwrap();
        assert_ne!(s1, s2);
        assert!(crashes_dir.join(s1.to_hex()).exists());
        assert!(crashes_dir.join(s2.to_hex()).exists());
    }

    #[test]
    fn should_dedupe_matches_crash_and_timeout() {
        assert!(should_dedupe(ExitKind::Crash));
        assert!(should_dedupe(ExitKind::EmulatorOOB));
        assert!(should_dedupe(ExitKind::Sanitizer));
        assert!(should_dedupe(ExitKind::Timeout));
        assert!(!should_dedupe(ExitKind::Ok));
        assert!(!should_dedupe(ExitKind::EmulatorLowFidelity));
    }
}
