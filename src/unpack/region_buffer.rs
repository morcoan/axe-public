//! Captured memory region — held in-process until dumped to disk.
//!
//! Each `RegionBuffer` corresponds to one entry in
//! `SnapshotManifest::regions`. The buffer is populated by
//! `snapshot_capture.rs` (Step 17) via `ReadProcessMemory` and
//! finalized via `dump_to()` which writes the raw bytes atomically
//! and returns the blob hash + entropy needed to build a
//! `RegionDescriptor`.
//!
//! # Why in-memory and not mmap-backed
//!
//! The plan's draft language called for mmap-backed buffers. In
//! practice, captured regions are typically a few KB to a few MB
//! (the unpacked payload section of a packed binary) and the
//! analyst's host has gigabytes of RAM. A plain `Vec<u8>` is
//! simpler, more portable across platforms (tests run on Linux),
//! and avoids the lifetime juggling of a borrowed mmap. The
//! atomic-write discipline is preserved by routing the dump
//! through `crate::atomic_write::write_atomic`.

use std::path::Path;

use crate::atomic_write::write_atomic;
use crate::unpack::snapshot::{RegionDescriptor, RegionOrigin};

/// Captured bytes from a single memory region of the target. Held
/// in process memory until `dump_to()` writes them to disk.
#[derive(Clone, Debug)]
pub struct RegionBuffer {
    /// Virtual address the bytes were read from in the target.
    pub va_base: u64,
    /// Raw bytes as they appeared at capture time.
    pub bytes: Vec<u8>,
    /// Number of write hits observed via `PAGE_GUARD` while the
    /// region was being populated. Counters maintained by
    /// `write_log.rs` (Step 15); copied here at finalize.
    pub writes_observed: u64,
    /// Number of distinct instruction-pointer hits observed
    /// inside this region. Maintained by `oep_detector.rs`
    /// (Step 21).
    pub executions_observed: u64,
}

impl RegionBuffer {
    pub fn new(va_base: u64) -> Self {
        Self {
            va_base,
            bytes: Vec::new(),
            writes_observed: 0,
            executions_observed: 0,
        }
    }

    pub fn with_capacity(va_base: u64, size: usize) -> Self {
        Self {
            va_base,
            bytes: Vec::with_capacity(size),
            writes_observed: 0,
            executions_observed: 0,
        }
    }

    pub fn from_bytes(va_base: u64, bytes: Vec<u8>) -> Self {
        Self {
            va_base,
            bytes,
            writes_observed: 0,
            executions_observed: 0,
        }
    }

    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Shannon entropy of the captured bytes in bits/byte (0.0
    /// for uniform zeros, ~8.0 for uniform random). Used by the
    /// OEP detector (Step 19): an entropy DROP between successive
    /// snapshots of the same region signals "encrypted blob just
    /// got decrypted into plaintext code".
    pub fn entropy(&self) -> f64 {
        shannon_entropy(&self.bytes)
    }

    /// BLAKE3 hash of the captured bytes as a lowercase hex
    /// string. Goes into `RegionDescriptor::blob_hash_blake3` so
    /// the consumer can verify the on-disk blob matches the
    /// manifest.
    pub fn hash_blake3(&self) -> String {
        let h = blake3::hash(&self.bytes);
        h.to_hex().to_string()
    }

    /// Atomically write the captured bytes to disk. Path must be
    /// the final on-disk location (typically
    /// `<out_dir>/regions/region_NN.bin`); `AtomicWriter` handles
    /// the temp+rename dance.
    pub fn dump_to(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        write_atomic(path, &self.bytes)
    }

    /// Build a `RegionDescriptor` for inclusion in a
    /// `SnapshotManifest`. The caller supplies the metadata that
    /// the buffer cannot infer alone (`id`, `permissions`,
    /// `origin`, `blob_path`).
    pub fn to_descriptor(
        &self,
        id: u32,
        permissions: &str,
        origin: RegionOrigin,
        blob_path: &str,
    ) -> RegionDescriptor {
        RegionDescriptor {
            id,
            va_base: format!("0x{:016x}", self.va_base),
            size_bytes: self.bytes.len() as u64,
            permissions: permissions.to_string(),
            origin,
            blob_path: blob_path.to_string(),
            blob_hash_blake3: self.hash_blake3(),
            entropy_final: self.entropy(),
            writes_observed: self.writes_observed,
            executions_observed: self.executions_observed,
        }
    }
}

/// Shannon entropy in bits/byte. Empty input returns 0.0 (not
/// NaN — convenient for downstream comparisons).
fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut h = 0.0_f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_buffer_size_zero_entropy_zero() {
        let b = RegionBuffer::new(0x140000000);
        assert_eq!(b.size(), 0);
        assert!(b.is_empty());
        assert_eq!(b.entropy(), 0.0);
    }

    #[test]
    fn all_zero_buffer_has_zero_entropy() {
        let b = RegionBuffer::from_bytes(0, vec![0u8; 4096]);
        assert_eq!(b.entropy(), 0.0);
    }

    #[test]
    fn uniform_random_buffer_entropy_near_eight() {
        // Deterministic pseudo-random fill — every byte value
        // appears equally often.
        let bytes: Vec<u8> = (0..=255u8).cycle().take(256 * 64).collect();
        let b = RegionBuffer::from_bytes(0, bytes);
        let e = b.entropy();
        assert!(
            (e - 8.0).abs() < 0.01,
            "expected entropy ≈ 8.0 for uniform-byte input, got {}",
            e
        );
    }

    #[test]
    fn blake3_hash_is_deterministic() {
        let b1 = RegionBuffer::from_bytes(0, vec![1, 2, 3, 4]);
        let b2 = RegionBuffer::from_bytes(0xdeadbeef, vec![1, 2, 3, 4]);
        // VA does not affect hash (only the bytes do).
        assert_eq!(b1.hash_blake3(), b2.hash_blake3());
    }

    #[test]
    fn blake3_hash_distinguishes_different_bytes() {
        let b1 = RegionBuffer::from_bytes(0, vec![1, 2, 3, 4]);
        let b2 = RegionBuffer::from_bytes(0, vec![1, 2, 3, 5]);
        assert_ne!(b1.hash_blake3(), b2.hash_blake3());
    }

    #[test]
    fn dump_writes_atomically_and_roundtrips() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("regions").join("region_00.bin");
        let b = RegionBuffer::from_bytes(0x140000000, vec![42u8; 1024]);
        b.dump_to(&path).expect("dump");
        let read = std::fs::read(&path).expect("read");
        assert_eq!(read.len(), 1024);
        assert!(read.iter().all(|&x| x == 42));
    }

    #[test]
    fn to_descriptor_pins_va_format_and_blob_path() {
        let b = RegionBuffer::from_bytes(0x140001000, vec![0; 4096]);
        let d = b.to_descriptor(
            7,
            "RWX",
            RegionOrigin {
                alloc_api: "VirtualAlloc".into(),
                alloc_site_va: "0x140001234".into(),
                alloc_size_requested: 4096,
            },
            "regions/region_07.bin",
        );
        assert_eq!(d.id, 7);
        assert_eq!(d.va_base, "0x0000000140001000");
        assert_eq!(d.size_bytes, 4096);
        assert_eq!(d.permissions, "RWX");
        assert_eq!(d.blob_path, "regions/region_07.bin");
        assert_eq!(d.entropy_final, 0.0);
    }

    #[test]
    fn writes_and_executions_counters_propagate_to_descriptor() {
        let mut b = RegionBuffer::from_bytes(0x140001000, vec![0; 64]);
        b.writes_observed = 17;
        b.executions_observed = 3;
        let d = b.to_descriptor(
            0,
            "RWX",
            RegionOrigin {
                alloc_api: "initial".into(),
                alloc_site_va: "0x0".into(),
                alloc_size_requested: 64,
            },
            "regions/region_00.bin",
        );
        assert_eq!(d.writes_observed, 17);
        assert_eq!(d.executions_observed, 3);
    }
}
