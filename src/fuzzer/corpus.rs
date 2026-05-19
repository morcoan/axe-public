//! Coverage-guided corpus: in-memory queue + on-disk persistence.
//!
//! Each [`QueueEntry`] represents one input that proved interesting
//! (new edge, new bucket, or improved reachability). Entries hold
//! enough metadata for the power scheduler and the LLM export layer
//! to operate without re-running the input.
//!
//! On-disk layout under the fuzzer's `queue/` directory:
//! ```text
//! queue/
//!   <id>             ← promoted (interesting) inputs
//!   .staging/
//!     <id>           ← pre-execute persistence (Codex finding 2)
//! ```
//!
//! SQLite-backed corpus metadata lives in `corpus.sqlite` and is
//! wired up in step 13; this step persists only the raw input bytes
//! plus in-memory metadata.

#![allow(dead_code)]

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::fuzzer::atomic_write::write_atomic;
use crate::fuzzer::coverage::Novelty;
use crate::fuzzer::staging::InputStaging;

/// One corpus entry — an input that produced new coverage and was
/// kept for further mutation.
#[derive(Clone, Debug)]
pub struct QueueEntry {
    pub id: String,
    pub parent_id: Option<String>,
    pub input: Vec<u8>,
    pub metadata: QueueMetadata,
}

/// Lightweight metadata held alongside each `QueueEntry`. The
/// scheduler reads this to compute energy; the LLM export layer
/// projects a subset of it onto the NDJSON event stream.
#[derive(Clone, Debug, Default)]
pub struct QueueMetadata {
    pub novelty_new_edges: u32,
    pub novelty_new_buckets: u32,
    pub exec_us: u64,
    pub depth: u32,
    pub coverage_hash: u64,
    pub bitmap_size: u32,
    pub favored: bool,
    pub times_fuzzed: u64,
    pub created_at_ms: u128,
    /// Function VAs reached by this input. Populated in step 10 when
    /// reachability scoring lands; empty for step 4.
    pub reached_functions: Vec<u64>,
}

impl QueueMetadata {
    pub fn from_novelty(n: Novelty, exec_us: u64) -> Self {
        Self {
            novelty_new_edges: n.new_edges,
            novelty_new_buckets: n.new_buckets,
            exec_us,
            depth: 0,
            coverage_hash: 0,
            bitmap_size: 0,
            favored: false,
            times_fuzzed: 0,
            created_at_ms: now_ms(),
            reached_functions: Vec::new(),
        }
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Compute an ID for an input. Format: `"blake3-<16hex>"` — short
/// enough to keep filenames manageable, long enough to make
/// collisions effectively impossible.
///
/// The separator is `-` rather than `:` because `:` is not a legal
/// filename character on Windows (NTFS treats it as the alternate
/// data stream separator), and IDs are used directly as filenames
/// under `queue/`.
pub fn input_id(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let bytes_arr = digest.as_bytes();
    format!(
        "blake3-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes_arr[0],
        bytes_arr[1],
        bytes_arr[2],
        bytes_arr[3],
        bytes_arr[4],
        bytes_arr[5],
        bytes_arr[6],
        bytes_arr[7],
    )
}

/// The fuzzer's working corpus.
pub struct FuzzCorpus {
    entries: Vec<QueueEntry>,
    by_id: HashMap<String, usize>,
    queue_dir: PathBuf,
    staging: InputStaging,
}

impl FuzzCorpus {
    /// Open (or create) the on-disk corpus rooted at `queue_dir`.
    /// Sets up `queue_dir/.staging/` for the pre-execute persistence
    /// path required by Codex finding 2.
    pub fn open(queue_dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(queue_dir)?;
        let staging = InputStaging::open(queue_dir)?;
        Ok(Self {
            entries: Vec::new(),
            by_id: HashMap::new(),
            queue_dir: queue_dir.to_path_buf(),
            staging,
        })
    }

    /// Append a new entry to the corpus and persist it to disk
    /// atomically. Returns the entry's index in the in-memory queue.
    pub fn add(&mut self, entry: QueueEntry) -> io::Result<usize> {
        if let Some(&existing) = self.by_id.get(&entry.id) {
            // Deduplicate by content-hash: same bytes → same id → no-op.
            return Ok(existing);
        }
        self.persist_input(&entry.id, &entry.input)?;
        let idx = self.entries.len();
        self.by_id.insert(entry.id.clone(), idx);
        self.entries.push(entry);
        Ok(idx)
    }

    /// Pick an entry for the next fuzz iteration. Step 4 ships a
    /// simple round-robin picker; step 7 replaces this with the
    /// power schedule.
    pub fn pick_round_robin(&self, cursor: usize) -> Option<&QueueEntry> {
        if self.entries.is_empty() {
            None
        } else {
            Some(&self.entries[cursor % self.entries.len()])
        }
    }

    pub fn get(&self, id: &str) -> Option<&QueueEntry> {
        self.by_id.get(id).map(|&idx| &self.entries[idx])
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &QueueEntry> {
        self.entries.iter()
    }

    pub fn queue_dir(&self) -> &Path {
        &self.queue_dir
    }

    pub fn staging(&self) -> &InputStaging {
        &self.staging
    }

    /// Stage `bytes` to `queue/.staging/<id>` and fsync before
    /// returning. The caller MUST invoke `add()` (which promotes the
    /// staged file to `queue/<id>`) or `staging.discard()` after the
    /// execution finishes; orphan recovery on next session start will
    /// catch any that get dropped.
    pub fn stage_for_execution(&self, id: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        self.staging.stage(id, bytes)
    }

    fn persist_input(&self, id: &str, bytes: &[u8]) -> io::Result<()> {
        let path = self.queue_dir.join(id);
        write_atomic(&path, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn input_id_is_deterministic() {
        let a = input_id(b"hello world");
        let b = input_id(b"hello world");
        assert_eq!(a, b);
        assert!(a.starts_with("blake3-"));
        // 16 hex chars after the prefix
        assert_eq!(a.len(), "blake3-".len() + 16);
    }

    #[test]
    fn input_id_differs_for_different_inputs() {
        assert_ne!(input_id(b"alpha"), input_id(b"beta"));
    }

    #[test]
    fn add_persists_input_atomically_to_disk() {
        let tmp = TempDir::new().unwrap();
        let queue_dir = tmp.path().join("queue");
        let mut corpus = FuzzCorpus::open(&queue_dir).unwrap();

        let bytes = b"test input".to_vec();
        let id = input_id(&bytes);
        let entry = QueueEntry {
            id: id.clone(),
            parent_id: None,
            input: bytes.clone(),
            metadata: QueueMetadata::default(),
        };
        corpus.add(entry).unwrap();

        // On-disk file exists at queue_dir/<id>.
        let disk_path = queue_dir.join(&id);
        assert!(disk_path.exists());
        assert_eq!(std::fs::read(&disk_path).unwrap(), bytes);
        // No .tmp leftover.
        assert!(!queue_dir.join(format!("{id}.tmp")).exists());
    }

    #[test]
    fn add_dedupes_by_id() {
        let tmp = TempDir::new().unwrap();
        let mut corpus = FuzzCorpus::open(tmp.path()).unwrap();
        let bytes = b"same content".to_vec();
        let id = input_id(&bytes);
        let entry = QueueEntry {
            id: id.clone(),
            parent_id: None,
            input: bytes,
            metadata: QueueMetadata::default(),
        };
        let idx_a = corpus.add(entry.clone()).unwrap();
        let idx_b = corpus.add(entry).unwrap();
        assert_eq!(idx_a, idx_b, "same id -> same index, no duplicate");
        assert_eq!(corpus.len(), 1);
    }

    #[test]
    fn round_robin_picker_cycles_entries() {
        let tmp = TempDir::new().unwrap();
        let mut corpus = FuzzCorpus::open(tmp.path()).unwrap();
        for i in 0..3u32 {
            let bytes = vec![i as u8];
            corpus
                .add(QueueEntry {
                    id: input_id(&bytes),
                    parent_id: None,
                    input: bytes,
                    metadata: QueueMetadata::default(),
                })
                .unwrap();
        }
        let a = corpus.pick_round_robin(0).unwrap().input.clone();
        let b = corpus.pick_round_robin(1).unwrap().input.clone();
        let c = corpus.pick_round_robin(2).unwrap().input.clone();
        let wrap = corpus.pick_round_robin(3).unwrap().input.clone();
        assert_eq!(a, vec![0]);
        assert_eq!(b, vec![1]);
        assert_eq!(c, vec![2]);
        assert_eq!(wrap, a, "cursor wraps modulo len");
    }

    #[test]
    fn picker_returns_none_for_empty_corpus() {
        let tmp = TempDir::new().unwrap();
        let corpus = FuzzCorpus::open(tmp.path()).unwrap();
        assert!(corpus.pick_round_robin(0).is_none());
    }

    #[test]
    fn stage_for_execution_writes_to_staging_subdir() {
        let tmp = TempDir::new().unwrap();
        let corpus = FuzzCorpus::open(tmp.path()).unwrap();
        let id = "test-id";
        let path = corpus.stage_for_execution(id, b"pre-exec").unwrap();
        assert!(path.exists());
        // Lives under .staging/, not queue root.
        assert!(path.components().any(|c| c.as_os_str() == ".staging"));
    }

    #[test]
    fn metadata_from_novelty_preserves_counts() {
        let n = Novelty {
            new_edges: 5,
            new_buckets: 2,
        };
        let m = QueueMetadata::from_novelty(n, 1234);
        assert_eq!(m.novelty_new_edges, 5);
        assert_eq!(m.novelty_new_buckets, 2);
        assert_eq!(m.exec_us, 1234);
        assert!(m.created_at_ms > 0);
    }
}
