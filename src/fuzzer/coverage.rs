//! AFL-style edge bitmap with hitcount bucketing.
//!
//! Two parallel maps participate in coverage feedback:
//! - **`local`**: per-execution raw hitcounts. Each call to
//!   [`CoverageMap::record_edge`] does `local[edge_hash] += 1`
//!   (saturating). Reset between executions via [`CoverageMap::clear`].
//! - **`global`**: cross-execution max bucket ever seen per edge. AFL
//!   calls this `virgin_bits` (modulo inversion); we store it directly
//!   so "is this run interesting?" is a single byte compare per edge.
//!
//! Both maps are the same `[u8; MAP_SIZE]` shape so they can be
//! compared word-by-word in [`classify`]. `MAP_SIZE` is a power of two
//! so `& (MAP_SIZE - 1)` replaces the modulo on the hot hashing path.
//!
//! Collision math: at 50k distinct edges the expected collision rate
//! is ~0.04%, acceptable for fuzzing feedback (collisions
//! over-report rather than under-report novelty). If we ever push past
//! ~250k edges, bump `MAP_SIZE` to `1 << 22`.

#![allow(dead_code)]

use std::hash::Hasher;

/// 1 MiB edge bitmap. Power of two so the hash mask is fast.
pub const MAP_SIZE: usize = 1 << 20;
pub const MAP_MASK: usize = MAP_SIZE - 1;

/// Per-edge byte-wide hit counter (raw) or max bucket (global).
/// Wrapped in `Box` because a stack-allocated `[u8; 1 << 20]` would
/// overflow the default 1 MiB Rust stack on every constructor call.
///
/// `Clone` is derived because the concolic bridge's
/// [`crate::concolic::fuzzer_bridge::CorpusBridge::promote_if_novel`]
/// takes a snapshot of the global map before its read-only novelty
/// check (Codex finding 2 transactional discipline).
#[derive(Clone)]
pub struct CoverageMap {
    inner: Box<[u8; MAP_SIZE]>,
}

impl CoverageMap {
    pub fn new() -> Self {
        // The `vec! → Box<[u8]> → Box<[u8; MAP_SIZE]>` dance is
        // necessary because `Box::new([0u8; MAP_SIZE])` builds the
        // array on the stack first.
        let boxed_slice: Box<[u8]> = vec![0u8; MAP_SIZE].into_boxed_slice();
        let inner: Box<[u8; MAP_SIZE]> = boxed_slice.try_into().expect("vec was sized to MAP_SIZE");
        Self { inner }
    }

    /// Bump the hitcount for an edge identified by `(from_va, to_va)`.
    /// Saturating so a hot loop doesn't wrap the bucket back to zero.
    pub fn record_edge(&mut self, from: u64, to: u64) {
        let idx = edge_hash(from, to);
        self.inner[idx] = self.inner[idx].saturating_add(1);
    }

    /// Reset every byte to zero. Called between executions to wipe the
    /// per-run map; the global map persists.
    pub fn clear(&mut self) {
        self.inner.fill(0);
    }

    /// Raw byte slice view. Used by [`classify`] and tests.
    pub fn as_slice(&self) -> &[u8; MAP_SIZE] {
        &self.inner
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8; MAP_SIZE] {
        &mut self.inner
    }
}

impl Default for CoverageMap {
    fn default() -> Self {
        Self::new()
    }
}

/// Bucket a raw hitcount into one of 9 AFL-style buckets. This makes
/// "loop iteration count varied slightly" not look like new coverage
/// while still distinguishing "ran once" from "ran a hundred times."
#[inline]
pub fn bucket(hits: u8) -> u8 {
    match hits {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4..=7 => 4,
        8..=15 => 5,
        16..=31 => 6,
        32..=127 => 7,
        _ => 8,
    }
}

/// Hash an `(from_va, to_va)` edge into a bitmap slot. The `& MAP_MASK`
/// is correct (not biased) because `MAP_SIZE` is a power of two.
#[inline]
pub fn edge_hash(from: u64, to: u64) -> usize {
    let mut hasher = ahash::AHasher::default();
    hasher.write_u64(from);
    hasher.write_u64(to);
    (hasher.finish() as usize) & MAP_MASK
}

/// Verdict from comparing a per-run map against the global map.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Novelty {
    /// Edges that were 0 in the global map and non-zero in the local
    /// run. These are "first time we've ever hit this edge."
    pub new_edges: u32,
    /// Edges that existed in the global map but whose bucket strictly
    /// increased after this run. Per AFL, these still count as novel
    /// — the loop count climbed into a new bucket.
    pub new_buckets: u32,
}

impl Novelty {
    pub fn is_interesting(self) -> bool {
        self.new_edges > 0 || self.new_buckets > 0
    }
}

/// Classify `local` (raw per-run hitcounts) against `global` (max
/// bucket ever seen per edge). Updates `global` in place to the new
/// max-bucket value for any edge whose bucket strictly increased.
///
/// Returns the [`Novelty`] verdict — the scheduler uses this to decide
/// whether to keep the candidate in the corpus.
///
/// This is now a thin combiner of [`classify_against_snapshot`] +
/// [`merge_into_global`] (Codex finding 2 split). Direct callers
/// using this single function get byte-identical behavior to the
/// pre-split version; the concolic [`crate::concolic::fuzzer_bridge`]
/// uses the split halves to make promotion transactional.
pub fn classify(local: &CoverageMap, global: &mut CoverageMap) -> Novelty {
    let novelty = classify_against_snapshot(local, global);
    merge_into_global(local, global);
    novelty
}

/// **Codex finding 2 — read-only half of [`classify`]**.
///
/// Compute the [`Novelty`] of `local` against `snapshot` WITHOUT
/// mutating `snapshot`. The concolic bridge in
/// [`crate::concolic::fuzzer_bridge::CorpusBridge::promote_if_novel`]
/// calls this BEFORE the durable input write / corpus add, so a
/// failure between the novelty check and the corpus.add can never
/// leave the global map mutated for an edge that has no on-disk
/// reproducer.
///
/// The snapshot passed in is conventionally a clone of the
/// fuzzer-shared global map at the moment the promotion attempt
/// started.
pub fn classify_against_snapshot(local: &CoverageMap, snapshot: &CoverageMap) -> Novelty {
    let mut novelty = Novelty::default();
    let local_bytes = local.as_slice();
    let snap_bytes = snapshot.as_slice();
    for i in 0..MAP_SIZE {
        let raw = local_bytes[i];
        if raw == 0 {
            continue;
        }
        let local_bucket = bucket(raw);
        let snap_bucket = snap_bytes[i];
        if snap_bucket == 0 {
            novelty.new_edges += 1;
        } else if local_bucket > snap_bucket {
            novelty.new_buckets += 1;
        }
    }
    novelty
}

/// **Codex finding 2 — mutation-only half of [`classify`]**.
///
/// Merge `local`'s per-edge buckets into `global`, taking the max.
/// The concolic bridge calls this ONLY after the durable input write
/// and the corpus.add both succeed — so any partial failure
/// short-circuits without corrupting the shared coverage view.
pub fn merge_into_global(local: &CoverageMap, global: &mut CoverageMap) {
    let local_bytes = local.as_slice();
    let global_bytes = global.as_mut_slice();
    for i in 0..MAP_SIZE {
        let raw = local_bytes[i];
        if raw == 0 {
            continue;
        }
        let local_bucket = bucket(raw);
        let global_bucket = global_bytes[i];
        if local_bucket > global_bucket {
            global_bytes[i] = local_bucket;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_constructor_zeros_every_byte() {
        let m = CoverageMap::new();
        assert!(m.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn bucket_boundaries_match_afl_table() {
        assert_eq!(bucket(0), 0);
        assert_eq!(bucket(1), 1);
        assert_eq!(bucket(2), 2);
        assert_eq!(bucket(3), 3);
        assert_eq!(bucket(4), 4);
        assert_eq!(bucket(7), 4);
        assert_eq!(bucket(8), 5);
        assert_eq!(bucket(15), 5);
        assert_eq!(bucket(16), 6);
        assert_eq!(bucket(31), 6);
        assert_eq!(bucket(32), 7);
        assert_eq!(bucket(127), 7);
        assert_eq!(bucket(128), 8);
        assert_eq!(bucket(255), 8);
    }

    #[test]
    fn record_edge_is_saturating() {
        let mut m = CoverageMap::new();
        for _ in 0..1000 {
            m.record_edge(0x1000, 0x1010);
        }
        // Any single edge tops out at u8::MAX, not wrap-to-zero.
        let idx = edge_hash(0x1000, 0x1010);
        assert_eq!(m.as_slice()[idx], 255);
    }

    #[test]
    fn edge_hash_is_deterministic_within_run() {
        // Same call twice → same slot. (Hash construction with default
        // seed is deterministic for a single program run.)
        let h1 = edge_hash(0x1000, 0x1010);
        let h2 = edge_hash(0x1000, 0x1010);
        assert_eq!(h1, h2);
    }

    #[test]
    fn edge_hash_distinguishes_directionality() {
        // (a, b) vs (b, a) must hash to (almost certainly) different
        // slots — AFL's prev-pc XOR trick is for the same reason.
        let h1 = edge_hash(0x1000, 0x1010);
        let h2 = edge_hash(0x1010, 0x1000);
        assert_ne!(h1, h2, "edge directionality must affect the hash");
    }

    #[test]
    fn edge_hash_is_in_range() {
        for from in [0u64, 1, 0xdeadbeef, u64::MAX] {
            for to in [0u64, 1, 0xfeedface, u64::MAX] {
                assert!(edge_hash(from, to) < MAP_SIZE);
            }
        }
    }

    #[test]
    fn classify_reports_new_edge_on_first_hit() {
        let mut local = CoverageMap::new();
        let mut global = CoverageMap::new();
        local.record_edge(0x1000, 0x1010);
        let n = classify(&local, &mut global);
        assert_eq!(n.new_edges, 1);
        assert_eq!(n.new_buckets, 0);
        assert!(n.is_interesting());
    }

    #[test]
    fn classify_reports_new_bucket_when_hitcount_climbs() {
        let mut local = CoverageMap::new();
        let mut global = CoverageMap::new();
        // First run: 1 hit → bucket 1.
        local.record_edge(0x1000, 0x1010);
        let _ = classify(&local, &mut global);

        // Second run: 5 hits → bucket 4 (strictly greater).
        local.clear();
        for _ in 0..5 {
            local.record_edge(0x1000, 0x1010);
        }
        let n = classify(&local, &mut global);
        assert_eq!(n.new_edges, 0, "edge already known");
        assert_eq!(n.new_buckets, 1, "hitcount climbed from bucket 1 to 4");
    }

    #[test]
    fn classify_reports_no_novelty_for_same_or_lower_bucket() {
        let mut local = CoverageMap::new();
        let mut global = CoverageMap::new();
        // Establish bucket 4 in global.
        for _ in 0..5 {
            local.record_edge(0x1000, 0x1010);
        }
        let _ = classify(&local, &mut global);

        // Re-run at same hitcount: no novelty.
        local.clear();
        for _ in 0..5 {
            local.record_edge(0x1000, 0x1010);
        }
        let n = classify(&local, &mut global);
        assert!(!n.is_interesting(), "same bucket -> not interesting");

        // Re-run at LOWER hitcount: still no novelty.
        local.clear();
        local.record_edge(0x1000, 0x1010);
        let n = classify(&local, &mut global);
        assert!(!n.is_interesting(), "lower bucket -> not interesting");
    }

    #[test]
    fn classify_handles_multiple_edges() {
        let mut local = CoverageMap::new();
        let mut global = CoverageMap::new();
        local.record_edge(0x1000, 0x1010);
        local.record_edge(0x1020, 0x1030);
        local.record_edge(0x1040, 0x1050);
        let n = classify(&local, &mut global);
        assert_eq!(n.new_edges, 3, "all three edges are first-hit");
    }
}
