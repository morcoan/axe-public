//! Power scheduler — decides which corpus entry to fuzz next and how
//! much energy to assign it.
//!
//! Step 7 ships the baseline schedule (rare-edge bonus + speed bonus
//! + over-fuzz penalty). The reachability bonus is wired in step 10
//! once `reachability.rs` produces per-entry target distances. The
//! `score` function is intentionally cheap so the picker can call it
//! every iteration without becoming a hot spot.

#![allow(dead_code)]

use std::collections::HashMap;

use crate::fuzzer::corpus::{FuzzCorpus, QueueEntry};
use crate::fuzzer::coverage::CoverageMap;
use crate::fuzzer::mutators::Xorshift64;

/// Tunable weights for the power schedule. All defaults come from the
/// plan's reachability-priority table; tweak per-binary by overriding
/// these via `FuzzOptions`.
#[derive(Clone, Copy, Debug)]
pub struct PowerSchedule {
    pub rare_edge_weight: u32,
    pub reachability_weight: u32,
    pub speed_weight: u32,
    pub recent_discovery_weight: u32,
    pub fuzz_count_penalty_div: u32,
}

impl Default for PowerSchedule {
    fn default() -> Self {
        Self {
            rare_edge_weight: 3,
            reachability_weight: 2,
            speed_weight: 1,
            recent_discovery_weight: 1,
            // Every 10 fuzz attempts on an entry subtracts 1 from score
            // (saturating). Gentle penalty; prevents one entry from
            // monopolizing the schedule.
            fuzz_count_penalty_div: 10,
        }
    }
}

/// Per-slot global hit counter — tracks how often each edge slot has
/// appeared in a corpus entry. An edge is "rare" when its global
/// count is below the rarity threshold; corpus entries that include
/// rare edges get a power-schedule bonus.
pub struct RareEdges {
    counts: HashMap<usize, u32>,
    rarity_threshold: u32,
}

impl RareEdges {
    pub fn new(rarity_threshold: u32) -> Self {
        Self {
            counts: HashMap::new(),
            rarity_threshold,
        }
    }

    /// Observe that a corpus entry covers `slot`. Increment its
    /// global hit counter.
    pub fn observe_slot(&mut self, slot: usize) {
        *self.counts.entry(slot).or_insert(0) += 1;
    }

    /// Observe every non-zero slot in `map`. Useful for ingesting an
    /// entry's per-run coverage map at corpus-add time.
    pub fn observe_map(&mut self, map: &CoverageMap) {
        for (slot, &b) in map.as_slice().iter().enumerate() {
            if b > 0 {
                self.observe_slot(slot);
            }
        }
    }

    /// Count how many of `slots` are currently rare.
    pub fn rare_count(&self, slots: &[usize]) -> u32 {
        slots
            .iter()
            .filter(|s| {
                self.counts
                    .get(s)
                    .map_or(true, |&c| c <= self.rarity_threshold)
            })
            .count() as u32
    }

    pub fn rarity_threshold(&self) -> u32 {
        self.rarity_threshold
    }
}

impl PowerSchedule {
    /// Compute the (relative) score for a queue entry. Higher score
    /// → more likely to be picked. The picker normalizes scores into
    /// a weighted distribution; absolute magnitude doesn't matter.
    pub fn score(&self, entry: &QueueEntry, _rare: &RareEdges) -> u32 {
        let m = &entry.metadata;
        let mut s = 1u32;
        // Bonus for the novelty this entry contributed.
        s = s.saturating_add(self.rare_edge_weight.saturating_mul(m.novelty_new_edges));
        s = s.saturating_add((self.rare_edge_weight / 2).saturating_mul(m.novelty_new_buckets));
        // Speed bonus — sub-millisecond runs are cheap to fuzz so we
        // can afford more iterations on them.
        if m.exec_us < 1000 {
            s = s.saturating_add(self.speed_weight);
        } else if m.exec_us < 10_000 {
            // Still reasonably fast — half bonus.
            s = s.saturating_add(self.speed_weight / 2);
        }
        // Favored entries (set by minimization in a later step) get a
        // hard bonus.
        if m.favored {
            s = s.saturating_add(5);
        }
        // Over-fuzz penalty.
        let penalty = (m.times_fuzzed / self.fuzz_count_penalty_div as u64) as u32;
        s = s.saturating_sub(penalty);
        s.max(1)
    }

    /// Pick a queue entry's index via weighted random selection. Each
    /// entry's weight is its score; ties are broken by RNG order.
    pub fn pick<'a>(
        &self,
        corpus: &'a FuzzCorpus,
        rare: &RareEdges,
        rng: &mut Xorshift64,
    ) -> Option<usize> {
        if corpus.is_empty() {
            return None;
        }
        let weights: Vec<u32> = corpus.iter().map(|e| self.score(e, rare)).collect();
        let total: u64 = weights.iter().map(|&w| w as u64).sum();
        if total == 0 {
            return Some(0);
        }
        let mut needle = rng.next_u64() % total;
        for (idx, &w) in weights.iter().enumerate() {
            let w = w as u64;
            if needle < w {
                return Some(idx);
            }
            needle -= w;
        }
        Some(weights.len() - 1)
    }

    /// Update an entry's fuzz counter after a pick. Called by the
    /// session loop after `pick` to age the entry.
    pub fn update_after_pick(entry: &mut QueueEntry) {
        entry.metadata.times_fuzzed = entry.metadata.times_fuzzed.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzer::corpus::{input_id, QueueEntry, QueueMetadata};

    fn entry(id_seed: &[u8], novelty: u32, exec_us: u64, times_fuzzed: u64) -> QueueEntry {
        let bytes = id_seed.to_vec();
        QueueEntry {
            id: input_id(&bytes),
            parent_id: None,
            input: bytes,
            metadata: QueueMetadata {
                novelty_new_edges: novelty,
                exec_us,
                times_fuzzed,
                ..QueueMetadata::default()
            },
        }
    }

    #[test]
    fn rare_edges_track_observation_counts() {
        let mut r = RareEdges::new(2);
        r.observe_slot(0);
        r.observe_slot(0);
        r.observe_slot(1);
        // slot 0 has 2 observations (still <= threshold 2), slot 1 has
        // 1 — both rare. slot 99 has 0 — also rare.
        assert_eq!(r.rare_count(&[0, 1, 99]), 3);
        r.observe_slot(0); // pushes slot 0 above threshold
        r.observe_slot(0);
        assert_eq!(r.rare_count(&[0]), 0);
    }

    #[test]
    fn novelty_increases_score() {
        let sched = PowerSchedule::default();
        let rare = RareEdges::new(2);
        let plain = entry(b"plain", 0, 500, 0);
        let novel = entry(b"novel", 10, 500, 0);
        assert!(sched.score(&novel, &rare) > sched.score(&plain, &rare));
    }

    #[test]
    fn speed_increases_score() {
        let sched = PowerSchedule::default();
        let rare = RareEdges::new(2);
        let fast = entry(b"fast", 0, 100, 0);
        let slow = entry(b"slow", 0, 50_000, 0);
        assert!(sched.score(&fast, &rare) > sched.score(&slow, &rare));
    }

    #[test]
    fn over_fuzz_penalty_kicks_in() {
        let sched = PowerSchedule::default();
        let rare = RareEdges::new(2);
        let fresh = entry(b"fresh", 5, 500, 0);
        let stale = entry(b"stale", 5, 500, 100);
        assert!(sched.score(&fresh, &rare) > sched.score(&stale, &rare));
    }

    #[test]
    fn score_never_below_one() {
        let sched = PowerSchedule::default();
        let rare = RareEdges::new(2);
        let over_fuzzed = entry(b"e", 0, 60_000, 10_000);
        assert!(sched.score(&over_fuzzed, &rare) >= 1);
    }

    #[test]
    fn pick_returns_none_for_empty_corpus() {
        let sched = PowerSchedule::default();
        let rare = RareEdges::new(2);
        let mut rng = Xorshift64::new(1);
        let tmp = tempfile::TempDir::new().unwrap();
        let corpus = FuzzCorpus::open(tmp.path()).unwrap();
        assert!(sched.pick(&corpus, &rare, &mut rng).is_none());
    }

    #[test]
    fn pick_selects_entries_proportional_to_score() {
        // Add two entries; one has 10x novelty bonus. Over many
        // picks, the higher-scored one should dominate.
        let sched = PowerSchedule::default();
        let rare = RareEdges::new(2);
        let mut rng = Xorshift64::new(7);
        let tmp = tempfile::TempDir::new().unwrap();
        let mut corpus = FuzzCorpus::open(tmp.path()).unwrap();
        corpus.add(entry(b"low", 0, 50_000, 0)).unwrap();
        corpus.add(entry(b"high", 50, 500, 0)).unwrap();

        let mut hits = [0u32; 2];
        for _ in 0..2000 {
            let idx = sched.pick(&corpus, &rare, &mut rng).unwrap();
            hits[idx] += 1;
        }
        assert!(
            hits[1] > hits[0] * 4,
            "high-score entry should dominate (got low={} high={})",
            hits[0],
            hits[1]
        );
    }
}
