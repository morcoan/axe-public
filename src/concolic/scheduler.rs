//! Frontier priority queue + power-scheduling math for the concolic
//! loop.
//!
//! Each branch we *might* want to flip becomes a [`FrontierItem`].
//! [`ConcolicBacklog`] owns the queue (heap + dedup + LRU at a cap),
//! [`ConcolicScheduler`] computes priority scores and ages losers so
//! nothing starves forever.
//!
//! Why a custom heap rather than `priority_queue` or LibAFL's
//! schedulers: the scoring formula is bespoke (per the plan) and the
//! dedup key is composite (`branch_pc + branch_index`). Wrapping a
//! library in this small a piece adds dependency surface without
//! reducing code.

#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, VecDeque};

use serde::Serialize;

use crate::concolic::expr::NodeId;

/// Hard cap on the backlog. LRU-evicts on insertion past this. The
/// number is from the plan; lifting it is a one-liner if telemetry
/// shows evictions hitting the frontier we wanted to explore.
pub const BACKLOG_CAP: usize = 4_096;

/// Cap on consecutive timeouts the scheduler will hold against a
/// branch. Past this, the penalty is constant — we never permanently
/// blacklist (so the periodic external-retry sweep in `ladder.rs` has
/// something to retry).
pub const TIMEOUT_CAP: u32 = 3;

/// A single candidate branch the concolic engine should try to flip.
#[derive(Clone, Debug)]
pub struct FrontierItem {
    /// Stable identifier for the symbolic path that produced this
    /// branch event (e.g. `"con:0x4012a0:0042"`).
    pub path_id: String,
    /// Program-counter VA of the branch instruction.
    pub branch_pc: u64,
    /// Position of this branch within the symbolic path.
    /// Disambiguates loop bodies that re-fire the same `branch_pc`.
    pub branch_index: u32,
    /// Depth in the slice (number of upstream constraints).
    pub depth: u32,
    /// How many times the fuzzer has hit this branch.
    pub hit_count: u32,
    /// Number of expr-DAG nodes in the constraint slice for this
    /// branch. Used as a complexity penalty (log-scaled).
    pub expr_complexity: u32,
    /// `Some(ms)` if this branch has been solved before (timeout or
    /// otherwise); `None` if never attempted. Drives the "unsolved
    /// bonus" weight.
    pub last_solver_ms: Option<u64>,
    /// Coverage-novelty score from the fuzzer's [`crate::fuzzer::reachability`]
    /// — proximity to the closest target.
    pub novelty_score: f32,
    /// Seed ID that originally produced this branch event. Used by
    /// the bridge as `parent_id` for any promoted model.
    pub origin_seed_id: String,
    /// Distance (in CFG edges) from this branch to the nearest user
    /// target, from [`crate::fuzzer::reachability::ReachabilityObs`].
    /// `u32::MAX` if no target visible.
    pub reachability_distance: u32,
    /// `true` if the branch comparison's RHS is a concrete literal.
    /// Z3 likes equalities-to-constants; small bonus.
    pub rhs_is_concrete: bool,
    /// How many times we've timed out at this `branch_pc` in this
    /// session. Capped at [`TIMEOUT_CAP`] by the scheduler.
    pub prior_timeouts: u32,
    /// Target branch [`NodeId`] in the Expr DAG. The session builds
    /// a [`crate::concolic::backend::BranchQuery`] from this and the
    /// constraints below.
    pub target_branch: NodeId,
    /// Path constraints reaching this branch — Bool NodeIds in the
    /// shared DAG. The ladder's slicer reduces this to the
    /// subset reachable from `target_branch`.
    pub path_constraints: Vec<NodeId>,
    /// Number of symbolic input bytes the solver should declare.
    pub input_bytes: u32,
    /// `true` to assert the target branch's positive form; `false`
    /// to assert its negation (try to take the opposite side).
    pub want_taken: bool,
    /// Optional PC of the *opposite* branch leg, used by the
    /// validator to confirm the model actually flipped the branch.
    pub expected_flip_pc: Option<u64>,
}

impl FrontierItem {
    pub fn dedup_key(&self) -> (u64, u32) {
        (self.branch_pc, self.branch_index)
    }
}

/// Weighted-sum priority. See the plan's "Power-schedule formula"
/// table — the numbers here are the canonical weights. Returns a
/// value floored at `0.1` so even penalized items remain pickable
/// (subject to LRU eviction).
pub fn score_item(item: &FrontierItem) -> f32 {
    let mut s: f32 = 0.0;

    // Unsolved bonus.
    if item.last_solver_ms.is_none() {
        s += 2.0;
    }

    // Novelty × 4.
    s += 4.0 * item.novelty_score;

    // Inverse-distance × 3 (closer to a target is better).
    let reach = item.reachability_distance.min(1024) as f32;
    s += 3.0 / (1.0 + reach);

    // Inverse complexity × 2 (small slices solve fast).
    let complexity = item.expr_complexity.max(1) as f32;
    s += 2.0 / (1.0 + complexity.log2());

    // RHS-concrete bonus.
    if item.rhs_is_concrete {
        s += 1.5;
    }

    // Timeout penalty (capped) × 3.
    let timeouts = item.prior_timeouts.min(TIMEOUT_CAP) as f32;
    s -= 3.0 * timeouts;

    // Depth penalty × 0.05.
    s -= 0.05 * (item.depth as f32);

    s.max(0.1)
}

/// Heap-sortable wrapper: `BinaryHeap` is a max-heap, and we want
/// the highest scoring item on top — so the natural ordering works
/// once we sort on the score. Ties broken by `branch_pc` for
/// determinism across runs with the same seed.
#[derive(Clone, Debug)]
struct ScoredItem {
    score_bits: u32,
    pc_tiebreak: u64,
    key: (u64, u32),
}
impl PartialEq for ScoredItem {
    fn eq(&self, other: &Self) -> bool {
        self.score_bits == other.score_bits && self.pc_tiebreak == other.pc_tiebreak
    }
}
impl Eq for ScoredItem {}
impl Ord for ScoredItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score_bits
            .cmp(&other.score_bits)
            .then_with(|| self.pc_tiebreak.cmp(&other.pc_tiebreak))
    }
}
impl PartialOrd for ScoredItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Pack an `f32` score into a sortable `u32` (positive floats only).
/// Negative scores can't happen here — `score_item` floors at `0.1`.
fn pack_score(s: f32) -> u32 {
    s.max(0.0).to_bits()
}

/// Frontier queue with dedup + LRU eviction.
///
/// Two indices kept in sync:
/// - `heap`: max-heap keyed on score; `pop` returns the highest-score item.
/// - `by_key`: dedup map from `(branch_pc, branch_index)` → item.
///   New pushes for an existing key overwrite the item (keeping
///   freshly-scored data) and don't add a second heap entry.
/// - `lru_order`: insertion order for cap-eviction; oldest key drops
///   when we exceed [`BACKLOG_CAP`].
pub struct ConcolicBacklog {
    heap: BinaryHeap<ScoredItem>,
    by_key: HashMap<(u64, u32), FrontierItem>,
    lru_order: VecDeque<(u64, u32)>,
    cap: usize,
    aging_factor: f32,
}

impl ConcolicBacklog {
    pub fn new() -> Self {
        Self::with_capacity(BACKLOG_CAP)
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            heap: BinaryHeap::with_capacity(cap),
            by_key: HashMap::with_capacity(cap),
            lru_order: VecDeque::with_capacity(cap),
            cap,
            aging_factor: 1.05,
        }
    }

    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Insert (or update) an item. Returns the evicted key if the
    /// cap was hit and an oldest entry was dropped.
    pub fn push(&mut self, item: FrontierItem) -> Option<(u64, u32)> {
        let key = item.dedup_key();
        let evicted = if !self.by_key.contains_key(&key) && self.by_key.len() >= self.cap {
            // LRU eviction: drop the oldest key not yet popped.
            let drop_key = self.lru_order.pop_front();
            if let Some(k) = drop_key {
                self.by_key.remove(&k);
                Some(k)
            } else {
                None
            }
        } else {
            None
        };
        let score = score_item(&item);
        let pc = item.branch_pc;
        // Update LRU order: insertion appends, update moves to back.
        if self.by_key.contains_key(&key) {
            // Move to back. Linear in LRU length but lru_order is
            // capped at cap, so worst case is O(cap).
            if let Some(pos) = self.lru_order.iter().position(|k| *k == key) {
                self.lru_order.remove(pos);
            }
        }
        self.lru_order.push_back(key);
        self.by_key.insert(key, item);
        self.heap.push(ScoredItem {
            score_bits: pack_score(score),
            pc_tiebreak: pc,
            key,
        });
        evicted
    }

    /// Pop the highest-priority item. Skips stale heap entries whose
    /// keys were already popped or evicted.
    pub fn pop(&mut self) -> Option<FrontierItem> {
        while let Some(top) = self.heap.pop() {
            if let Some(item) = self.by_key.remove(&top.key) {
                // Remove from LRU order.
                if let Some(pos) = self.lru_order.iter().position(|k| *k == top.key) {
                    self.lru_order.remove(pos);
                }
                // Aging sweep: bump every other item's novelty so it
                // creeps up the priority order on the next pop.
                self.age_others_after_pop();
                return Some(item);
            }
            // Otherwise that heap entry was a stale duplicate (we
            // pushed the same key twice with different scores) or
            // the key was evicted; skip it.
        }
        None
    }

    /// Peek the highest-priority item without removing it. Used by
    /// tests; rebuild-the-heap logic doesn't matter here.
    pub fn peek(&self) -> Option<&FrontierItem> {
        // We can't trust `heap.peek` because of stale entries —
        // walk the underlying vector to find the active max. This is
        // O(n), fine for tests.
        self.by_key.values().max_by(|a, b| {
            score_item(a)
                .partial_cmp(&score_item(b))
                .unwrap_or(Ordering::Equal)
        })
    }

    /// Aging: after a successful `pop`, multiply every remaining
    /// item's `novelty_score` by `aging_factor` (default 1.05) so
    /// repeatedly-skipped items eventually float to the top.
    /// Re-pushes the bumped items so the heap sees the new scores.
    fn age_others_after_pop(&mut self) {
        if self.by_key.is_empty() {
            return;
        }
        let mut updated: Vec<FrontierItem> = self
            .by_key
            .values()
            .cloned()
            .map(|mut it| {
                it.novelty_score *= self.aging_factor;
                it
            })
            .collect();
        self.by_key.clear();
        self.lru_order.clear();
        self.heap.clear();
        for it in updated.drain(..) {
            // We can't recursively call push (that would re-age) —
            // inline the simple insertion path.
            let key = it.dedup_key();
            let score = score_item(&it);
            let pc = it.branch_pc;
            self.lru_order.push_back(key);
            self.by_key.insert(key, it);
            self.heap.push(ScoredItem {
                score_bits: pack_score(score),
                pc_tiebreak: pc,
                key,
            });
        }
    }
}

impl Default for ConcolicBacklog {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrapper exposing the backlog + scoring through a single facade.
///
/// Holds no real state beyond the backlog today; the type exists so
/// the session can swap scoring strategies later (e.g. a determinism
/// mode that picks lowest-pc-first) without rewriting call sites.
pub struct ConcolicScheduler {
    backlog: ConcolicBacklog,
}

impl ConcolicScheduler {
    pub fn new() -> Self {
        Self {
            backlog: ConcolicBacklog::new(),
        }
    }

    pub fn enqueue(&mut self, item: FrontierItem) -> Option<(u64, u32)> {
        self.backlog.push(item)
    }

    pub fn next(&mut self) -> Option<FrontierItem> {
        self.backlog.pop()
    }

    pub fn len(&self) -> usize {
        self.backlog.len()
    }

    pub fn is_empty(&self) -> bool {
        self.backlog.is_empty()
    }
}

impl Default for ConcolicScheduler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_item(pc: u64, idx: u32, novelty: f32) -> FrontierItem {
        FrontierItem {
            path_id: format!("con:{pc:x}:{idx:04}"),
            branch_pc: pc,
            branch_index: idx,
            depth: 5,
            hit_count: 0,
            expr_complexity: 4,
            last_solver_ms: None,
            novelty_score: novelty,
            origin_seed_id: "seed_0001".into(),
            reachability_distance: 3,
            rhs_is_concrete: true,
            prior_timeouts: 0,
            target_branch: 0,
            path_constraints: vec![],
            input_bytes: 4,
            want_taken: false,
            expected_flip_pc: None,
        }
    }

    #[test]
    fn higher_novelty_scores_higher() {
        let lo = make_item(0x4000, 0, 0.1);
        let hi = make_item(0x4010, 0, 0.9);
        assert!(score_item(&hi) > score_item(&lo));
    }

    #[test]
    fn timeout_penalty_reduces_score_but_floors_at_one_tenth() {
        let mut it = make_item(0x4000, 0, 0.5);
        let base = score_item(&it);
        it.prior_timeouts = 3;
        let after = score_item(&it);
        assert!(after < base, "score should decrease after timeouts");
        assert!(after >= 0.1, "score floors at 0.1 (got {after})");
    }

    #[test]
    fn timeout_penalty_caps_at_three() {
        let mut a = make_item(0x4000, 0, 0.5);
        a.prior_timeouts = 3;
        let mut b = a.clone();
        b.prior_timeouts = 100;
        assert_eq!(
            score_item(&a),
            score_item(&b),
            "timeout penalty must cap at 3 attempts"
        );
    }

    #[test]
    fn unsolved_bonus_only_applies_when_last_solver_ms_is_none() {
        let mut a = make_item(0x4000, 0, 0.5);
        a.last_solver_ms = None;
        let mut b = a.clone();
        b.last_solver_ms = Some(42);
        assert!(score_item(&a) > score_item(&b));
    }

    #[test]
    fn rhs_concrete_bonus_applies() {
        let mut with_lit = make_item(0x4000, 0, 0.5);
        with_lit.rhs_is_concrete = true;
        let mut without = with_lit.clone();
        without.rhs_is_concrete = false;
        assert!(score_item(&with_lit) > score_item(&without));
    }

    #[test]
    fn depth_penalty_reduces_deep_slices() {
        let mut shallow = make_item(0x4000, 0, 0.5);
        shallow.depth = 1;
        let mut deep = shallow.clone();
        deep.depth = 100;
        assert!(score_item(&shallow) > score_item(&deep));
    }

    #[test]
    fn complexity_log_scales_so_huge_slices_only_slightly_penalized() {
        let mut small = make_item(0x4000, 0, 0.5);
        small.expr_complexity = 2;
        let mut huge = small.clone();
        huge.expr_complexity = 100_000;
        let s = score_item(&small);
        let h = score_item(&huge);
        assert!(s > h);
        // The log-scaling means the gap is bounded.
        assert!(
            s - h < 2.5,
            "log-scaled gap should stay bounded (got {})",
            s - h
        );
    }

    #[test]
    fn backlog_pop_returns_highest_score_first() {
        let mut backlog = ConcolicBacklog::new();
        backlog.push(make_item(0x4000, 0, 0.1));
        backlog.push(make_item(0x4010, 0, 0.9));
        backlog.push(make_item(0x4020, 0, 0.5));
        let first = backlog.pop().unwrap();
        assert_eq!(first.branch_pc, 0x4010);
    }

    #[test]
    fn backlog_dedup_overwrites_same_key() {
        let mut backlog = ConcolicBacklog::new();
        backlog.push(make_item(0x4000, 0, 0.1));
        backlog.push(make_item(0x4000, 0, 0.9)); // same key
        assert_eq!(backlog.len(), 1);
        let it = backlog.pop().unwrap();
        // Overwrite kept the latest item's novelty.
        assert!(
            (it.novelty_score - 0.9).abs() < 1e-6,
            "latest push wins on dedup"
        );
    }

    #[test]
    fn backlog_dedup_differs_on_branch_index() {
        let mut backlog = ConcolicBacklog::new();
        backlog.push(make_item(0x4000, 0, 0.1));
        backlog.push(make_item(0x4000, 1, 0.9)); // same pc, different index
        assert_eq!(backlog.len(), 2);
    }

    #[test]
    fn backlog_lru_evicts_when_capped() {
        let mut backlog = ConcolicBacklog::with_capacity(3);
        backlog.push(make_item(0x4000, 0, 0.1));
        backlog.push(make_item(0x4010, 0, 0.2));
        backlog.push(make_item(0x4020, 0, 0.3));
        // Cap full. Fourth push evicts the oldest (0x4000).
        let evicted = backlog.push(make_item(0x4030, 0, 0.4));
        assert_eq!(evicted, Some((0x4000, 0)));
        assert_eq!(backlog.len(), 3);
    }

    #[test]
    fn backlog_aging_bumps_unpicked_items_for_next_pop() {
        let mut backlog = ConcolicBacklog::new();
        backlog.push(make_item(0x4000, 0, 0.1));
        backlog.push(make_item(0x4010, 0, 0.5));
        // First pop: 0x4010 wins.
        let first = backlog.pop().unwrap();
        assert_eq!(first.branch_pc, 0x4010);
        // After aging, the leftover item's novelty should have grown
        // by ~5%.
        let leftover = backlog.peek().unwrap();
        assert!(
            leftover.novelty_score > 0.1,
            "novelty should have aged up (got {})",
            leftover.novelty_score
        );
        assert!(
            (leftover.novelty_score - 0.105).abs() < 1e-4,
            "expected ~5% bump, got {}",
            leftover.novelty_score
        );
    }

    #[test]
    fn scheduler_facade_passes_through() {
        let mut sched = ConcolicScheduler::new();
        sched.enqueue(make_item(0x4000, 0, 0.1));
        sched.enqueue(make_item(0x4010, 0, 0.9));
        assert_eq!(sched.len(), 2);
        let pick = sched.next().unwrap();
        assert_eq!(pick.branch_pc, 0x4010);
        assert_eq!(sched.len(), 1);
    }

    #[test]
    fn pop_from_empty_returns_none() {
        let mut backlog = ConcolicBacklog::new();
        assert!(backlog.pop().is_none());
    }
}
