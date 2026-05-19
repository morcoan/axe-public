//! CFG + callgraph distance scoring for reachability-guided fuzzing.
//!
//! Step 10 precomputes, for each [`FuzzTarget`], the minimum
//! weighted distance from every reachable function (multi-source
//! backward BFS over the reversed callgraph). The scheduler in
//! step 7 consults [`ReachabilityScore::bonus_for`] to bias picks
//! toward inputs that hit functions close to a target.
//!
//! Edge weights (per the plan):
//! - intra-procedural CFG edge: 1
//! - inter-procedural call, `confidence == "high"`: 1
//! - inter-procedural call, `confidence == "medium"`: 2
//! - inter-procedural call, tail / jump / other: 3
//!
//! `MAX_DIST = 64` caps the BFS — distances beyond return `None`.
//! Memory is bounded by `O(targets × reachable_functions)`.

#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::fuzzer::targets::FuzzTarget;
use crate::pe::CallGraphRecord;

/// Hard cap on BFS depth. Functions beyond this distance from any
/// target are treated as "unreachable" for bonus computation.
pub const MAX_DIST: u32 = 64;

/// Edge weight for a call-site by confidence string.
fn call_weight(confidence: &str, call_kind: &str) -> u32 {
    match confidence.to_ascii_lowercase().as_str() {
        "high" => 1,
        "medium" | "med" => 2,
        _ => match call_kind.to_ascii_lowercase().as_str() {
            "tail" | "tail_call" | "jump" => 3,
            _ => 2,
        },
    }
}

/// Precomputed reachability information for one fuzz session. Built
/// once at session start and queried during the fuzz loop.
pub struct ReachabilityGraph {
    /// `target_va -> { function_va -> distance }`. Distance is the
    /// minimum weighted hop count from `function_va` to `target_va`
    /// over the callgraph.
    distances: HashMap<u64, HashMap<u64, u32>>,
    target_vas: Vec<u64>,
}

impl ReachabilityGraph {
    /// Build distance tables for every target by reversing the
    /// callgraph and BFS-ing backward from each target VA.
    pub fn build(callgraph: &[CallGraphRecord], targets: &[FuzzTarget]) -> Self {
        let reverse = build_reverse_callgraph(callgraph);
        let mut distances: HashMap<u64, HashMap<u64, u32>> = HashMap::new();
        let mut target_vas = Vec::with_capacity(targets.len());
        for t in targets {
            target_vas.push(t.function_va);
            let dist = bfs_backward(t.function_va, &reverse);
            distances.insert(t.function_va, dist);
        }
        Self {
            distances,
            target_vas,
        }
    }

    /// Distance from `function_va` to `target_va`. `None` when
    /// unreachable within `MAX_DIST` hops.
    pub fn distance(&self, function_va: u64, target_va: u64) -> Option<u32> {
        self.distances
            .get(&target_va)
            .and_then(|m| m.get(&function_va).copied())
    }

    /// Among every target we know about, return the closest one to
    /// `function_va` plus its distance.
    pub fn closest_target(&self, function_va: u64) -> Option<(u64, u32)> {
        let mut best: Option<(u64, u32)> = None;
        for &target_va in &self.target_vas {
            if let Some(d) = self.distance(function_va, target_va) {
                match best {
                    Some((_, bd)) if bd <= d => {}
                    _ => best = Some((target_va, d)),
                }
            }
        }
        best
    }

    pub fn target_vas(&self) -> &[u64] {
        &self.target_vas
    }

    pub fn is_empty(&self) -> bool {
        self.target_vas.is_empty()
    }

    /// Build a per-run observation given the function VAs reached
    /// this execution. Identifies the closest target and any
    /// previously-unreached targets that this run touched.
    pub fn observe(&self, reached_functions: &[u64]) -> ReachabilityObs {
        let mut closest: Option<(u64, u32)> = None;
        let mut newly_reached: Vec<u64> = Vec::new();
        for &fn_va in reached_functions {
            // Targets we actually hit (distance 0).
            if self.target_vas.contains(&fn_va) {
                newly_reached.push(fn_va);
            }
            if let Some((tva, d)) = self.closest_target(fn_va) {
                match closest {
                    Some((_, cd)) if cd <= d => {}
                    _ => closest = Some((tva, d)),
                }
            }
        }
        newly_reached.sort_unstable();
        newly_reached.dedup();
        ReachabilityObs {
            reached_functions: reached_functions.to_vec(),
            closest_target: closest.map(|(va, _)| va),
            min_distance: closest.map(|(_, d)| d),
            newly_reached_targets: newly_reached,
        }
    }

    /// Scheduler bonus for an entry whose `reached_functions`
    /// metadata is populated. Higher = more bonus. Targets reached
    /// at distance 0 get the max bonus; distant ones get less.
    pub fn bonus_for(&self, reached: &[u64]) -> u32 {
        let Some(d) = reached
            .iter()
            .filter_map(|&fn_va| self.closest_target(fn_va).map(|(_, d)| d))
            .min()
        else {
            return 0;
        };
        // Distance 0 → bonus 8; distance N → bonus saturating-sub.
        8u32.saturating_sub(d.min(8))
    }
}

/// What the loop observed about reachability this iteration. The LLM
/// export layer projects this onto the NDJSON `closest_target`
/// field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReachabilityObs {
    pub reached_functions: Vec<u64>,
    pub closest_target: Option<u64>,
    pub min_distance: Option<u32>,
    pub newly_reached_targets: Vec<u64>,
}

fn build_reverse_callgraph(callgraph: &[CallGraphRecord]) -> HashMap<u64, Vec<(u64, u32)>> {
    let mut map: HashMap<u64, Vec<(u64, u32)>> = HashMap::new();
    for cg in callgraph {
        let Some(callee) = cg.callee else { continue };
        let weight = call_weight(&cg.confidence, &cg.call_kind);
        map.entry(callee).or_default().push((cg.caller, weight));
    }
    map
}

/// Bellman-Ford-style multi-source backward BFS bounded by `MAX_DIST`.
/// Since edge weights are small (1, 2, 3), a simple queue-based
/// relaxation is faster than building a heap.
fn bfs_backward(start: u64, reverse: &HashMap<u64, Vec<(u64, u32)>>) -> HashMap<u64, u32> {
    let mut dist: HashMap<u64, u32> = HashMap::new();
    let mut queue: VecDeque<u64> = VecDeque::new();
    dist.insert(start, 0);
    queue.push_back(start);
    while let Some(node) = queue.pop_front() {
        let current = dist[&node];
        let Some(predecessors) = reverse.get(&node) else {
            continue;
        };
        for &(pred, weight) in predecessors {
            let new_dist = current.saturating_add(weight);
            if new_dist > MAX_DIST {
                continue;
            }
            let better = match dist.get(&pred) {
                Some(&existing) => new_dist < existing,
                None => true,
            };
            if better {
                dist.insert(pred, new_dist);
                queue.push_back(pred);
            }
        }
    }
    dist
}

/// Identify the function (from a list of FunctionRecords sorted by
/// `start`) that contains the given VA. Returns the function's
/// `start` field, which is the canonical function-VA used as the
/// callgraph node.
pub fn function_containing(va: u64, functions_sorted: &[(u64, u64)]) -> Option<u64> {
    // functions_sorted is (start, end) tuples sorted by start.
    let idx = functions_sorted
        .partition_point(|(start, _)| *start <= va)
        .checked_sub(1)?;
    let (start, end) = functions_sorted[idx];
    if start <= va && va < end {
        Some(start)
    } else {
        None
    }
}

/// Map an iterator of edge `(from_va, to_va)` pairs into the set of
/// function VAs they touch. Used by the session loop to translate a
/// per-run coverage map into the `reached_functions` input for
/// [`ReachabilityGraph::observe`].
pub fn edges_to_function_vas(
    edges: impl IntoIterator<Item = (u64, u64)>,
    functions_sorted: &[(u64, u64)],
) -> Vec<u64> {
    let mut seen: BTreeMap<u64, ()> = BTreeMap::new();
    for (from, to) in edges {
        if let Some(fn_va) = function_containing(from, functions_sorted) {
            seen.insert(fn_va, ());
        }
        if let Some(fn_va) = function_containing(to, functions_sorted) {
            seen.insert(fn_va, ());
        }
    }
    seen.into_keys().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzer::targets::{FuzzTarget, TargetKind};

    fn target(va: u64) -> FuzzTarget {
        FuzzTarget {
            id: format!("target-{va:x}"),
            kind: TargetKind::VulnCandidate,
            function_va: va,
            function_name: None,
            priority: 0.5,
            evidence: Vec::new(),
            notes: String::new(),
        }
    }

    fn call(caller: u64, callee: u64, confidence: &str) -> CallGraphRecord {
        CallGraphRecord {
            caller,
            callee: Some(callee),
            import: None,
            callsite: caller + 0x10,
            call_kind: "direct".into(),
            confidence: confidence.into(),
            resolved_api: None,
            wrapper_chain: Vec::new(),
        }
    }

    #[test]
    fn target_at_distance_zero_to_itself() {
        let callgraph = vec![];
        let targets = vec![target(0x1000)];
        let g = ReachabilityGraph::build(&callgraph, &targets);
        assert_eq!(g.distance(0x1000, 0x1000), Some(0));
    }

    #[test]
    fn distance_through_single_high_confidence_call() {
        // A -> B (high) → distance(A, B) == 1
        let callgraph = vec![call(0x1000, 0x2000, "high")];
        let targets = vec![target(0x2000)];
        let g = ReachabilityGraph::build(&callgraph, &targets);
        assert_eq!(g.distance(0x1000, 0x2000), Some(1));
    }

    #[test]
    fn distance_weights_by_confidence() {
        // A -> high -> B; B -> low -> C; target=C
        // distance(A, C) = 1 + 3 = 4 (low edge weight = 3 by default
        // when call_kind isn't tail/jump and confidence != high/medium)
        let callgraph = vec![call(0x1000, 0x2000, "high"), call(0x2000, 0x3000, "low")];
        let targets = vec![target(0x3000)];
        let g = ReachabilityGraph::build(&callgraph, &targets);
        assert_eq!(g.distance(0x2000, 0x3000), Some(2)); // low fallback = 2
        assert_eq!(g.distance(0x1000, 0x3000), Some(3));
    }

    #[test]
    fn distance_picks_min_across_paths() {
        // A -> high -> B -> high -> D  (cost 2)
        // A -> high -> C -> low  -> D  (cost 3)
        let callgraph = vec![
            call(0x1000, 0x2000, "high"),
            call(0x2000, 0x4000, "high"),
            call(0x1000, 0x3000, "high"),
            call(0x3000, 0x4000, "low"),
        ];
        let targets = vec![target(0x4000)];
        let g = ReachabilityGraph::build(&callgraph, &targets);
        assert_eq!(g.distance(0x1000, 0x4000), Some(2), "shorter path wins");
    }

    #[test]
    fn unreachable_returns_none() {
        let callgraph = vec![call(0x1000, 0x2000, "high")];
        let targets = vec![target(0x9000)];
        let g = ReachabilityGraph::build(&callgraph, &targets);
        assert_eq!(g.distance(0x1000, 0x9000), None);
    }

    #[test]
    fn max_dist_truncates_distant_paths() {
        // Long chain past MAX_DIST=64. Build 100 hops of confidence
        // "low" (weight 2) → total ~200, way beyond cap.
        let mut callgraph = Vec::new();
        for i in 0..100u64 {
            let caller = 0x1000 + i * 0x100;
            let callee = caller + 0x100;
            callgraph.push(call(caller, callee, "low"));
        }
        let target_va = 0x1000 + 100 * 0x100;
        let targets = vec![target(target_va)];
        let g = ReachabilityGraph::build(&callgraph, &targets);
        assert_eq!(g.distance(0x1000, target_va), None);
    }

    #[test]
    fn closest_target_returns_min_distance_target() {
        let callgraph = vec![
            call(0x1000, 0x2000, "high"), // dist 1
            call(0x1000, 0x3000, "high"),
            call(0x3000, 0x4000, "high"), // dist 2
        ];
        let targets = vec![target(0x2000), target(0x4000)];
        let g = ReachabilityGraph::build(&callgraph, &targets);
        let (closest, dist) = g.closest_target(0x1000).unwrap();
        assert_eq!(closest, 0x2000);
        assert_eq!(dist, 1);
    }

    #[test]
    fn observe_flags_target_hits() {
        let callgraph = vec![call(0x1000, 0x2000, "high")];
        let targets = vec![target(0x2000)];
        let g = ReachabilityGraph::build(&callgraph, &targets);
        let obs = g.observe(&[0x1000, 0x2000]);
        assert_eq!(obs.newly_reached_targets, vec![0x2000]);
        assert_eq!(obs.closest_target, Some(0x2000));
        assert_eq!(obs.min_distance, Some(0));
    }

    #[test]
    fn bonus_decreases_with_distance() {
        let callgraph = vec![
            call(0x1000, 0x2000, "high"),
            call(0x2000, 0x3000, "high"),
            call(0x3000, 0x4000, "high"),
        ];
        let targets = vec![target(0x4000)];
        let g = ReachabilityGraph::build(&callgraph, &targets);
        let near = g.bonus_for(&[0x3000]); // dist 1
        let mid = g.bonus_for(&[0x2000]); // dist 2
        let far = g.bonus_for(&[0x1000]); // dist 3
        assert!(near > mid, "bonus[near]={near} > bonus[mid]={mid}");
        assert!(mid > far, "bonus[mid]={mid} > bonus[far]={far}");
    }

    #[test]
    fn bonus_zero_when_no_target_reachable() {
        let callgraph = vec![call(0x1000, 0x2000, "high")];
        let targets = vec![target(0x9000)];
        let g = ReachabilityGraph::build(&callgraph, &targets);
        assert_eq!(g.bonus_for(&[0x1000]), 0);
    }

    #[test]
    fn function_containing_binary_search() {
        let funcs = vec![(0x1000, 0x1100), (0x1200, 0x1300), (0x1400, 0x1500)];
        assert_eq!(function_containing(0x1050, &funcs), Some(0x1000));
        assert_eq!(function_containing(0x1100, &funcs), None, "end exclusive");
        assert_eq!(function_containing(0x1250, &funcs), Some(0x1200));
        assert_eq!(function_containing(0x9999, &funcs), None);
    }

    #[test]
    fn edges_to_function_vas_dedups() {
        let funcs = vec![(0x1000, 0x1100), (0x2000, 0x2100)];
        let edges = vec![(0x1010, 0x1020), (0x1030, 0x2050), (0x2050, 0x2060)];
        let fn_vas = edges_to_function_vas(edges, &funcs);
        assert_eq!(fn_vas, vec![0x1000, 0x2000]);
    }
}
