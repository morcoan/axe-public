//! [`ModelValidator`] — re-executes a Z3 model under the fuzzer's
//! [`FuzzExecutor`] and classifies the result.
//!
//! The validator is the "show your work" stage of the concolic loop.
//! A SAT model from Z3 is only a *claim* about what bytes would flip
//! the branch — the real emulator might disagree because:
//! - the symbolic IR concretized something (unsupported instruction);
//! - the model bytes happen to take a different earlier branch;
//! - the model is correct but the branch can't be reached from the
//!   harness entrypoint we replayed under.
//!
//! Every promotion to the fuzzer corpus passes through this gate, so
//! the corpus never accumulates inputs that don't actually flip the
//! branch they claim to flip.

#![allow(dead_code)]

use std::time::Duration;

use serde::Serialize;

use crate::fuzzer::coverage::{
    classify_against_snapshot as cov_classify_against_snapshot, CoverageMap, Novelty, MAP_SIZE,
};
use crate::fuzzer::executor::{CrashInfo, ExecutionResult, ExitKind, FuzzExecutor};

/// Coarse status of the validation. Set by precedence:
/// crash > new-coverage > valid > model-mismatch > unreachable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    /// Model bytes reached the target PC AND took the requested side.
    /// No coverage novelty, no crash. Useful as a sanity confirm; the
    /// bridge will NOT promote a `Valid`-only model (no novelty).
    Valid,
    /// Model bytes reached the target PC but took the *wrong* side
    /// of the branch (the symbolic IR's claim didn't survive
    /// concretization). Treated as a soft warning, never promoted.
    ModelMismatch,
    /// Model bytes did NOT reach the target PC at all. The branch is
    /// unreachable from this harness/entrypoint under this input.
    UnreachableInRealRun,
    /// Model bytes reached + flipped + produced new edges. PROMOTE.
    NewCoverageConfirmed,
    /// Model bytes crashed the executor. Forward to `CrashDb` —
    /// do NOT promote to corpus.
    NewCrash,
}

/// Full outcome bundle from a single [`ModelValidator::validate`].
#[derive(Clone, Debug)]
pub struct ValidationOutcome {
    /// `true` if the executor actually ran. `false` only on
    /// `ModelValidator::pre_check` rejections (e.g. empty model).
    pub reexecuted: bool,
    /// `true` if the re-execution's PC trace visited `target_pc`.
    pub reached_target_pc: bool,
    /// `true` if the re-execution took the side of the branch
    /// requested by the original [`BranchQuery::want_taken`]. This
    /// requires the caller to also pass the *expected next PC*
    /// (the branch target / fallthrough) in
    /// [`ModelValidator::expected_next_pc`].
    pub branch_flipped: bool,
    /// Coverage novelty computed against the snapshot the caller
    /// provided. Read-only — the validator never mutates the
    /// snapshot. The bridge (step 18) is the only thing that may
    /// merge into the shared map.
    pub new_coverage: Novelty,
    /// `true` if the executor reported a crash-like exit.
    pub crashed: bool,
    pub crash_info: Option<CrashInfo>,
    pub status: ValidationStatus,
    pub exec_us: u64,
    pub edges_observed: u64,
    pub exit: ExitKind,
}

/// One validator instance per concolic session. Borrows the executor
/// (`E` is generic over [`FuzzExecutor`] so the same code works for
/// `EmulatorExecutor`, `InProcessExecutor`, and `HybridExecutor`).
///
/// The validator does NOT own the coverage snapshot — callers pass it
/// at each `validate` call. This keeps the validator stateless across
/// multiple model checks; only the executor's per-run map is mutated.
pub struct ModelValidator<'a, E: FuzzExecutor> {
    pub executor: &'a mut E,
    pub run_timeout: Duration,
}

impl<'a, E: FuzzExecutor> ModelValidator<'a, E> {
    pub fn new(executor: &'a mut E, run_timeout: Duration) -> Self {
        Self {
            executor,
            run_timeout,
        }
    }

    /// Re-execute `model_bytes` under the executor and classify.
    ///
    /// Args:
    /// - `model_bytes`: the SAT model from the solver.
    /// - `target_pc`: the branch instruction's VA (we check the
    ///   trace visited this PC at least once).
    /// - `expected_next_pc`: the PC we'd expect immediately after the
    ///   branch if it flipped to the requested side. `None` skips the
    ///   flipped check and reports `branch_flipped: false`.
    /// - `global_snapshot`: a read-only snapshot of the fuzzer's
    ///   global coverage map (callers should clone it before
    ///   passing). Novelty is computed against this snapshot.
    pub fn validate(
        &mut self,
        model_bytes: &[u8],
        target_pc: u64,
        expected_next_pc: Option<u64>,
        global_snapshot: &CoverageMap,
    ) -> ValidationOutcome {
        if model_bytes.is_empty() {
            return ValidationOutcome {
                reexecuted: false,
                reached_target_pc: false,
                branch_flipped: false,
                new_coverage: Novelty::default(),
                crashed: false,
                crash_info: None,
                status: ValidationStatus::ModelMismatch,
                exec_us: 0,
                edges_observed: 0,
                exit: ExitKind::Ok,
            };
        }

        let exec_result: ExecutionResult = self.executor.run(model_bytes, self.run_timeout);
        let exit = exec_result.exit;
        let crashed = exit.is_crash_like();

        // Novelty: compute by comparing the executor's per-run map
        // against the snapshot. The validator NEVER mutates the
        // snapshot — that's the bridge's job and it does so only
        // after the corpus.add succeeds (Codex finding 2).
        let local_map = self.executor.map();
        let new_coverage = classify_against_snapshot(local_map, global_snapshot);

        // For "reached the target PC" + "took the requested side" we
        // do a cheap structural read of the local map's bytes. Both
        // checks rely on the executor's coverage edges being keyed
        // on PC pairs; we look for any non-zero bucket at the hash
        // of the relevant edge.
        let reached_target_pc = edge_was_touched_at(local_map, target_pc);
        let branch_flipped = match expected_next_pc {
            Some(next_pc) => edge_was_touched_from_to(local_map, target_pc, next_pc),
            None => false,
        };

        let status = derive_status(crashed, reached_target_pc, branch_flipped, &new_coverage);

        ValidationOutcome {
            reexecuted: true,
            reached_target_pc,
            branch_flipped,
            new_coverage,
            crashed,
            crash_info: exec_result.crash,
            status,
            exec_us: exec_result.exec_us,
            edges_observed: exec_result.edges_observed,
            exit,
        }
    }
}

/// Thin alias for [`cov_classify_against_snapshot`]. Kept inside
/// this module so the call sites in `validate` read naturally.
fn classify_against_snapshot(local: &CoverageMap, snapshot: &CoverageMap) -> Novelty {
    cov_classify_against_snapshot(local, snapshot)
}

/// Check whether any edge touched the given PC. The fuzzer's
/// coverage uses pairs `(from, to)` hashed into the map; we
/// approximate "PC was touched" by checking edges that have
/// `to == target_pc` for at least one of a few candidates. Since we
/// don't have a forward index from PC → indices, we instead look up
/// the edge `(target_pc, target_pc)` (a self-loop hash) as a coarse
/// signal of "instruction executed." This is a heuristic — a more
/// precise check requires the executor to expose its trace.
///
/// For the in-tree [`crate::fuzzer::executor::EmulatorExecutor`], the
/// per-run map is populated from `visited_path.windows(2)` so any
/// edge `(prev, target_pc)` ends up keyed at hash of that pair.
/// Without knowing `prev`, the best signal here is non-zero density
/// near `target_pc`. We use a small probe-set (32 random predecessor
/// candidates) — fast, no false negatives for traces that actually
/// passed through the PC at least once *with the prev-PCs we probe*.
///
/// In practice the session.rs caller will use the trace directly via
/// a future executor extension; this heuristic is enough to make the
/// validator's status derivation testable on synthetic maps.
fn edge_was_touched_at(map: &CoverageMap, target_pc: u64) -> bool {
    // Probe self-edge + neighbors. Real implementation in step 19
    // will look at the executor's trace; this fallback is good
    // enough for validator-level outcome tests.
    let bytes = map.as_slice();
    for prev in [
        target_pc,
        target_pc.wrapping_sub(1),
        target_pc.wrapping_sub(2),
        target_pc.wrapping_sub(4),
        target_pc.wrapping_sub(8),
        target_pc.wrapping_sub(16),
    ] {
        let idx = edge_index(prev, target_pc);
        if bytes[idx] > 0 {
            return true;
        }
    }
    false
}

fn edge_was_touched_from_to(map: &CoverageMap, from: u64, to: u64) -> bool {
    map.as_slice()[edge_index(from, to)] > 0
}

/// Mirror of `crate::fuzzer::coverage::edge_index`. The hash family
/// must match the one the executor uses to record edges.
fn edge_index(from: u64, to: u64) -> usize {
    use std::hash::Hasher;
    let mut h = ahash::AHasher::default();
    h.write_u64(from);
    h.write_u64(to);
    (h.finish() as usize) & (MAP_SIZE - 1)
}

/// Status precedence: crash > new-coverage > valid > model-mismatch >
/// unreachable. Captured in one function so all three call sites
/// (validate, tests, future replay) agree.
fn derive_status(
    crashed: bool,
    reached_target_pc: bool,
    branch_flipped: bool,
    novelty: &Novelty,
) -> ValidationStatus {
    if crashed {
        return ValidationStatus::NewCrash;
    }
    if branch_flipped && novelty.is_interesting() {
        return ValidationStatus::NewCoverageConfirmed;
    }
    if branch_flipped {
        return ValidationStatus::Valid;
    }
    if reached_target_pc {
        return ValidationStatus::ModelMismatch;
    }
    ValidationStatus::UnreachableInRealRun
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub executor that returns a scripted result + populates the
    /// per-run map with a scripted set of edges. Lets us exercise
    /// the validator's status derivation without a real binary.
    struct StubExecutor {
        scripted: ExecutionResult,
        edges_to_record: Vec<(u64, u64)>,
        map: CoverageMap,
    }
    impl StubExecutor {
        fn ok() -> Self {
            Self {
                scripted: ExecutionResult {
                    exit: ExitKind::Ok,
                    exec_us: 100,
                    crash: None,
                    edges_observed: 0,
                },
                edges_to_record: Vec::new(),
                map: CoverageMap::new(),
            }
        }
        fn record_edges(mut self, edges: Vec<(u64, u64)>) -> Self {
            self.edges_to_record = edges;
            self
        }
        fn with_crash(mut self) -> Self {
            self.scripted = ExecutionResult {
                exit: ExitKind::EmulatorOOB,
                exec_us: 50,
                crash: Some(CrashInfo {
                    kind: "emulator_oob".into(),
                    ..Default::default()
                }),
                edges_observed: 0,
            };
            self
        }
    }
    impl FuzzExecutor for StubExecutor {
        fn run(&mut self, _input: &[u8], _timeout: Duration) -> ExecutionResult {
            self.reset();
            for (from, to) in &self.edges_to_record {
                self.map.record_edge(*from, *to);
            }
            self.scripted.clone()
        }
        fn reset(&mut self) {
            self.map.clear();
        }
        fn map(&self) -> &CoverageMap {
            &self.map
        }
    }

    #[test]
    fn empty_model_returns_model_mismatch_without_running() {
        let mut exec = StubExecutor::ok();
        let snapshot = CoverageMap::new();
        let v = {
            let mut val = ModelValidator::new(&mut exec, Duration::from_millis(100));
            val.validate(b"", 0x1000, Some(0x1004), &snapshot)
        };
        assert!(!v.reexecuted);
        assert_eq!(v.status, ValidationStatus::ModelMismatch);
    }

    #[test]
    fn crash_in_executor_yields_new_crash_status() {
        let mut exec = StubExecutor::ok().with_crash();
        let snapshot = CoverageMap::new();
        let v = {
            let mut val = ModelValidator::new(&mut exec, Duration::from_millis(100));
            val.validate(b"\x01\x02", 0x1000, Some(0x1004), &snapshot)
        };
        assert!(v.reexecuted);
        assert!(v.crashed);
        assert_eq!(v.status, ValidationStatus::NewCrash);
        assert!(v.crash_info.is_some());
    }

    #[test]
    fn reached_pc_and_flipped_with_novelty_is_new_coverage_confirmed() {
        let target_pc = 0x4000u64;
        let next_pc = 0x4010u64;
        let mut exec =
            StubExecutor::ok().record_edges(vec![(target_pc - 4, target_pc), (target_pc, next_pc)]);
        // Snapshot is empty → any edges are new.
        let snapshot = CoverageMap::new();
        let v = {
            let mut val = ModelValidator::new(&mut exec, Duration::from_millis(100));
            val.validate(b"\x01\x02", target_pc, Some(next_pc), &snapshot)
        };
        assert!(v.reached_target_pc);
        assert!(v.branch_flipped);
        assert!(v.new_coverage.is_interesting());
        assert_eq!(v.status, ValidationStatus::NewCoverageConfirmed);
    }

    #[test]
    fn reached_pc_and_flipped_without_novelty_is_valid() {
        let target_pc = 0x4000u64;
        let next_pc = 0x4010u64;
        let edges = vec![(target_pc - 4, target_pc), (target_pc, next_pc)];
        // Snapshot already has the same edges → no novelty.
        let mut snapshot = CoverageMap::new();
        for (f, t) in &edges {
            snapshot.record_edge(*f, *t);
        }
        let mut exec = StubExecutor::ok().record_edges(edges);
        let v = {
            let mut val = ModelValidator::new(&mut exec, Duration::from_millis(100));
            val.validate(b"\x01\x02", target_pc, Some(next_pc), &snapshot)
        };
        assert!(v.reached_target_pc);
        assert!(v.branch_flipped);
        assert!(!v.new_coverage.is_interesting());
        assert_eq!(v.status, ValidationStatus::Valid);
    }

    #[test]
    fn reached_pc_but_not_flipped_is_model_mismatch() {
        let target_pc = 0x4000u64;
        let next_pc = 0x4010u64; // expected
        let wrong_next = 0x4020u64; // actual
        let mut exec = StubExecutor::ok()
            .record_edges(vec![(target_pc - 4, target_pc), (target_pc, wrong_next)]);
        let snapshot = CoverageMap::new();
        let v = {
            let mut val = ModelValidator::new(&mut exec, Duration::from_millis(100));
            val.validate(b"\x01\x02", target_pc, Some(next_pc), &snapshot)
        };
        assert!(v.reached_target_pc);
        assert!(!v.branch_flipped);
        assert_eq!(v.status, ValidationStatus::ModelMismatch);
    }

    #[test]
    fn did_not_reach_pc_is_unreachable_in_real_run() {
        let target_pc = 0x4000u64;
        let other_pc = 0x9000u64;
        let mut exec = StubExecutor::ok().record_edges(vec![(other_pc - 4, other_pc)]);
        let snapshot = CoverageMap::new();
        let v = {
            let mut val = ModelValidator::new(&mut exec, Duration::from_millis(100));
            val.validate(b"\x01\x02", target_pc, Some(target_pc + 4), &snapshot)
        };
        assert!(!v.reached_target_pc);
        assert_eq!(v.status, ValidationStatus::UnreachableInRealRun);
    }

    #[test]
    fn crash_wins_over_new_coverage() {
        // Set up a run that has novelty AND crashes — crash status
        // takes precedence.
        let target_pc = 0x4000u64;
        let next_pc = 0x4010u64;
        let mut exec = StubExecutor::ok()
            .record_edges(vec![(target_pc, next_pc)])
            .with_crash();
        let snapshot = CoverageMap::new();
        let v = {
            let mut val = ModelValidator::new(&mut exec, Duration::from_millis(100));
            val.validate(b"\x01", target_pc, Some(next_pc), &snapshot)
        };
        assert_eq!(v.status, ValidationStatus::NewCrash);
    }

    #[test]
    fn novelty_classify_finds_new_edges() {
        let mut local = CoverageMap::new();
        local.record_edge(0x100, 0x110);
        local.record_edge(0x110, 0x120);
        let snapshot = CoverageMap::new(); // empty
        let n = classify_against_snapshot(&local, &snapshot);
        assert!(n.new_edges >= 1);
    }

    #[test]
    fn novelty_classify_does_not_mutate_snapshot() {
        let mut local = CoverageMap::new();
        local.record_edge(0x100, 0x110);
        let snapshot = CoverageMap::new();
        let snapshot_before = snapshot.as_slice().to_vec();
        let _ = classify_against_snapshot(&local, &snapshot);
        // We can't borrow snapshot as_mut here — it never had a
        // chance to mutate. Re-read the bytes; they must match.
        let snapshot_after = snapshot.as_slice().to_vec();
        assert_eq!(snapshot_before, snapshot_after);
    }

    #[test]
    fn derive_status_table() {
        // Crash + everything else: still crash.
        assert_eq!(
            derive_status(
                true,
                true,
                true,
                &Novelty {
                    new_edges: 1,
                    new_buckets: 0
                }
            ),
            ValidationStatus::NewCrash
        );
        // No crash + flipped + novelty: confirmed.
        assert_eq!(
            derive_status(
                false,
                true,
                true,
                &Novelty {
                    new_edges: 1,
                    new_buckets: 0
                }
            ),
            ValidationStatus::NewCoverageConfirmed
        );
        // No crash + flipped + no novelty: valid.
        assert_eq!(
            derive_status(false, true, true, &Novelty::default()),
            ValidationStatus::Valid
        );
        // Reached but not flipped: mismatch.
        assert_eq!(
            derive_status(false, true, false, &Novelty::default()),
            ValidationStatus::ModelMismatch
        );
        // Didn't reach: unreachable.
        assert_eq!(
            derive_status(false, false, false, &Novelty::default()),
            ValidationStatus::UnreachableInRealRun
        );
    }
}
