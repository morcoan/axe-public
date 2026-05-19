//! [`CorpusBridge`] — the bidirectional wiring between the concolic
//! engine and the fuzzer's [`FuzzCorpus`] + global [`CoverageMap`].
//!
//! This is the **Codex finding 2 mitigation** in code. The earlier
//! design called `coverage::classify` (which mutates the global map)
//! BEFORE writing the model input to disk. A crash or `corpus.add`
//! failure between those two points would mark an edge as covered
//! while leaving no reproducer behind — exactly the kind of "we lost
//! the seed but think we have coverage" desync the original review
//! flagged. The bridge enforces a strict four-step ordering:
//!
//! 1. **`classify_against_snapshot`** — read-only novelty check
//!    against a clone of the current shared global map. No mutation.
//! 2. **`stage_for_execution`** — durable input write to
//!    `queue/.staging/<id>` with fsync.
//! 3. **`corpus.add`** — atomic-rename the staged file into
//!    `queue/<id>` + in-memory insert.
//! 4. **`merge_into_global`** — *only now* mutate the shared
//!    coverage map.
//!
//! Any failure short-circuits without touching the shared map. The
//! staged file persists for orphan recovery to pick up.
//!
//! Lock-order discipline: callers MUST acquire `corpus` BEFORE
//! `coverage_merge`. We document the order here and enforce it
//! structurally by acquiring them in this order inside
//! `promote_if_novel`.

#![allow(dead_code)]

use std::io;
use std::sync::{Arc, Mutex};

use crate::concolic::validator::{ValidationOutcome, ValidationStatus};
use crate::fuzzer::corpus::{input_id, FuzzCorpus, QueueEntry, QueueMetadata};
use crate::fuzzer::coverage::{classify_against_snapshot, merge_into_global, CoverageMap, Novelty};

/// Errors specific to a promotion attempt. Most are pass-through I/O
/// from the corpus / staging layer; the typed wrapper makes it easy
/// to assert "no shared-state mutation happened" in tests.
#[derive(Debug)]
pub enum PromoteError {
    /// `stage_for_execution` failed (disk full, permission, etc.).
    StagingFailed(io::Error),
    /// `corpus.add` failed AFTER the input was staged. The staged
    /// file is left on disk for orphan recovery.
    CorpusAddFailed(io::Error),
}

impl std::fmt::Display for PromoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StagingFailed(e) => write!(f, "staging failed: {e}"),
            Self::CorpusAddFailed(e) => {
                write!(f, "corpus.add failed (input staged but not promoted): {e}")
            }
        }
    }
}

impl std::error::Error for PromoteError {}

/// Result of a single [`CorpusBridge::promote_if_novel`] call.
#[derive(Debug)]
pub enum PromoteOutcome {
    /// The validation didn't qualify for promotion (status was
    /// `Valid`, `ModelMismatch`, `UnreachableInRealRun`, or
    /// `NewCrash` — crashes go through `CrashDb`, not corpus).
    Skipped { reason: &'static str },
    /// Novelty check against the snapshot showed nothing new. No
    /// shared state was mutated.
    NotNovel { snapshot_novelty: Novelty },
    /// Promotion succeeded. Coverage map was merged.
    Promoted { model_id: String, novelty: Novelty },
}

/// Wraps the fuzzer's corpus + shared coverage map behind a single
/// promotion entrypoint that enforces the transactional discipline.
///
/// `Arc<Mutex<...>>` ownership is required because:
/// (a) concolic + fuzzer may run concurrently in v2;
/// (b) the bridge outlives any single `validate()` call inside the
///     concolic loop;
/// (c) contention is rare — the fuzzer's hot loop holds no concolic
///     locks; the bridge mutates only on confirmed novelty.
pub struct CorpusBridge {
    corpus: Arc<Mutex<FuzzCorpus>>,
    coverage_merge: Arc<Mutex<CoverageMap>>,
}

impl CorpusBridge {
    pub fn new(corpus: Arc<Mutex<FuzzCorpus>>, coverage_merge: Arc<Mutex<CoverageMap>>) -> Self {
        Self {
            corpus,
            coverage_merge,
        }
    }

    /// Attempt to promote `input_bytes` into the fuzzer corpus.
    ///
    /// Steps (Codex finding 2 transactional order):
    /// 1. Reject by validation status before any I/O.
    /// 2. Clone the global map and call `classify_against_snapshot`
    ///    on `local_map`. No shared mutation.
    /// 3. If novelty is interesting, stage the input bytes
    ///    (durable fsync).
    /// 4. Insert the [`QueueEntry`] into the corpus (atomic rename
    ///    of the staged file).
    /// 5. Merge `local_map` into the shared global map. ONLY HERE
    ///    does the shared coverage view change.
    ///
    /// Returns a [`PromoteOutcome`] describing what happened. Errors
    /// at staging or corpus.add return a [`PromoteError`]; the
    /// shared coverage map is guaranteed byte-identical to before
    /// the call on any error path.
    pub fn promote_if_novel(
        &self,
        input_bytes: &[u8],
        parent_seed_id: Option<&str>,
        validation: &ValidationOutcome,
        local_map: &CoverageMap,
    ) -> Result<PromoteOutcome, PromoteError> {
        // Step 0 — Validation status gate. Only NewCoverageConfirmed
        // qualifies for corpus promotion. NewCrash goes to CrashDb
        // (caller's responsibility). Other statuses produce no
        // corpus entry.
        match validation.status {
            ValidationStatus::NewCoverageConfirmed => {}
            ValidationStatus::NewCrash => {
                return Ok(PromoteOutcome::Skipped {
                    reason: "new_crash_handled_by_crashdb",
                });
            }
            ValidationStatus::Valid => {
                return Ok(PromoteOutcome::Skipped {
                    reason: "valid_no_new_coverage",
                });
            }
            ValidationStatus::ModelMismatch => {
                return Ok(PromoteOutcome::Skipped {
                    reason: "model_mismatch",
                });
            }
            ValidationStatus::UnreachableInRealRun => {
                return Ok(PromoteOutcome::Skipped {
                    reason: "unreachable_in_real_run",
                });
            }
        }

        // Step 1 — Snapshot the global map (cheap clone of fixed-
        // size byte array). Acquire lock briefly to clone; release
        // before any I/O.
        let snapshot: CoverageMap = {
            let g = self
                .coverage_merge
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            g.clone()
        };

        // Step 2 — Read-only novelty check.
        let novelty = classify_against_snapshot(local_map, &snapshot);
        if !novelty.is_interesting() {
            return Ok(PromoteOutcome::NotNovel {
                snapshot_novelty: novelty,
            });
        }

        // Step 3 — Compute id and stage to disk. Lock the corpus
        // for the duration of staging+add (this is the documented
        // lock order: corpus BEFORE coverage_merge).
        let model_id = input_id(input_bytes);
        let entry = QueueEntry {
            id: model_id.clone(),
            parent_id: parent_seed_id.map(|s| s.to_string()),
            input: input_bytes.to_vec(),
            metadata: QueueMetadata::from_novelty(novelty, validation.exec_us),
        };

        {
            let corpus = self.corpus.lock().unwrap_or_else(|p| p.into_inner());

            // Step 3a — Stage (durable write to .staging/<id>).
            corpus
                .stage_for_execution(&model_id, input_bytes)
                .map_err(PromoteError::StagingFailed)?;

            // Step 3b — Drop corpus lock to re-acquire as mutable
            // for `add`. (FuzzCorpus.add needs &mut self; we only
            // hold &self for stage_for_execution.)
            drop(corpus);
        }
        {
            let mut corpus = self.corpus.lock().unwrap_or_else(|p| p.into_inner());
            corpus.add(entry).map_err(PromoteError::CorpusAddFailed)?;
        }

        // Step 4 — ONLY NOW mutate the shared coverage map.
        {
            let mut g = self
                .coverage_merge
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            merge_into_global(local_map, &mut g);
        }

        Ok(PromoteOutcome::Promoted { model_id, novelty })
    }

    pub fn corpus(&self) -> Arc<Mutex<FuzzCorpus>> {
        self.corpus.clone()
    }

    pub fn coverage_merge(&self) -> Arc<Mutex<CoverageMap>> {
        self.coverage_merge.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzer::executor::ExitKind;
    use tempfile::TempDir;

    fn make_validation(status: ValidationStatus, with_coverage: bool) -> ValidationOutcome {
        let novelty = if with_coverage {
            Novelty {
                new_edges: 3,
                new_buckets: 0,
            }
        } else {
            Novelty::default()
        };
        ValidationOutcome {
            reexecuted: true,
            reached_target_pc: true,
            branch_flipped: matches!(
                status,
                ValidationStatus::NewCoverageConfirmed | ValidationStatus::Valid
            ),
            new_coverage: novelty,
            crashed: matches!(status, ValidationStatus::NewCrash),
            crash_info: None,
            status,
            exec_us: 100,
            edges_observed: 10,
            exit: ExitKind::Ok,
        }
    }

    fn fresh_bridge(tmp: &TempDir) -> CorpusBridge {
        let queue_dir = tmp.path().join("queue");
        let corpus = Arc::new(Mutex::new(FuzzCorpus::open(&queue_dir).unwrap()));
        let global = Arc::new(Mutex::new(CoverageMap::new()));
        CorpusBridge::new(corpus, global)
    }

    fn nontrivial_map() -> CoverageMap {
        let mut m = CoverageMap::new();
        m.record_edge(0x1000, 0x1010);
        m.record_edge(0x1010, 0x1020);
        m
    }

    #[test]
    fn skipped_when_validation_is_not_new_coverage() {
        let tmp = TempDir::new().unwrap();
        let bridge = fresh_bridge(&tmp);
        let local = nontrivial_map();

        for status in [
            ValidationStatus::Valid,
            ValidationStatus::ModelMismatch,
            ValidationStatus::UnreachableInRealRun,
            ValidationStatus::NewCrash,
        ] {
            let v = make_validation(status, true);
            let outcome = bridge.promote_if_novel(b"input", None, &v, &local).unwrap();
            assert!(
                matches!(outcome, PromoteOutcome::Skipped { .. }),
                "{status:?}"
            );
        }

        // Shared coverage map must NOT have been mutated by any of those.
        let g = bridge.coverage_merge.lock().unwrap();
        assert!(g.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn promotes_on_new_coverage_confirmed_and_merges_only_after_corpus_add() {
        let tmp = TempDir::new().unwrap();
        let bridge = fresh_bridge(&tmp);
        let local = nontrivial_map();
        let v = make_validation(ValidationStatus::NewCoverageConfirmed, true);
        let outcome = bridge
            .promote_if_novel(b"interesting input", None, &v, &local)
            .unwrap();
        match outcome {
            PromoteOutcome::Promoted { model_id, novelty } => {
                assert!(model_id.starts_with("blake3-"));
                assert!(novelty.is_interesting());
            }
            _ => panic!("expected Promoted, got {outcome:?}"),
        }
        // Shared map now has the new edges.
        let g = bridge.coverage_merge.lock().unwrap();
        let nonzero = g.as_slice().iter().filter(|&&b| b > 0).count();
        assert!(nonzero >= 1, "global map should hold the merged edges");
        // Corpus has the entry.
        let c = bridge.corpus.lock().unwrap();
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn does_not_promote_when_novelty_against_snapshot_is_empty() {
        let tmp = TempDir::new().unwrap();
        let bridge = fresh_bridge(&tmp);
        let local = nontrivial_map();
        // Pre-seed the global map so the local has nothing new.
        {
            let mut g = bridge.coverage_merge.lock().unwrap();
            merge_into_global(&local, &mut g);
        }
        let v = make_validation(ValidationStatus::NewCoverageConfirmed, true);
        let outcome = bridge
            .promote_if_novel(b"already seen", None, &v, &local)
            .unwrap();
        assert!(matches!(outcome, PromoteOutcome::NotNovel { .. }));
        let c = bridge.corpus.lock().unwrap();
        assert_eq!(c.len(), 0, "no entry added when nothing was novel");
    }

    #[test]
    fn promotion_records_parent_seed_id_lineage() {
        let tmp = TempDir::new().unwrap();
        let bridge = fresh_bridge(&tmp);
        let local = nontrivial_map();
        let v = make_validation(ValidationStatus::NewCoverageConfirmed, true);
        let _ = bridge
            .promote_if_novel(b"child input", Some("parent_seed_xyz"), &v, &local)
            .unwrap();
        let c = bridge.corpus.lock().unwrap();
        let entry = c.iter().next().unwrap();
        assert_eq!(entry.parent_id.as_deref(), Some("parent_seed_xyz"));
    }

    #[test]
    fn staging_failure_does_not_mutate_shared_coverage() {
        // Hard to force a stage failure on a real corpus; instead,
        // verify the order: if we construct a bridge with a corpus
        // whose queue_dir is read-only, stage_for_execution returns
        // Err, and the shared coverage map stays at zero.
        let tmp = TempDir::new().unwrap();
        let queue_dir = tmp.path().join("readonly_queue");
        std::fs::create_dir_all(&queue_dir).unwrap();
        let corpus = FuzzCorpus::open(&queue_dir).unwrap();
        // Make the queue dir read-only AFTER FuzzCorpus::open
        // succeeded (open creates .staging/, which we need).
        let staging_path = queue_dir.join(".staging");
        // Best-effort: on some platforms making a directory read-only
        // doesn't block file creation. Instead, simulate by removing
        // the .staging directory entirely so stage_for_execution
        // fails with NotFound.
        std::fs::remove_dir_all(&staging_path).unwrap();

        let bridge = CorpusBridge::new(
            Arc::new(Mutex::new(corpus)),
            Arc::new(Mutex::new(CoverageMap::new())),
        );
        let local = nontrivial_map();
        let v = make_validation(ValidationStatus::NewCoverageConfirmed, true);
        let result = bridge.promote_if_novel(b"will fail to stage", None, &v, &local);
        assert!(
            matches!(result, Err(PromoteError::StagingFailed(_))),
            "expected StagingFailed, got {result:?}"
        );
        // Critical invariant: shared coverage map must not have been touched.
        let g = bridge.coverage_merge.lock().unwrap();
        assert!(
            g.as_slice().iter().all(|&b| b == 0),
            "shared coverage map must be unchanged after stage failure"
        );
    }

    #[test]
    fn snapshot_clone_does_not_mutate_shared_map_under_promotion() {
        // Sanity: after a Skipped/NotNovel promotion, the shared map
        // must still be byte-identical to its starting state.
        let tmp = TempDir::new().unwrap();
        let bridge = fresh_bridge(&tmp);
        let initial = {
            let g = bridge.coverage_merge.lock().unwrap();
            g.as_slice().to_vec()
        };
        let local = nontrivial_map();
        let v = make_validation(ValidationStatus::Valid, true);
        let _ = bridge.promote_if_novel(b"x", None, &v, &local).unwrap();
        let after = {
            let g = bridge.coverage_merge.lock().unwrap();
            g.as_slice().to_vec()
        };
        assert_eq!(initial, after, "Skipped promotion must not mutate global");
    }

    #[test]
    fn promotion_outcome_format_for_skipped_carries_reason() {
        let tmp = TempDir::new().unwrap();
        let bridge = fresh_bridge(&tmp);
        let local = nontrivial_map();
        let v = make_validation(ValidationStatus::NewCrash, false);
        let outcome = bridge.promote_if_novel(b"x", None, &v, &local).unwrap();
        if let PromoteOutcome::Skipped { reason } = outcome {
            assert!(reason.contains("crash"));
        } else {
            panic!("expected Skipped");
        }
    }
}
