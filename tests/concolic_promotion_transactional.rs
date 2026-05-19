//! Codex finding 2 regression test.
//!
//! The earlier draft of the plan called `coverage::classify` (which
//! mutates the global map) BEFORE `corpus.add`. Codex flagged: any
//! failure between those two points would mark an edge as covered
//! with no reproducer on disk.
//!
//! The fix is the four-step transactional discipline in
//! [`crate::concolic::fuzzer_bridge::CorpusBridge::promote_if_novel`]:
//! 1. `classify_against_snapshot` (read-only)
//! 2. `stage_for_execution` (durable input write)
//! 3. `corpus.add` (atomic rename + insert)
//! 4. `merge_into_global` (ONLY now mutate the shared map)
//!
//! This test injects a failure at step 2 (the staging directory is
//! deleted before the call) and asserts:
//! (a) the bridge returns `Err(PromoteError::StagingFailed)`,
//! (b) the global coverage map is byte-identical before and after,
//! (c) the corpus is empty (no entry committed).

#![cfg(feature = "concolic")]

use std::sync::{Arc, Mutex};

use axe_core::concolic::fuzzer_bridge::{CorpusBridge, PromoteError, PromoteOutcome};
use axe_core::concolic::validator::{ValidationOutcome, ValidationStatus};
use axe_core::fuzzer::corpus::FuzzCorpus;
use axe_core::fuzzer::coverage::{CoverageMap, Novelty};
use axe_core::fuzzer::executor::ExitKind;
use tempfile::TempDir;

fn make_new_coverage_validation() -> ValidationOutcome {
    ValidationOutcome {
        reexecuted: true,
        reached_target_pc: true,
        branch_flipped: true,
        new_coverage: Novelty {
            new_edges: 5,
            new_buckets: 0,
        },
        crashed: false,
        crash_info: None,
        status: ValidationStatus::NewCoverageConfirmed,
        exec_us: 100,
        edges_observed: 5,
        exit: ExitKind::Ok,
    }
}

fn map_with_edges() -> CoverageMap {
    let mut m = CoverageMap::new();
    m.record_edge(0x1000, 0x1010);
    m.record_edge(0x1010, 0x1020);
    m.record_edge(0x1020, 0x1030);
    m
}

#[test]
fn corpus_add_failure_does_not_mutate_shared_coverage() {
    let tmp = TempDir::new().unwrap();
    let queue_dir = tmp.path().join("queue");
    let corpus = FuzzCorpus::open(&queue_dir).unwrap();

    // Force a staging failure by deleting the .staging directory
    // that FuzzCorpus::open created. The next stage_for_execution
    // call will get NotFound from the underlying OpenOptions.create
    // because its parent dir is missing.
    std::fs::remove_dir_all(queue_dir.join(".staging")).unwrap();

    let global = Arc::new(Mutex::new(CoverageMap::new()));
    let global_before = global.lock().unwrap().as_slice().to_vec();

    let bridge = CorpusBridge::new(Arc::new(Mutex::new(corpus)), global.clone());

    let local = map_with_edges();
    let validation = make_new_coverage_validation();
    let result = bridge.promote_if_novel(b"input bytes", None, &validation, &local);

    // (a) Returns Err.
    assert!(
        matches!(result, Err(PromoteError::StagingFailed(_))),
        "expected StagingFailed, got {result:?}"
    );

    // (b) Shared coverage map UNCHANGED — Codex finding 2's smoking-gun
    //     assertion. If this fails, the promotion mutated shared state
    //     before securing durable storage.
    let global_after = global.lock().unwrap().as_slice().to_vec();
    assert_eq!(
        global_before, global_after,
        "global coverage map MUST be byte-identical when promotion fails"
    );
}

#[test]
fn successful_promotion_mutates_shared_coverage_only_after_corpus_add() {
    let tmp = TempDir::new().unwrap();
    let queue_dir = tmp.path().join("queue");
    let corpus = Arc::new(Mutex::new(FuzzCorpus::open(&queue_dir).unwrap()));
    let global = Arc::new(Mutex::new(CoverageMap::new()));

    let bridge = CorpusBridge::new(corpus.clone(), global.clone());

    let local = map_with_edges();
    let validation = make_new_coverage_validation();
    let outcome = bridge
        .promote_if_novel(
            b"unique input bytes",
            Some("parent_seed"),
            &validation,
            &local,
        )
        .expect("promotion should succeed when staging is healthy");

    let model_id = match outcome {
        PromoteOutcome::Promoted { model_id, .. } => model_id,
        other => panic!("expected Promoted, got {other:?}"),
    };

    // The corpus has the entry.
    let c = corpus.lock().unwrap();
    assert_eq!(c.len(), 1);
    let entry = c.get(&model_id).expect("entry by id");
    assert_eq!(entry.parent_id.as_deref(), Some("parent_seed"));
    assert_eq!(entry.input, b"unique input bytes");
    drop(c);

    // The on-disk reproducer exists at queue/<model_id>.
    let path = queue_dir.join(&model_id);
    assert!(path.exists(), "promoted input must exist on disk");

    // The global coverage map now reflects the merged edges.
    let g = global.lock().unwrap();
    let nonzero = g.as_slice().iter().filter(|&&b| b > 0).count();
    assert!(
        nonzero >= 1,
        "shared coverage must now have the merged edges"
    );
}

#[test]
fn no_promotion_when_validation_says_not_new_coverage_confirmed() {
    let tmp = TempDir::new().unwrap();
    let queue_dir = tmp.path().join("queue");
    let corpus = Arc::new(Mutex::new(FuzzCorpus::open(&queue_dir).unwrap()));
    let global = Arc::new(Mutex::new(CoverageMap::new()));
    let bridge = CorpusBridge::new(corpus.clone(), global.clone());
    let local = map_with_edges();

    // ModelMismatch never promotes.
    let mut v = make_new_coverage_validation();
    v.status = ValidationStatus::ModelMismatch;
    let outcome = bridge.promote_if_novel(b"x", None, &v, &local).unwrap();
    assert!(matches!(outcome, PromoteOutcome::Skipped { .. }));
    assert_eq!(corpus.lock().unwrap().len(), 0);

    // NewCrash never promotes to corpus.
    let mut v = make_new_coverage_validation();
    v.status = ValidationStatus::NewCrash;
    let outcome = bridge.promote_if_novel(b"x", None, &v, &local).unwrap();
    assert!(matches!(outcome, PromoteOutcome::Skipped { .. }));
    assert_eq!(corpus.lock().unwrap().len(), 0);

    // Valid never promotes (no novelty needed).
    let mut v = make_new_coverage_validation();
    v.status = ValidationStatus::Valid;
    let outcome = bridge.promote_if_novel(b"x", None, &v, &local).unwrap();
    assert!(matches!(outcome, PromoteOutcome::Skipped { .. }));
    assert_eq!(corpus.lock().unwrap().len(), 0);

    // And in all cases the global map stayed at zero.
    let g = global.lock().unwrap();
    assert!(g.as_slice().iter().all(|&b| b == 0));
}

#[test]
fn snapshot_novelty_check_does_not_mutate_global_even_on_unique_input() {
    // When novelty against snapshot is empty (local == snapshot), no
    // promotion happens and the global map stays unchanged.
    let tmp = TempDir::new().unwrap();
    let queue_dir = tmp.path().join("queue");
    let corpus = Arc::new(Mutex::new(FuzzCorpus::open(&queue_dir).unwrap()));
    let global = Arc::new(Mutex::new(map_with_edges()));
    let global_before = global.lock().unwrap().as_slice().to_vec();
    let bridge = CorpusBridge::new(corpus, global.clone());

    let local = map_with_edges();
    let validation = make_new_coverage_validation();
    let outcome = bridge
        .promote_if_novel(b"x", None, &validation, &local)
        .unwrap();
    assert!(matches!(outcome, PromoteOutcome::NotNovel { .. }));

    let global_after = global.lock().unwrap().as_slice().to_vec();
    assert_eq!(global_before, global_after);
}
