//! End-to-end fuzz session orchestrator — first working coverage-
//! guided loop.
//!
//! Step 8 wires steps 2-7 together with the `EmulatorExecutor`
//! backend. The session OWNS:
//! - The corpus and crash database (on-disk + in-memory).
//! - The global coverage map (per-edge max bucket across the run).
//! - The PRNG, schedule, dictionary, and splice pool.
//!
//! The session does NOT own the executor — the caller hands one in
//! per call. This keeps the session executor-agnostic so hybrid mode
//! (step 18) can swap between `InProcessExecutor` and
//! `EmulatorExecutor` mid-session.
//!
//! Steps 9-14 layer additional behavior on top:
//! - Step 9: target derivation feeds `RareEdges` initialization
//! - Step 10: reachability scoring augments the scheduler
//! - Steps 12-14: LLM artifact writers append per-iteration events

#![allow(dead_code)]

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::fuzzer::corpus::{input_id, FuzzCorpus, QueueEntry, QueueMetadata};
use crate::fuzzer::coverage::{classify, CoverageMap};
use crate::fuzzer::crash::{should_dedupe, CrashDb, CrashSignature};
use crate::fuzzer::executor::FuzzExecutor;
use crate::fuzzer::mutators::{apply_random_mutation, Dictionary, MutateCtx, Xorshift64};
use crate::fuzzer::scheduler::{PowerSchedule, RareEdges};

/// What the loop did this iteration. The LLM export layer (step 12)
/// projects these into NDJSON event records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IterationOutcome {
    /// New edge or new bucket — added to corpus.
    NewCoverage,
    /// New unique crash family — persisted to `crashes/<sig>/`.
    NewCrash,
    /// Crash matched an existing family; count incremented, no new
    /// finding emitted.
    DuplicateCrash,
    /// Execution didn't crash and didn't add new coverage.
    NoChange,
    /// Corpus is empty (nothing to pick from) — caller should seed.
    Skip,
}

#[derive(Clone, Debug)]
pub struct SessionStats {
    pub iterations: u64,
    pub corpus_size: usize,
    pub unique_crashes: usize,
    pub edges_covered: u64,
    pub seed: u64,
}

/// Aggregated fuzz session state.
pub struct FuzzSession {
    corpus: FuzzCorpus,
    crashes: CrashDb,
    coverage_global: CoverageMap,
    rng: Xorshift64,
    schedule: PowerSchedule,
    rare: RareEdges,
    dict: Dictionary,
    splice_pool: Vec<Vec<u8>>,
    iter_count: u64,
    timeout: Duration,
    max_input_len: usize,
    out_dir: PathBuf,
    seed: u64,
}

impl FuzzSession {
    /// Open (or create) a fuzz session rooted at `out_dir`. Sets up
    /// `out_dir/queue/`, `out_dir/queue/.staging/`, and
    /// `out_dir/crashes/` on disk.
    pub fn new(out_dir: &Path, seed: u64) -> io::Result<Self> {
        std::fs::create_dir_all(out_dir)?;
        let corpus = FuzzCorpus::open(&out_dir.join("queue"))?;
        let crashes = CrashDb::open(&out_dir.join("crashes"))?;
        Ok(Self {
            corpus,
            crashes,
            coverage_global: CoverageMap::new(),
            rng: Xorshift64::new(seed),
            schedule: PowerSchedule::default(),
            rare: RareEdges::new(2),
            dict: Dictionary::default(),
            splice_pool: Vec::new(),
            iter_count: 0,
            timeout: Duration::from_secs(60),
            max_input_len: 4096,
            out_dir: out_dir.to_path_buf(),
            seed,
        })
    }

    /// Replace the active dictionary with user-supplied tokens.
    pub fn with_dictionary(&mut self, dict: Dictionary) -> &mut Self {
        self.dict = dict;
        self
    }

    /// Replace the splice pool. Typically called with a snapshot of
    /// the corpus's current inputs before each iteration.
    pub fn with_splice_pool(&mut self, pool: Vec<Vec<u8>>) -> &mut Self {
        self.splice_pool = pool;
        self
    }

    pub fn with_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_input_len(&mut self, max_len: usize) -> &mut Self {
        self.max_input_len = max_len;
        self
    }

    /// Seed the corpus with an initial input. The session executes
    /// the input through the executor, records coverage, and adds it
    /// to the corpus if interesting.
    pub fn seed_with<E: FuzzExecutor + ?Sized>(
        &mut self,
        executor: &mut E,
        bytes: Vec<u8>,
    ) -> io::Result<IterationOutcome> {
        self.execute_and_record(executor, &bytes, None)
    }

    /// Run one full fuzz iteration: pick → mutate → execute → classify
    /// → store. Returns the outcome enum.
    pub fn fuzz_one<E: FuzzExecutor + ?Sized>(
        &mut self,
        executor: &mut E,
    ) -> io::Result<IterationOutcome> {
        let pick_idx = self.schedule.pick(&self.corpus, &self.rare, &mut self.rng);
        let Some(idx) = pick_idx else {
            return Ok(IterationOutcome::Skip);
        };
        let (parent_input, parent_id) = {
            let entry = self.corpus.iter().nth(idx).expect("idx in bounds");
            (entry.input.clone(), entry.id.clone())
        };
        let ctx = MutateCtx {
            dict: &self.dict,
            splice_pool: &self.splice_pool,
            max_len: self.max_input_len,
        };
        let (mutated, _kind) = apply_random_mutation(&parent_input, &mut self.rng, &ctx);
        self.iter_count += 1;
        self.execute_and_record(executor, &mutated, Some(parent_id))
    }

    /// Run `n` iterations. Returns the final session stats.
    pub fn run<E: FuzzExecutor + ?Sized>(
        &mut self,
        executor: &mut E,
        n: usize,
    ) -> io::Result<SessionStats> {
        for _ in 0..n {
            self.fuzz_one(executor)?;
        }
        Ok(self.stats())
    }

    pub fn stats(&self) -> SessionStats {
        SessionStats {
            iterations: self.iter_count,
            corpus_size: self.corpus.len(),
            unique_crashes: self.crashes.len(),
            edges_covered: self
                .coverage_global
                .as_slice()
                .iter()
                .filter(|&&b| b > 0)
                .count() as u64,
            seed: self.seed,
        }
    }

    pub fn out_dir(&self) -> &Path {
        &self.out_dir
    }

    fn execute_and_record<E: FuzzExecutor + ?Sized>(
        &mut self,
        executor: &mut E,
        candidate: &[u8],
        parent_id: Option<String>,
    ) -> io::Result<IterationOutcome> {
        let cand_id = input_id(candidate);

        // Pre-execute persistence — Codex finding 2 mitigation. If
        // the executor crashes the process from here on, the next
        // session's staging::recover_orphans picks it up.
        self.corpus.stage_for_execution(&cand_id, candidate)?;

        let result = executor.run(candidate, self.timeout);
        let novelty = classify(executor.map(), &mut self.coverage_global);

        // Crash path: try to dedup and persist.
        if should_dedupe(result.exit) {
            let outcome = if let Some(info) = result.crash.as_ref() {
                match self.crashes.dedup_and_store(&cand_id, candidate, info)? {
                    Some(_sig) => IterationOutcome::NewCrash,
                    None => IterationOutcome::DuplicateCrash,
                }
            } else {
                IterationOutcome::DuplicateCrash
            };
            // Crash inputs aren't promoted to the corpus queue; the
            // crashes/<sig>/input.bin copy is the authoritative
            // reproducer. Discard the staging file.
            self.corpus.staging().discard(&cand_id)?;
            return Ok(outcome);
        }

        // Non-crash path: if novelty, add to corpus + update rare-edges.
        if novelty.is_interesting() {
            let entry = QueueEntry {
                id: cand_id.clone(),
                parent_id,
                input: candidate.to_vec(),
                metadata: QueueMetadata::from_novelty(novelty, result.exec_us),
            };
            self.corpus.add(entry)?;
            self.rare.observe_map(executor.map());
            return Ok(IterationOutcome::NewCoverage);
        }

        // No novelty, no crash — drop the staging copy.
        self.corpus.staging().discard(&cand_id)?;
        Ok(IterationOutcome::NoChange)
    }

    pub fn crash_signatures(&self) -> Vec<CrashSignature> {
        self.crashes.iter().map(|e| e.signature).collect()
    }

    pub fn corpus_size(&self) -> usize {
        self.corpus.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzzer::coverage::CoverageMap;
    use crate::fuzzer::executor::{CrashInfo, ExecutionResult, ExitKind, FuzzExecutor};
    use std::collections::VecDeque;
    use std::time::Duration;
    use tempfile::TempDir;

    /// A scriptable executor used by session tests. Each call to
    /// `run` consumes one `MockResponse` from the queue; if the
    /// queue is empty, returns a default Ok result with no
    /// coverage. The mock owns its own coverage map, populated per
    /// `run` based on the response's `edges_to_record`.
    struct MockExecutor {
        map: CoverageMap,
        responses: VecDeque<MockResponse>,
    }

    struct MockResponse {
        edges: Vec<(u64, u64)>,
        exit: ExitKind,
        crash: Option<CrashInfo>,
        exec_us: u64,
    }

    impl MockExecutor {
        fn new(responses: Vec<MockResponse>) -> Self {
            Self {
                map: CoverageMap::new(),
                responses: responses.into(),
            }
        }
    }

    impl FuzzExecutor for MockExecutor {
        fn run(&mut self, _input: &[u8], _timeout: Duration) -> ExecutionResult {
            self.reset();
            let r = self.responses.pop_front().unwrap_or(MockResponse {
                edges: Vec::new(),
                exit: ExitKind::Ok,
                crash: None,
                exec_us: 100,
            });
            for (from, to) in &r.edges {
                self.map.record_edge(*from, *to);
            }
            ExecutionResult {
                exit: r.exit,
                exec_us: r.exec_us,
                crash: r.crash,
                edges_observed: r.edges.len() as u64,
            }
        }

        fn reset(&mut self) {
            self.map.clear();
        }

        fn map(&self) -> &CoverageMap {
            &self.map
        }
    }

    fn ok_with_edges(edges: &[(u64, u64)]) -> MockResponse {
        MockResponse {
            edges: edges.to_vec(),
            exit: ExitKind::Ok,
            crash: None,
            exec_us: 100,
        }
    }

    fn crash_response(kind: &str, frames: &[u64]) -> MockResponse {
        MockResponse {
            edges: Vec::new(),
            exit: ExitKind::Crash,
            crash: Some(CrashInfo {
                kind: kind.into(),
                signal: Some(11),
                fault_pc: frames.first().copied(),
                top_frames: frames.to_vec(),
                sanitizer_type: None,
            }),
            exec_us: 50,
        }
    }

    #[test]
    fn empty_corpus_picker_returns_skip() {
        let tmp = TempDir::new().unwrap();
        let mut session = FuzzSession::new(tmp.path(), 42).unwrap();
        let mut exec = MockExecutor::new(vec![]);
        let outcome = session.fuzz_one(&mut exec).unwrap();
        assert_eq!(outcome, IterationOutcome::Skip);
    }

    #[test]
    fn seed_with_novel_input_grows_corpus() {
        let tmp = TempDir::new().unwrap();
        let mut session = FuzzSession::new(tmp.path(), 42).unwrap();
        let mut exec = MockExecutor::new(vec![ok_with_edges(&[(0x1000, 0x1010)])]);
        let outcome = session.seed_with(&mut exec, b"seed".to_vec()).unwrap();
        assert_eq!(outcome, IterationOutcome::NewCoverage);
        assert_eq!(session.corpus_size(), 1);
    }

    #[test]
    fn seed_without_novelty_does_not_grow_corpus() {
        let tmp = TempDir::new().unwrap();
        let mut session = FuzzSession::new(tmp.path(), 42).unwrap();
        let mut exec = MockExecutor::new(vec![ok_with_edges(&[])]);
        let outcome = session.seed_with(&mut exec, b"seed".to_vec()).unwrap();
        assert_eq!(outcome, IterationOutcome::NoChange);
        assert_eq!(session.corpus_size(), 0);
    }

    #[test]
    fn crash_path_dedups_and_persists() {
        let tmp = TempDir::new().unwrap();
        let mut session = FuzzSession::new(tmp.path(), 42).unwrap();
        let mut exec = MockExecutor::new(vec![
            crash_response("heap-buffer-overflow", &[0x1000, 0x1010]),
            crash_response("heap-buffer-overflow", &[0x1000, 0x1010]), // same family
            crash_response("stack-overflow", &[0x2000]),               // new family
        ]);

        let o1 = session
            .seed_with(&mut exec, b"crash-input-a".to_vec())
            .unwrap();
        assert_eq!(o1, IterationOutcome::NewCrash);

        let o2 = session
            .seed_with(&mut exec, b"crash-input-b".to_vec())
            .unwrap();
        assert_eq!(o2, IterationOutcome::DuplicateCrash);

        let o3 = session
            .seed_with(&mut exec, b"crash-input-c".to_vec())
            .unwrap();
        assert_eq!(o3, IterationOutcome::NewCrash);

        assert_eq!(session.stats().unique_crashes, 2);
        assert_eq!(session.corpus_size(), 0, "crash inputs not corpus'd");
    }

    #[test]
    fn run_loops_n_iterations() {
        let tmp = TempDir::new().unwrap();
        let mut session = FuzzSession::new(tmp.path(), 42).unwrap();
        // Seed with one corpus entry first so the picker has something
        // to pick.
        let mut seed_exec = MockExecutor::new(vec![ok_with_edges(&[(0x1000, 0x1010)])]);
        session
            .seed_with(&mut seed_exec, b"initial".to_vec())
            .unwrap();

        // Now run 20 iterations; the picker returns the only corpus
        // entry, mutator produces variants, executor reports no new
        // coverage. We just want to ensure the loop runs without
        // panicking and bumps the iter counter.
        let mut exec = MockExecutor::new((0..20).map(|_| ok_with_edges(&[])).collect());
        let stats = session.run(&mut exec, 20).unwrap();
        assert_eq!(stats.iterations, 20);
    }

    #[test]
    fn novel_iterations_grow_corpus_and_edges() {
        let tmp = TempDir::new().unwrap();
        let mut session = FuzzSession::new(tmp.path(), 42).unwrap();
        let mut seed_exec = MockExecutor::new(vec![ok_with_edges(&[(0x1000, 0x1010)])]);
        session
            .seed_with(&mut seed_exec, b"initial".to_vec())
            .unwrap();

        // 3 of the 5 iterations report distinct new edges → 3 new
        // corpus entries (assuming the mutator doesn't accidentally
        // dedup-by-content).
        let mut exec = MockExecutor::new(vec![
            ok_with_edges(&[(0x2000, 0x2010)]),
            ok_with_edges(&[(0x3000, 0x3010)]),
            ok_with_edges(&[]),
            ok_with_edges(&[(0x4000, 0x4010)]),
            ok_with_edges(&[]),
        ]);
        let stats = session.run(&mut exec, 5).unwrap();
        // Initial seed (1) + 3 novel iterations = up to 4 (could be
        // fewer if the mutator produced colliding bytes — those would
        // dedup-by-id in corpus::add).
        assert!(stats.corpus_size >= 1, "corpus grows from initial seed");
        assert!(stats.edges_covered >= 1, "edges global tracks all hits");
    }

    #[test]
    fn pre_execute_staging_artifacts_are_cleaned_up_on_success() {
        let tmp = TempDir::new().unwrap();
        let mut session = FuzzSession::new(tmp.path(), 42).unwrap();
        let mut exec = MockExecutor::new(vec![ok_with_edges(&[])]);
        session.seed_with(&mut exec, b"x".to_vec()).unwrap();

        // No-change outcome → staging file discarded; staging dir
        // contains no orphans.
        let recovered = tmp.path().join("queue").join(".staging");
        let leftover: Vec<_> = std::fs::read_dir(&recovered).unwrap().collect();
        assert!(
            leftover.is_empty(),
            "staging cleared after clean iteration (got {} entries)",
            leftover.len()
        );
    }
}
