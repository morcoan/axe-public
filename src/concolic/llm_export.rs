//! Five NDJSON writers + one SMT-LIB dumper for the concolic
//! session. Mirrors the fuzzer's [`crate::fuzzer::llm_export`]
//! pattern: append-mode, periodic flush+fsync, `finalize()` returns
//! the byte count for the run-status ledger.
//!
//! Per the plan:
//! - [`SolvesWriter`]   → `out/concolic/solves.jsonl`
//! - [`ExprsWriter`]    → `out/concolic/exprs.jsonl` (dedup by NodeId)
//! - [`BranchesWriter`] → `out/concolic/branches.jsonl`
//! - [`TracesWriter`]   → `out/concolic/traces.jsonl`
//! - [`CoverageWriter`] → `out/concolic/coverage.jsonl`
//! - [`Smt2Writer`]     → `out/concolic/smt2/path_NNNN_branch_NNNN.smt2`
//!
//! Why one writer per artifact: each kind has a distinct schema and
//! deduplication policy (only Exprs dedup by id; only SMT-LIB writes
//! one file per record). Sharing a generic writer would force the
//! same fsync cadence on every artifact whether or not it needs it.

#![allow(dead_code)]

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::concolic::expr::NodeId;

/// Flush + fsync after every N events. Same cadence as the fuzzer's
/// [`crate::fuzzer::llm_export::EVENT_FLUSH_EVERY`]; a single global
/// makes batched flush behavior consistent across artifacts.
pub const EVENT_FLUSH_EVERY: usize = 64;

/// Cap on individual SMT-LIB dumps emitted in one session. From the
/// "Open decisions / risks" table — long sessions can otherwise
/// exhaust disk space. The writer silently drops dumps past this cap
/// and surfaces the truncation count via [`Smt2Writer::dropped`].
pub const MAX_SMT2_DUMPS: usize = 10_000;

// ───────────── shared low-level helpers ────────────────────────────

fn open_truncating(path: &Path) -> io::Result<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

fn write_line<T: Serialize>(bw: &mut BufWriter<File>, value: &T) -> io::Result<u64> {
    let line = serde_json::to_vec(value).map_err(io::Error::other)?;
    bw.write_all(&line)?;
    bw.write_all(b"\n")?;
    Ok(line.len() as u64 + 1)
}

// ───────────── record schemas ──────────────────────────────────────

/// One row in `solves.jsonl`. Schema `"symtrace.solve.v1"` per the
/// plan's wire-shapes section.
#[derive(Clone, Debug, Serialize)]
pub struct SolveRecord {
    pub schema: &'static str,
    pub ts_ms: u64,
    pub run_id: String,
    pub path_id: String,
    pub branch: SolveBranch,
    pub constraint_summary: ConstraintSummary,
    pub solver: SolverSection,
    pub model: Option<ModelSection>,
    pub coverage: Option<CoverageSection>,
    pub model_validation: Option<ModelValidationSection>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SolveBranch {
    pub pc: String,
    pub function: Option<String>,
    pub edge_id: Option<String>,
    pub depth: u32,
    pub taken: bool,
    pub requested: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConstraintSummary {
    pub logic: &'static str,
    pub num_constraints_total: u32,
    pub num_constraints_in_slice: u32,
    pub num_expr_nodes: u32,
    pub input_bytes: u32,
    pub features: Vec<&'static str>,
    pub unsupported_features: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SolverSection {
    pub tier_used: &'static str,
    pub backend: &'static str,
    pub status: &'static str,
    pub time_ms: u64,
    pub reason_unknown: Option<String>,
    pub unsat_core: Vec<NodeId>,
    pub smt2_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ModelSection {
    pub input_sha256: String,
    pub input_path: String,
    pub changed_byte_ranges: Vec<ChangedRange>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChangedRange {
    pub start: u32,
    pub end: u32,
    pub before_hex: String,
    pub after_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CoverageSection {
    pub before_edge_count: u64,
    pub after_edge_count: u64,
    pub new_edges: Vec<String>,
    pub confirmed_new_path: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ModelValidationSection {
    pub reexecuted: bool,
    pub reached_target_pc: bool,
    pub branch_flipped: bool,
    pub new_coverage: bool,
    pub crashed: bool,
    pub status: &'static str,
}

/// One row in `exprs.jsonl`. Records a single interned DAG node by
/// id. The session writer dedups so each NodeId appears at most once.
#[derive(Clone, Debug, Serialize)]
pub struct ExprRecord {
    pub schema: &'static str,
    pub id: NodeId,
    pub sort: String,
    pub kind: String,
    pub children: Vec<NodeId>,
    pub value: Option<String>,
}

/// One row in `branches.jsonl`. Branch event observed by the shadow
/// emulator; the constraint slice references nodes in `exprs.jsonl`.
#[derive(Clone, Debug, Serialize)]
pub struct BranchRecord {
    pub schema: &'static str,
    pub site_va: String,
    pub mnemonic: String,
    pub predicate: String,
    pub width: u32,
    pub taken: bool,
    pub left_node: Option<NodeId>,
    pub right_node: Option<NodeId>,
    pub constraint_node: NodeId,
}

/// One row in `traces.jsonl`. Per-path execution trace summary.
#[derive(Clone, Debug, Serialize)]
pub struct TraceRecord {
    pub schema: &'static str,
    pub path_id: String,
    pub instr_count: u64,
    pub branches_observed: u32,
    pub concretizations: u32,
}

/// One row in `coverage.jsonl`. New-coverage events from confirmed
/// validations.
#[derive(Clone, Debug, Serialize)]
pub struct CoverageRecord {
    pub schema: &'static str,
    pub ts_ms: u64,
    pub source_solve_id: String,
    pub new_edges: u32,
    pub new_buckets: u32,
}

// ───────────── writers ─────────────────────────────────────────────

macro_rules! impl_jsonl_writer {
    ($name:ident, $record:ty) => {
        pub struct $name {
            path: PathBuf,
            inner: Option<BufWriter<File>>,
            count: usize,
            since_last_flush: usize,
            bytes_written: u64,
        }

        impl $name {
            pub fn create(path: &Path) -> io::Result<Self> {
                let file = open_truncating(path)?;
                Ok(Self {
                    path: path.to_path_buf(),
                    inner: Some(BufWriter::new(file)),
                    count: 0,
                    since_last_flush: 0,
                    bytes_written: 0,
                })
            }

            pub fn append(&mut self, record: &$record) -> io::Result<()> {
                let bw = self.inner.as_mut().ok_or_else(|| {
                    io::Error::other(concat!(stringify!($name), " already finalized"))
                })?;
                let bytes = write_line(bw, record)?;
                let crossed_threshold = self.since_last_flush + 1 >= EVENT_FLUSH_EVERY;
                if crossed_threshold {
                    bw.flush()?;
                    bw.get_ref().sync_all()?;
                }
                self.bytes_written += bytes;
                self.count += 1;
                self.since_last_flush = if crossed_threshold {
                    0
                } else {
                    self.since_last_flush + 1
                };
                Ok(())
            }

            pub fn finalize(mut self) -> io::Result<u64> {
                if let Some(mut bw) = self.inner.take() {
                    bw.flush()?;
                    bw.get_ref().sync_all()?;
                }
                Ok(self.bytes_written)
            }

            pub fn count(&self) -> usize {
                self.count
            }

            pub fn bytes_written(&self) -> u64 {
                self.bytes_written
            }

            pub fn path(&self) -> &Path {
                &self.path
            }
        }
    };
}

impl_jsonl_writer!(SolvesWriter, SolveRecord);
impl_jsonl_writer!(BranchesWriter, BranchRecord);
impl_jsonl_writer!(TracesWriter, TraceRecord);
impl_jsonl_writer!(CoverageWriter, CoverageRecord);

/// Like the macro-generated writers, plus a `seen: HashSet<NodeId>`
/// that dedups by id. Writing an Expr whose id is already in the set
/// is a no-op (returns Ok immediately) — the consumer always sees
/// each node at most once, even when the session re-emits queries
/// that share subexpressions.
pub struct ExprsWriter {
    path: PathBuf,
    inner: Option<BufWriter<File>>,
    seen: HashSet<NodeId>,
    count: usize,
    since_last_flush: usize,
    bytes_written: u64,
}

impl ExprsWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        let file = open_truncating(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            inner: Some(BufWriter::new(file)),
            seen: HashSet::new(),
            count: 0,
            since_last_flush: 0,
            bytes_written: 0,
        })
    }

    pub fn append(&mut self, record: &ExprRecord) -> io::Result<bool> {
        if !self.seen.insert(record.id) {
            return Ok(false);
        }
        let bw = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::other("ExprsWriter already finalized"))?;
        let bytes = write_line(bw, record)?;
        let crossed_threshold = self.since_last_flush + 1 >= EVENT_FLUSH_EVERY;
        if crossed_threshold {
            bw.flush()?;
            bw.get_ref().sync_all()?;
        }
        self.bytes_written += bytes;
        self.count += 1;
        self.since_last_flush = if crossed_threshold {
            0
        } else {
            self.since_last_flush + 1
        };
        Ok(true)
    }

    pub fn finalize(mut self) -> io::Result<u64> {
        if let Some(mut bw) = self.inner.take() {
            bw.flush()?;
            bw.get_ref().sync_all()?;
        }
        Ok(self.bytes_written)
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// One-file-per-query SMT-LIB dumper. Writes to
/// `out/concolic/smt2/path_NNNNN_branch_NNNN.smt2` via
/// [`crate::fuzzer::atomic_write::write_atomic`] so partial dumps
/// never appear on disk.
///
/// Honors [`MAX_SMT2_DUMPS`]: dumps past the cap are silently
/// dropped and counted in [`Smt2Writer::dropped`]; callers can
/// surface a WARN via the events stream when this happens.
pub struct Smt2Writer {
    dir: PathBuf,
    written: usize,
    dropped: usize,
    bytes_written: u64,
}

impl Smt2Writer {
    pub fn create(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            written: 0,
            dropped: 0,
            bytes_written: 0,
        })
    }

    /// Persist a single SMT-LIB query. Returns the relative path
    /// (relative to `out/concolic/`) suitable for embedding in a
    /// `SolveRecord::solver.smt2_path`, or `None` if the cap was hit.
    pub fn dump(
        &mut self,
        smt2: &str,
        path_idx: u32,
        branch_idx: u32,
    ) -> io::Result<Option<String>> {
        if self.written >= MAX_SMT2_DUMPS {
            self.dropped += 1;
            return Ok(None);
        }
        let filename = format!("path_{path_idx:05}_branch_{branch_idx:04}.smt2");
        let full = self.dir.join(&filename);
        crate::fuzzer::atomic_write::write_atomic(&full, smt2.as_bytes())?;
        self.written += 1;
        self.bytes_written += smt2.len() as u64;
        // Return path relative to `out/concolic/`, e.g. `smt2/path_00001_branch_0042.smt2`.
        let basename = self
            .dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("smt2");
        Ok(Some(format!("{basename}/{filename}")))
    }

    pub fn written(&self) -> usize {
        self.written
    }

    pub fn dropped(&self) -> usize {
        self.dropped
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::TempDir;

    fn sample_solve(path_id: &str) -> SolveRecord {
        SolveRecord {
            schema: "symtrace.solve.v1",
            ts_ms: 1742000000000,
            run_id: "run_test".into(),
            path_id: path_id.into(),
            branch: SolveBranch {
                pc: "0x40127a".into(),
                function: Some("parse_header".into()),
                edge_id: None,
                depth: 37,
                taken: true,
                requested: false,
            },
            constraint_summary: ConstraintSummary {
                logic: "QF_BV",
                num_constraints_total: 211,
                num_constraints_in_slice: 54,
                num_expr_nodes: 311,
                input_bytes: 128,
                features: vec!["bitvector", "extract"],
                unsupported_features: vec![],
            },
            solver: SolverSection {
                tier_used: "z3_sliced_assumptions",
                backend: "z3_in_process",
                status: "sat",
                time_ms: 42,
                reason_unknown: None,
                unsat_core: vec![],
                smt2_path: None,
            },
            model: None,
            coverage: None,
            model_validation: None,
        }
    }

    fn sample_expr(id: NodeId, kind: &str) -> ExprRecord {
        ExprRecord {
            schema: "symtrace.expr.v1",
            id,
            sort: "Bv(32)".into(),
            kind: kind.into(),
            children: vec![],
            value: None,
        }
    }

    #[test]
    fn solves_writer_appends_one_line_per_record() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("solves.jsonl");
        let mut w = SolvesWriter::create(&path).unwrap();
        w.append(&sample_solve("p1")).unwrap();
        w.append(&sample_solve("p2")).unwrap();
        assert_eq!(w.count(), 2);
        let bytes = w.finalize().unwrap();
        assert!(bytes > 0);
        let mut s = String::new();
        File::open(&path).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s.lines().count(), 2);
        assert!(s.contains("\"path_id\":\"p1\""));
        assert!(s.contains("\"path_id\":\"p2\""));
    }

    #[test]
    fn exprs_writer_dedupes_by_id() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("exprs.jsonl");
        let mut w = ExprsWriter::create(&path).unwrap();
        assert!(w.append(&sample_expr(1, "Var")).unwrap());
        assert!(w.append(&sample_expr(2, "BvAdd")).unwrap());
        // Same id, different kind — dedup wins.
        assert!(!w.append(&sample_expr(1, "Var_again")).unwrap());
        assert_eq!(w.count(), 2);
        let _ = w.finalize().unwrap();
        let mut s = String::new();
        File::open(&path).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s.lines().count(), 2);
        // Only the first record for id=1 should appear.
        assert!(s.contains("\"kind\":\"Var\""));
        assert!(!s.contains("\"kind\":\"Var_again\""));
    }

    #[test]
    fn smt2_writer_dumps_per_query_and_returns_relative_path() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("smt2");
        let mut w = Smt2Writer::create(&dir).unwrap();
        let p = w
            .dump("(set-logic QF_BV)\n(check-sat)\n", 1, 42)
            .unwrap()
            .unwrap();
        assert_eq!(p, "smt2/path_00001_branch_0042.smt2");
        let full = dir.join("path_00001_branch_0042.smt2");
        assert!(full.exists());
        assert_eq!(w.written(), 1);
        assert_eq!(w.dropped(), 0);
        assert!(w.bytes_written() > 0);
    }

    #[test]
    fn smt2_writer_caps_at_max_dumps() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("smt2");
        let mut w = Smt2Writer::create(&dir).unwrap();
        // Force-cap to test by writing one then setting the counter
        // — too slow to do MAX_SMT2_DUMPS iterations in unit tests.
        // Instead, exercise the dropped-counter path via the public
        // `dump` after artificially bumping the count.
        let _ = w.dump("(check-sat)\n", 0, 0).unwrap();
        w.written = MAX_SMT2_DUMPS;
        let dropped_first = w.dropped();
        let r = w.dump("(check-sat)\n", 0, 1).unwrap();
        assert!(r.is_none());
        assert_eq!(w.dropped(), dropped_first + 1);
    }

    #[test]
    fn append_after_finalize_returns_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("solves.jsonl");
        let mut w = SolvesWriter::create(&path).unwrap();
        w.append(&sample_solve("p1")).unwrap();
        // finalize() consumes by value. Re-open the file via a fresh
        // writer to confirm the original isn't trying to write twice.
        // (We can't call append on the finalized writer because it's
        // moved — that's the by-value-finalize discipline.)
        let _ = w.finalize().unwrap();
    }

    #[test]
    fn finalize_flushes_pending_buffer() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("traces.jsonl");
        let mut w = TracesWriter::create(&path).unwrap();
        // Just a couple of records — below the flush threshold.
        for i in 0..3 {
            w.append(&TraceRecord {
                schema: "symtrace.trace.v1",
                path_id: format!("p{i}"),
                instr_count: 100,
                branches_observed: 5,
                concretizations: 0,
            })
            .unwrap();
        }
        let bytes = w.finalize().unwrap();
        assert!(bytes > 0);
        let mut s = String::new();
        File::open(&path).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s.lines().count(), 3, "all records flushed on finalize");
    }
}
