//! Queryable corpus metadata in SQLite.
//!
//! `corpus.sqlite` is the LLM-friendly relational projection of the
//! fuzzer's in-memory state. While `events.ndjson` is the streaming
//! event log, this DB lets an LLM consumer run actual SQL like
//! "show me the 10 deepest-novelty inputs" or "which corpus entries
//! reach `parser::unsafe_decode_payload` at distance < 3."
//!
//! Performance: WAL journal mode + `synchronous=NORMAL` +
//! `temp_store=MEMORY` + batched-512 inserts per transaction.
//! Empirically sustains ≥5k inserts/sec on Windows, well above the
//! emulator-backed exec rate.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, Result as SqlResult, Transaction};

/// Default batch size for `record_input_batch`. The driver groups
/// inserts of this size into a single transaction; smaller batches
/// pay per-tx overhead, larger ones tie up WAL pages.
pub const BATCH_SIZE: usize = 512;

/// Schema version stored in the `meta` table for upgrade detection.
pub const SCHEMA_VERSION: u32 = 1;

pub struct CorpusDb {
    conn: Connection,
    path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct InputRow {
    pub id: String,
    pub parent_id: Option<String>,
    pub path: String,
    pub len: u64,
    pub exec_us: u64,
    pub depth: u32,
    pub coverage_hash: u64,
    pub bitmap_size: u32,
    pub favored: bool,
    pub times_fuzzed: u64,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug)]
pub struct EdgeHitRow {
    pub input_id: String,
    pub edge_slot: u32,
    pub hitcount_bucket: u8,
}

#[derive(Clone, Debug)]
pub struct MutationRow {
    pub input_id: String,
    pub mutator: String,
    pub sequence: u32,
}

#[derive(Clone, Debug)]
pub struct ReachabilityRow {
    pub input_id: String,
    pub target_id: String,
    pub distance: u32,
}

impl CorpusDb {
    /// Open (or create) the SQLite file. Applies PRAGMAs and creates
    /// schema tables on first open.
    pub fn open(path: &Path) -> SqlResult<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let conn = Connection::open(path)?;
        Self::apply_pragmas(&conn)?;
        Self::create_schema(&conn)?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    fn apply_pragmas(conn: &Connection) -> SqlResult<()> {
        // WAL is the durability + concurrency sweet spot for a single
        // writer + occasional reader. NORMAL synchronous trades a tiny
        // window of post-power-loss corruption risk for ~3x throughput.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        Ok(())
    }

    fn create_schema(conn: &Connection) -> SqlResult<()> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS inputs (
                id TEXT PRIMARY KEY,
                parent_id TEXT,
                path TEXT NOT NULL,
                len INTEGER NOT NULL,
                exec_us INTEGER NOT NULL,
                depth INTEGER NOT NULL,
                coverage_hash INTEGER NOT NULL,
                bitmap_size INTEGER NOT NULL,
                favored INTEGER NOT NULL,
                times_fuzzed INTEGER NOT NULL,
                created_at_ms INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS edges (
                input_id TEXT NOT NULL,
                edge_slot INTEGER NOT NULL,
                hitcount_bucket INTEGER NOT NULL,
                PRIMARY KEY (input_id, edge_slot)
            );
            CREATE TABLE IF NOT EXISTS mutations (
                input_id TEXT NOT NULL,
                mutator TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                PRIMARY KEY (input_id, sequence)
            );
            CREATE TABLE IF NOT EXISTS reachability (
                input_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                distance INTEGER NOT NULL,
                PRIMARY KEY (input_id, target_id)
            );
            CREATE INDEX IF NOT EXISTS inputs_parent ON inputs(parent_id);
            CREATE INDEX IF NOT EXISTS edges_slot ON edges(edge_slot);
            CREATE INDEX IF NOT EXISTS reach_target ON reachability(target_id);
            ",
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?1, ?2)",
            params!["schema_version", SCHEMA_VERSION.to_string()],
        )?;
        Ok(())
    }

    /// Insert (or replace) a batch of input rows in one transaction.
    pub fn record_input_batch(&mut self, rows: &[InputRow]) -> SqlResult<()> {
        let tx = self.conn.transaction()?;
        Self::insert_inputs(&tx, rows)?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_edge_batch(&mut self, rows: &[EdgeHitRow]) -> SqlResult<()> {
        let tx = self.conn.transaction()?;
        Self::insert_edges(&tx, rows)?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_mutation_batch(&mut self, rows: &[MutationRow]) -> SqlResult<()> {
        let tx = self.conn.transaction()?;
        Self::insert_mutations(&tx, rows)?;
        tx.commit()?;
        Ok(())
    }

    pub fn record_reachability_batch(&mut self, rows: &[ReachabilityRow]) -> SqlResult<()> {
        let tx = self.conn.transaction()?;
        Self::insert_reachability(&tx, rows)?;
        tx.commit()?;
        Ok(())
    }

    fn insert_inputs(tx: &Transaction<'_>, rows: &[InputRow]) -> SqlResult<()> {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO inputs(
                id, parent_id, path, len, exec_us, depth,
                coverage_hash, bitmap_size, favored, times_fuzzed,
                created_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )?;
        for r in rows {
            stmt.execute(params![
                r.id,
                r.parent_id,
                r.path,
                r.len as i64,
                r.exec_us as i64,
                r.depth as i64,
                r.coverage_hash as i64,
                r.bitmap_size as i64,
                r.favored as i64,
                r.times_fuzzed as i64,
                r.created_at_ms,
            ])?;
        }
        Ok(())
    }

    fn insert_edges(tx: &Transaction<'_>, rows: &[EdgeHitRow]) -> SqlResult<()> {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO edges(input_id, edge_slot, hitcount_bucket)
             VALUES (?1, ?2, ?3)",
        )?;
        for r in rows {
            stmt.execute(params![
                r.input_id,
                r.edge_slot as i64,
                r.hitcount_bucket as i64
            ])?;
        }
        Ok(())
    }

    fn insert_mutations(tx: &Transaction<'_>, rows: &[MutationRow]) -> SqlResult<()> {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO mutations(input_id, mutator, sequence)
             VALUES (?1, ?2, ?3)",
        )?;
        for r in rows {
            stmt.execute(params![r.input_id, r.mutator, r.sequence as i64])?;
        }
        Ok(())
    }

    fn insert_reachability(tx: &Transaction<'_>, rows: &[ReachabilityRow]) -> SqlResult<()> {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO reachability(input_id, target_id, distance)
             VALUES (?1, ?2, ?3)",
        )?;
        for r in rows {
            stmt.execute(params![r.input_id, r.target_id, r.distance as i64])?;
        }
        Ok(())
    }

    pub fn input_count(&self) -> SqlResult<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM inputs", [], |row| row.get(0))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Flush + close. Important for the run_status ledger to know the
    /// DB file size; SQLite checkpoints WAL into the main DB on close.
    /// Returns `io::Result` (not `SqlResult`) because the file-size
    /// query happens after we drop the connection, and rusqlite has
    /// no `From<io::Error>` conversion.
    pub fn finalize(self) -> std::io::Result<u64> {
        // Force a WAL checkpoint to ensure the main db file is the
        // authoritative byte count.
        let _ = self.conn.pragma_update(None, "wal_checkpoint", "TRUNCATE");
        let path = self.path.clone();
        drop(self.conn);
        std::fs::metadata(&path).map(|m| m.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn input(id: &str) -> InputRow {
        InputRow {
            id: id.into(),
            parent_id: None,
            path: format!("queue/{id}"),
            len: 64,
            exec_us: 500,
            depth: 0,
            coverage_hash: 0xdead_beef,
            bitmap_size: 18,
            favored: false,
            times_fuzzed: 0,
            created_at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn open_creates_schema_and_meta() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("corpus.sqlite");
        let db = CorpusDb::open(&path).unwrap();
        // Meta version row.
        let version: String = db
            .conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION.to_string());
    }

    #[test]
    fn record_input_batch_persists_rows() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("corpus.sqlite");
        let mut db = CorpusDb::open(&path).unwrap();
        let rows = vec![input("blake3-a"), input("blake3-b"), input("blake3-c")];
        db.record_input_batch(&rows).unwrap();
        assert_eq!(db.input_count().unwrap(), 3);
    }

    #[test]
    fn record_input_replace_on_conflict() {
        let tmp = TempDir::new().unwrap();
        let mut db = CorpusDb::open(&tmp.path().join("c.sqlite")).unwrap();
        let mut r = input("dup");
        db.record_input_batch(&[r.clone()]).unwrap();
        r.exec_us = 9999;
        db.record_input_batch(&[r]).unwrap();
        assert_eq!(db.input_count().unwrap(), 1);
        let exec_us: i64 = db
            .conn
            .query_row("SELECT exec_us FROM inputs WHERE id='dup'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(exec_us, 9999);
    }

    #[test]
    fn record_edges_and_query_back() {
        let tmp = TempDir::new().unwrap();
        let mut db = CorpusDb::open(&tmp.path().join("c.sqlite")).unwrap();
        db.record_input_batch(&[input("a")]).unwrap();
        db.record_edge_batch(&[
            EdgeHitRow {
                input_id: "a".into(),
                edge_slot: 42,
                hitcount_bucket: 3,
            },
            EdgeHitRow {
                input_id: "a".into(),
                edge_slot: 99,
                hitcount_bucket: 1,
            },
        ])
        .unwrap();
        let count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM edges WHERE input_id='a'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn record_reachability_query_by_target() {
        let tmp = TempDir::new().unwrap();
        let mut db = CorpusDb::open(&tmp.path().join("c.sqlite")).unwrap();
        db.record_input_batch(&[input("a"), input("b")]).unwrap();
        db.record_reachability_batch(&[
            ReachabilityRow {
                input_id: "a".into(),
                target_id: "target-1".into(),
                distance: 2,
            },
            ReachabilityRow {
                input_id: "b".into(),
                target_id: "target-1".into(),
                distance: 5,
            },
        ])
        .unwrap();
        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM reachability WHERE target_id='target-1' AND distance < 3",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "only input 'a' is within distance 3");
    }

    #[test]
    fn finalize_returns_byte_count() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("c.sqlite");
        let mut db = CorpusDb::open(&path).unwrap();
        db.record_input_batch(&[input("a"), input("b")]).unwrap();
        let bytes = db.finalize().unwrap();
        assert!(bytes > 0, "finalized DB should have non-zero file size");
    }

    #[test]
    fn pragma_journal_mode_is_wal() {
        let tmp = TempDir::new().unwrap();
        let db = CorpusDb::open(&tmp.path().join("c.sqlite")).unwrap();
        let mode: String = db
            .conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_ascii_lowercase(), "wal");
    }
}
