//! Durable SQLite-backed store + streaming NDJSON writer.
//!
//! Two artifact families ship from this module:
//! - `trace.sqlite` — durable cross-run store via [`TraceStore`].
//!   Schema version tracked in `meta` table; v1 uses `journal_mode =
//!   MEMORY` so antivirus-driven `.sqlite-wal` lock contention on
//!   Windows can't stall the session. The NDJSON ledger is the
//!   authoritative record of truth for crash recovery.
//! - `events.ndjson` — append-mode NDJSON stream via
//!   [`TraceEventWriter`]. Flushes + fsyncs every 64 events (same
//!   discipline as `src/fuzzer/llm_export.rs:128-199` so a
//!   parent-process crash bounds data loss to <64 events).

#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection};

use crate::dynamic_trace::event::{EntityRef, EventType, TraceEvent};

pub const STORE_SCHEMA_VERSION: i64 = 1;
pub const EVENT_FLUSH_EVERY: usize = 64;

// ---------------------------------------------------------------------
// TraceStore — durable SQLite-backed store.
// ---------------------------------------------------------------------

pub struct TraceStore {
    conn: Connection,
    inserted: u64,
}

impl TraceStore {
    /// Open or create the store at the given path. Creates the parent
    /// directory if missing. Runs schema migration up to
    /// [`STORE_SCHEMA_VERSION`].
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        }
        let conn = Connection::open(path)?;
        // PRAGMA journal_mode=MEMORY: sacrifices crash-durability of
        // the SQLite store (the NDJSON ledger is the durable record of
        // truth) for AV/Defender compatibility on Windows where
        // .sqlite-wal locks can stall under contention.
        conn.pragma_update(None, "journal_mode", "MEMORY")?;
        conn.pragma_update(None, "synchronous", "OFF")?;
        let mut store = Self { conn, inserted: 0 };
        store.migrate()?;
        Ok(store)
    }

    /// In-memory store for tests.
    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let mut store = Self { conn, inserted: 0 };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> rusqlite::Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                event_id     TEXT PRIMARY KEY,
                run_id       TEXT NOT NULL,
                ts_ns        INTEGER NOT NULL,
                pid          INTEGER NOT NULL,
                tid          INTEGER NOT NULL,
                event_type   TEXT NOT NULL,
                operation    TEXT NOT NULL,
                subject_id   TEXT NOT NULL,
                object_id    TEXT,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS events_ts_idx   ON events(ts_ns);
            CREATE INDEX IF NOT EXISTS events_type_idx ON events(event_type);
            CREATE INDEX IF NOT EXISTS events_subj_idx ON events(subject_id);
            CREATE TABLE IF NOT EXISTS entities (
                entity_id TEXT PRIMARY KEY,
                kind      TEXT NOT NULL,
                name      TEXT,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS edges (
                src         TEXT NOT NULL,
                dst         TEXT NOT NULL,
                edge_type   TEXT NOT NULL,
                first_ts_ns INTEGER NOT NULL,
                last_ts_ns  INTEGER NOT NULL,
                count       INTEGER NOT NULL DEFAULT 1,
                event_refs  TEXT NOT NULL,
                PRIMARY KEY (src, dst, edge_type)
            );
            CREATE TABLE IF NOT EXISTS behavior_facts (
                fact_id            TEXT PRIMARY KEY,
                category           TEXT NOT NULL,
                claim              TEXT NOT NULL,
                confidence_band    TEXT NOT NULL,
                confidence_score   REAL NOT NULL,
                evidence_event_ids TEXT NOT NULL,
                uncertainty        TEXT,
                payload_json       TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS run_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params!["schema_version", STORE_SCHEMA_VERSION.to_string()],
        )?;
        tx.commit()
    }

    pub fn schema_version(&self) -> rusqlite::Result<i64> {
        self.conn
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get::<_, String>(0),
            )?
            .parse::<i64>()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
    }

    pub fn insert_event(&mut self, event: &TraceEvent) -> rusqlite::Result<()> {
        let payload = serde_json::to_string(event)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let object_id: Option<&str> = event.object.as_ref().map(|o| o.id.as_str());
        self.conn.execute(
            r#"INSERT OR REPLACE INTO events
                (event_id, run_id, ts_ns, pid, tid, event_type, operation, subject_id, object_id, payload_json)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)"#,
            params![
                event.event_id,
                event.run_id,
                event.ts_ns as i64,
                event.pid as i64,
                event.tid as i64,
                event.event_type.as_dotted(),
                event.operation,
                event.subject.id,
                object_id,
                payload,
            ],
        )?;
        self.inserted += 1;
        Ok(())
    }

    pub fn insert_entity(&mut self, entity: &EntityRef) -> rusqlite::Result<()> {
        let payload = serde_json::to_string(entity)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let kind = format!("{:?}", entity.kind).to_lowercase();
        self.conn.execute(
            "INSERT OR REPLACE INTO entities (entity_id, kind, name, payload_json) VALUES (?1, ?2, ?3, ?4)",
            params![entity.id, kind, entity.name, payload],
        )?;
        Ok(())
    }

    /// Insert or upsert an edge. If a row with the same
    /// `(src, dst, edge_type)` already exists, update `last_ts_ns`,
    /// `count` and append the event_id to `event_refs`.
    pub fn upsert_edge(
        &mut self,
        src: &str,
        dst: &str,
        edge_type: &str,
        ts_ns: u64,
        event_id: &str,
    ) -> rusqlite::Result<()> {
        let existing: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT count, event_refs FROM edges WHERE src=?1 AND dst=?2 AND edge_type=?3",
                params![src, dst, edge_type],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        match existing {
            Some((count, refs_json)) => {
                let mut refs: Vec<String> = serde_json::from_str(&refs_json).unwrap_or_default();
                refs.push(event_id.to_string());
                // Cap event_refs per edge to keep storage bounded.
                if refs.len() > 128 {
                    refs.drain(0..refs.len() - 128);
                }
                let refs_json = serde_json::to_string(&refs)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                self.conn.execute(
                    "UPDATE edges SET last_ts_ns=?1, count=?2, event_refs=?3
                     WHERE src=?4 AND dst=?5 AND edge_type=?6",
                    params![ts_ns as i64, count + 1, refs_json, src, dst, edge_type],
                )?;
            }
            None => {
                let refs_json = serde_json::to_string(&vec![event_id.to_string()])
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                self.conn.execute(
                    "INSERT INTO edges (src, dst, edge_type, first_ts_ns, last_ts_ns, count, event_refs)
                     VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)",
                    params![src, dst, edge_type, ts_ns as i64, ts_ns as i64, refs_json],
                )?;
            }
        }
        Ok(())
    }

    pub fn set_run_meta(&mut self, key: &str, value: &str) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO run_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_run_meta(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM run_meta WHERE key=?1",
                params![key],
                |r| r.get(0),
            )
            .ok()
    }

    pub fn count_events(&self) -> rusqlite::Result<u64> {
        self.conn.query_row("SELECT COUNT(*) FROM events", [], |r| {
            r.get::<_, i64>(0).map(|n| n as u64)
        })
    }

    pub fn count_entities(&self) -> rusqlite::Result<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM entities", [], |r| {
                r.get::<_, i64>(0).map(|n| n as u64)
            })
    }

    pub fn count_edges(&self) -> rusqlite::Result<u64> {
        self.conn.query_row("SELECT COUNT(*) FROM edges", [], |r| {
            r.get::<_, i64>(0).map(|n| n as u64)
        })
    }

    pub fn list_events(&self) -> rusqlite::Result<Vec<TraceEvent>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM events ORDER BY ts_ns")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let s = row?;
            let ev: TraceEvent = serde_json::from_str(&s)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            out.push(ev);
        }
        Ok(out)
    }

    pub fn list_events_by_type(&self, et: EventType) -> rusqlite::Result<Vec<TraceEvent>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM events WHERE event_type=?1 ORDER BY ts_ns")?;
        let rows = stmt.query_map(params![et.as_dotted()], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let s = row?;
            let ev: TraceEvent = serde_json::from_str(&s)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            out.push(ev);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------
// TraceEventWriter — append-mode NDJSON.
// ---------------------------------------------------------------------

/// Append-mode NDJSON writer for [`TraceEvent`]s. Flushes + fsyncs
/// every [`EVENT_FLUSH_EVERY`] events. Adapts the `EventWriter`
/// pattern from `src/fuzzer/llm_export.rs:128-199`.
pub struct TraceEventWriter {
    path: PathBuf,
    inner: Option<BufWriter<File>>,
    count: usize,
    since_last_flush: usize,
    bytes_written: u64,
}

impl TraceEventWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            inner: Some(BufWriter::new(file)),
            count: 0,
            since_last_flush: 0,
            bytes_written: 0,
        })
    }

    pub fn append(&mut self, event: &TraceEvent) -> io::Result<()> {
        let bw = self
            .inner
            .as_mut()
            .ok_or_else(|| io::Error::other("TraceEventWriter already finalized"))?;
        let line = serde_json::to_vec(event).map_err(io::Error::other)?;
        bw.write_all(&line)?;
        bw.write_all(b"\n")?;
        let line_bytes = line.len() as u64 + 1;
        let crossed_threshold = self.since_last_flush + 1 >= EVENT_FLUSH_EVERY;
        if crossed_threshold {
            bw.flush()?;
            bw.get_ref().sync_all()?;
        }
        self.bytes_written += line_bytes;
        self.count += 1;
        if crossed_threshold {
            self.since_last_flush = 0;
        } else {
            self.since_last_flush += 1;
        }
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

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic_trace::event::{EventResult, EventSource, EventType, HostOs};
    use tempfile::TempDir;

    fn mk_event(counter: u64, ts_ns: u64, et: EventType) -> TraceEvent {
        let mut ev = TraceEvent::new(
            &TraceEvent::format_event_id(counter),
            "blake3:run",
            ts_ns,
            HostOs::Windows,
            EventSource::Etw,
            4210,
            4214,
            et,
            "op",
            EntityRef::process(4210, "2026-05-17T11:23:04Z", Some("cmd.exe")),
        );
        ev.object = Some(EntityRef::file("C:\\tmp\\probe.txt"));
        ev.result = Some(EventResult::success());
        ev
    }

    #[test]
    fn schema_version_round_trip_after_migration() {
        let store = TraceStore::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), STORE_SCHEMA_VERSION);
    }

    #[test]
    fn insert_event_then_count_returns_one() {
        let mut store = TraceStore::open_in_memory().unwrap();
        let ev = mk_event(1, 100, EventType::FileWrite);
        store.insert_event(&ev).unwrap();
        assert_eq!(store.count_events().unwrap(), 1);
    }

    #[test]
    fn list_events_returns_inserted_in_ts_order() {
        let mut store = TraceStore::open_in_memory().unwrap();
        // Insert out of order; list should sort by ts_ns.
        store
            .insert_event(&mk_event(2, 300, EventType::FileRead))
            .unwrap();
        store
            .insert_event(&mk_event(1, 100, EventType::FileWrite))
            .unwrap();
        store
            .insert_event(&mk_event(3, 200, EventType::FileOpen))
            .unwrap();
        let events = store.list_events().unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].ts_ns, 100);
        assert_eq!(events[1].ts_ns, 200);
        assert_eq!(events[2].ts_ns, 300);
    }

    #[test]
    fn list_events_by_type_filters_correctly() {
        let mut store = TraceStore::open_in_memory().unwrap();
        store
            .insert_event(&mk_event(1, 100, EventType::FileWrite))
            .unwrap();
        store
            .insert_event(&mk_event(2, 200, EventType::FileRead))
            .unwrap();
        store
            .insert_event(&mk_event(3, 300, EventType::FileWrite))
            .unwrap();
        let writes = store.list_events_by_type(EventType::FileWrite).unwrap();
        assert_eq!(writes.len(), 2);
        assert!(writes.iter().all(|e| e.event_type == EventType::FileWrite));
    }

    #[test]
    fn upsert_edge_creates_then_increments_count_and_extends_refs() {
        let mut store = TraceStore::open_in_memory().unwrap();
        store
            .upsert_edge("proc:1@t", "file:/tmp/x", "write", 100, "evt_1")
            .unwrap();
        store
            .upsert_edge("proc:1@t", "file:/tmp/x", "write", 200, "evt_2")
            .unwrap();
        store
            .upsert_edge("proc:1@t", "file:/tmp/x", "write", 300, "evt_3")
            .unwrap();
        assert_eq!(store.count_edges().unwrap(), 1);
        let (count, refs_json): (i64, String) = store
            .conn
            .query_row(
                "SELECT count, event_refs FROM edges WHERE src='proc:1@t' AND dst='file:/tmp/x'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(count, 3);
        let refs: Vec<String> = serde_json::from_str(&refs_json).unwrap();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0], "evt_1");
        assert_eq!(refs[2], "evt_3");
    }

    #[test]
    fn run_meta_round_trip() {
        let mut store = TraceStore::open_in_memory().unwrap();
        store.set_run_meta("events_dropped", "42").unwrap();
        assert_eq!(store.get_run_meta("events_dropped").as_deref(), Some("42"));
        assert!(store.get_run_meta("missing").is_none());
    }

    #[test]
    fn store_on_disk_creates_parent_directory() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("nested").join("trace.sqlite");
        let _store = TraceStore::open(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn writer_round_trip_via_ndjson_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.ndjson");
        let mut w = TraceEventWriter::create(&path).unwrap();
        for i in 0..5 {
            w.append(&mk_event(i + 1, 100 * (i + 1), EventType::FileWrite))
                .unwrap();
        }
        let bytes = w.finalize().unwrap();
        assert!(bytes > 0);
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 5);
        // Each line parses back to a TraceEvent with dotted event_type.
        for line in lines {
            let ev: TraceEvent = serde_json::from_str(line).unwrap();
            assert_eq!(ev.event_type, EventType::FileWrite);
        }
    }

    #[test]
    fn writer_fsyncs_every_flush_threshold() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.ndjson");
        let mut w = TraceEventWriter::create(&path).unwrap();
        // Append exactly EVENT_FLUSH_EVERY events.
        for i in 0..EVENT_FLUSH_EVERY {
            w.append(&mk_event(
                (i + 1) as u64,
                100 * (i + 1) as u64,
                EventType::FileRead,
            ))
            .unwrap();
        }
        // After flush threshold, file on disk should contain all events.
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), EVENT_FLUSH_EVERY);
        w.finalize().unwrap();
    }

    #[test]
    fn writer_append_after_finalize_errors() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("events.ndjson");
        let mut w = TraceEventWriter::create(&path).unwrap();
        w.append(&mk_event(1, 100, EventType::FileWrite)).unwrap();
        let mut w_finalized = w;
        // Manually take the inner so finalize is simulated without
        // consuming `w` for the assert below.
        let _ = w_finalized.inner.take();
        let result = w_finalized.append(&mk_event(2, 200, EventType::FileWrite));
        assert!(result.is_err());
    }
}
