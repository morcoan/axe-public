//! Pre-execute input persistence — Codex finding 2 mitigation.
//!
//! Every candidate input is fsync'd to `queue/.staging/<id>` BEFORE
//! the executor runs it. If the harness crashes (taking the parent
//! process with it under `InProcessExecutor`), the staged file is
//! still on disk; the next session's
//! [`recover_orphans`](InputStaging::recover_orphans) finds it and
//! replays under [`EmulatorExecutor`] (which cannot itself crash),
//! recovering the lost finding.
//!
//! The staging directory uses a leading `.` so it doesn't collide
//! with the main `queue/<id>` corpus listing.

#![allow(dead_code)]

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const STAGING_SUBDIR: &str = ".staging";

/// File-backed pre-execute staging area.
pub struct InputStaging {
    staging_dir: PathBuf,
}

impl InputStaging {
    /// Open a staging area rooted at `queue_dir/.staging/`. Creates
    /// the directory if missing.
    pub fn open(queue_dir: &Path) -> io::Result<Self> {
        let staging_dir = queue_dir.join(STAGING_SUBDIR);
        fs::create_dir_all(&staging_dir)?;
        Ok(Self { staging_dir })
    }

    /// Persist `bytes` for input `id` and fsync. Returns the path of
    /// the staged file. Caller MUST invoke either [`promote`] or
    /// [`discard`] after the execution finishes; otherwise the file
    /// is left behind for orphan recovery.
    ///
    /// [`promote`]: Self::promote
    /// [`discard`]: Self::discard
    pub fn stage(&self, id: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let path = self.staging_dir.join(id);
        let mut file = File::create(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(path)
    }

    /// Move a staged input to its final corpus location. Atomic on
    /// same-volume rename.
    pub fn promote(&self, id: &str, dest: &Path) -> io::Result<()> {
        let src = self.staging_dir.join(id);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&src, dest)
    }

    /// Remove a staged input — the execution finished cleanly and the
    /// caller decided not to promote (e.g., not interesting).
    pub fn discard(&self, id: &str) -> io::Result<()> {
        let path = self.staging_dir.join(id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Scan the staging directory for any files left behind by a
    /// previous (crashed) session. Returns `(id, bytes)` pairs.
    /// Files are not removed by this call — the caller decides whether
    /// to replay each one and then `discard` it, or `promote` it.
    pub fn recover_orphans(&self) -> io::Result<Vec<(String, Vec<u8>)>> {
        let mut out = Vec::new();
        let read_dir = match fs::read_dir(&self.staging_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let id = match path.file_name().and_then(|n| n.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let mut buf = Vec::new();
            File::open(&path)?.read_to_end(&mut buf)?;
            out.push((id, buf));
        }
        Ok(out)
    }

    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn stage_then_promote_moves_file_to_dest() {
        let tmp = TempDir::new().unwrap();
        let queue = tmp.path().join("queue");
        let staging = InputStaging::open(&queue).unwrap();

        let id = "blake3-abc123";
        let staged = staging.stage(id, b"input bytes").unwrap();
        assert!(staged.exists());

        let dest = queue.join(id);
        staging.promote(id, &dest).unwrap();
        assert!(dest.exists());
        assert!(!staged.exists(), "staging file moved, not copied");
        assert_eq!(fs::read(&dest).unwrap(), b"input bytes");
    }

    #[test]
    fn stage_then_discard_removes_file() {
        let tmp = TempDir::new().unwrap();
        let staging = InputStaging::open(tmp.path()).unwrap();
        staging.stage("id1", b"abc").unwrap();
        staging.discard("id1").unwrap();
        assert!(!staging.staging_dir().join("id1").exists());
    }

    #[test]
    fn discard_is_idempotent_on_missing_files() {
        let tmp = TempDir::new().unwrap();
        let staging = InputStaging::open(tmp.path()).unwrap();
        // Discarding a never-staged id must succeed.
        staging.discard("never_existed").unwrap();
    }

    #[test]
    fn recover_orphans_returns_left_behind_files() {
        let tmp = TempDir::new().unwrap();
        let staging = InputStaging::open(tmp.path()).unwrap();
        staging.stage("id1", b"orphan one").unwrap();
        staging.stage("id2", b"orphan two").unwrap();
        // Simulate a parent crash: drop without promoting or discarding.

        let recovered = staging.recover_orphans().unwrap();
        assert_eq!(recovered.len(), 2);
        let map: std::collections::HashMap<_, _> = recovered.into_iter().collect();
        assert_eq!(map.get("id1").unwrap(), b"orphan one");
        assert_eq!(map.get("id2").unwrap(), b"orphan two");
    }

    #[test]
    fn recover_orphans_handles_missing_staging_dir() {
        let tmp = TempDir::new().unwrap();
        // Open but then delete the staging dir to simulate fresh start.
        let staging = InputStaging::open(tmp.path()).unwrap();
        fs::remove_dir_all(staging.staging_dir()).unwrap();
        let recovered = staging.recover_orphans().unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn promote_creates_destination_parent_directory() {
        let tmp = TempDir::new().unwrap();
        let queue = tmp.path().join("queue");
        let staging = InputStaging::open(&queue).unwrap();
        staging.stage("id1", b"data").unwrap();
        let dest = queue.join("nested").join("deeper").join("id1");
        staging.promote("id1", &dest).unwrap();
        assert!(dest.exists());
    }
}
