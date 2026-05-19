//! Temp-write-then-rename file writer — feature-neutral.
//!
//! Originally landed in `src/fuzzer/atomic_write.rs`. Relocated here
//! in Step 2 of the dynamic-trace plan (Codex finding 1 fix) so the
//! `dynamic-trace` feature can reuse this discipline without enabling
//! the `fuzzer` feature stack. The fuzzer module re-exports
//! [`AtomicWriter`] and [`write_atomic`] for unchanged call sites.
//!
//! Discipline:
//! 1. `AtomicWriter::create(target)` opens `<target>.tmp` for writing.
//! 2. The caller streams bytes into it via the `Write` impl.
//! 3. `AtomicWriter::finalize()` flushes, `sync_all()`s, and renames
//!    `<target>.tmp` → `<target>`. The rename is atomic on POSIX and
//!    on Windows same-volume (via `MoveFileExW` with
//!    `MOVEFILE_REPLACE_EXISTING`).
//! 4. If the writer is dropped WITHOUT `finalize()` (process killed,
//!    panic, etc.), the `.tmp` file stays on disk so an orphan-recovery
//!    sweep can detect it.

#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

/// One-shot atomic file write. Convenience wrapper around
/// [`AtomicWriter`] for the common case of "write these bytes
/// atomically to this path."
pub fn write_atomic(target: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut w = AtomicWriter::create(target)?;
    w.write_all(bytes)?;
    w.finalize()
}

/// Streaming atomic writer. Bytes go to `<target>.tmp` until
/// `finalize()` swaps it into place.
pub struct AtomicWriter {
    target: PathBuf,
    tmp: PathBuf,
    inner: Option<BufWriter<File>>,
}

impl AtomicWriter {
    /// Open `<target>.tmp` for buffered writing. Creates the parent
    /// directory if missing.
    pub fn create(target: &Path) -> io::Result<Self> {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = with_tmp_extension(target);
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        Ok(Self {
            target: target.to_path_buf(),
            tmp,
            inner: Some(BufWriter::new(file)),
        })
    }

    /// Flush, fsync, and rename `<target>.tmp` → `<target>`. Consumes
    /// `self` so a writer can only be finalized once.
    pub fn finalize(mut self) -> io::Result<()> {
        let mut bw = self
            .inner
            .take()
            .expect("inner writer present until finalize");
        bw.flush()?;
        let file = bw.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&self.tmp, &self.target)?;
        Ok(())
    }

    /// Discard the partial file. Use when the writer wants to bail
    /// out cleanly without leaving a `.tmp` artifact for orphan
    /// recovery to flag.
    pub fn abort(mut self) -> io::Result<()> {
        let _ = self.inner.take();
        match std::fs::remove_file(&self.tmp) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Path of the in-progress `.tmp` file. Useful for diagnostics.
    pub fn tmp_path(&self) -> &Path {
        &self.tmp
    }

    /// Path the writer will atomically promote to on `finalize`.
    pub fn target_path(&self) -> &Path {
        &self.target
    }
}

impl Write for AtomicWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner
            .as_mut()
            .expect("writer is open until finalize/abort")
            .write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner
            .as_mut()
            .expect("writer is open until finalize/abort")
            .flush()
    }
}

// Drop is intentionally empty (no implicit finalize, no implicit
// cleanup). A dropped-without-finalize writer leaves <target>.tmp on
// disk so orphan-recovery can detect the partial state.

fn with_tmp_extension(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn write_atomic_roundtrips_bytes() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("out.bin");
        write_atomic(&target, b"hello world").unwrap();
        let read = fs::read(&target).unwrap();
        assert_eq!(read, b"hello world");
    }

    #[test]
    fn write_atomic_replaces_existing_file() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("out.bin");
        write_atomic(&target, b"version one").unwrap();
        write_atomic(&target, b"version two").unwrap();
        let read = fs::read(&target).unwrap();
        assert_eq!(read, b"version two");
    }

    #[test]
    fn streaming_writer_finalizes_to_target() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("out.bin");
        let mut w = AtomicWriter::create(&target).unwrap();
        w.write_all(b"chunk one ").unwrap();
        w.write_all(b"chunk two").unwrap();
        w.finalize().unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"chunk one chunk two");
        // The tmp file is gone after finalize.
        assert!(!tmp.path().join("out.bin.tmp").exists());
    }

    #[test]
    fn dropped_without_finalize_leaves_tmp_artifact() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("out.bin");
        {
            let mut w = AtomicWriter::create(&target).unwrap();
            w.write_all(b"partial bytes").unwrap();
            // explicit drop — no finalize() call
        }
        // Target was NEVER promoted
        assert!(!target.exists());
        // .tmp remains so orphan recovery can see it
        assert!(
            target.with_extension("bin.tmp").exists() || tmp.path().join("out.bin.tmp").exists()
        );
    }

    #[test]
    fn abort_removes_tmp_file_cleanly() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("out.bin");
        let mut w = AtomicWriter::create(&target).unwrap();
        w.write_all(b"discarded").unwrap();
        w.abort().unwrap();
        assert!(!target.exists());
        // tmp also gone since we explicitly aborted
        assert!(!tmp.path().join("out.bin.tmp").exists());
    }

    #[test]
    fn create_makes_parent_directory() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("nested").join("deep").join("out.bin");
        write_atomic(&target, b"deep").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"deep");
    }
}
