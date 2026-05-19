//! Step 59 — end-to-end Aurora smoke.
//!
//! Drives `run_session` against a real Windows target (`cmd.exe`)
//! with a short budget so the run actually completes. Verifies
//! the on-disk artifact set + that `PEImage::from_snapshot` can
//! re-consume the snapshot.

#![cfg(all(windows, feature = "unpack"))]

use std::path::PathBuf;
use std::time::Duration;

use axe_core::unpack::session::run_session;
use axe_core::unpack::{UnpackMode, UnpackOptions, UnpackOutcome};
use axe_core::PEImage;

fn cmd_exe() -> Option<PathBuf> {
    let p = PathBuf::from(
        std::env::var("ComSpec").unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into()),
    );
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

#[test]
fn run_session_against_cmd_exe_emits_snapshot_and_round_trips() {
    let Some(cmd) = cmd_exe() else {
        return;
    };
    let tmp = tempfile::TempDir::new().unwrap();
    let opts = UnpackOptions {
        mode: UnpackMode::On,
        out_dir: tmp.path().to_path_buf(),
        timeout_secs: 5,
        instr_budget: 10_000_000,
        ..UnpackOptions::default()
    };
    let report = run_session(&cmd, &opts).expect("run_session");
    assert!(matches!(
        report.outcome,
        UnpackOutcome::Complete | UnpackOutcome::Partial
    ));
    let manifest_path = tmp.path().join("unpack_provenance.json");
    assert!(manifest_path.exists(), "manifest must be emitted");
    assert!(
        tmp.path().join("run_status.json").exists(),
        "ledger must be emitted"
    );
    assert!(report.regions_dumped >= 1);

    // Re-consume via PEImage::from_snapshot
    let image = PEImage::from_snapshot(&manifest_path).expect("re-consume snapshot");
    assert!(!image.sections.is_empty());
    let _ = Duration::from_secs(1);
}

#[test]
fn run_session_off_mode_is_noop_skipped() {
    let tmp = tempfile::TempDir::new().unwrap();
    let opts = UnpackOptions {
        mode: UnpackMode::Off,
        out_dir: tmp.path().to_path_buf(),
        ..UnpackOptions::default()
    };
    let report =
        run_session(std::path::Path::new("/anything"), &opts).expect("Off mode never errors");
    assert_eq!(report.outcome, UnpackOutcome::Skipped);
    assert!(!tmp.path().join("unpack_provenance.json").exists());
    assert!(!tmp.path().join("run_status.json").exists());
}
