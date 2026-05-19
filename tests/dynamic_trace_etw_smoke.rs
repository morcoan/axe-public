//! Windows ETW end-to-end smoke test.
//!
//! Requires:
//! - Windows
//! - `--features dynamic-trace-etw`
//! - An ADMINISTRATOR shell (kernel ETW providers need elevation)
//!
//! Invocation:
//! ```
//! cargo test --features dynamic-trace-etw -- --ignored \
//!     dynamic_trace_etw_smoke --test-threads=1
//! ```
//!
//! `--test-threads=1` is required because each test starts/stops a
//! private ETW session, and two parallel tests would either collide
//! on session names or oversubscribe the system-logger slot budget.

#![cfg(all(windows, feature = "dynamic-trace-etw"))]

use std::path::PathBuf;
use std::time::Duration;

use axe_core::dynamic_trace::dyn_run_status::read_dynamic_trace_run_status;
use axe_core::dynamic_trace::privilege::is_elevated;
use axe_core::dynamic_trace::{
    run_dynamic_trace_session, DynamicTraceOptions, LossPolicy, ProviderKind, TargetSpec,
};
use tempfile::TempDir;

fn require_elevated() {
    assert!(
        is_elevated(),
        "dynamic_trace_etw_smoke MUST run elevated. \
         Open an Administrator shell and re-run: \
         cargo test --features dynamic-trace-etw -- --ignored --test-threads=1"
    );
}

#[test]
#[ignore = "requires Administrator + Windows + ferrisetw runtime verification"]
fn etw_session_captures_file_write_from_cmd_exe_probe() {
    require_elevated();

    let tmp = TempDir::new().unwrap();
    let probe_file = tmp.path().join("axe-etw-probe.txt");
    let probe_str = probe_file.to_string_lossy().to_string();

    let out = tmp.path().join("dynamic_trace");
    std::fs::create_dir_all(&out).unwrap();

    // Spawn cmd.exe to write a few bytes to the probe file. Using
    // `cmd.exe /c` is portable across Windows versions and produces a
    // deterministic single-file file.write event.
    let opts = DynamicTraceOptions {
        out_dir: out.clone(),
        duration: Some(Duration::from_secs(3)),
        target: TargetSpec::Spawn {
            exe: PathBuf::from("cmd.exe"),
            args: vec!["/c".into(), format!("echo hi > \"{probe_str}\"")],
        },
        providers: ProviderKind::v1_default_bundle(),
        loss_policy: LossPolicy::Partial,
        seed: 0,
    };

    let report =
        run_dynamic_trace_session(&opts).expect("session should complete cleanly under admin");

    // The probe file must exist (cmd.exe ran).
    assert!(
        probe_file.exists(),
        "expected probe file at {} after session",
        probe_file.display()
    );

    // Run status must show Complete with zero drops on a trivial probe.
    let parsed = read_dynamic_trace_run_status(&out.join("run_status.json"))
        .expect("ledger must be written");
    assert!(
        parsed.base.outcome == axe_core::run_status::RunOutcome::Complete
            || parsed.base.outcome == axe_core::run_status::RunOutcome::Partial,
        "outcome was {:?}",
        parsed.base.outcome
    );
    assert_eq!(parsed.run_meta.events_dropped, 0);

    // events.ndjson must exist and contain ≥1 line.
    let events_path = out.join("events.ndjson");
    assert!(events_path.exists());
    let content = std::fs::read_to_string(&events_path).unwrap();
    assert!(
        content.lines().count() >= 1,
        "expected ≥1 event in events.ndjson"
    );

    // At least one of those events should be a file.write referencing
    // our probe file.
    let probe_basename = probe_file
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let mut found = false;
    for line in content.lines() {
        if line.contains("\"file.write\"")
            && line.to_lowercase().contains(&probe_basename.to_lowercase())
        {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "expected a file.write event for {} in events.ndjson; got {} line(s)",
        probe_basename,
        content.lines().count()
    );

    println!(
        "report: emitted={} dropped={} facts={}",
        report.events_emitted, report.events_dropped, report.behavior_facts_count
    );
}

#[test]
#[ignore = "requires Administrator — non-elevated returns Failed cleanly"]
fn non_elevated_session_fails_fast_without_spawning_target() {
    // This test is intended to be RUN UNDER A NON-ELEVATED shell.
    // It verifies that capability_probe fails cleanly with no target
    // spawn. We can't enforce non-elevation from inside the test, so
    // it just documents the expected behavior.
    if is_elevated() {
        eprintln!("Skipping: run this test from a non-elevated shell to verify the failure path.");
        return;
    }

    let tmp = TempDir::new().unwrap();
    let out = tmp.path().join("dynamic_trace");
    std::fs::create_dir_all(&out).unwrap();
    let opts = DynamicTraceOptions {
        out_dir: out.clone(),
        duration: Some(Duration::from_secs(1)),
        target: TargetSpec::None,
        ..Default::default()
    };
    let result = run_dynamic_trace_session(&opts);
    assert!(
        result.is_err(),
        "non-elevated session should return Err, got {result:?}"
    );
    let parsed = read_dynamic_trace_run_status(&out.join("run_status.json"))
        .expect("ledger must be written even on capability_probe failure");
    assert_eq!(
        parsed.base.outcome,
        axe_core::run_status::RunOutcome::Failed
    );
    assert!(parsed.base.error.is_some());
}
