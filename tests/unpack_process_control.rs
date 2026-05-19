//! Group B integration test — composes spawn + attach + event
//! loop + budget watchdog + containment on a real Windows
//! target (cmd.exe). Windows-only; skipped silently on other
//! platforms.

#![cfg(all(windows, feature = "unpack"))]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axe_core::unpack::containment::{
    spawn_budget_watchdog, suppress_wer_fault, update_kill_switch_target, Budget,
};
use axe_core::unpack::debug_loop::{run_loop, ContinueAction};
use axe_core::unpack::process_control::{
    attach_debugger, is_alive, resume_main_thread, spawn_suspended, terminate,
};

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
fn full_pipeline_spawn_attach_resume_loop_to_exit() {
    let Some(cmd) = cmd_exe() else {
        return; // CI image without cmd.exe — skip silently
    };
    suppress_wer_fault();
    let target = spawn_suspended(&cmd, &["/c".into(), "exit 0".into()]).expect("spawn");
    let pid = target.pid;
    attach_debugger(pid).expect("attach");
    resume_main_thread(&target).expect("resume");

    let stats = run_loop(Duration::from_secs(10), |_ev| ContinueAction::Continue).expect("loop");

    assert!(stats.target_exited, "cmd.exe must exit");
    assert_eq!(stats.final_exit_code, Some(0));
    assert!(stats.dlls_loaded >= 3, "expected ≥3 DLL loads");
    assert!(
        stats.exceptions_seen >= 1,
        "expected loader initial breakpoint to fire"
    );
    terminate(&target); // no-op if already exited
}

#[test]
fn budget_watchdog_terminates_runaway_target() {
    // `cmd.exe /c pause` waits for a keypress; without the
    // watchdog it would hang forever. Budget = 200 ms wall-clock
    // so the watchdog kills it quickly.
    let Some(cmd) = cmd_exe() else {
        return;
    };
    suppress_wer_fault();
    let target = spawn_suspended(&cmd, &["/c".into(), "pause >nul".into()]).expect("spawn");
    let pid = target.pid;
    attach_debugger(pid).expect("attach");
    resume_main_thread(&target).expect("resume");

    let budget = Arc::new(Budget::new(Duration::from_millis(200), 100_000_000));
    // Take a strong handle so the watchdog can read events_seen.
    let budget_for_loop = budget.clone();
    let _watchdog = spawn_budget_watchdog(budget.clone(), pid, |p| {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        unsafe {
            if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, p) {
                let _ = TerminateProcess(h, 1);
                let _ = CloseHandle(h);
            }
        }
    });

    // The loop ticks the budget on every event; the watchdog
    // wakes up every 50 ms and kills the target when the wall
    // clock expires. WaitForDebugEvent then returns
    // ERROR_SEM_TIMEOUT / WAIT_TIMEOUT (clean exit) OR
    // ERROR_INVALID_HANDLE if the kill happened mid-call.
    let _ = run_loop(Duration::from_millis(100), |_ev| {
        budget_for_loop.tick_event();
        ContinueAction::Continue
    });

    // Wait for the watchdog to land + kernel to reap.
    for _ in 0..100 {
        if !is_alive(pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("watchdog failed to terminate runaway target within 5s");
}

#[test]
fn handler_stop_short_circuits_loop_before_target_exits() {
    let Some(cmd) = cmd_exe() else {
        return;
    };
    suppress_wer_fault();
    let target = spawn_suspended(&cmd, &["/c".into(), "exit 0".into()]).expect("spawn");
    attach_debugger(target.pid).expect("attach");
    resume_main_thread(&target).expect("resume");

    let stats = run_loop(Duration::from_secs(5), |_ev| ContinueAction::Stop).expect("loop");

    assert_eq!(stats.events_seen, 1, "Stop returns after 1 event");
    assert!(!stats.target_exited, "loop exited before target");
    terminate(&target);
}

#[test]
fn invalid_input_path_surfaces_input_not_found() {
    let result = spawn_suspended(std::path::Path::new("C:\\definitely\\not\\here.exe"), &[]);
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        format!("{}", err).contains("input binary not found"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn budget_update_kill_switch_target_does_not_panic() {
    // Just confirms the cross-thread kill-switch update API is
    // safe to call from a test thread (no actual Ctrl-C fired).
    update_kill_switch_target(std::process::id());
    update_kill_switch_target(0);
}
