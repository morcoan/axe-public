//! WaitForDebugEvent loop.
//!
//! Owns the per-iteration dispatch from raw `DEBUG_EVENT` ->
//! typed `DebugEventKind` -> caller-supplied handler closure ->
//! `ContinueDebugEvent` with the disposition the handler chose.
//!
//! # Thread invariant
//!
//! `run_loop` MUST be called from the same OS thread that called
//! `process_control::attach_debugger`. The Windows debug
//! subsystem associates the debugger identity with the calling
//! thread; trying to drain events from a different thread
//! returns `ERROR_ACCESS_DENIED`.
//!
//! # Initial events (informational)
//!
//! After `attach_debugger` + `ResumeThread`, the loop fires in
//! this order on a typical target:
//!
//! 1. `CreateProcess` — image base + entry of the target
//! 2. one or more `LoadDll` events — ntdll first, then KERNELBASE,
//!    KERNEL32, msvcrt, …
//! 3. an `Exception { code: EXCEPTION_BREAKPOINT }` — the loader's
//!    "initial breakpoint" at `LdrpDoDebuggerBreak`. Handler
//!    should reply `Continue`.
//! 4. user-mode execution proceeds, dispatching `Exception` events
//!    for INT3 / guard-page / hardware breakpoints set in
//!    `breakpoints.rs` + `guard_pages.rs` (Steps 10 + 14).
//!
//! The handler decides what each event means for the unpacking
//! pipeline. `run_loop` is purely the dispatch and continuation
//! plumbing.

use std::time::Duration;

use crate::unpack::UnpackError;

/// Typed projection of a Windows `DEBUG_EVENT`. Only the fields
/// Aurora actually needs are surfaced; raw OS handles are kept
/// opaque (callers route them back through `process_control`).
#[derive(Clone, Debug)]
pub enum DebugEventKind {
    CreateProcess {
        pid: u32,
        tid: u32,
        image_base: u64,
        entry_va: u64,
    },
    ExitProcess {
        pid: u32,
        exit_code: u32,
    },
    CreateThread {
        pid: u32,
        tid: u32,
        start_address: u64,
    },
    ExitThread {
        pid: u32,
        tid: u32,
        exit_code: u32,
    },
    LoadDll {
        pid: u32,
        base: u64,
    },
    UnloadDll {
        pid: u32,
        base: u64,
    },
    OutputDebugString {
        pid: u32,
        is_unicode: bool,
        length: u16,
    },
    Exception {
        pid: u32,
        tid: u32,
        code: u32,
        address: u64,
        first_chance: bool,
    },
    Rip {
        pid: u32,
        error: u32,
        rip_type: u32,
    },
}

/// Caller's reply telling `run_loop` how to continue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContinueAction {
    /// `ContinueDebugEvent` with `DBG_CONTINUE` (0x00010002).
    /// Use for OS-internal exceptions Aurora has handled.
    Continue,
    /// `ContinueDebugEvent` with `DBG_EXCEPTION_NOT_HANDLED`
    /// (0x80010001). Use for exceptions Aurora chose NOT to
    /// handle — the OS dispatches them to the target's normal
    /// exception machinery.
    NotHandled,
    /// Exit the loop after replying with `DBG_CONTINUE`. Used
    /// when Aurora has captured everything it needs (OEP
    /// reached + snapshot complete).
    Stop,
}

/// Summary statistics surfaced by `run_loop` after it returns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DebugStats {
    pub events_seen: u64,
    pub exceptions_seen: u64,
    pub dlls_loaded: u64,
    pub dlls_unloaded: u64,
    pub threads_created: u64,
    pub threads_exited: u64,
    /// True if the loop exited because the target exited (vs.
    /// the handler returning `Stop` or a timeout).
    pub target_exited: bool,
    /// `Some(code)` if `target_exited`.
    pub final_exit_code: Option<u32>,
}

/// Drain debug events from the target until the handler asks to
/// stop OR the target exits OR a single `WaitForDebugEvent` call
/// times out.
///
/// `timeout_per_event` is the per-call timeout passed to
/// `WaitForDebugEvent`. The session orchestrator's wall-clock
/// budget (Step 11) wraps this — when budget elapses, the
/// orchestrator calls `terminate()` from a different thread and
/// the next `WaitForDebugEvent` returns `ERROR_INVALID_HANDLE`,
/// which surfaces as `UnpackError::Pipeline`.
#[cfg(windows)]
pub fn run_loop<F>(timeout_per_event: Duration, mut handler: F) -> Result<DebugStats, UnpackError>
where
    F: FnMut(&DebugEventKind) -> ContinueAction,
{
    use windows::Win32::Foundation::{DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, WAIT_TIMEOUT};
    use windows::Win32::System::Diagnostics::Debug::{
        ContinueDebugEvent, WaitForDebugEvent, CREATE_PROCESS_DEBUG_EVENT,
        CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
        EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT,
        UNLOAD_DLL_DEBUG_EVENT,
    };

    let mut stats = DebugStats::default();
    let timeout_ms: u32 = timeout_per_event.as_millis().min(u32::MAX as u128) as u32;

    loop {
        let mut ev: DEBUG_EVENT = unsafe { std::mem::zeroed() };
        let wait = unsafe { WaitForDebugEvent(&mut ev, timeout_ms) };
        if let Err(e) = wait {
            // ERROR_SEM_TIMEOUT is the documented timeout return,
            // but in practice WaitForDebugEvent sets last-error
            // to WAIT_TIMEOUT on a clean per-call timeout. Surface
            // that as a soft exit rather than a Pipeline error so
            // the orchestrator can resume the loop after handling
            // a side-thread wake (Ctrl-C, budget check).
            let raw = e.code().0 as u32;
            if raw == WAIT_TIMEOUT.0 {
                return Ok(stats);
            }
            return Err(UnpackError::Pipeline(format!(
                "WaitForDebugEvent failed: {} (code 0x{:08x})",
                e, raw
            )));
        }

        stats.events_seen += 1;
        let pid = ev.dwProcessId;
        let tid = ev.dwThreadId;
        let kind = unsafe { decode_event(&ev, pid, tid) };
        match &kind {
            DebugEventKind::Exception { .. } => stats.exceptions_seen += 1,
            DebugEventKind::LoadDll { .. } => stats.dlls_loaded += 1,
            DebugEventKind::UnloadDll { .. } => stats.dlls_unloaded += 1,
            DebugEventKind::CreateThread { .. } => stats.threads_created += 1,
            DebugEventKind::ExitThread { .. } => stats.threads_exited += 1,
            DebugEventKind::ExitProcess { exit_code, .. } => {
                stats.target_exited = true;
                stats.final_exit_code = Some(*exit_code);
            }
            _ => {}
        }

        let decision = handler(&kind);
        let continue_status = match decision {
            ContinueAction::Continue | ContinueAction::Stop => DBG_CONTINUE,
            ContinueAction::NotHandled => DBG_EXCEPTION_NOT_HANDLED,
        };
        // Even on target exit we still ContinueDebugEvent — the
        // kernel needs the ack to reap the process correctly.
        let _ = ev.dwDebugEventCode;
        let _ = (
            CREATE_PROCESS_DEBUG_EVENT,
            CREATE_THREAD_DEBUG_EVENT,
            EXIT_PROCESS_DEBUG_EVENT,
            EXIT_THREAD_DEBUG_EVENT,
            LOAD_DLL_DEBUG_EVENT,
            UNLOAD_DLL_DEBUG_EVENT,
            OUTPUT_DEBUG_STRING_EVENT,
            EXCEPTION_DEBUG_EVENT,
            RIP_EVENT,
        ); // silence unused warnings on the imports
        unsafe {
            ContinueDebugEvent(pid, tid, continue_status).map_err(|e| {
                UnpackError::Pipeline(format!(
                    "ContinueDebugEvent failed: {} (pid={}, tid={})",
                    e, pid, tid
                ))
            })?;
        }

        if stats.target_exited || decision == ContinueAction::Stop {
            return Ok(stats);
        }
    }
}

#[cfg(not(windows))]
pub fn run_loop<F>(_timeout_per_event: Duration, _handler: F) -> Result<DebugStats, UnpackError>
where
    F: FnMut(&DebugEventKind) -> ContinueAction,
{
    Err(UnpackError::UnsupportedPlatform)
}

#[cfg(windows)]
unsafe fn decode_event(
    ev: &windows::Win32::System::Diagnostics::Debug::DEBUG_EVENT,
    pid: u32,
    tid: u32,
) -> DebugEventKind {
    use windows::Win32::System::Diagnostics::Debug::{
        CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
        EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
        OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, UNLOAD_DLL_DEBUG_EVENT,
    };
    match ev.dwDebugEventCode {
        CREATE_PROCESS_DEBUG_EVENT => {
            let info = ev.u.CreateProcessInfo;
            DebugEventKind::CreateProcess {
                pid,
                tid,
                image_base: info.lpBaseOfImage as u64,
                entry_va: info.lpStartAddress.map(|f| f as usize).unwrap_or(0) as u64,
            }
        }
        EXIT_PROCESS_DEBUG_EVENT => DebugEventKind::ExitProcess {
            pid,
            exit_code: ev.u.ExitProcess.dwExitCode,
        },
        CREATE_THREAD_DEBUG_EVENT => DebugEventKind::CreateThread {
            pid,
            tid,
            start_address: ev
                .u
                .CreateThread
                .lpStartAddress
                .map(|f| f as usize)
                .unwrap_or(0) as u64,
        },
        EXIT_THREAD_DEBUG_EVENT => DebugEventKind::ExitThread {
            pid,
            tid,
            exit_code: ev.u.ExitThread.dwExitCode,
        },
        LOAD_DLL_DEBUG_EVENT => DebugEventKind::LoadDll {
            pid,
            base: ev.u.LoadDll.lpBaseOfDll as u64,
        },
        UNLOAD_DLL_DEBUG_EVENT => DebugEventKind::UnloadDll {
            pid,
            base: ev.u.UnloadDll.lpBaseOfDll as u64,
        },
        OUTPUT_DEBUG_STRING_EVENT => DebugEventKind::OutputDebugString {
            pid,
            is_unicode: ev.u.DebugString.fUnicode != 0,
            length: ev.u.DebugString.nDebugStringLength,
        },
        EXCEPTION_DEBUG_EVENT => {
            let exc = ev.u.Exception;
            DebugEventKind::Exception {
                pid,
                tid,
                code: exc.ExceptionRecord.ExceptionCode.0 as u32,
                address: exc.ExceptionRecord.ExceptionAddress as u64,
                first_chance: exc.dwFirstChance != 0,
            }
        }
        RIP_EVENT => DebugEventKind::Rip {
            pid,
            error: ev.u.RipInfo.dwError,
            rip_type: ev.u.RipInfo.dwType.0 as u32,
        },
        // Any future / unrecognized event code: treat as Rip
        // with the raw code so the handler can see "something
        // unexpected fired" without us crashing the loop.
        other => DebugEventKind::Rip {
            pid,
            error: other.0,
            rip_type: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continue_action_variants_are_distinct() {
        assert_ne!(ContinueAction::Continue, ContinueAction::NotHandled);
        assert_ne!(ContinueAction::Continue, ContinueAction::Stop);
        assert_ne!(ContinueAction::NotHandled, ContinueAction::Stop);
    }

    #[test]
    fn default_stats_are_all_zero() {
        let s = DebugStats::default();
        assert_eq!(s.events_seen, 0);
        assert_eq!(s.exceptions_seen, 0);
        assert_eq!(s.dlls_loaded, 0);
        assert!(!s.target_exited);
        assert!(s.final_exit_code.is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn run_loop_on_non_windows_returns_unsupported() {
        let result = run_loop(Duration::from_millis(10), |_| ContinueAction::Stop);
        match result {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!("expected UnsupportedPlatform, got {:?}", other),
        }
    }

    #[cfg(windows)]
    #[test]
    fn run_loop_drains_to_target_exit_for_simple_hello() {
        // End-to-end smoke: spawn cmd.exe /c exit 0 with
        // CREATE_SUSPENDED, attach, resume, run the loop. The
        // handler does nothing but ack every event. The loop
        // must terminate with target_exited=true.
        use crate::unpack::process_control::{
            attach_debugger, resume_main_thread, spawn_suspended, terminate,
        };

        let cmd_exe = std::path::PathBuf::from(
            std::env::var("ComSpec").unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into()),
        );
        if !cmd_exe.exists() {
            return;
        }
        let target =
            spawn_suspended(&cmd_exe, &["/c".into(), "exit 0".into()]).expect("spawn cmd.exe");
        let pid = target.pid;
        attach_debugger(pid).expect("attach");
        resume_main_thread(&target).expect("resume");

        // Drive the loop until the target exits. Per-event timeout
        // is generous (1s) because the loader is slow on cold cmd.
        let stats =
            run_loop(Duration::from_secs(5), |_ev| ContinueAction::Continue).expect("loop ok");
        assert!(stats.target_exited, "cmd.exe must exit");
        assert_eq!(
            stats.final_exit_code,
            Some(0),
            "cmd.exe /c exit 0 must exit with code 0"
        );
        // cmd.exe loads ntdll + KERNEL32 + KERNELBASE + several
        // others; ≥3 dll loads is a safe lower bound.
        assert!(
            stats.dlls_loaded >= 3,
            "expected ≥3 LoadDll events for cmd.exe, got {}",
            stats.dlls_loaded
        );
        // At least one exception fires: the loader's initial
        // breakpoint.
        assert!(
            stats.exceptions_seen >= 1,
            "expected ≥1 exception (loader initial breakpoint)"
        );
        // Best-effort cleanup if the kernel hasn't reaped yet.
        terminate(&target);
    }

    #[cfg(windows)]
    #[test]
    fn run_loop_handler_stop_short_circuits() {
        // Spawn suspended, attach, resume, but the handler
        // returns Stop after the FIRST event. Loop must exit
        // before target_exited.
        use crate::unpack::process_control::{
            attach_debugger, resume_main_thread, spawn_suspended, terminate,
        };

        let cmd_exe = std::path::PathBuf::from(
            std::env::var("ComSpec").unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into()),
        );
        if !cmd_exe.exists() {
            return;
        }
        let target =
            spawn_suspended(&cmd_exe, &["/c".into(), "exit 0".into()]).expect("spawn cmd.exe");
        attach_debugger(target.pid).expect("attach");
        resume_main_thread(&target).expect("resume");

        let stats = run_loop(Duration::from_secs(5), |_| ContinueAction::Stop).expect("loop ok");
        assert_eq!(stats.events_seen, 1, "Stop must exit after 1 event");
        assert!(!stats.target_exited);
        // Now kill the target since the loop bailed early.
        terminate(&target);
    }
}
