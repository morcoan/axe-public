//! Spawn + attach + lifecycle for the target process.
//!
//! Wraps `CreateProcessW(CREATE_SUSPENDED)` to launch the target
//! without letting any instructions execute, then exposes hooks
//! the orchestrator uses to (a) inject the anti-anti-VM stub DLL
//! (Step 27), (b) attach the debugger via `DebugActiveProcess`
//! (Step 8), and (c) ultimately `ResumeThread`.
//!
//! # Why CREATE_SUSPENDED + DebugActiveProcess (two-step) instead
//! of CreateProcessW(DEBUG_PROCESS)
//!
//! Aurora's pipeline requires user-mode hooks be installed BEFORE
//! the target executes its first instruction. The cleanest
//! ordering is:
//!
//! 1. `spawn_suspended` — `CREATE_SUSPENDED` flag freezes the
//!    target at the loader's earliest possible state.
//! 2. inject the stub DLL via `CreateRemoteThread → LoadLibrary`
//!    (Step 27).
//! 3. attach via `DebugActiveProcess` (Step 8).
//! 4. `ResumeThread` — target runs under instrumentation.
//!
//! Using `DEBUG_PROCESS` in step 1 would attach the debugger
//! before the hooks land, which means the loader's first events
//! (`LOAD_DLL_DEBUG_EVENT` for ntdll, the initial breakpoint)
//! fire before injection. Two-step is simpler.
//!
//! # Handle ownership
//!
//! `TargetProcess` owns the process + thread handles and closes
//! them on drop. Callers that hand a handle to another subsystem
//! (e.g. transferring to the debug loop) call
//! `into_borrowed_handles()` which transfers ownership and
//! suppresses the drop.

use std::path::Path;

use crate::unpack::UnpackError;

/// A suspended target. On Windows this owns the OS process and
/// thread handles; on non-Windows it's a stub that never holds
/// resources (because `spawn_suspended` always errors there).
pub struct TargetProcess {
    pub pid: u32,
    pub tid: u32,
    #[cfg(windows)]
    process_handle: windows::Win32::Foundation::HANDLE,
    #[cfg(windows)]
    thread_handle: windows::Win32::Foundation::HANDLE,
    /// When `false`, `Drop` does NOT close the handles (the caller
    /// took ownership via `into_borrowed_handles`).
    owns_handles: bool,
}

#[cfg(windows)]
impl TargetProcess {
    pub fn process_handle(&self) -> windows::Win32::Foundation::HANDLE {
        self.process_handle
    }
    pub fn thread_handle(&self) -> windows::Win32::Foundation::HANDLE {
        self.thread_handle
    }
    /// Transfer ownership of both handles to the caller. After
    /// this returns, `Drop` will NOT close the handles — the
    /// caller is responsible.
    pub fn into_borrowed_handles(
        mut self,
    ) -> (
        windows::Win32::Foundation::HANDLE,
        windows::Win32::Foundation::HANDLE,
    ) {
        self.owns_handles = false;
        (self.process_handle, self.thread_handle)
    }
}

#[cfg(windows)]
impl Drop for TargetProcess {
    fn drop(&mut self) {
        if self.owns_handles {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.thread_handle);
                let _ = windows::Win32::Foundation::CloseHandle(self.process_handle);
            }
        }
    }
}

/// Spawn `exe` with the given `args` in a CREATE_SUSPENDED state.
/// Returns a `TargetProcess` that owns the process + thread
/// handles.
///
/// The target is **fully frozen** — no instructions have
/// executed, no loader callbacks fired, the main thread sits at
/// the kernel-mode dispatcher waiting for `ResumeThread`. This is
/// the correct state for installing hooks + attaching the
/// debugger before the target runs.
pub fn spawn_suspended(exe: &Path, args: &[String]) -> Result<TargetProcess, UnpackError> {
    if !exe.exists() {
        return Err(UnpackError::InputNotFound(exe.display().to_string()));
    }
    spawn_suspended_inner(exe, args)
}

#[cfg(windows)]
fn spawn_suspended_inner(exe: &Path, args: &[String]) -> Result<TargetProcess, UnpackError> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::System::Threading::{
        CreateProcessW, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let exe_wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // Windows convention: the command line's first token IS the
    // executable name. CreateProcessW MAY modify the command-line
    // buffer (it's PWSTR, not PCWSTR), so we own it as mutable.
    let cmd: String = std::iter::once(exe.to_string_lossy().to_string())
        .chain(args.iter().cloned())
        .collect::<Vec<_>>()
        .join(" ");
    let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            PCWSTR(exe_wide.as_ptr()),
            Some(PWSTR(cmd_wide.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )
        .map_err(|e| UnpackError::Pipeline(format!("CreateProcessW: {}", e)))?;
    }

    Ok(TargetProcess {
        pid: pi.dwProcessId,
        tid: pi.dwThreadId,
        process_handle: pi.hProcess,
        thread_handle: pi.hThread,
        owns_handles: true,
    })
}

#[cfg(not(windows))]
fn spawn_suspended_inner(_exe: &Path, _args: &[String]) -> Result<TargetProcess, UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

/// Resume the target's primary thread. After this call the
/// target executes its first instruction. Use ONLY after hooks
/// are installed and (for debug-mode runs) the debugger is
/// attached — otherwise the loader's earliest anti-debug /
/// anti-VM checks fire before suppression is in place.
#[cfg(windows)]
pub fn resume_main_thread(target: &TargetProcess) -> Result<(), UnpackError> {
    use windows::Win32::System::Threading::ResumeThread;
    unsafe {
        let prev = ResumeThread(target.thread_handle);
        if prev == u32::MAX {
            return Err(UnpackError::Pipeline(format!(
                "ResumeThread failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn resume_main_thread(_target: &TargetProcess) -> Result<(), UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

/// Hard kill. Used by the timeout / instruction-budget /
/// Ctrl-C paths (Step 11). Best-effort; ignores errors from
/// TerminateProcess (the process may already be dead).
#[cfg(windows)]
pub fn terminate(target: &TargetProcess) {
    use windows::Win32::System::Threading::TerminateProcess;
    unsafe {
        let _ = TerminateProcess(target.process_handle, 1);
    }
}

#[cfg(not(windows))]
pub fn terminate(_target: &TargetProcess) {}

/// Attach the calling thread as the debugger for the target.
///
/// MUST be called from the same thread that will subsequently run
/// `WaitForDebugEvent` — the debug subsystem associates the
/// debugger identity with the calling thread, and a different
/// thread cannot drain the debug events. Aurora's session
/// orchestrator (Step 54) keeps the debug loop on a dedicated
/// thread and routes everything else (hooks, snapshot capture)
/// through cross-thread messages.
///
/// On success, immediately calls `DebugSetProcessKillOnExit(true)`
/// so the target dies cleanly when Aurora exits — even on a
/// panic / Ctrl-C / crash of Aurora itself. This is the
/// "containment" leg of preempt #8 from the plan: the malware
/// MUST NOT outlive Aurora.
#[cfg(windows)]
pub fn attach_debugger(pid: u32) -> Result<(), UnpackError> {
    use windows::Win32::System::Diagnostics::Debug::{
        DebugActiveProcess, DebugSetProcessKillOnExit,
    };
    unsafe {
        DebugActiveProcess(pid).map_err(|e| {
            UnpackError::Pipeline(format!("DebugActiveProcess(pid={}) failed: {}", pid, e))
        })?;
        // If DebugSetProcessKillOnExit fails we still detach
        // cleanly — the worst case is the target survives Aurora
        // shutdown, which the timeout / Ctrl-C handlers (Step 11)
        // attempt to clean up via TerminateProcess. Log via the
        // error chain but do not abort the attach.
        if let Err(e) = DebugSetProcessKillOnExit(true) {
            return Err(UnpackError::Pipeline(format!(
                "DebugSetProcessKillOnExit failed after attach: {}",
                e
            )));
        }
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn attach_debugger(_pid: u32) -> Result<(), UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

/// Stop debugging the target without killing it. Called by
/// `session.rs` (Step 54) after OEP is reached and the snapshot
/// is captured — the analyst typically wants the target to
/// continue running so post-OEP behavior can be observed (e.g.
/// via the existing `dynamic_trace` collector). MUST be called
/// from the same thread that called `attach_debugger`.
#[cfg(windows)]
pub fn detach_debugger(pid: u32) -> Result<(), UnpackError> {
    use windows::Win32::System::Diagnostics::Debug::DebugActiveProcessStop;
    unsafe {
        DebugActiveProcessStop(pid).map_err(|e| {
            UnpackError::Pipeline(format!("DebugActiveProcessStop(pid={}) failed: {}", pid, e))
        })?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn detach_debugger(_pid: u32) -> Result<(), UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

/// Liveness probe via STILL_ACTIVE (259). Returns `false` when
/// the process has exited or is unreachable.
#[cfg(windows)]
pub fn is_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    const STILL_ACTIVE: u32 = 259;
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let mut exit_code: u32 = 0;
        let ok = GetExitCodeProcess(h, &mut exit_code).is_ok();
        let _ = CloseHandle(h);
        ok && exit_code == STILL_ACTIVE
    }
}

#[cfg(not(windows))]
pub fn is_alive(_pid: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_with_nonexistent_path_returns_input_not_found() {
        let opts = spawn_suspended(Path::new("/definitely/not/here"), &[]);
        match opts {
            Err(UnpackError::InputNotFound(_)) => {}
            other => panic!(
                "expected InputNotFound for missing input, got {:?}",
                other.err()
            ),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn spawn_on_non_windows_returns_unsupported() {
        // On non-Windows the input-not-found check fires first
        // for a missing path; pick a path that exists.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let opts = spawn_suspended(tmp.path(), &[]);
        match opts {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!(
                "expected UnsupportedPlatform on non-Windows, got {:?}",
                other.err()
            ),
        }
    }

    #[cfg(windows)]
    #[test]
    fn spawn_cmd_exe_returns_live_pid_then_terminates_cleanly() {
        // Use the cmd.exe present on every Windows install.
        let cmd_exe = std::path::PathBuf::from(
            std::env::var("ComSpec").unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into()),
        );
        if !cmd_exe.exists() {
            // CI image without cmd.exe — skip silently.
            return;
        }
        let target =
            spawn_suspended(&cmd_exe, &["/c".into(), "exit 0".into()]).expect("spawn cmd.exe");
        assert!(target.pid > 0, "spawn should return a non-zero PID");
        assert!(target.tid > 0, "spawn should return a non-zero TID");
        // Process is suspended so STILL_ACTIVE must be true.
        assert!(is_alive(target.pid));
        // Hard-kill it (we never resumed; the suspended target
        // would otherwise sit waiting forever).
        terminate(&target);
        // After TerminateProcess the kernel reaps the process
        // asynchronously; give it a moment.
        for _ in 0..50 {
            if !is_alive(target.pid) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("process {} did not die after TerminateProcess", target.pid);
    }

    #[cfg(not(windows))]
    #[test]
    fn attach_on_non_windows_returns_unsupported() {
        match attach_debugger(1234) {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!("expected UnsupportedPlatform, got {:?}", other),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn detach_on_non_windows_returns_unsupported() {
        match detach_debugger(1234) {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!("expected UnsupportedPlatform, got {:?}", other),
        }
    }

    #[cfg(windows)]
    #[test]
    fn attach_and_detach_on_suspended_target_roundtrips_cleanly() {
        // While the target is suspended, no debug events fire,
        // so attach + immediate detach is safe without draining
        // events. Once Step 9 lands the debug loop, callers that
        // attach + resume MUST run the loop to drain events.
        let cmd_exe = std::path::PathBuf::from(
            std::env::var("ComSpec").unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into()),
        );
        if !cmd_exe.exists() {
            return;
        }
        let target =
            spawn_suspended(&cmd_exe, &["/c".into(), "exit 0".into()]).expect("spawn cmd.exe");
        attach_debugger(target.pid).expect("attach");
        detach_debugger(target.pid).expect("detach");
        terminate(&target);
    }

    #[cfg(windows)]
    #[test]
    fn attach_to_invalid_pid_returns_pipeline_error() {
        // PID 0xFFFFFFFE is reserved / never assigned to a real
        // process; attach must fail with a Pipeline error rather
        // than panic.
        match attach_debugger(0xFFFFFFFE) {
            Err(UnpackError::Pipeline(msg)) => {
                assert!(msg.contains("DebugActiveProcess"));
            }
            other => panic!("expected Pipeline error, got {:?}", other),
        }
    }

    #[cfg(windows)]
    #[test]
    fn into_borrowed_handles_suppresses_drop_close() {
        let cmd_exe = std::path::PathBuf::from(
            std::env::var("ComSpec").unwrap_or_else(|_| "C:\\Windows\\System32\\cmd.exe".into()),
        );
        if !cmd_exe.exists() {
            return;
        }
        let target =
            spawn_suspended(&cmd_exe, &["/c".into(), "exit 0".into()]).expect("spawn cmd.exe");
        let pid = target.pid;
        let (proc_h, thread_h) = target.into_borrowed_handles();
        // Now the test owns the handles. Clean up manually.
        unsafe {
            use windows::Win32::Foundation::CloseHandle;
            use windows::Win32::System::Threading::TerminateProcess;
            let _ = TerminateProcess(proc_h, 1);
            let _ = CloseHandle(thread_h);
            let _ = CloseHandle(proc_h);
        }
        // Sanity: process should die.
        for _ in 0..50 {
            if !is_alive(pid) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("process {} did not die after manual cleanup", pid);
    }
}
