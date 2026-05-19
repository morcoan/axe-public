//! Crash containment — wall-clock budget, event-count budget,
//! Ctrl-C kill-switch, and WerFault popup suppression.
//!
//! Per preempt #8 of the plan, every Aurora run is bounded so a
//! hung target cannot run forever:
//!
//! - `Budget` tracks elapsed wall-clock + observed event count
//!   and answers `is_expired()` in the debug loop.
//! - `install_ctrl_c_kill_switch(pid)` registers a process-wide
//!   `SetConsoleCtrlHandler` that calls `TerminateProcess(pid)`
//!   on Ctrl-C so the analyst can hard-stop a misbehaving target.
//! - `suppress_wer_fault()` sets process error mode so the
//!   target's unhandled exceptions don't pop a WerFault dialog
//!   that blocks the CI pipeline.
//!
//! # Instruction-count budget is approximate
//!
//! A true per-instruction count requires Intel PT or
//! single-stepping (Trap Flag) the entire run, neither of which
//! is acceptable for normal use. Aurora uses **observed debug
//! event count** as a proxy: a chatty target generates many
//! events, and `Budget::tick_event()` from the debug loop
//! enforces a coarse cap. The default budget is generous
//! (`100M` notional instructions); the cap mostly catches
//! pathological "spin in a tight loop generating syscalls"
//! cases.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::unpack::UnpackError;

/// Run-wide budget. Shared across threads via `Arc<Budget>`.
pub struct Budget {
    started: Instant,
    wall_clock: Duration,
    /// Each `tick_event()` adds `1` to events_seen. The notional
    /// per-event-to-instruction conversion is `~1000` — i.e. a
    /// budget of `100M instructions` corresponds to ≈100k debug
    /// events, which is roughly what a normal unpacking session
    /// produces.
    events_seen: AtomicU64,
    event_cap: u64,
}

impl Budget {
    pub fn new(wall_clock: Duration, notional_instr_budget: u64) -> Self {
        // ~1000 instructions per debug event is a generous fit
        // for crimeware-grade unpacking. Round up so a budget
        // below 1k still gives at least 1 event.
        let event_cap = (notional_instr_budget / 1000).max(1);
        Self {
            started: Instant::now(),
            wall_clock,
            events_seen: AtomicU64::new(0),
            event_cap,
        }
    }

    pub fn tick_event(&self) {
        self.events_seen.fetch_add(1, Ordering::Relaxed);
    }

    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    pub fn events_seen(&self) -> u64 {
        self.events_seen.load(Ordering::Relaxed)
    }

    pub fn is_wall_clock_expired(&self) -> bool {
        self.elapsed() >= self.wall_clock
    }

    pub fn is_event_cap_hit(&self) -> bool {
        self.events_seen() >= self.event_cap
    }

    pub fn is_expired(&self) -> bool {
        self.is_wall_clock_expired() || self.is_event_cap_hit()
    }
}

// -------------------------------------------------------------
// Ctrl-C kill-switch
// -------------------------------------------------------------

/// Once installed, a Ctrl-C in Aurora's console terminates the
/// PID stored here. `0` means "no target registered yet".
static KILL_SWITCH_PID: AtomicU32 = AtomicU32::new(0);
/// Tracks whether the handler is installed so installing twice
/// does not register two handlers.
static KILL_SWITCH_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Arm the Ctrl-C kill-switch on `target_pid`. Returns `Ok(())`
/// once the handler is registered (or was already registered);
/// the kill-switch persists for the rest of Aurora's lifetime.
///
/// Uses the `ctrlc` crate (already an axe-core dependency) to
/// avoid the windows-rs `PHANDLER_ROUTINE` Option-of-Option
/// signature dance.
pub fn install_ctrl_c_kill_switch(target_pid: u32) -> Result<(), UnpackError> {
    KILL_SWITCH_PID.store(target_pid, Ordering::Relaxed);
    if KILL_SWITCH_INSTALLED.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    ctrlc::set_handler(move || {
        let pid = KILL_SWITCH_PID.load(Ordering::Relaxed);
        if pid != 0 {
            terminate_pid(pid);
        }
        std::process::exit(130); // 128 + SIGINT(2)
    })
    .map_err(|e| UnpackError::Pipeline(format!("ctrlc::set_handler failed: {}", e)))?;
    Ok(())
}

#[cfg(windows)]
fn terminate_pid(pid: u32) {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    unsafe {
        if let Ok(h) = OpenProcess(PROCESS_TERMINATE, false, pid) {
            let _ = TerminateProcess(h, 1);
            let _ = CloseHandle(h);
        }
    }
}

#[cfg(not(windows))]
fn terminate_pid(_pid: u32) {}

/// Update the kill-switch's target — useful when a new unpack
/// session begins in the same Aurora process. No-op if the
/// handler was never installed.
pub fn update_kill_switch_target(target_pid: u32) {
    KILL_SWITCH_PID.store(target_pid, Ordering::Relaxed);
}

/// Disarm the kill-switch by setting the target to 0. The
/// console handler stays registered (Windows doesn't always
/// give us a clean uninstall path) but it no-ops when target is 0.
pub fn disarm_kill_switch() {
    KILL_SWITCH_PID.store(0, Ordering::Relaxed);
}

// -------------------------------------------------------------
// WerFault suppression
// -------------------------------------------------------------

/// Suppress WerFault popups + general critical-error dialogs
/// for the current process AND, importantly, propagate the
/// setting to child processes (the target). Without this an
/// unhandled access violation in the target opens an
/// interactive dialog that blocks CI.
#[cfg(windows)]
pub fn suppress_wer_fault() {
    use windows::Win32::System::Diagnostics::Debug::{
        SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
    };
    unsafe {
        let _ =
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }
}

#[cfg(not(windows))]
pub fn suppress_wer_fault() {}

// -------------------------------------------------------------
// Convenience: share a Budget across the debug loop + watchdog
// -------------------------------------------------------------

/// Spawn a watchdog thread that calls `terminate_fn(pid)` when
/// the budget expires. The watchdog wakes every ~50 ms; tight
/// enough for analyst-grade responsiveness without burning CPU.
pub fn spawn_budget_watchdog<F>(
    budget: Arc<Budget>,
    target_pid: u32,
    mut terminate_fn: F,
) -> std::thread::JoinHandle<()>
where
    F: FnMut(u32) + Send + 'static,
{
    std::thread::spawn(move || loop {
        if budget.is_expired() {
            terminate_fn(target_pid);
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_starts_unexpired_for_generous_caps() {
        let b = Budget::new(Duration::from_secs(60), 100_000_000);
        assert!(!b.is_expired());
        assert_eq!(b.events_seen(), 0);
        assert!(b.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn budget_event_cap_fires_after_enough_ticks() {
        let b = Budget::new(Duration::from_secs(60), 5_000); // 5 events cap
        for _ in 0..4 {
            b.tick_event();
        }
        assert!(!b.is_event_cap_hit());
        b.tick_event();
        assert!(b.is_event_cap_hit());
        assert!(b.is_expired());
    }

    #[test]
    fn budget_wall_clock_fires_after_elapsed() {
        let b = Budget::new(Duration::from_millis(10), 100_000_000);
        assert!(!b.is_wall_clock_expired());
        std::thread::sleep(Duration::from_millis(30));
        assert!(b.is_wall_clock_expired());
        assert!(b.is_expired());
    }

    #[test]
    fn budget_minimum_event_cap_is_one() {
        // 999 notional instructions / 1000 = 0; we clamp to 1.
        let b = Budget::new(Duration::from_secs(60), 999);
        b.tick_event();
        assert!(b.is_event_cap_hit());
    }

    #[test]
    fn budget_is_send_sync() {
        // The whole point: shared across the debug loop thread
        // and the watchdog thread. Won't compile if not.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Budget>();
    }

    #[test]
    fn kill_switch_target_update_does_not_panic_without_install() {
        update_kill_switch_target(1234);
        disarm_kill_switch();
        // Just verifying these are no-ops without the handler.
    }

    // ctrlc handler can only be installed ONCE per process. The
    // install_kill_switch_then_disarm test below covers the
    // happy path; we don't add a separate "install twice fails"
    // test because ctrlc's swap-on-second-install behavior is
    // implementation-defined.

    #[cfg(windows)]
    #[test]
    fn suppress_wer_fault_does_not_panic() {
        // No way to observe SetErrorMode without WaitForSingleObject
        // on a child process, which is out of scope here. Just
        // confirm the FFI call is safe.
        suppress_wer_fault();
    }

    #[test]
    fn install_kill_switch_then_disarm_does_not_terminate_target() {
        // ctrlc only allows ONE handler install per process and
        // tests run in parallel, so we can race with other test
        // threads — install may fail, may have already happened,
        // and KILL_SWITCH_PID may be touched by other tests. We
        // verify only the *update + disarm path*, not the install
        // race.
        let pid = std::process::id();
        let _ = install_ctrl_c_kill_switch(pid);
        update_kill_switch_target(pid);
        assert_eq!(KILL_SWITCH_PID.load(Ordering::Relaxed), pid);
        disarm_kill_switch();
        assert_eq!(KILL_SWITCH_PID.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn watchdog_terminates_when_wall_clock_expires() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let budget = Arc::new(Budget::new(Duration::from_millis(50), 100_000_000));
        let observed = Arc::new(AtomicU32::new(0));
        let observed2 = observed.clone();
        let handle = spawn_budget_watchdog(budget.clone(), 4242, move |pid| {
            observed2.store(pid, Ordering::Relaxed);
        });
        handle.join().expect("watchdog");
        assert_eq!(observed.load(Ordering::Relaxed), 4242);
    }

    #[test]
    fn watchdog_terminates_when_event_cap_hit() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let budget = Arc::new(Budget::new(Duration::from_secs(60), 5_000));
        let observed = Arc::new(AtomicU32::new(0));
        let observed2 = observed.clone();
        // Fire enough ticks BEFORE spawning so the watchdog sees
        // the cap on its first wake.
        for _ in 0..10 {
            budget.tick_event();
        }
        let handle = spawn_budget_watchdog(budget, 7777, move |pid| {
            observed2.store(pid, Ordering::Relaxed);
        });
        handle.join().expect("watchdog");
        assert_eq!(observed.load(Ordering::Relaxed), 7777);
    }
}
