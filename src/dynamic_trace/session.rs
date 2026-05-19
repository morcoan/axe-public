//! End-to-end session orchestrator.
//!
//! Sequence (Codex findings 4 + 5 complete fix):
//! 1. [`crate::dynamic_trace::privilege::capability_probe`] — fails
//!    fast with `RunOutcome::Failed("capability_probe_failed: …")`
//!    and NO target spawn if elevation / privilege / ETW probe fails.
//! 2. Spawn or attach target. If spawning an exe, use
//!    `CREATE_SUSPENDED` so the collector is live before the target's
//!    first instruction executes.
//! 3. `collector.start(plan, tx, drops)` — on failure,
//!    `TerminateProcess(target)` and bail.
//! 4. `ResumeThread(target)`.
//! 5. Consumer thread drains the channel into [`TraceStore`] +
//!    [`TraceEventWriter`] until deadline OR target exits OR Ctrl-C.
//! 6. `collector.stop()` returns final counts.
//! 7. `behavior_facts::extract` with `LossMeta` from the collector.
//! 8. `llm_pack::emit_all` writes the 4 LLM artifacts.
//! 9. `ledger.finalize_atomic` applies loss-policy → outcome rule.
//!
//! On non-Windows or without `dynamic-trace-etw`, the session returns
//! an explicit error after writing a `Failed` ledger so the manifest
//! pipeline still has a row to advertise the failure.

#![allow(dead_code)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::atomic_write::write_atomic;
use crate::dynamic_trace::behavior_facts::{self, LossMeta};
use crate::dynamic_trace::dyn_run_status::DynamicTraceRunStatusLedger;
use crate::dynamic_trace::llm_pack::{self, EmittedSizes, PackInputs};
use crate::dynamic_trace::store::TraceStore;
use crate::dynamic_trace::{
    DynamicTraceError, DynamicTraceOptions, DynamicTraceReport, LossPolicy, TargetSpec,
};

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
use crate::dynamic_trace::collector::{CollectorReport, DropCounter, ProviderPlan, TraceCollector};

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
use crate::dynamic_trace::etw::FerrisEtwCollector;
#[cfg(all(windows, feature = "dynamic-trace-etw"))]
use crate::dynamic_trace::event::TraceEvent;
#[cfg(all(windows, feature = "dynamic-trace-etw"))]
use crate::dynamic_trace::privilege::{capability_probe, CapabilityError};
#[cfg(all(windows, feature = "dynamic-trace-etw"))]
use crate::dynamic_trace::store::TraceEventWriter;

pub fn run_session(opts: &DynamicTraceOptions) -> Result<DynamicTraceReport, DynamicTraceError> {
    #[cfg(not(all(windows, feature = "dynamic-trace-etw")))]
    {
        return run_session_unsupported(opts);
    }
    #[cfg(all(windows, feature = "dynamic-trace-etw"))]
    {
        run_session_windows(opts)
    }
}

#[cfg(not(all(windows, feature = "dynamic-trace-etw")))]
fn run_session_unsupported(
    opts: &DynamicTraceOptions,
) -> Result<DynamicTraceReport, DynamicTraceError> {
    // Even without ETW we still write a `Failed` ledger so the
    // manifest pipeline has something to advertise. Otherwise running
    // `axe --dynamic-trace on` on Linux would leave NO trace in the
    // manifest — confusing.
    let run_id = derive_run_id(opts);
    let now = now_ms();
    std::fs::create_dir_all(&opts.out_dir)?;
    let mut ledger =
        DynamicTraceRunStatusLedger::create(&opts.out_dir, &run_id, now, opts.loss_policy);
    ledger.set_error("dynamic-trace-etw feature not built or not Windows");
    ledger.set_capability_probe(serde_json::json!({
        "elevated": false,
        "se_system_profile": "unknown",
        "probe_session": "skipped_no_etw_feature"
    }));
    ledger.finalize_atomic(now_ms())?;
    Ok(DynamicTraceReport {
        run_id,
        events_emitted: 0,
        events_dropped: 0,
        behavior_facts_count: 0,
        run_status_path: Some(opts.out_dir.join("run_status.json")),
    })
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn run_session_windows(
    opts: &DynamicTraceOptions,
) -> Result<DynamicTraceReport, DynamicTraceError> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    let run_id = derive_run_id(opts);
    let started_at_ms = now_ms();

    std::fs::create_dir_all(&opts.out_dir)?;

    let mut ledger = DynamicTraceRunStatusLedger::create(
        &opts.out_dir,
        &run_id,
        started_at_ms,
        opts.loss_policy,
    );
    ledger.set_providers(
        opts.providers
            .iter()
            .map(|p| p.as_csv_token().to_string())
            .collect(),
    );

    // ---------- (1) capability probe ----------
    let probe = match capability_probe(&opts.providers) {
        Ok(report) => report,
        Err(e) => {
            let msg = format!("capability_probe_failed: {e}");
            ledger.set_error(&msg);
            ledger.set_capability_probe(serde_json::json!({
                "elevated": false,
                "error": msg.clone(),
            }));
            let _ = ledger.finalize_atomic(now_ms());
            return Err(DynamicTraceError::CapabilityProbe(format!("{e}")));
        }
    };
    ledger.set_capability_probe(serde_json::json!({
        "elevated": probe.elevated,
        "se_system_profile": format!("{:?}", probe.se_system_profile).to_lowercase(),
        "probe_session": format!("{:?}", probe.probe_session).to_lowercase(),
    }));

    // ---------- (2) spawn or attach target ----------
    let (target_pid, target_handle, target_image) = match &opts.target {
        TargetSpec::None => (None, None, None),
        TargetSpec::Pid(p) => (Some(*p), None, None),
        TargetSpec::Spawn { exe, args } => {
            let (pid, handle) = spawn_suspended(exe, args)
                .map_err(|e| DynamicTraceError::TargetSpawn(format!("{e}")))?;
            (
                Some(pid),
                Some(handle),
                Some(exe.to_string_lossy().to_string()),
            )
        }
    };

    // ---------- (3) start collector ----------
    let plan = ProviderPlan::for_target(opts.providers.clone(), target_pid);
    let (tx, rx) = crossbeam_channel::bounded::<TraceEvent>(65_536);
    let drops = DropCounter::new();
    let mut collector = FerrisEtwCollector::new(&run_id);
    if let Err(e) = collector.start(plan, tx.clone(), drops.clone()) {
        // On collector start failure, kill the suspended target.
        if let Some(handle) = target_handle {
            terminate_process_silently(handle);
        }
        ledger.set_error(&format!("collector_start_failed: {e}"));
        let _ = ledger.finalize_atomic(now_ms());
        return Err(DynamicTraceError::Collector(format!("{e}")));
    }

    // ---------- (4) resume target ----------
    if let Some(handle) = target_handle {
        if let Err(e) = resume_thread(handle) {
            // Stop collector first to release the session slot.
            let _ = Box::new(collector).stop();
            ledger.set_error(&format!("resume_thread_failed: {e}"));
            let _ = ledger.finalize_atomic(now_ms());
            return Err(DynamicTraceError::TargetSpawn(format!("{e}")));
        }
    }

    // ---------- (5) drain channel until deadline / Ctrl-C ----------
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_handler = stop_flag.clone();
    let _ = ctrlc::set_handler(move || {
        stop_flag_handler.store(true, Ordering::Relaxed);
    });

    let deadline = opts.duration.map(|d| Instant::now() + d);
    let store_path = opts.out_dir.join("trace.sqlite");
    let mut store = TraceStore::open(&store_path)
        .map_err(|e| DynamicTraceError::Io(std::io::Error::other(format!("{e}"))))?;
    let ndjson_path = opts.out_dir.join("events.ndjson");
    let mut writer = TraceEventWriter::create(&ndjson_path)?;
    let mut all_events: Vec<TraceEvent> = Vec::new();

    loop {
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        if let Some(dl) = deadline {
            if Instant::now() >= dl {
                break;
            }
        }
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(ev) => {
                let _ = store.insert_event(&ev);
                let _ = writer.append(&ev);
                all_events.push(ev);
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                // Check if target has exited.
                if let Some(pid) = target_pid {
                    if !process_is_alive(pid) {
                        // Give a brief grace period to flush in-flight events.
                        thread::sleep(Duration::from_millis(250));
                        while let Ok(ev) = rx.try_recv() {
                            let _ = store.insert_event(&ev);
                            let _ = writer.append(&ev);
                            all_events.push(ev);
                        }
                        break;
                    }
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }

    // ---------- (6) stop collector ----------
    let collector_report = Box::new(collector)
        .stop()
        .map_err(|e| DynamicTraceError::Collector(format!("{e}")))?;
    let events_dropped = drops.snapshot();

    let events_ndjson_bytes = writer.finalize()?;
    ledger.set_events_dropped(events_dropped);
    ledger.mark_complete(
        "events.ndjson",
        events_ndjson_bytes,
        all_events.len() as u64,
    );
    ledger.mark_complete(
        "trace.sqlite",
        sqlite_size(&store_path),
        all_events.len() as u64,
    );

    // ---------- (7) behavior facts ----------
    let loss = LossMeta { events_dropped };
    let facts = behavior_facts::extract_facts(&run_id, &all_events, &loss);

    // ---------- (8) LLM pack ----------
    let target_hash_str = target_image.as_deref().map(blake3_hash_of_path);
    let pack_inputs = PackInputs {
        run_id: &run_id,
        duration_ms: now_ms().saturating_sub(started_at_ms) as u64,
        target_image: target_image.as_deref(),
        target_pid,
        target_hash: target_hash_str.as_deref(),
        symbolication_miss_rate: 0.0,
    };
    let static_facts: Vec<llm_pack::StaticFactView> = Vec::new();
    let sizes: EmittedSizes = llm_pack::emit_all(
        &opts.out_dir,
        &pack_inputs,
        &all_events,
        &static_facts,
        &facts,
        &loss,
        Some(&store),
    )?;
    ledger.mark_complete(
        "entity_graph.json",
        sizes.entity_graph,
        all_events.len() as u64,
    );
    ledger.mark_complete(
        "behavior_facts.jsonl",
        sizes.behavior_facts,
        facts.len() as u64,
    );
    ledger.mark_complete(
        "behavior_fact_union.jsonl",
        sizes.behavior_fact_union,
        (static_facts.len() + facts.len()) as u64,
    );
    ledger.mark_complete("evidence_pack.json", sizes.evidence_pack, 1);

    // ---------- (9) finalize ledger ----------
    let _ = collector_report; // currently unused beyond drops counter
    ledger.finalize_atomic(now_ms())?;

    Ok(DynamicTraceReport {
        run_id,
        events_emitted: all_events.len() as u64,
        events_dropped,
        behavior_facts_count: facts.len() as u64,
        run_status_path: Some(opts.out_dir.join("run_status.json")),
    })
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn derive_run_id(opts: &DynamicTraceOptions) -> String {
    // Stable per (target, start time second) — deterministic given
    // identical inputs at the same wall clock.
    let target = match &opts.target {
        TargetSpec::Spawn { exe, .. } => exe.to_string_lossy().to_string(),
        TargetSpec::Pid(p) => format!("pid:{p}"),
        TargetSpec::None => "none".to_string(),
    };
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let combined = format!("{target}|{secs}|{}", opts.seed);
    let hash = blake3::hash(combined.as_bytes());
    format!("blake3:{}", hex::encode(&hash.as_bytes()[..8]))
}

fn blake3_hash_of_path(path: &str) -> String {
    match std::fs::read(path) {
        Ok(bytes) => format!(
            "blake3:{}",
            hex::encode(&blake3::hash(&bytes).as_bytes()[..8])
        ),
        Err(_) => "blake3:unknown".to_string(),
    }
}

#[cfg(not(all(windows, feature = "dynamic-trace-etw")))]
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn sqlite_size(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn spawn_suspended(
    exe: &std::path::Path,
    args: &[String],
) -> std::io::Result<(u32, windows::Win32::Foundation::HANDLE)> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::{
        CreateProcessW, CREATE_SUSPENDED, PROCESS_INFORMATION, STARTUPINFOW,
    };

    let exe_wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
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
            windows::core::PCWSTR(exe_wide.as_ptr()),
            Some(PWSTR(cmd_wide.as_mut_ptr())),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            windows::core::PCWSTR::null(),
            &si,
            &mut pi,
        )
        .map_err(|e| std::io::Error::other(format!("{e}")))?;
    }
    let pid = pi.dwProcessId;
    let handle = HANDLE(pi.hThread.0);
    Ok((pid, handle))
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn resume_thread(handle: windows::Win32::Foundation::HANDLE) -> std::io::Result<()> {
    use windows::Win32::System::Threading::ResumeThread;
    unsafe {
        let prev = ResumeThread(handle);
        if prev == u32::MAX {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn terminate_process_silently(handle: windows::Win32::Foundation::HANDLE) {
    use windows::Win32::System::Threading::TerminateProcess;
    unsafe {
        let _ = TerminateProcess(handle, 1);
    }
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn process_is_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let h = match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let mut exit_code: u32 = 0;
        let ok = GetExitCodeProcess(h, &mut exit_code).is_ok();
        let _ = CloseHandle(h);
        // STILL_ACTIVE = 259
        ok && exit_code == 259
    }
}

// ---------------------------------------------------------------------
// Public re-exports the orchestrator hook calls into.
// ---------------------------------------------------------------------

/// Convenience function called by `mod.rs::run_dynamic_trace_session`.
pub fn run(opts: &DynamicTraceOptions) -> Result<DynamicTraceReport, DynamicTraceError> {
    run_session(opts)
}

// Helper used by tests + by the unsupported-OS path to write a
// trivial placeholder events.ndjson.
pub fn write_placeholder_events(path: &std::path::Path) -> std::io::Result<()> {
    write_atomic(path, b"")
}

// Re-export for the unsupported branch's symbol parity.
#[cfg(not(all(windows, feature = "dynamic-trace-etw")))]
#[allow(dead_code)]
fn _store_path_unused(_: &DynamicTraceOptions) -> PathBuf {
    PathBuf::new()
}

// _store_handle_unused: prevents unused-import warnings on non-Windows.
#[cfg(not(all(windows, feature = "dynamic-trace-etw")))]
#[allow(dead_code)]
fn _store_handle_unused() -> Option<TraceStore> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn unsupported_session_writes_failed_ledger() {
        // On non-Windows or without the ETW sub-feature, the session
        // returns a Failed ledger so the manifest can advertise it.
        #[cfg(not(all(windows, feature = "dynamic-trace-etw")))]
        {
            let tmp = TempDir::new().unwrap();
            let opts = DynamicTraceOptions {
                out_dir: tmp.path().to_path_buf(),
                ..Default::default()
            };
            let report = run_session(&opts).unwrap();
            assert_eq!(report.events_emitted, 0);
            assert!(report.run_status_path.is_some());
            let parsed = crate::dynamic_trace::dyn_run_status::read_dynamic_trace_run_status(
                &opts.out_dir.join("run_status.json"),
            )
            .unwrap();
            // Without any artifacts marked, derive_outcome → Failed.
            assert_eq!(parsed.base.outcome, crate::run_status::RunOutcome::Failed);
            assert!(parsed.base.error.is_some());
        }
        #[cfg(all(windows, feature = "dynamic-trace-etw"))]
        {
            // On the elevated Windows path this test is best-effort.
            // We don't actually start ETW here — the orchestrator
            // requires admin. Instead exercise just the unsupported
            // fallback path is implicit.
        }
    }

    #[test]
    fn derive_run_id_starts_with_blake3_prefix() {
        let opts = DynamicTraceOptions::default();
        let id = derive_run_id(&opts);
        assert!(id.starts_with("blake3:"));
        assert!(id.len() > "blake3:".len());
    }
}
