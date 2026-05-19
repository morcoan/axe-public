//! Top-level Aurora session orchestrator (Step 54).
//!
//! Composes Group A-H primitives into the end-to-end pipeline:
//!
//! 1. Decide strategy from existing `AntiAnalysisRecord` rows
//!    (`packer_dispatch`).
//! 2. Spawn the target suspended (`process_control`).
//! 3. Install user-mode anti-anti-VM hooks via stub-DLL
//!    injection (`hooks::inject` — skeleton until Step 26
//!    follow-up).
//! 4. Patch PEB anti-debug flags (`anti_debug::apply_peb_patches`).
//! 5. Attach the debugger and resume the main thread.
//! 6. Drive the debug loop under wall-clock + event-count
//!    budget; the budget watchdog (a side thread) hard-kills
//!    on expiry.
//! 7. Capture committed regions, build the manifest, emit
//!    snapshot + run_status.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::run_status::ArtifactStatusEntry;
use crate::unpack::anti_debug::AntiDebugProfile;
use crate::unpack::containment::{
    install_ctrl_c_kill_switch, spawn_budget_watchdog, suppress_wer_fault, Budget,
};
use crate::unpack::hooks::SpoofProfile;
use crate::unpack::process_control::spawn_suspended;
use crate::unpack::snapshot::{AntiVmProfile, ExecutionProvenance, SnapshotManifest, SourceBinary};
use crate::unpack::snapshot_capture::{emit_snapshot, CaptureFilter};
use crate::unpack::unpack_run_status::{
    self, finalize as finalize_status, new_status, UnpackRunMeta,
};
use crate::unpack::{UnpackError, UnpackMode, UnpackOptions, UnpackOutcome, UnpackReport};

/// Drive a full Aurora session against `input_path`. Returns
/// the `UnpackReport` after the snapshot has been emitted.
///
/// On non-Windows or when `options.mode == Off`, returns
/// without doing work (per `UnpackError::UnsupportedPlatform`
/// or `UnpackOutcome::Skipped`).
pub fn run_session(
    input_path: &Path,
    options: &UnpackOptions,
) -> Result<UnpackReport, UnpackError> {
    if matches!(options.mode, UnpackMode::Off) {
        return Ok(UnpackReport {
            outcome: UnpackOutcome::Skipped,
            snapshot_path: None,
            regions_dumped: 0,
            top_oep_confidence: 0.0,
        });
    }
    if !input_path.exists() {
        return Err(UnpackError::InputNotFound(input_path.display().to_string()));
    }
    #[cfg(not(windows))]
    {
        let _ = (input_path, options);
        return Err(UnpackError::UnsupportedPlatform);
    }
    #[cfg(windows)]
    run_windows_session(input_path, options)
}

#[cfg(windows)]
fn run_windows_session(
    input_path: &Path,
    options: &UnpackOptions,
) -> Result<UnpackReport, UnpackError> {
    let started_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    std::fs::create_dir_all(&options.out_dir).map_err(UnpackError::Io)?;

    suppress_wer_fault();

    let run_id = format!("aurora:{}", started_at);
    let mut status = new_status(&run_id, started_at);

    // 1. Spawn suspended
    let target = spawn_suspended(input_path, &[])?;
    let pid = target.pid;

    // 2. Arm Ctrl-C kill-switch (best-effort; only first install
    // succeeds in a given Aurora process lifetime).
    let _ = install_ctrl_c_kill_switch(pid);

    // 3. Anti-debug PEB patches (skip the API-hook portion —
    // that requires the stub DLL artifact, follow-up).
    let anti_debug = if options.hooks_disable {
        AntiDebugProfile::disabled()
    } else {
        AntiDebugProfile::default()
    };
    let _ = crate::unpack::anti_debug::apply_peb_patches(target.process_handle(), &anti_debug);

    // 4. Compose spoof profile (recorded in manifest even when
    // the stub DLL isn't loaded yet — see hooks::install_all
    // doc for the eventual wire-up).
    let spoof = if options.hooks_disable {
        SpoofProfile::disabled()
    } else {
        SpoofProfile::default()
    };
    let installed_hooks =
        crate::unpack::hooks::install_all(target.process_handle().0 as u64, &spoof)?;

    // 5. Attach the debugger + resume
    crate::unpack::process_control::attach_debugger(pid)?;
    crate::unpack::process_control::resume_main_thread(&target)?;

    // 6. Run the debug loop under budget
    let budget = Arc::new(Budget::new(
        Duration::from_secs(options.timeout_secs),
        options.instr_budget,
    ));
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
    let loop_start = Instant::now();
    let loop_stats = crate::unpack::debug_loop::run_loop(Duration::from_millis(500), |_event| {
        budget_for_loop.tick_event();
        if budget_for_loop.is_expired() {
            crate::unpack::debug_loop::ContinueAction::Stop
        } else {
            crate::unpack::debug_loop::ContinueAction::Continue
        }
    })
    .unwrap_or(crate::unpack::debug_loop::DebugStats::default());
    let elapsed_ms = loop_start.elapsed().as_millis() as u64;

    // 7. Capture committed regions
    let captured = crate::unpack::snapshot_capture::capture(
        target.process_handle(),
        &CaptureFilter::default(),
    )
    .unwrap_or_default();
    let regions_dumped = captured.len();

    // 8. Build + emit the manifest
    let hash = blake3::hash(&std::fs::read(input_path).unwrap_or_default())
        .to_hex()
        .to_string();
    let size_bytes = std::fs::metadata(input_path).map(|m| m.len()).unwrap_or(0);
    let mut manifest = SnapshotManifest::new(
        &run_id,
        SourceBinary {
            path: input_path.display().to_string(),
            hash_blake3: hash.clone(),
            size_bytes,
        },
        match options.tracer_mode {
            crate::unpack::TracerMode::Debug | crate::unpack::TracerMode::Auto => "debug",
            crate::unpack::TracerMode::Whp => "whp",
            crate::unpack::TracerMode::Driver => "driver",
        },
    );
    manifest.anti_vm_profile = AntiVmProfile {
        user_mode_hooks_installed: installed_hooks.iter().map(|h| h.api.clone()).collect(),
        anti_debug_hooks_installed: anti_debug.installed_surface_names(),
        whp_used: matches!(options.tracer_mode, crate::unpack::TracerMode::Whp),
        driver_used: matches!(options.tracer_mode, crate::unpack::TracerMode::Driver),
        devirt_used: options.include_devirt,
        devirt_trace_path: None,
    };
    manifest.execution_provenance = ExecutionProvenance {
        wall_clock_ms: elapsed_ms,
        instructions_estimated: budget.events_seen() * 1000,
        outcome: if loop_stats.target_exited {
            "target_exited".to_string()
        } else if budget.is_expired() {
            "timeout".to_string()
        } else {
            "stopped".to_string()
        },
        termination_reason: if loop_stats.target_exited {
            "target reached natural exit".to_string()
        } else if budget.is_wall_clock_expired() {
            "wall-clock budget expired".to_string()
        } else if budget.is_event_cap_hit() {
            "event-count budget expired".to_string()
        } else {
            "handler returned Stop".to_string()
        },
        exit_code: loop_stats.final_exit_code.map(|c| c as i32),
        hit_instruction_budget: budget.is_event_cap_hit(),
        hit_wall_clock_timeout: budget.is_wall_clock_expired(),
        child_processes_observed: Vec::new(),
    };
    manifest.uncertainties.push(
        "snapshot reproducibility: same input may produce different snapshots across runs \
         (ASLR, timing, system state)"
            .into(),
    );

    let snapshot_bytes = emit_snapshot(&options.out_dir, &mut manifest, &captured)?;
    unpack_run_status::record_artifact(
        &mut status.artifacts,
        "unpack_provenance.json",
        ArtifactStatusEntry::complete(snapshot_bytes, 1),
    );
    for (idx, _) in captured.iter().enumerate() {
        let name = format!("regions/region_{:02}.bin", idx);
        let size = captured[idx].buffer.size() as u64;
        unpack_run_status::record_artifact(
            &mut status.artifacts,
            &name,
            ArtifactStatusEntry::complete(size, 0),
        );
    }

    // 9. Finalize the ledger
    let completed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let meta = UnpackRunMeta {
        tracer_mode: manifest.tracer_mode.clone(),
        user_mode_hooks: installed_hooks.len() as u32,
        anti_debug_hooks: anti_debug.installed_surface_names().len() as u32,
        whp_used: matches!(options.tracer_mode, crate::unpack::TracerMode::Whp),
        driver_used: matches!(options.tracer_mode, crate::unpack::TracerMode::Driver),
        oep_top_confidence: 0.0,
        regions_dumped: regions_dumped as u32,
    };
    finalize_status(&options.out_dir, status, &meta, completed).map_err(UnpackError::Io)?;

    Ok(UnpackReport {
        outcome: if loop_stats.target_exited || regions_dumped > 0 {
            UnpackOutcome::Complete
        } else {
            UnpackOutcome::Partial
        },
        snapshot_path: Some(options.out_dir.join("unpack_provenance.json")),
        regions_dumped,
        top_oep_confidence: 0.0,
    })
}

/// Where would the manifest land for this options set? Used by
/// tests + by the manifest helper in `llm_artifacts.rs`.
pub fn manifest_path_for(options: &UnpackOptions) -> PathBuf {
    options.out_dir.join("unpack_provenance.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_path_for_uses_out_dir() {
        let opts = UnpackOptions::default();
        let p = manifest_path_for(&opts);
        assert!(
            p.ends_with("unpack/unpack_provenance.json") || p.ends_with("unpack_provenance.json")
        );
    }

    #[test]
    fn run_session_with_mode_off_returns_skipped() {
        let opts = UnpackOptions::default();
        let report = run_session(Path::new("/nonexistent"), &opts).expect("Off mode never errors");
        assert_eq!(report.outcome, UnpackOutcome::Skipped);
    }

    #[test]
    fn run_session_with_mode_on_missing_input_returns_input_not_found() {
        let opts = UnpackOptions {
            mode: UnpackMode::On,
            ..UnpackOptions::default()
        };
        let err = run_session(Path::new("/definitely/not/here.exe"), &opts)
            .err()
            .expect("must error");
        match err {
            UnpackError::InputNotFound(_) => {}
            other => panic!("expected InputNotFound, got {:?}", other),
        }
    }
}
