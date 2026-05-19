//! v1.1 harness-verify integration test (Step 36).
//!
//! Validates Codex round-1 finding 2 end-to-end through the session
//! orchestrator:
//! - Binary-only PE entries (the default kind for axe-discovered
//!   chains) ALWAYS produce only `.skeleton.md`, never `.runnable.rs`.
//! - The Skeleton tier remains the default; promotion to Runnable
//!   requires an explicit `verify_runnable` PASS, not just being
//!   "source-available".
//! - Even when `--vuln-harness-tier both` is set, binary-only kinds
//!   continue to skip runnable emission (structural defense).
//!
//! Direct unit tests for the harness API live in
//! `src/vuln/harness_synth.rs` and `src/vuln/harness_verify.rs`; this
//! integration test verifies the session-level wire shape produced
//! to disk.

#![cfg(feature = "vuln-discovery")]

use axe_core::vuln::harness_synth::{synthesize, HarnessKind, HarnessTier, HarnessVerification};
use axe_core::vuln::harness_verify::{try_promote_to_runnable, VerificationOutcome};
use axe_core::vuln::llm_pack::emit_harness_artifacts;
use axe_core::vuln::query::CandidateChain;
use axe_core::vuln::session::{run, VulnInputs};
use axe_core::vuln::sinks::SinkCatalog;
use axe_core::vuln::taint::PropagationMode;
use axe_core::vuln::{HarnessTierMode, VulnOptions};
use axe_core::{ApiFlowRecord, FunctionRecord};
use tempfile::TempDir;

fn func(va: u64) -> FunctionRecord {
    FunctionRecord {
        start: va,
        end: va + 0x100,
        size: 0x100,
        source: "test".into(),
        calls: vec![],
        calls_imports: vec![],
        strings: vec![],
        xrefs: 0,
    }
}

fn af(function: u64, callsite: u64, api: &str) -> ApiFlowRecord {
    ApiFlowRecord {
        flow_id: format!("af_{callsite:x}"),
        function,
        callsite,
        api: api.into(),
        normalized_api: api.into(),
        api_tier: "user".into(),
        api_family: "memory".into(),
        semantic_relevance: "high".into(),
        noise_reason: None,
        api_categories: vec![],
        value: "rcx".into(),
        value_tags: vec![],
        argument: "rcx".into(),
        argument_register: Some("rcx".into()),
        argument_index: Some(0),
        argument_name: Some("dst".into()),
        confidence: "high".into(),
        mode: "static".into(),
        resolved_api: None,
        wrapper_chain: vec![],
        evidence: vec![],
    }
}

fn fixture_chain() -> CandidateChain {
    CandidateChain {
        chain_id: "C-T-001".into(),
        template_id: "unchecked_copy_length".into(),
        source_kind: "network_recv".into(),
        source_function_va: 0x140001000,
        source_site_va: 0x140001100,
        sink_api: "memcpy".into(),
        sink_function_va: 0x140002000,
        sink_site_va: 0x1400022a4,
        propagation_mode: PropagationMode::Exact,
        hop_count: 0,
        dominating_guard_count: 0,
        matched_integer_pattern: false,
    }
}

// =====================================================================
// Session-level wire-shape tests
// =====================================================================

#[test]
fn session_emits_skeleton_md_for_every_finding() {
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        harness_tier: HarnessTierMode::SkeletonOnly,
        ..Default::default()
    };
    let functions = vec![func(0x1000)];
    let api_flows = vec![af(0x1000, 0x1100, "recv"), af(0x1000, 0x1200, "DeleteFile")];
    let inputs = VulnInputs {
        run_id: "test-run",
        functions: &functions,
        api_flows: &api_flows,
        ..Default::default()
    };
    run(&opts, &inputs).unwrap();
    let harnesses_dir = tmp.path().join("harnesses");
    assert!(harnesses_dir.exists(), "harnesses/ dir must exist");
    // At least one .skeleton.md was written.
    let mut count_skeleton = 0;
    let mut count_runnable = 0;
    for entry in std::fs::read_dir(&harnesses_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if name.ends_with(".skeleton.md") {
            count_skeleton += 1;
        } else if name.ends_with(".runnable.rs") {
            count_runnable += 1;
        }
    }
    assert!(count_skeleton > 0, "no .skeleton.md files written");
    // SkeletonOnly mode: NO .runnable.rs files at all.
    assert_eq!(
        count_runnable, 0,
        "Codex finding 2 violation: .runnable.rs written in SkeletonOnly mode"
    );
}

#[test]
fn session_default_harness_kind_is_binary_only_so_no_runnable_files_ever() {
    // Codex finding 2 strict default: axe doesn't know how to call
    // arbitrary PE entries, so the default kind is BinaryOnlyPeEntry,
    // which makes runnable_rust None. Even with HarnessTierMode::Both
    // there's no runnable_rust to emit.
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        harness_tier: HarnessTierMode::Both,
        ..Default::default()
    };
    let functions = vec![func(0x1000)];
    let api_flows = vec![af(0x1000, 0x1100, "recv"), af(0x1000, 0x1200, "DeleteFile")];
    let inputs = VulnInputs {
        run_id: "test-run",
        functions: &functions,
        api_flows: &api_flows,
        ..Default::default()
    };
    run(&opts, &inputs).unwrap();
    let harnesses_dir = tmp.path().join("harnesses");
    let mut count_runnable = 0;
    for entry in std::fs::read_dir(&harnesses_dir).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        if name.ends_with(".runnable.rs") {
            count_runnable += 1;
        }
    }
    assert_eq!(
        count_runnable, 0,
        "BinaryOnlyPeEntry default must not emit .runnable.rs in any tier mode"
    );
}

#[test]
fn skeleton_md_contains_chain_provenance_and_codex_rationale() {
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        harness_tier: HarnessTierMode::SkeletonOnly,
        ..Default::default()
    };
    let functions = vec![func(0x1000)];
    let api_flows = vec![af(0x1000, 0x1100, "recv"), af(0x1000, 0x1200, "DeleteFile")];
    let inputs = VulnInputs {
        run_id: "test-run",
        functions: &functions,
        api_flows: &api_flows,
        ..Default::default()
    };
    run(&opts, &inputs).unwrap();
    let harnesses_dir = tmp.path().join("harnesses");
    let first_skeleton = std::fs::read_dir(&harnesses_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .find(|e| {
            e.file_name()
                .into_string()
                .map(|n| n.ends_with(".skeleton.md"))
                .unwrap_or(false)
        })
        .expect("at least one .skeleton.md must exist");
    let content = std::fs::read_to_string(first_skeleton.path()).unwrap();
    // Provenance: chain id + sink VA + bug class.
    assert!(content.contains("Chain"), "skeleton must mention 'Chain'");
    assert!(
        content.contains("DeleteFile"),
        "skeleton must mention sink api"
    );
    // Codex finding 2 rationale (binary-only chains).
    assert!(
        content.contains("Codex finding 2"),
        "skeleton must cite Codex finding 2 rationale"
    );
}

// =====================================================================
// Promotion-discipline tests (verify_runnable + emit_harness_artifacts)
// =====================================================================

#[test]
fn binary_only_harness_stays_skeleton_after_promotion_attempt_and_emit_writes_no_runnable() {
    let tmp = TempDir::new().unwrap();
    let mut h = synthesize(
        &fixture_chain(),
        &SinkCatalog::v1_0(),
        HarnessKind::BinaryOnlyPeEntry,
    );
    assert_eq!(h.tier, HarnessTier::Skeleton);
    // Attempt promotion — the structural guard in verify_runnable
    // must refuse to call the runner.
    let intended = h.intended_sink_va;
    let promoted = try_promote_to_runnable(&mut h, &[vec![0u8; 16]], |_| {
        VerificationOutcome::reached(intended)
    });
    assert!(!promoted);
    assert_eq!(h.tier, HarnessTier::Skeleton);
    assert_eq!(h.verification, HarnessVerification::SkippedBinaryOnly);

    // Wire shape: emit MUST NOT produce .runnable.rs for this
    // harness even after the (failed) promotion attempt.
    let dir = tmp.path().join("harnesses");
    emit_harness_artifacts(&dir, &[h]).unwrap();
    assert!(dir.join("H-C-T-001.skeleton.md").exists());
    assert!(!dir.join("H-C-T-001.runnable.rs").exists());
}

#[test]
fn source_available_harness_runnable_only_after_verify_pass() {
    let tmp = TempDir::new().unwrap();
    let mut h = synthesize(
        &fixture_chain(),
        &SinkCatalog::v1_0(),
        HarnessKind::SourceAvailableFnByteSlice,
    );
    // Before verification: Skeleton tier, no .runnable.rs on disk
    // (even though runnable_rust is populated in memory).
    let dir = tmp.path().join("before");
    emit_harness_artifacts(&dir, &[h.clone()]).unwrap();
    assert!(dir.join("H-C-T-001.skeleton.md").exists());
    assert!(
        !dir.join("H-C-T-001.runnable.rs").exists(),
        "Skeleton tier must NOT emit .runnable.rs"
    );

    // Promote via a passing runner.
    let intended = h.intended_sink_va;
    let promoted = try_promote_to_runnable(&mut h, &[vec![0u8; 16]], |_| {
        VerificationOutcome::reached(intended)
    });
    assert!(promoted);
    assert_eq!(h.tier, HarnessTier::Runnable);

    // After promotion: BOTH files on disk.
    let dir_after = tmp.path().join("after");
    emit_harness_artifacts(&dir_after, &[h]).unwrap();
    assert!(dir_after.join("H-C-T-001.skeleton.md").exists());
    assert!(dir_after.join("H-C-T-001.runnable.rs").exists());
}

#[test]
fn source_available_harness_stays_skeleton_when_verify_fails() {
    let tmp = TempDir::new().unwrap();
    let mut h = synthesize(
        &fixture_chain(),
        &SinkCatalog::v1_0(),
        HarnessKind::SourceAvailableFnByteSlice,
    );
    // Runner reaches the WRONG sink VA — Codex finding 2 attribution
    // discipline says this is NOT a pass.
    let promoted = try_promote_to_runnable(&mut h, &[vec![0u8; 16]], |_| {
        VerificationOutcome::reached(0xdead_beef)
    });
    assert!(!promoted);
    assert_eq!(h.tier, HarnessTier::Skeleton);

    let dir = tmp.path().join("harnesses");
    emit_harness_artifacts(&dir, &[h]).unwrap();
    assert!(dir.join("H-C-T-001.skeleton.md").exists());
    assert!(!dir.join("H-C-T-001.runnable.rs").exists());
}

#[test]
fn user_supplied_harness_follows_same_promotion_discipline() {
    let tmp = TempDir::new().unwrap();
    let mut h = synthesize(
        &fixture_chain(),
        &SinkCatalog::v1_0(),
        HarnessKind::UserSuppliedEntryPoint,
    );
    let intended = h.intended_sink_va;
    let promoted = try_promote_to_runnable(&mut h, &[vec![0u8; 16]], |_| {
        VerificationOutcome::reached(intended)
    });
    assert!(promoted);
    let dir = tmp.path().join("harnesses");
    emit_harness_artifacts(&dir, &[h]).unwrap();
    assert!(dir.join("H-C-T-001.runnable.rs").exists());
}

#[test]
fn empty_input_set_does_not_promote_to_runnable() {
    let mut h = synthesize(
        &fixture_chain(),
        &SinkCatalog::v1_0(),
        HarnessKind::SourceAvailableFnByteSlice,
    );
    let promoted = try_promote_to_runnable(&mut h, &[], |_| {
        unreachable!("runner must not be invoked when no inputs")
    });
    assert!(!promoted);
    assert_eq!(h.tier, HarnessTier::Skeleton);
}

#[test]
fn harnesses_dir_is_registered_in_run_status_ledger() {
    // Wire-shape contract: the ledger MUST track harnesses as an
    // artifact so the manifest (Step 35) registers it.
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        harness_tier: HarnessTierMode::SkeletonOnly,
        ..Default::default()
    };
    let functions = vec![func(0x1000)];
    let api_flows = vec![af(0x1000, 0x1100, "recv"), af(0x1000, 0x1200, "memcpy")];
    let inputs = VulnInputs {
        run_id: "test-run",
        functions: &functions,
        api_flows: &api_flows,
        ..Default::default()
    };
    run(&opts, &inputs).unwrap();
    let rs: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(tmp.path().join("run_status.json")).unwrap())
            .unwrap();
    let artifacts = rs["artifacts"].as_object().unwrap();
    assert!(
        artifacts.contains_key("harnesses"),
        "run_status.json must register 'harnesses' artifact"
    );
}
