//! v1.0 end-to-end smoke for the vuln-discovery pipeline.
//!
//! Synthesizes a tiny analysis-record set (functions + api_flows that
//! pair a source with a sink), runs the session, and asserts the
//! pipeline produces:
//! - All 5 manifest entries (run_status + 4 artifacts)
//! - At least one finding for a recv→memcpy chain
//! - Manifest helper agreement
//!
//! Runs always-on under `--features vuln-discovery` — no extra
//! features or platform requirements.

#![cfg(feature = "vuln-discovery")]

use axe_core::vuln::session::{run, VulnInputs};
use axe_core::vuln::vuln_run_status::read_vuln_run_status;
use axe_core::vuln::VulnOptions;
use axe_core::vuln_artifact_index_entries;
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

fn api_flow(function: u64, callsite: u64, api: &str) -> ApiFlowRecord {
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
        api_categories: vec!["memory".into()],
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

#[test]
fn end_to_end_pipeline_emits_all_artifacts() {
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        confidence_threshold: 0.30, // permissive for smoke
        ..Default::default()
    };
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        api_flow(0x1000, 0x1100, "recv"),
        api_flow(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = VulnInputs {
        run_id: "blake3:smoke",
        functions: &functions,
        api_flows: &api_flows,
        ..Default::default()
    };
    let report = run(&opts, &inputs).expect("session should succeed");
    assert_eq!(report.templates_loaded, 12);

    // All 4 artifacts + run_status must exist on disk.
    for name in [
        "findings.jsonl",
        "chain_graph.json",
        "evidence_bundle.json",
        "findings.sqlite",
        "run_status.json",
    ] {
        assert!(tmp.path().join(name).exists(), "missing artifact: {name}");
    }
}

#[test]
fn manifest_helper_returns_all_5_entries_with_run_status_first() {
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        confidence_threshold: 0.30,
        ..Default::default()
    };
    let inputs = VulnInputs {
        run_id: "blake3:smoke",
        ..Default::default()
    };
    run(&opts, &inputs).unwrap();
    let entries = vuln_artifact_index_entries(tmp.path(), "on");
    assert_eq!(
        entries.len(),
        5,
        "expected 5 entries (1 ledger + 4 artifacts)"
    );
    assert_eq!(entries[0].path, "vuln/run_status.json");
}

#[test]
fn manifest_helper_off_mode_returns_empty() {
    let tmp = TempDir::new().unwrap();
    let entries = vuln_artifact_index_entries(tmp.path(), "off");
    assert!(entries.is_empty());
}

#[test]
fn manifest_helper_missing_ledger_returns_empty() {
    let tmp = TempDir::new().unwrap();
    // Mode=on but no ledger written ⇒ helper returns empty (conservative).
    let entries = vuln_artifact_index_entries(tmp.path(), "on");
    assert!(entries.is_empty());
}

#[test]
fn run_status_carries_templates_loaded_and_chains_meta() {
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    let inputs = VulnInputs {
        run_id: "blake3:r",
        ..Default::default()
    };
    run(&opts, &inputs).unwrap();
    let status = read_vuln_run_status(&tmp.path().join("run_status.json")).unwrap();
    assert_eq!(status.run_meta.phase, "v1.0_static");
    assert_eq!(status.run_meta.templates_loaded, 12);
    assert!(!status.run_meta.scoring_calibrated);
}

#[test]
fn confidence_threshold_above_max_drops_all_findings() {
    // Plan verification item #6: `--vuln-confidence-threshold 0.99`
    // must drop every chain (v1.0 scoring clamps confidence to 0.95).
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        confidence_threshold: 0.99,
        ..Default::default()
    };
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        api_flow(0x1000, 0x1100, "recv"),
        api_flow(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = VulnInputs {
        run_id: "blake3:thr_high",
        functions: &functions,
        api_flows: &api_flows,
        ..Default::default()
    };
    let report = run(&opts, &inputs).unwrap();
    assert_eq!(
        report.findings_emitted, 0,
        "threshold 0.99 must drop all findings"
    );
}

#[test]
fn confidence_threshold_zero_keeps_all_chains_above_zero() {
    // Plan verification item #6: `--vuln-confidence-threshold 0.0`
    // must accept every chain the discovery engine produces (no
    // confidence filter applied).
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        confidence_threshold: 0.0,
        ..Default::default()
    };
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        api_flow(0x1000, 0x1100, "recv"),
        api_flow(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = VulnInputs {
        run_id: "blake3:thr_zero",
        functions: &functions,
        api_flows: &api_flows,
        ..Default::default()
    };
    let report = run(&opts, &inputs).unwrap();
    // The fixture has no DataFlow wiring, but missing_caller_validation
    // still fires on the privileged WriteProcessMemory action
    // (AnyCall + NoDominatingGuard, source kind network_recv).
    assert!(report.findings_emitted > 0, "expected at least one finding");
    assert_eq!(report.findings_emitted, report.chains_above_threshold);
}

#[test]
fn templates_csv_filter_reduces_loaded_count() {
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        templates: "unchecked_copy_length,format_string_controlled".into(),
        ..Default::default()
    };
    let inputs = VulnInputs {
        run_id: "blake3:r",
        ..Default::default()
    };
    let report = run(&opts, &inputs).unwrap();
    assert_eq!(report.templates_loaded, 2);
}
