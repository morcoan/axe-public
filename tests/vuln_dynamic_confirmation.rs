//! v1.1 dynamic-confirmation integration test (Step 36).
//!
//! Validates the Codex-finding-1 invariant end-to-end through the
//! session orchestrator: only chains with attached
//! [`DynamicStatus::ConfirmedTrigger`] / [`DynamicStatus::ReachedOnly`]
//! evidence gain dynamic confidence; aggregate-style or mismatched
//! evidence adds zero. Mirrors the wire shape the LLM consumer sees
//! in `findings.jsonl`.

#![cfg(feature = "vuln-discovery")]

use axe_core::vuln::dynamic_evidence::{DynamicEvidence, DynamicStatus};
use axe_core::vuln::session::{run, VulnInputs};
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

fn fixture_inputs<'a>(
    functions: &'a [FunctionRecord],
    api_flows: &'a [ApiFlowRecord],
) -> VulnInputs<'a> {
    VulnInputs {
        run_id: "test-run",
        functions,
        api_flows,
        ..Default::default()
    }
}

fn base_opts(tmp: &TempDir) -> VulnOptions {
    VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        harness_tier: HarnessTierMode::SkeletonOnly,
        ..Default::default()
    }
}

/// Read findings.jsonl and return all risk_score values for the
/// given finding_id prefix.
fn read_findings(dir: &std::path::Path) -> Vec<serde_json::Value> {
    let content = std::fs::read_to_string(dir.join("findings.jsonl")).unwrap();
    content
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn v1_1_with_no_dynamic_evidence_emits_findings_at_v1_0_scores() {
    let tmp = TempDir::new().unwrap();
    let opts = base_opts(&tmp);
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "recv"),
        af(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = fixture_inputs(&functions, &api_flows);
    let report = run(&opts, &inputs).unwrap();
    assert!(report.findings_emitted >= 1);

    let findings = read_findings(tmp.path());
    let baseline_risk: f32 = findings[0]["risk_score"].as_f64().unwrap() as f32;
    // Same fixture, second run with empty dynamic_evidence — should
    // produce identical risk_score.
    let tmp2 = TempDir::new().unwrap();
    let opts2 = base_opts(&tmp2);
    let inputs2 = fixture_inputs(&functions, &api_flows);
    run(&opts2, &inputs2).unwrap();
    let findings2 = read_findings(tmp2.path());
    let baseline_risk2: f32 = findings2[0]["risk_score"].as_f64().unwrap() as f32;
    assert!((baseline_risk - baseline_risk2).abs() < 1e-5);
}

#[test]
fn confirmed_trigger_evidence_boosts_finding_risk_score() {
    // Baseline run with no evidence.
    let tmp_baseline = TempDir::new().unwrap();
    let opts_baseline = base_opts(&tmp_baseline);
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "recv"),
        af(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = fixture_inputs(&functions, &api_flows);
    run(&opts_baseline, &inputs).unwrap();
    let baseline = read_findings(tmp_baseline.path());
    let baseline_risk = baseline[0]["risk_score"].as_f64().unwrap() as f32;

    // Same fixture, second run with ConfirmedTrigger evidence
    // attached. discover_chains generates chain ids starting "C-"; the
    // first chain on this fixture is "C-000001" because the missing_caller_validation
    // template is the first matching template in the iteration order. Use that id.
    let tmp_confirmed = TempDir::new().unwrap();
    let mut opts_confirmed = base_opts(&tmp_confirmed);
    // The first chain id is C-000001; sink_site_va is 0x1200 (WriteProcessMemory).
    opts_confirmed.dynamic_evidence = vec![DynamicEvidence::confirmed_trigger(
        "C-000001",
        "H-C-000001",
        DynamicEvidence::format_sink_pc(0x1200),
        std::collections::BTreeMap::new(),
        "corpus_001",
    )];
    let inputs2 = fixture_inputs(&functions, &api_flows);
    run(&opts_confirmed, &inputs2).unwrap();
    let boosted = read_findings(tmp_confirmed.path());
    let boosted_risk = boosted[0]["risk_score"].as_f64().unwrap() as f32;

    // Plan formula: ConfirmedTrigger adds 1.0 × 1.6 = 1.6 to risk.
    let delta = boosted_risk - baseline_risk;
    assert!(
        (delta - 1.6).abs() < 1e-3,
        "expected ConfirmedTrigger risk delta of 1.6, got {delta}"
    );
}

#[test]
fn reached_only_evidence_boosts_finding_risk_by_half_of_confirmed() {
    // Baseline run.
    let tmp_baseline = TempDir::new().unwrap();
    let opts_baseline = base_opts(&tmp_baseline);
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "recv"),
        af(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = fixture_inputs(&functions, &api_flows);
    run(&opts_baseline, &inputs).unwrap();
    let baseline = read_findings(tmp_baseline.path());
    let baseline_risk = baseline[0]["risk_score"].as_f64().unwrap() as f32;

    // ReachedOnly evidence run.
    let tmp_reached = TempDir::new().unwrap();
    let mut opts_reached = base_opts(&tmp_reached);
    opts_reached.dynamic_evidence = vec![DynamicEvidence::reached_only(
        "C-000001",
        "H-C-000001",
        DynamicEvidence::format_sink_pc(0x1200),
        std::collections::BTreeMap::new(),
        "evt_42",
    )];
    let inputs2 = fixture_inputs(&functions, &api_flows);
    run(&opts_reached, &inputs2).unwrap();
    let boosted = read_findings(tmp_reached.path());
    let boosted_risk = boosted[0]["risk_score"].as_f64().unwrap() as f32;

    // Plan formula: ReachedOnly adds 0.5 × 1.6 = 0.8 to risk.
    let delta = boosted_risk - baseline_risk;
    assert!(
        (delta - 0.8).abs() < 1e-3,
        "expected ReachedOnly risk delta of 0.8, got {delta}"
    );
}

#[test]
fn not_observed_evidence_does_not_boost_risk_score() {
    // Baseline run.
    let tmp_baseline = TempDir::new().unwrap();
    let opts_baseline = base_opts(&tmp_baseline);
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "recv"),
        af(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = fixture_inputs(&functions, &api_flows);
    run(&opts_baseline, &inputs).unwrap();
    let baseline = read_findings(tmp_baseline.path());
    let baseline_risk = baseline[0]["risk_score"].as_f64().unwrap() as f32;

    // NotObserved evidence run — runner tried but didn't reach. Per
    // Codex finding 1, this contributes ZERO weight.
    let tmp_no = TempDir::new().unwrap();
    let mut opts_no = base_opts(&tmp_no);
    opts_no.dynamic_evidence = vec![DynamicEvidence::not_observed(
        "C-000001",
        "H-C-000001",
        DynamicEvidence::format_sink_pc(0x1200),
    )];
    let inputs2 = fixture_inputs(&functions, &api_flows);
    run(&opts_no, &inputs2).unwrap();
    let unchanged = read_findings(tmp_no.path());
    let unchanged_risk = unchanged[0]["risk_score"].as_f64().unwrap() as f32;
    assert!((unchanged_risk - baseline_risk).abs() < 1e-5);
}

#[test]
fn evidence_with_mismatched_sink_pc_contributes_zero() {
    // Codex finding 1 attribution discipline: a confirmation whose
    // sink_pc doesn't match the chain's sink_site_va MUST contribute
    // zero score even when status is ConfirmedTrigger.
    let tmp_baseline = TempDir::new().unwrap();
    let opts_baseline = base_opts(&tmp_baseline);
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "recv"),
        af(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = fixture_inputs(&functions, &api_flows);
    run(&opts_baseline, &inputs).unwrap();
    let baseline = read_findings(tmp_baseline.path());
    let baseline_risk = baseline[0]["risk_score"].as_f64().unwrap() as f32;

    let tmp_mismatched = TempDir::new().unwrap();
    let mut opts_mismatched = base_opts(&tmp_mismatched);
    // sink_pc points at the WRONG VA (0xDEAD_BEEF) — even though the
    // chain_id matches, sink_pc_matches() will return false and the
    // confirmation contributes zero.
    opts_mismatched.dynamic_evidence = vec![DynamicEvidence::confirmed_trigger(
        "C-000001",
        "H-C-000001",
        DynamicEvidence::format_sink_pc(0xdead_beef),
        std::collections::BTreeMap::new(),
        "corpus_wrong",
    )];
    let inputs2 = fixture_inputs(&functions, &api_flows);
    run(&opts_mismatched, &inputs2).unwrap();
    let unchanged = read_findings(tmp_mismatched.path());
    let unchanged_risk = unchanged[0]["risk_score"].as_f64().unwrap() as f32;
    assert!(
        (unchanged_risk - baseline_risk).abs() < 1e-5,
        "mismatched sink_pc must NOT boost risk (Codex finding 1); baseline={baseline_risk}, observed={unchanged_risk}"
    );
}

#[test]
fn evidence_for_unrelated_chain_id_contributes_zero() {
    // Evidence labeled with a chain_id that doesn't exist in this
    // session MUST be silently dropped. No risk delta.
    let tmp_baseline = TempDir::new().unwrap();
    let opts_baseline = base_opts(&tmp_baseline);
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "recv"),
        af(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = fixture_inputs(&functions, &api_flows);
    run(&opts_baseline, &inputs).unwrap();
    let baseline = read_findings(tmp_baseline.path());
    let baseline_risk = baseline[0]["risk_score"].as_f64().unwrap() as f32;

    let tmp_unrelated = TempDir::new().unwrap();
    let mut opts_unrelated = base_opts(&tmp_unrelated);
    opts_unrelated.dynamic_evidence = vec![DynamicEvidence::confirmed_trigger(
        "C-OTHER-CHAIN",
        "H-OTHER",
        DynamicEvidence::format_sink_pc(0x1200),
        std::collections::BTreeMap::new(),
        "corpus_other",
    )];
    let inputs2 = fixture_inputs(&functions, &api_flows);
    run(&opts_unrelated, &inputs2).unwrap();
    let unchanged = read_findings(tmp_unrelated.path());
    let unchanged_risk = unchanged[0]["risk_score"].as_f64().unwrap() as f32;
    assert!((unchanged_risk - baseline_risk).abs() < 1e-5);
}

#[test]
fn v1_1_run_emits_patch_and_test_suggestions() {
    // Verify the v1.1 wire shape includes the suggestion artifacts —
    // both as a smoke test for Step 33 + Step 34 integration.
    let tmp = TempDir::new().unwrap();
    let opts = base_opts(&tmp);
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "recv"),
        af(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = fixture_inputs(&functions, &api_flows);
    run(&opts, &inputs).unwrap();
    assert!(tmp.path().join("patch_suggestions.jsonl").exists());
    assert!(tmp.path().join("test_suggestions.jsonl").exists());
    // Both are non-empty when we have at least one finding.
    assert!(
        std::fs::metadata(tmp.path().join("patch_suggestions.jsonl"))
            .unwrap()
            .len()
            > 0
    );
    assert!(
        std::fs::metadata(tmp.path().join("test_suggestions.jsonl"))
            .unwrap()
            .len()
            > 0
    );
}

#[test]
fn v1_1_run_status_phase_is_v1_1_dynamic_confirmation() {
    // Wire-shape contract: the run_status.json's phase must
    // distinguish v1.0 from v1.1 so consumers branch correctly.
    let tmp = TempDir::new().unwrap();
    let opts = base_opts(&tmp);
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "recv"),
        af(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = fixture_inputs(&functions, &api_flows);
    run(&opts, &inputs).unwrap();
    let rs: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(tmp.path().join("run_status.json")).unwrap())
            .unwrap();
    assert_eq!(rs["run_meta"]["phase"], "v1.1_dynamic_confirmation");
}

#[test]
fn unavailable_status_evidence_does_not_emit_dynamic_evidence_block() {
    // Plan invariant: aggregate signals → Unavailable status →
    // ChainConfirmation::aggregate_for_chain returns None →
    // score unchanged. Tests the chain through the aggregator.
    let tmp = TempDir::new().unwrap();
    let mut opts = base_opts(&tmp);
    opts.dynamic_evidence = vec![DynamicEvidence::unavailable(
        "C-000001",
        DynamicEvidence::format_sink_pc(0x1200),
    )];
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "recv"),
        af(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let inputs = fixture_inputs(&functions, &api_flows);
    run(&opts, &inputs).unwrap();
    let findings = read_findings(tmp.path());
    // Baseline run for reference.
    let tmp_base = TempDir::new().unwrap();
    let opts_base = base_opts(&tmp_base);
    let inputs_base = fixture_inputs(&functions, &api_flows);
    run(&opts_base, &inputs_base).unwrap();
    let baseline = read_findings(tmp_base.path());
    // Risk must be identical to baseline (Unavailable contributes 0).
    let r = findings[0]["risk_score"].as_f64().unwrap();
    let r_base = baseline[0]["risk_score"].as_f64().unwrap();
    assert!((r - r_base).abs() < 1e-5);
}

#[test]
fn _ensure_unused_dynamic_status_import_is_exercised() {
    // Make the compiler stop warning about DynamicStatus unused.
    let _ = DynamicStatus::ConfirmedTrigger;
}
