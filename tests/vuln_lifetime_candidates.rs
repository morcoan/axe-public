//! v1.1 lifetime-candidates integration test (Step 36).
//!
//! Validates Codex round-1 finding 3 end-to-end through the session
//! orchestrator:
//! - Without `--vuln-include-lifetime`, no UAF/double-free template
//!   loads; `lifetime_candidates.jsonl` is NOT emitted.
//! - With the flag on AND the `vuln-discovery-lifetime` feature
//!   compiled, lifetime findings emit to
//!   `lifetime_candidates.jsonl` ONLY — never `findings.jsonl`.
//! - `evidence_bundle.json::top_findings` EXCLUDES lifetime fact ids
//!   even when those findings have the highest risk_score.

#![cfg(feature = "vuln-discovery-lifetime")]

use axe_core::vuln::session::{run, VulnInputs};
use axe_core::vuln::{HarnessTierMode, VulnOptions};
use axe_core::{ApiFlowRecord, DataflowEdgeRecord, FunctionRecord, SsaValueRecord};
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

fn ssa(id: &str, va: u64) -> SsaValueRecord {
    SsaValueRecord {
        ssa_id: id.into(),
        function: 0x1000,
        block: Some(0x1000),
        site_va: va,
        storage: "rax".into(),
        version: 1,
        kind: "def".into(),
        source: "test".into(),
        value: None,
        evidence: vec![],
        confidence: "medium".into(),
    }
}

fn dflow(from: &str, to: &str) -> DataflowEdgeRecord {
    DataflowEdgeRecord {
        edge_id: format!("e_{from}_{to}"),
        function: 0x1000,
        from_value: Some(from.into()),
        to_value: to.into(),
        from_va: None,
        to_va: 0x2000,
        from_storage: None,
        to_storage: "rax".into(),
        edge_kind: "def_use".into(),
        type_tag: None,
        evidence: vec![],
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
        argument_name: Some("ptr".into()),
        confidence: "high".into(),
        mode: "static".into(),
        resolved_api: None,
        wrapper_chain: vec![],
        evidence: vec![],
    }
}

/// Build a fixture with a UAF shape: malloc returns pointer `p`,
/// free takes `p_for_free` (aliased to `p`), and memcpy takes
/// `p_for_use` (also aliased to `p`). `discover_lifetime_candidates`
/// fires uaf_candidate because free's pointer is in the same SSA
/// alias class as a non-free CallSite's pointer.
///
/// All three SSA values share `storage = "rax"` so they pass the
/// caller-saved-register filter in `ingest_callsite_ssa_bridge`.
/// Each SSA value's site_va matches the corresponding callsite's va
/// so the bridge wires them together within the ±16-byte window.
fn uaf_fixture_inputs() -> (
    Vec<FunctionRecord>,
    Vec<ApiFlowRecord>,
    Vec<SsaValueRecord>,
    Vec<DataflowEdgeRecord>,
) {
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "malloc"),
        af(0x1000, 0x1200, "free"),
        af(0x1000, 0x1300, "memcpy"),
    ];
    let ssa_records = vec![
        ssa("p", 0x1100),
        ssa("p_for_free", 0x1200),
        ssa("p_for_use", 0x1300),
    ];
    // Connect p → p_for_free and p → p_for_use so alias.rs clusters
    // all three into the same equivalence class.
    let dataflow = vec![dflow("p", "p_for_free"), dflow("p", "p_for_use")];
    (functions, api_flows, ssa_records, dataflow)
}

fn fixture_inputs<'a>(
    functions: &'a [FunctionRecord],
    api_flows: &'a [ApiFlowRecord],
    ssa_records: &'a [SsaValueRecord],
    dataflow: &'a [DataflowEdgeRecord],
) -> VulnInputs<'a> {
    VulnInputs {
        run_id: "test-run",
        functions,
        api_flows,
        ssa: ssa_records,
        dataflow,
        ..Default::default()
    }
}

#[test]
fn include_lifetime_off_does_not_emit_lifetime_candidates_jsonl() {
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        include_lifetime: false, // flag OFF
        harness_tier: HarnessTierMode::SkeletonOnly,
        ..Default::default()
    };
    let (functions, api_flows, ssa_records, dataflow) = uaf_fixture_inputs();
    let inputs = fixture_inputs(&functions, &api_flows, &ssa_records, &dataflow);
    run(&opts, &inputs).unwrap();
    // The file must NOT be created when the flag is off.
    assert!(
        !tmp.path().join("lifetime_candidates.jsonl").exists(),
        "lifetime_candidates.jsonl emitted despite --vuln-include-lifetime being off"
    );
}

#[test]
fn include_lifetime_on_routes_uaf_to_lifetime_candidates_jsonl() {
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        include_lifetime: true, // flag ON
        harness_tier: HarnessTierMode::SkeletonOnly,
        ..Default::default()
    };
    let (functions, api_flows, ssa_records, dataflow) = uaf_fixture_inputs();
    let inputs = fixture_inputs(&functions, &api_flows, &ssa_records, &dataflow);
    run(&opts, &inputs).unwrap();
    let lifetime_path = tmp.path().join("lifetime_candidates.jsonl");
    assert!(
        lifetime_path.exists(),
        "lifetime_candidates.jsonl was not emitted with include_lifetime=true"
    );
    let content = std::fs::read_to_string(&lifetime_path).unwrap();
    // At least one record (the uaf_candidate from the fixture).
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "lifetime_candidates.jsonl is empty");
    // Every record's bug_class is a lifetime template id.
    for line in &lines {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        let bc = parsed["bug_class"].as_str().unwrap();
        assert!(
            bc == "uaf_candidate" || bc == "double_free_candidate",
            "non-lifetime bug_class {bc} leaked into lifetime_candidates.jsonl"
        );
    }
}

#[test]
fn lifetime_findings_are_absent_from_findings_jsonl_by_construction() {
    // Codex finding 3 enforcement: even when both files exist,
    // findings.jsonl must NOT carry lifetime bug_class entries.
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        include_lifetime: true,
        harness_tier: HarnessTierMode::SkeletonOnly,
        ..Default::default()
    };
    let (functions, api_flows, ssa_records, dataflow) = uaf_fixture_inputs();
    let inputs = fixture_inputs(&functions, &api_flows, &ssa_records, &dataflow);
    run(&opts, &inputs).unwrap();
    let findings_path = tmp.path().join("findings.jsonl");
    let content = std::fs::read_to_string(&findings_path).unwrap_or_default();
    for line in content.lines().filter(|l| !l.is_empty()) {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        let bc = parsed["bug_class"].as_str().unwrap();
        assert!(
            bc != "uaf_candidate" && bc != "double_free_candidate",
            "lifetime bug_class {bc} leaked into findings.jsonl"
        );
    }
}

#[test]
fn evidence_bundle_top_findings_excludes_lifetime_ids_even_with_highest_risk() {
    // Wire shape contract: even if a lifetime finding has the
    // HIGHEST risk in the run, it MUST NOT appear in top_findings.
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        include_lifetime: true,
        harness_tier: HarnessTierMode::SkeletonOnly,
        ..Default::default()
    };
    let (functions, api_flows, ssa_records, dataflow) = uaf_fixture_inputs();
    let inputs = fixture_inputs(&functions, &api_flows, &ssa_records, &dataflow);
    run(&opts, &inputs).unwrap();
    let bundle_path = tmp.path().join("evidence_bundle.json");
    let bundle: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&bundle_path).unwrap()).unwrap();
    let top: Vec<String> = bundle["top_findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    // Lifetime finding ids look like "F-NNNNNN" too — we can't filter
    // by id pattern alone. Instead: assert top_findings is a strict
    // subset of the IDs present in findings.jsonl (which excludes
    // lifetime by construction).
    let findings = std::fs::read_to_string(tmp.path().join("findings.jsonl")).unwrap_or_default();
    let allowed_ids: std::collections::HashSet<String> = findings
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let p: serde_json::Value = serde_json::from_str(l).unwrap();
            p["finding_id"].as_str().unwrap().to_string()
        })
        .collect();
    for id in &top {
        assert!(
            allowed_ids.contains(id),
            "top_findings id {id} not in findings.jsonl — must be a lifetime id leaked into top-N"
        );
    }
}

#[test]
fn safe_pattern_fixture_produces_no_lifetime_candidates() {
    // Codex finding 3 negative-fixture discipline at the integration
    // level: a safe-cleanup pattern (alloc → free with no other use)
    // must NOT produce any UAF candidate.
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        include_lifetime: true,
        harness_tier: HarnessTierMode::SkeletonOnly,
        ..Default::default()
    };
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "malloc"),
        af(0x1000, 0x1200, "free"),
        // Note: no third callsite — clean alloc + free pattern.
    ];
    let ssa_records = vec![ssa("p", 0x1100)];
    let dataflow = vec![dflow("p", "p")];
    let inputs = fixture_inputs(&functions, &api_flows, &ssa_records, &dataflow);
    run(&opts, &inputs).unwrap();
    // Either the file doesn't exist or it's empty — both are
    // acceptable "no candidates" wire shapes.
    let p = tmp.path().join("lifetime_candidates.jsonl");
    if p.exists() {
        let content = std::fs::read_to_string(&p).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        assert!(
            lines.is_empty(),
            "safe alloc+free pattern produced UAF candidate(s): {content}"
        );
    }
}

#[test]
fn lifetime_candidates_jsonl_carries_candidate_tier_marker() {
    // Defense in depth: the wire shape MUST show evidence_tier =
    // candidate so an LLM consumer who misroutes a lifetime record
    // still sees the tier downgrade.
    let tmp = TempDir::new().unwrap();
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        include_lifetime: true,
        harness_tier: HarnessTierMode::SkeletonOnly,
        ..Default::default()
    };
    let (functions, api_flows, ssa_records, dataflow) = uaf_fixture_inputs();
    let inputs = fixture_inputs(&functions, &api_flows, &ssa_records, &dataflow);
    run(&opts, &inputs).unwrap();
    let content = std::fs::read_to_string(tmp.path().join("lifetime_candidates.jsonl")).unwrap();
    for line in content.lines().filter(|l| !l.is_empty()) {
        let p: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(p["evidence_tier"], "candidate");
    }
}
