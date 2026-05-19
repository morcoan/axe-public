#![cfg(feature = "vuln-discovery")]

use std::collections::BTreeMap;
use std::fs;

use axe_core::vuln::dynamic_evidence::DynamicEvidence;
use axe_core::vuln::session::{run, VulnInputs};
use axe_core::vuln::{HarnessTierMode, VulnOptions};
use axe_core::{ApiFlowRecord, FunctionRecord};
use serde_json::Value;
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

#[test]
fn v1_1_emits_llm_ready_proof_packets_for_confirmed_chains() {
    let tmp = TempDir::new().unwrap();
    let functions = vec![func(0x1000)];
    let api_flows = vec![
        af(0x1000, 0x1100, "recv"),
        af(0x1000, 0x1200, "WriteProcessMemory"),
    ];
    let mut observed = BTreeMap::new();
    observed.insert("n".to_string(), Value::from(1024));
    observed.insert("dst_capacity_inferred".to_string(), Value::from(256));
    let opts = VulnOptions {
        out_dir: tmp.path().to_path_buf(),
        enable_v1_1: true,
        harness_tier: HarnessTierMode::SkeletonOnly,
        dynamic_evidence: vec![DynamicEvidence::confirmed_trigger(
            "C-000001",
            "H-C-000001",
            DynamicEvidence::format_sink_pc(0x1200),
            observed,
            "unit_reproducer_001",
        )],
        dynamic_confirmation_sources: "all".to_string(),
        ..Default::default()
    };
    let inputs = VulnInputs {
        run_id: "test-run",
        functions: &functions,
        api_flows: &api_flows,
        ..Default::default()
    };

    let report = run(&opts, &inputs).unwrap();
    assert!(report.findings_emitted >= 1);

    let manifest_path = tmp.path().join("vuln_packets").join("manifest.json");
    let manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read proof manifest")).unwrap();
    assert_eq!(
        manifest["schema"],
        "vuln_discovery.proof_packet_manifest.v1"
    );
    assert!(
        manifest["packet_count"].as_u64().unwrap_or(0) >= 1,
        "expected at least one packet entry"
    );

    let first_path = manifest["packets"][0]["path"].as_str().unwrap();
    let packet_path = tmp.path().join(first_path);
    let packet: Value =
        serde_json::from_slice(&fs::read(&packet_path).expect("read first proof packet")).unwrap();
    assert_eq!(packet["schema"], "vuln_discovery.proof_packet.v1");
    assert_eq!(packet["run_id"], "test-run");
    assert!(packet["finding_id"].as_str().unwrap().starts_with("F-"));
    assert!(packet["chain_id"].as_str().unwrap().starts_with("C-"));
    assert_eq!(
        packet["source_to_sink_chain"]["sink_api"],
        "WriteProcessMemory"
    );
    assert!(
        packet["why_this_function_matters"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );
    assert!(
        !packet["all_evidence_touching_this_sink"]
            .as_array()
            .unwrap()
            .is_empty(),
        "packet should include API evidence around the sink"
    );
    assert_eq!(
        packet["dynamic_confirmation"]["status"],
        "confirmed_trigger"
    );
    assert_eq!(
        packet["dynamic_confirmation"]["reproducer_ids"][0],
        "unit_reproducer_001"
    );
    assert!(packet["harness"]["skeleton_path"]
        .as_str()
        .unwrap()
        .ends_with(".skeleton.md"));
    assert!(!packet["what_to_verify_dynamically_next"]
        .as_array()
        .unwrap()
        .is_empty());
}
