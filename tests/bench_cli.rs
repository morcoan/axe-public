#![cfg(feature = "vuln-discovery")]

use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const TINY_X64_CODE: &[u8] = &[0x31, 0xC0, 0xC3];

#[test]
fn axe_bench_emits_summary_cases_findings_and_report() {
    let tmp = TempDir::new().expect("tempdir");
    let fixture = tmp.path().join("clean.elf");
    write_minimal_elf(&fixture);
    let manifest = tmp.path().join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "axe_benchmark_manifest/1",
            "cases": [{
                "id": "clean-elf",
                "path": fixture,
                "corpus": "local",
                "expected_clean": true,
                "expected_signatures": [],
                "top_k": 5
            }]
        }))
        .unwrap(),
    )
    .expect("write manifest");
    let out = tmp.path().join("bench");

    assert_cmd::Command::cargo_bin("axe-bench")
        .expect("axe-bench bin")
        .arg("--manifest")
        .arg(&manifest)
        .arg("--out")
        .arg(&out)
        .arg("--preset")
        .arg("real-5")
        .assert()
        .success();

    for name in [
        "benchmark_summary.json",
        "benchmark_cases.jsonl",
        "benchmark_findings.jsonl",
        "benchmark_report.md",
    ] {
        assert!(out.join(name).is_file(), "missing {name}");
    }

    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("benchmark_summary.json")).unwrap()).unwrap();
    assert_eq!(summary["schema"], "axe_benchmark_summary/1");
    assert_eq!(summary["case_count"], 1);
    assert_eq!(summary["real_5_gate"], "fail");
    assert_eq!(
        summary["skipped_dynamic_source_counted_as_confirmation"],
        false
    );
}

#[test]
fn axe_bench_rejects_wrong_manifest_schema() {
    let tmp = TempDir::new().expect("tempdir");
    let manifest = tmp.path().join("manifest.json");
    fs::write(&manifest, r#"{"schema":"wrong","cases":[]}"#).expect("write manifest");

    assert_cmd::Command::cargo_bin("axe-bench")
        .expect("axe-bench bin")
        .arg("--manifest")
        .arg(&manifest)
        .arg("--out")
        .arg(tmp.path().join("bench"))
        .assert()
        .failure()
        .stderr(predicates::str::contains("axe_benchmark_manifest/1"));
}

#[test]
fn axe_bench_real_9_does_not_execute_dynamic_probe_without_safety_flag() {
    let tmp = TempDir::new().expect("tempdir");
    let fixture = tmp.path().join("clean.elf");
    write_minimal_elf(&fixture);
    let manifest = tmp.path().join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "axe_benchmark_manifest/1",
            "cases": [{
                "id": "real9-no-exec",
                "path": fixture,
                "corpus": "source_built_real9",
                "expected_clean": true,
                "dynamic_probe": {
                    "argv": ["--should-not-run"],
                    "evidence_source": "debug_probe",
                    "status": "reached_only"
                },
                "require_dynamic_confirmation": true,
                "top_k": 5
            }]
        }))
        .unwrap(),
    )
    .expect("write manifest");
    let out = tmp.path().join("bench");

    assert_cmd::Command::cargo_bin("axe-bench")
        .expect("axe-bench bin")
        .arg("--manifest")
        .arg(&manifest)
        .arg("--out")
        .arg(&out)
        .arg("--preset")
        .arg("real-9")
        .assert()
        .success();

    assert!(
        !out.join("cases")
            .join("real9-no-exec")
            .join("dynamic_probe.json")
            .exists(),
        "Real-9 must not execute dynamic probes without the explicit safety flag"
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("benchmark_summary.json")).unwrap()).unwrap();
    assert!(
        summary["real_9_gate_reasons"]
            .as_array()
            .is_some_and(|reasons| {
                reasons
                    .iter()
                    .any(|reason| reason == "vulnerable_fixture_execution_not_allowed")
            }),
        "Real-9 summary should expose the safety gate reason"
    );
}

#[test]
fn axe_bench_real_9_reports_external_sources_not_staged() {
    let tmp = TempDir::new().expect("tempdir");
    let manifest = tmp.path().join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "axe_benchmark_manifest/1",
            "cases": [{
                "id": "real9-source-not-staged",
                "path": tmp.path().join("missing-target.exe"),
                "corpus": "source_built_real9_external",
                "vuln_id": "CVE-2099-0001",
                "source_url": "https://github.com/example/project.git",
                "source_ref": "0123456789abcdef0123456789abcdef01234567",
                "expected_clean": false,
                "expected_findings": [{
                    "id": "expected",
                    "bug_class": "unchecked_copy_length"
                }]
            }]
        }))
        .unwrap(),
    )
    .expect("write manifest");
    let out = tmp.path().join("bench");

    assert_cmd::Command::cargo_bin("axe-bench")
        .expect("axe-bench bin")
        .arg("--manifest")
        .arg(&manifest)
        .arg("--out")
        .arg(&out)
        .arg("--preset")
        .arg("real-9")
        .assert()
        .success();

    let stage: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("real9_stage.json")).unwrap()).unwrap();
    assert_eq!(stage["schema"], "axe_real9_stage/1");
    assert_eq!(stage["mode"], "off");
    assert_eq!(stage["status"], "not_requested");
    assert_eq!(stage["cases"][0]["status"], "not_requested");

    let grade: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("real9_grade.json")).unwrap()).unwrap();
    assert!(
        grade["gate_reasons"].as_array().is_some_and(|reasons| {
            reasons
                .iter()
                .any(|reason| reason == "external_sources_not_staged")
        }),
        "Real-9 grade should make external source staging a visible gate reason"
    );
}

#[test]
fn axe_bench_real_9_stage_fetch_refuses_unpinned_source_refs() {
    let tmp = TempDir::new().expect("tempdir");
    let manifest = tmp.path().join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "axe_benchmark_manifest/1",
            "cases": [{
                "id": "real9-manual-ref",
                "path": tmp.path().join("missing-target.exe"),
                "corpus": "source_built_real9_clean_baseline",
                "source_url": "https://example.invalid/project.git",
                "source_ref": "fixed-release",
                "expected_clean": true,
                "expected_findings": [],
                "false_positive_cap": 0
            }]
        }))
        .unwrap(),
    )
    .expect("write manifest");
    let out = tmp.path().join("bench");

    assert_cmd::Command::cargo_bin("axe-bench")
        .expect("axe-bench bin")
        .arg("--manifest")
        .arg(&manifest)
        .arg("--out")
        .arg(&out)
        .arg("--preset")
        .arg("real-9")
        .arg("--real9-stage")
        .arg("fetch")
        .arg("--real9-source-root")
        .arg(tmp.path().join("sources"))
        .assert()
        .success();

    let stage: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("real9_stage.json")).unwrap()).unwrap();
    assert_eq!(stage["mode"], "fetch");
    assert_eq!(stage["cases"][0]["status"], "manual_source_ref");
    assert!(
        stage["cases"][0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("40-character git SHA")),
        "unpinned refs should be reported before any network fetch"
    );
}

#[test]
fn axe_bench_scores_real_5_ctf_packet_and_dynamic_requirements() {
    let target = Path::new("calibration_runs/ctf_targets/vuln_ctf.exe");
    if !target.is_file() {
        eprintln!("skipping axe-bench CTF test: {target:?} is not present");
        return;
    }

    let tmp = TempDir::new().expect("tempdir");
    let manifest = tmp.path().join("manifest.json");
    let target_abs = fs::canonicalize(target).expect("canonicalize CTF target");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "axe_benchmark_manifest/1",
            "cases": [{
                "id": "ctf-vuln",
                "path": target_abs,
                "corpus": "controlled_ctf",
                "expected_clean": false,
                "expected_findings": [{
                    "id": "ctf_packet_memcpy",
                    "bug_class": "unchecked_copy_length",
                    "source_kind": "network_recv",
                    "sink_api": "memcpy",
                    "min_dynamic_status": "confirmed_trigger",
                    "require_proof_packet": true,
                    "required_evidence_source": "controlled_fixture",
                    "collapse_key": "unchecked_copy_length:network_recv:memcpy",
                    "min_rank": 10,
                    "allow_duplicate_matches": true
                }, {
                    "id": "ctf_request_malloc",
                    "bug_class": "tainted_allocation_size",
                    "source_kind": "network_recv",
                    "sink_api": "malloc",
                    "min_dynamic_status": "confirmed_trigger",
                    "require_proof_packet": true,
                    "required_evidence_source": "controlled_fixture",
                    "collapse_key": "tainted_allocation_size:network_recv:malloc",
                    "min_rank": 10,
                    "allow_duplicate_matches": true
                }, {
                    "id": "ctf_log_format_string",
                    "bug_class": "format_string_controlled",
                    "source_kind": "network_recv",
                    "sink_api": "__stdio_common_vfprintf",
                    "min_dynamic_status": "confirmed_trigger",
                    "require_proof_packet": true,
                    "required_evidence_source": "controlled_fixture",
                    "collapse_key": "format_string_controlled:network_recv:__stdio_common_vfprintf",
                    "min_rank": 10,
                    "allow_duplicate_matches": true
                }],
                "require_dynamic_confirmation": true,
                "require_proof_packets": true,
                "top_k": 10
            }]
        }))
        .unwrap(),
    )
    .expect("write manifest");
    let out = tmp.path().join("bench");

    assert_cmd::Command::cargo_bin("axe-bench")
        .expect("axe-bench bin")
        .arg("--manifest")
        .arg(&manifest)
        .arg("--out")
        .arg(&out)
        .arg("--preset")
        .arg("real-5")
        .assert()
        .success();

    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("benchmark_summary.json")).unwrap()).unwrap();
    assert_eq!(summary["real_5_gate"], "pass");
    assert_eq!(summary["requirement_failures"], 0);

    let cases_text = fs::read_to_string(out.join("benchmark_cases.jsonl")).unwrap();
    let case: serde_json::Value = serde_json::from_str(cases_text.lines().next().unwrap()).unwrap();
    assert_eq!(case["matched_expected_findings"], 3);
    assert_eq!(case["requirements_met"], true);
    assert_eq!(case["missed_expected_findings"], serde_json::json!([]));
    assert_eq!(case["false_positive_findings"], serde_json::json!([]));
    assert_eq!(case["collapsed_precision"], 1.0);
    assert_eq!(case["gate_reasons"], serde_json::json!([]));
    assert!(
        case["duplicate_matches"].as_array().is_some(),
        "case output should expose duplicate expected matches"
    );
    assert!(
        case["proof_packets_present"].as_u64().unwrap_or(0) > 0,
        "bench case should count proof packets"
    );
    assert!(
        case["dynamic_confirmed_findings"].as_u64().unwrap_or(0) > 0,
        "bench case should count dynamic confirmations"
    );

    let findings_text = fs::read_to_string(out.join("benchmark_findings.jsonl")).unwrap();
    assert!(
        findings_text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .any(|row| {
                row["matched_expected_finding"] == true
                    && row["proof_packet_present"] == true
                    && row["dynamic_status"] == "confirmed_trigger"
                    && row["evidence_sources"].as_array().is_some_and(|sources| {
                        sources.iter().any(|source| source == "controlled_fixture")
                    })
            }),
        "expected a matched finding with packet and confirmed dynamic status"
    );
}

#[test]
fn axe_bench_real_8_probe_reports_non_controlled_dynamic_evidence() {
    let target = Path::new("calibration_runs/ctf_targets/vuln_ctf.exe");
    if !target.is_file() {
        eprintln!("skipping axe-bench real-8 probe test: {target:?} is not present");
        return;
    }

    let tmp = TempDir::new().expect("tempdir");
    let manifest = tmp.path().join("manifest.json");
    let target_abs = fs::canonicalize(target).expect("canonicalize CTF target");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "axe_benchmark_manifest/1",
            "cases": [{
                "id": "real8-probed-ctf",
                "path": target_abs,
                "corpus": "real8_probe_smoke",
                "expected_clean": false,
                "dynamic_probe": {
                    "argv": ["--axe-probe"],
                    "evidence_source": "safe_fixture_probe",
                    "status": "reached_only",
                    "observed": {
                        "probe": "argv --axe-probe"
                    }
                },
                "expected_findings": [{
                    "id": "real8_probe_packet_memcpy",
                    "bug_class": "unchecked_copy_length",
                    "source_kind": "network_recv",
                    "sink_api": "memcpy",
                    "min_dynamic_status": "reached_only",
                    "require_proof_packet": true,
                    "required_evidence_source": "safe_fixture_probe",
                    "collapse_key": "unchecked_copy_length:network_recv:memcpy",
                    "min_rank": 10
                }],
                "require_dynamic_confirmation": true,
                "require_proof_packets": true,
                "top_k": 10
            }]
        }))
        .unwrap(),
    )
    .expect("write manifest");
    let out = tmp.path().join("bench");

    assert_cmd::Command::cargo_bin("axe-bench")
        .expect("axe-bench bin")
        .arg("--manifest")
        .arg(&manifest)
        .arg("--out")
        .arg(&out)
        .arg("--preset")
        .arg("real-8")
        .assert()
        .success();

    let summary: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("benchmark_summary.json")).unwrap()).unwrap();
    assert_eq!(summary["preset"], "real-8");
    assert_eq!(summary["real_8_gate"], "fail");
    assert!(
        summary["real_8_gate_reasons"]
            .as_array()
            .is_some_and(|reasons| reasons.iter().any(|reason| reason == "min_completed_cases")),
        "single-case smoke should fail real-8 breadth gate"
    );
    assert!(
        summary["non_controlled_dynamic_confirmed_findings"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "real-8 probe evidence should not be counted as controlled_fixture"
    );
    assert!(
        summary["dynamic_evidence_source_counts"]["safe_fixture_probe"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "summary should expose safe_fixture_probe evidence counts"
    );

    let findings_text = fs::read_to_string(out.join("benchmark_findings.jsonl")).unwrap();
    assert!(
        findings_text
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .any(|row| {
                row["matched_expected_finding"] == true
                    && row["dynamic_status"] == "reached_only"
                    && row["evidence_sources"].as_array().is_some_and(|sources| {
                        sources.iter().any(|source| source == "safe_fixture_probe")
                    })
            }),
        "expected a matched finding with real-8 safe fixture probe evidence"
    );
}

fn write_minimal_elf(path: &Path) {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text_id = obj.section_id(StandardSection::Text);
    let offset = obj.append_section_data(text_id, TINY_X64_CODE, 16);
    obj.add_symbol(Symbol {
        name: b"_start".to_vec(),
        value: offset,
        size: TINY_X64_CODE.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text_id),
        flags: SymbolFlags::None,
    });
    let bytes = obj.write().expect("write elf");
    fs::write(path, bytes).expect("write fixture");
}
