#![cfg(feature = "vuln-discovery")]

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn newest_run_dir(root: &Path) -> PathBuf {
    let mut dirs: Vec<_> = fs::read_dir(root)
        .expect("read out root")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .collect();
    dirs.sort_by_key(|entry| entry.file_name());
    dirs.pop().expect("axe should create a run dir").path()
}

#[test]
fn real_5_ctf_smoke_emits_closed_v1_1_packets_with_bounded_dynamic_evidence() {
    let target = Path::new("calibration_runs/ctf_targets/vuln_ctf.exe");
    if !target.is_file() {
        eprintln!("skipping real-5 CTF smoke: {target:?} is not present");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    assert_cmd::Command::cargo_bin("axe")
        .expect("axe bin")
        .arg(target)
        .arg("--preset")
        .arg("real-5")
        .arg("--vuln-discovery")
        .arg("on")
        .arg("--out-root")
        .arg(tmp.path())
        .assert()
        .success();

    let run_dir = newest_run_dir(tmp.path());
    let analysis: Value = serde_json::from_slice(
        &fs::read(run_dir.join("analysis.json")).expect("read analysis.json"),
    )
    .expect("parse analysis.json");
    assert_eq!(
        analysis.pointer("/options/preset"),
        Some(&Value::String("real-5".into()))
    );
    assert_eq!(
        analysis.pointer("/options/vuln_dynamic_confirmation"),
        Some(&Value::String("all".into()))
    );
    assert_eq!(
        analysis.pointer("/options/vuln_include_lifetime"),
        Some(&Value::Bool(true))
    );

    let vuln_dir = run_dir.join("vuln");
    let run_status: Value = serde_json::from_slice(
        &fs::read(vuln_dir.join("run_status.json")).expect("read vuln run_status.json"),
    )
    .expect("parse vuln run_status.json");
    assert_eq!(
        run_status.pointer("/run_meta/phase"),
        Some(&Value::String("v1.1_dynamic_confirmation".into()))
    );
    assert!(
        vuln_dir.join("harnesses").is_dir(),
        "missing v1.1 harnesses dir"
    );

    let dynamic_rows: Vec<Value> = fs::read_to_string(vuln_dir.join("dynamic_evidence.jsonl"))
        .expect("read dynamic_evidence.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse dynamic evidence row"))
        .collect();
    assert!(
        !dynamic_rows.is_empty(),
        "real-5 should emit dynamic evidence rows"
    );
    assert!(
        dynamic_rows.iter().any(|row| matches!(
            row.pointer("/status").and_then(Value::as_str),
            Some("confirmed_trigger" | "reached_only")
        )),
        "controlled CTF target should have at least one bounded dynamic confirmation: {dynamic_rows:?}"
    );
    assert!(
        dynamic_rows.iter().any(|row| {
            row.pointer("/evidence_source").and_then(Value::as_str) == Some("controlled_fixture")
        }),
        "controlled confirmations should expose evidence_source"
    );

    let dynamic_attempts: Vec<Value> = fs::read_to_string(vuln_dir.join("dynamic_attempts.jsonl"))
        .expect("read dynamic_attempts.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse dynamic attempt row"))
        .collect();
    assert!(
        dynamic_attempts.iter().any(|row| {
            row.pointer("/status").and_then(Value::as_str) == Some("confirmed_trigger")
                && row.pointer("/executor").and_then(Value::as_str) == Some("controlled_fixture")
                && row
                    .pointer("/evidence_refs")
                    .and_then(Value::as_array)
                    .is_some_and(|refs| {
                        refs.iter().any(|entry| {
                            entry
                                .as_str()
                                .is_some_and(|value| value.starts_with("dynamic_evidence.jsonl:"))
                        })
                    })
        }),
        "dynamic_attempts should explain confirmed controlled evidence"
    );
    assert!(
        dynamic_attempts.iter().any(|row| {
            row.pointer("/status").and_then(Value::as_str) == Some("unavailable")
                && row.pointer("/reason").and_then(Value::as_str).is_some()
        }),
        "binary-only chains without a runnable backend should produce unavailable attempts"
    );

    let findings =
        fs::read_to_string(vuln_dir.join("findings.jsonl")).expect("read findings.jsonl");
    assert!(
        !findings.trim().is_empty(),
        "CTF target should produce findings"
    );
    let parsed_findings: Vec<Value> = findings
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse finding row"))
        .collect();
    for bug_class in [
        "unchecked_copy_length",
        "tainted_allocation_size",
        "format_string_controlled",
    ] {
        assert!(
            parsed_findings
                .iter()
                .any(|row| row.pointer("/bug_class").and_then(Value::as_str) == Some(bug_class)),
            "missing planted CTF bug class {bug_class}"
        );
    }
    assert!(
        parsed_findings.iter().any(|row| matches!(
            row.pointer("/dynamic_evidence/status")
                .and_then(Value::as_str),
            Some("confirmed_trigger" | "reached_only")
        )),
        "ranked findings should carry exact dynamic provenance for confirmed chains"
    );
    assert!(
        parsed_findings.iter().any(|row| {
            row.pointer("/bug_class").and_then(Value::as_str) == Some("format_string_controlled")
                && row
                    .pointer("/dynamic_evidence/evidence_sources")
                    .and_then(Value::as_array)
                    .is_some_and(|sources| {
                        sources.iter().any(|source| source == "controlled_fixture")
                    })
        }),
        "format-string finding should carry controlled evidence source"
    );

    let packet_manifest_path = vuln_dir.join("vuln_packets").join("manifest.json");
    let packet_manifest: Value = serde_json::from_slice(
        &fs::read(&packet_manifest_path).expect("read vuln_packets manifest"),
    )
    .expect("parse vuln_packets manifest");
    assert_eq!(
        packet_manifest.pointer("/schema"),
        Some(&Value::String(
            "vuln_discovery.proof_packet_manifest.v1".into()
        ))
    );
    assert!(
        packet_manifest
            .pointer("/packet_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0,
        "proof packet manifest should list emitted packets"
    );
    assert!(
        packet_manifest
            .pointer("/packets")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .any(|entry| matches!(
                entry.pointer("/dynamic_status").and_then(Value::as_str),
                Some("confirmed_trigger" | "reached_only")
            )),
        "proof packet manifest should expose dynamic status per packet"
    );
}
