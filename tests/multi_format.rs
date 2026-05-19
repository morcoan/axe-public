//! Integration tests: ELF + Mach-O binaries flow through the full pipeline.
//!
//! Fixtures are synthesized at test time via `object::write` so the suite
//! is reproducible across platforms without checked-in binaries.

use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn default_options() -> axe_core::AnalysisOptions {
    axe_core::AnalysisOptions {
        preset: None,
        max_strings: 64,
        max_functions: 32,
        max_xrefs: 256,
        deep: true,
        precomputed_sha256: None,
        native_inner_workers: None,
        profile_analysis: false,
        semantic_level: "basic".to_string(),
        second_pass: "auto".to_string(),
        semantic_budget: "normal".to_string(),
        semantic_focus: "malware".to_string(),
        wrapper_collapse_depth: 4,
        pseudo_ir: "basic".to_string(),
        capability_profile: "native-max".to_string(),
        portable_tools_dir: "tools".to_string(),
        emulation_budget: "normal".to_string(),
        fuzz_mode: "off".to_string(),
        fuzz_iterations: 0,
        trace_dir: None,
        decompile_c: "off".to_string(),
        llm_artifacts: "all".to_string(),
        review_packs: "ranked".to_string(),
        decompile_source: "selected".to_string(),
        symbols: "basic".to_string(),
        symbol_packets: "ranked".to_string(),
        symbol_paths: Vec::new(),
        symbol_cache: None,
        progress_path: None,
        dynamic_trace_mode: "off".to_string(),
        dynamic_trace_duration_secs: 0,
        dynamic_trace_target: None,
        dynamic_trace_out: None,
        dynamic_trace_providers: String::new(),
        dynamic_trace_loss_policy: "partial".to_string(),
        vuln_discovery_mode: "off".to_string(),
        vuln_templates: "all".to_string(),
        vuln_confidence_threshold: 0.45,
        vuln_out: None,
        vuln_dynamic_confirmation: "off".to_string(),
        vuln_dynamic_evidence: Vec::new(),
        vuln_include_lifetime: false,
        vuln_harness_tier: "skeleton".to_string(),
        unpack_mode: "off".to_string(),
        unpack_tracer: "debug".to_string(),
        unpack_timeout_secs: 60,
        unpack_instr_budget: 100_000_000,
        unpack_out: None,
        unpack_hooks_disable: false,
        unpack_include_devirt: false,
    }
}

/// Minimal x86_64 instructions: `xor eax, eax; ret`. Two bytes each → 3 bytes total.
const TINY_X64_CODE: &[u8] = &[0x31, 0xC0, 0xC3];

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

fn write_minimal_macho(path: &Path) {
    let mut obj = Object::new(
        BinaryFormat::MachO,
        Architecture::X86_64,
        Endianness::Little,
    );
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
    let bytes = obj.write().expect("write macho");
    fs::write(path, bytes).expect("write fixture");
}

#[test]
fn elf_runs_full_pipeline_and_emits_analysis_json() {
    let tmp = TempDir::new().expect("tempdir");
    let fixture = tmp.path().join("tiny_x64.elf");
    write_minimal_elf(&fixture);

    let out_dir = tmp.path().join("out");
    let result = axe_core::analyze_path(
        fixture.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        default_options(),
    );
    assert!(result.is_ok(), "analyze failed: {:?}", result.err());

    let analysis_path = out_dir.join("analysis.json");
    assert!(
        analysis_path.is_file(),
        "expected analysis.json at {analysis_path:?}"
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&fs::read(&analysis_path).expect("read")).expect("json");
    let format = parsed.get("format").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        "elf", format,
        "analysis.json should report format=elf, got {parsed:?}"
    );
    assert!(parsed.get("sections").is_some(), "missing sections array");
    assert!(parsed.get("counts").is_some(), "missing counts block");

    let manifest_path = out_dir.join("analysis_manifest.json");
    assert!(manifest_path.is_file(), "missing analysis_manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest")).expect("json");
    assert_eq!(
        "llm_analysis_manifest/1",
        manifest
            .get("schema")
            .and_then(|v| v.as_str())
            .unwrap_or("")
    );
    assert!(manifest
        .get("recommended_reading_order")
        .and_then(|v| v.as_array())
        .is_some_and(|rows| rows.iter().any(|v| v == "graph/nodes.jsonl")));

    let nodes = read_jsonl(&out_dir.join("graph").join("nodes.jsonl"));
    let edges = read_jsonl(&out_dir.join("graph").join("edges.jsonl"));
    assert!(nodes.iter().any(|row| row["kind"] == "function"));
    assert!(nodes.iter().any(|row| row["kind"] == "symbol"));
    assert!(nodes.iter().any(|row| row["kind"] == "unsupported_lifter"));
    assert!(
        edges.iter().any(|row| row["kind"] == "contains")
            || edges.iter().any(|row| row["kind"] == "control_flow")
    );
    assert!(edges.iter().any(|row| row["kind"] == "resolves_symbol"));
    assert_graph_edges_resolve(&nodes, &edges);

    let symbols = read_jsonl(&out_dir.join("symbols.jsonl"));
    assert!(symbols
        .iter()
        .any(|row| row.get("name").and_then(|value| value.as_str()) == Some("_start")));
    assert!(out_dir.join("debug_modules.jsonl").is_file());
    assert!(out_dir.join("debug_identities.jsonl").is_file());
    assert!(out_dir.join("source_files.jsonl").is_file());
    assert!(out_dir.join("line_entries.jsonl").is_file());
    assert!(out_dir.join("symbol_uncertainty.jsonl").is_file());
    assert!(out_dir.join("symbol_graph.jsonl").is_file());
    assert!(out_dir.join("symbol_indexes.json").is_file());
    assert!(out_dir
        .join("symbol_packets")
        .join("manifest.json")
        .is_file());
    let symbol_graph = read_jsonl(&out_dir.join("symbol_graph.jsonl"));
    assert!(symbol_graph
        .iter()
        .any(|row| row.get("kind").and_then(|value| value.as_str()) == Some("function_symbol")));
    let indexes: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("symbol_indexes.json")).expect("read indexes"),
    )
    .expect("indexes json");
    assert!(indexes
        .get("address_range_index")
        .and_then(|value| value.as_array())
        .is_some_and(|rows| !rows.is_empty()));
    assert!(indexes
        .get("name_index")
        .and_then(|value| value.as_object())
        .is_some_and(|names| names.contains_key("_start")));
    let packet_manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(out_dir.join("symbol_packets").join("manifest.json")).expect("read packets"),
    )
    .expect("packet manifest");
    assert!(packet_manifest
        .get("packets")
        .and_then(|value| value.as_array())
        .is_some_and(|rows| !rows.is_empty()));

    let manifest_artifacts = manifest
        .get("artifact_index")
        .and_then(|value| value.as_array())
        .expect("artifact index");
    assert!(manifest_artifacts
        .iter()
        .any(|row| { row.get("path").and_then(|value| value.as_str()) == Some("symbols.jsonl") }));
    assert!(manifest_artifacts.iter().any(|row| {
        row.get("path").and_then(|value| value.as_str()) == Some("symbol_graph.jsonl")
    }));

    // Step 2: switches.jsonl is emitted and registered.
    // The trivial `xor eax, eax; ret` fixture has no switches, so the file
    // is expected to be an empty JSONL — that's genuine "no switches found"
    // because matchers are real (not stubs). The step-15 real-binary smoke
    // test asserts non-empty output on a binary that actually contains
    // switch statements.
    assert!(
        out_dir.join("switches.jsonl").is_file(),
        "missing switches.jsonl on disk"
    );
    let _switches_rows = read_jsonl(&out_dir.join("switches.jsonl"));
    assert!(
        manifest_artifacts.iter().any(|row| {
            row.get("path").and_then(|value| value.as_str()) == Some("switches.jsonl")
        }),
        "switches.jsonl missing from artifact_index"
    );

    // Step 4: eh.jsonl is emitted and registered. ELF fixtures hit the
    // early-return in eh::extract_eh (no PE → no MS EH), so an empty file
    // is genuine "no MSVC EH found" — the Itanium .eh_frame path lands in
    // step 6 and will populate this for ELF.
    assert!(
        out_dir.join("eh.jsonl").is_file(),
        "missing eh.jsonl on disk"
    );
    let _eh_rows = read_jsonl(&out_dir.join("eh.jsonl"));
    assert!(
        manifest_artifacts
            .iter()
            .any(|row| { row.get("path").and_then(|value| value.as_str()) == Some("eh.jsonl") }),
        "eh.jsonl missing from artifact_index"
    );

    // Step 9: classes.jsonl is emitted and registered. The trivial ELF
    // fixture has no DWARF type DIEs, so the file is expected to be empty.
    // Real-binary smoke test in step 15 exercises non-empty output.
    assert!(
        out_dir.join("classes.jsonl").is_file(),
        "missing classes.jsonl on disk"
    );
    let _class_rows = read_jsonl(&out_dir.join("classes.jsonl"));
    assert!(
        manifest_artifacts.iter().any(|row| {
            row.get("path").and_then(|value| value.as_str()) == Some("classes.jsonl")
        }),
        "classes.jsonl missing from artifact_index"
    );

    // Step 15: cross-fixture coverage invariant — addresses Codex's
    // adversarial finding. Every artifact registered in
    // `analysis_manifest.json` MUST have a corresponding file on disk
    // (catches "registered but never emitted" silent regressions).
    // Empty content is acceptable here because the matchers are real
    // (not stubs) — the trivial fixture genuinely has no
    // switches/EH/classes. A separate real-binary smoke test (not in
    // this hermetic suite) asserts non-empty output on a binary that
    // actually contains those structures.
    for artifact in manifest_artifacts {
        let Some(path) = artifact.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        // Skip non-file artifacts (e.g. graph subpaths or directory
        // manifests handled by their own assertions above).
        let full_path = out_dir.join(path);
        assert!(
            full_path.exists(),
            "manifest-registered artifact {path:?} is missing on disk at {full_path:?}"
        );
    }

    // Step 15: summary counts for the new capabilities are present.
    let counts = parsed
        .get("counts")
        .and_then(|v| v.as_object())
        .expect("counts block");
    for key in ["switches", "eh_facts", "class_facts"] {
        assert!(
            counts.contains_key(key),
            "missing count for {key} in analysis.json::counts: {counts:?}"
        );
    }

    assert!(
        out_dir.join("review_packs").join("manifest.json").is_file(),
        "missing review pack manifest"
    );
}

#[test]
fn symbol_query_cli_reads_existing_output_folder() {
    let tmp = TempDir::new().expect("tempdir");
    let fixture = tmp.path().join("tiny_x64.elf");
    write_minimal_elf(&fixture);

    let out_dir = tmp.path().join("analysis");
    axe_core::analyze_path(
        fixture.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        default_options(),
    )
    .expect("analysis");

    let assert = assert_cmd::Command::cargo_bin("axe")
        .expect("axe bin")
        .arg(&out_dir)
        .arg("--symbol-query")
        .arg("name")
        .arg("--symbol-query-value")
        .arg("_start")
        .assert()
        .success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).expect("stdout");
    let packet: serde_json::Value = serde_json::from_str(&stdout).expect("packet json");
    assert_eq!(
        Some("llm_symbol_packet/1"),
        packet.get("schema").and_then(|value| value.as_str())
    );
    assert!(packet
        .get("exact_matches")
        .and_then(|value| value.as_array())
        .is_some_and(|rows| !rows.is_empty()));
}

#[test]
fn macho_runs_full_pipeline_and_emits_analysis_json() {
    let tmp = TempDir::new().expect("tempdir");
    let fixture = tmp.path().join("tiny_x64.macho");
    write_minimal_macho(&fixture);

    let out_dir = tmp.path().join("out");
    let result = axe_core::analyze_path(
        fixture.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        default_options(),
    );
    assert!(result.is_ok(), "analyze failed: {:?}", result.err());

    let analysis_path = out_dir.join("analysis.json");
    assert!(analysis_path.is_file(), "expected analysis.json");
    let parsed: serde_json::Value =
        serde_json::from_slice(&fs::read(&analysis_path).expect("read")).expect("json");
    let format = parsed.get("format").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!("macho", format, "analysis.json should report format=macho");
}

#[test]
fn analysis_json_records_effective_options() {
    let tmp = TempDir::new().expect("tempdir");
    let fixture = tmp.path().join("tiny_x64.elf");
    write_minimal_elf(&fixture);

    let out_dir = tmp.path().join("out");
    let mut options = default_options();
    options.semantic_budget = "high".to_string();
    options.pseudo_ir = "expanded".to_string();
    axe_core::analyze_path(
        fixture.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        options,
    )
    .expect("analysis");

    let parsed: serde_json::Value =
        serde_json::from_slice(&fs::read(out_dir.join("analysis.json")).expect("read"))
            .expect("json");
    let effective = parsed
        .get("options")
        .and_then(|value| value.as_object())
        .expect("analysis.json must include effective options");
    assert_eq!(
        effective.get("semantic_budget").and_then(|v| v.as_str()),
        Some("high")
    );
    assert_eq!(
        effective.get("pseudo_ir").and_then(|v| v.as_str()),
        Some("expanded")
    );
    assert_eq!(
        effective
            .get("vuln_dynamic_confirmation")
            .and_then(|v| v.as_str()),
        Some("off")
    );
    assert_eq!(
        effective.get("unpack").and_then(|v| v.as_str()),
        Some("off")
    );
}

fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read jsonl {}: {err}", path.display()));
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("jsonl row"))
        .collect()
}

fn assert_graph_edges_resolve(nodes: &[serde_json::Value], edges: &[serde_json::Value]) {
    let ids = nodes
        .iter()
        .filter_map(|row| row.get("id").and_then(|value| value.as_str()))
        .collect::<std::collections::BTreeSet<_>>();
    assert!(!ids.is_empty(), "node graph has no ids");
    for edge in edges {
        let from = edge
            .get("from")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let to = edge
            .get("to")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        assert!(ids.contains(from), "dangling edge from {from}: {edge}");
        assert!(ids.contains(to), "dangling edge to {to}: {edge}");
    }
}

#[test]
fn unsupported_arch_returns_clear_error() {
    let tmp = TempDir::new().expect("tempdir");
    let fixture = tmp.path().join("tiny_arm64.elf");
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    let text_id = obj.section_id(StandardSection::Text);
    obj.append_section_data(text_id, &[0u8; 4], 16);
    let bytes = obj.write().expect("write");
    fs::write(&fixture, bytes).expect("write fixture");

    let out_dir = tmp.path().join("out");
    let result = axe_core::analyze_path(
        fixture.to_str().unwrap(),
        out_dir.to_str().unwrap(),
        default_options(),
    );
    assert!(result.is_err(), "ARM64 ELF must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unsupported_arch"),
        "expected unsupported_arch error, got: {err}"
    );
}
