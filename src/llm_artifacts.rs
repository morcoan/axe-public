use crate::debug_symbols::{
    DebugIdentityRecord, DebugModuleRecord, DebugSymbolRecord, DebugTypeRecord, InlineScopeRecord,
    LineEntryRecord, SourceFileRecord, SymbolUncertaintyRecord,
};
use crate::ir::IrInstruction;
use crate::pe::{
    ApiFlowRecord, BehaviorDossierRecord, CallGraphRecord, CfgRecord, DataflowEdgeRecord,
    FunctionDossierRecord, FunctionRecord, ImportRecord, InstructionRecord, PseudoIrRecord,
    SsaValueRecord, StringRecord, StructuredFlowRecord, TypeHintRecord, UncertaintyRecord,
    ValueGraphRecord, XrefRecord,
};
use crate::portable::{safe_file_component, DecompiledCRecord, VulnCandidateRecord};
use crate::symbol_graph::SymbolGraphRecord;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Clone, Serialize)]
pub struct GraphNodeRecord {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub function: Option<u64>,
    pub va: Option<u64>,
    pub end_va: Option<u64>,
    pub confidence: String,
    pub source: String,
    pub evidence: Vec<u64>,
    pub attributes: Value,
}

#[derive(Clone, Serialize)]
pub struct GraphEdgeRecord {
    pub id: String,
    pub kind: String,
    pub from: String,
    pub to: String,
    pub function: Option<u64>,
    pub va: Option<u64>,
    pub confidence: String,
    pub source: String,
    pub evidence: Vec<u64>,
    pub attributes: Value,
}

#[derive(Clone, Serialize)]
pub struct DecompiledSourceRecord {
    pub source_id: String,
    pub function: u64,
    pub language: String,
    pub status: String,
    pub output_path: String,
    pub source_of_truth: String,
    pub confidence: String,
    pub evidence: Vec<u64>,
    pub lines: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct ArtifactIndexRecord {
    pub path: String,
    pub kind: String,
    pub description: String,
    pub record_count: usize,
    /// Optional "partial" marker for fuzzer artifacts whose
    /// `run_status.json` ledger reports incomplete state. Defaults to
    /// `None` (skipped on serialize) so existing artifact entries
    /// (`switches.jsonl`, `eh.jsonl`, `classes.jsonl`, etc.) remain
    /// byte-identical on the wire. Codex finding 1 enforcement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Build [`ArtifactIndexRecord`]s for the fuzzer's artifact family
/// based on the `run_status.json` ledger. Returns an empty Vec when:
/// - `fuzzer_mode` is `"off"` (fuzzer wasn't requested), OR
/// - `run_status.json` is missing or unparseable (run didn't reach
///   the finalize phase â€” we conservatively advertise nothing).
///
/// When the ledger is present, registers ONLY artifacts with status
/// `Complete` or `Partial` (the latter with an explicit
/// `status: "partial"` field). `Failed` and `Skipped` artifacts are
/// omitted from the manifest entirely. The `run_status.json` itself
/// is always registered when fuzzer_mode is on, so consumers can
/// audit the gating decision.
///
/// This function is intentionally a free function (not a method on
/// LlmArtifactInput) so it can be unit-tested without constructing
/// the full input bundle.
#[cfg(feature = "fuzzer")]
pub fn fuzzer_artifact_index_entries(
    fuzzer_dir: &std::path::Path,
    fuzzer_mode: &str,
) -> Vec<ArtifactIndexRecord> {
    if fuzzer_mode == "off" {
        return Vec::new();
    }
    let status_path = fuzzer_dir.join("run_status.json");
    let status = match crate::fuzzer::run_status::read_run_status(&status_path) {
        Some(s) => s,
        None => {
            return Vec::new();
        }
    };

    let mut out = Vec::with_capacity(status.artifacts.len() + 1);
    out.push(ArtifactIndexRecord {
        path: "fuzzer/run_status.json".to_string(),
        kind: "fuzzer_run_status".to_string(),
        description: "Per-artifact finalization ledger; reads this first to know which other fuzzer artifacts are trustworthy.".to_string(),
        record_count: 1,
        status: None,
    });

    use crate::fuzzer::run_status::ArtifactStatus;
    for (name, entry) in &status.artifacts {
        let (kind, desc): (&str, &str) = match name.as_str() {
            "events.ndjson" => (
                "fuzzer_events",
                "Streaming NDJSON event log: new coverage, new crashes, mutator trace.",
            ),
            "findings.jsonl" => (
                "fuzzer_findings",
                "Unique crash/hang findings with dedup hashes and reproducer paths.",
            ),
            "corpus.sqlite" => (
                "fuzzer_corpus_db",
                "Queryable SQLite database of corpus inputs, edges, mutations, reachability.",
            ),
            "frontier.md" => (
                "fuzzer_frontier",
                "Auto-regenerated Markdown frontier â€” closest unreached targets, blocking comparisons, recent crashes.",
            ),
            "summary.json" => (
                "fuzzer_summary",
                "Top-of-funnel snapshot: exec count, coverage %, unique crashes, top targets.",
            ),
            _ => ("fuzzer_artifact", "Fuzzer artifact"),
        };
        let (status_field, include) = match entry.status {
            ArtifactStatus::Complete => (None, true),
            ArtifactStatus::Partial => (Some("partial".to_string()), true),
            ArtifactStatus::Failed | ArtifactStatus::Skipped => (None, false),
        };
        if !include {
            continue;
        }
        out.push(ArtifactIndexRecord {
            path: format!("fuzzer/{name}"),
            kind: kind.to_string(),
            description: desc.to_string(),
            record_count: entry.records as usize,
            status: status_field,
        });
    }

    out
}

/// Build [`ArtifactIndexRecord`]s for the concolic engine's artifact
/// family based on `out/concolic/run_status.json`. Mirrors
/// [`fuzzer_artifact_index_entries`] semantics exactly: same gating,
/// same `Complete`/`Partial`/`Failed`/`Skipped` discipline. Reads
/// the concolic ledger via [`crate::concolic::run_status::read_run_status`]
/// which is a passthrough to the fuzzer ledger reader (the wire
/// shapes are identical apart from the schema string).
///
/// Returns an empty Vec when:
/// - `mode == "off"` (concolic was not requested), OR
/// - `run_status.json` is missing or unparseable.
#[cfg(feature = "concolic")]
pub fn concolic_artifact_index_entries(
    concolic_dir: &std::path::Path,
    mode: &str,
) -> Vec<ArtifactIndexRecord> {
    if mode == "off" {
        return Vec::new();
    }
    let status_path = concolic_dir.join("run_status.json");
    let status = match crate::concolic::run_status::read_run_status(&status_path) {
        Some(s) => s,
        None => return Vec::new(),
    };

    let mut out = Vec::with_capacity(status.artifacts.len() + 1);
    out.push(ArtifactIndexRecord {
        path: "concolic/run_status.json".to_string(),
        kind: "concolic_run_status".to_string(),
        description: "Per-artifact finalization ledger for the concolic engine; read this first to know which other concolic artifacts are trustworthy.".to_string(),
        record_count: 1,
        status: None,
    });

    use crate::fuzzer::run_status::ArtifactStatus;
    for (name, entry) in &status.artifacts {
        let (kind, desc): (&str, &str) = match name.as_str() {
            "solves.jsonl" => (
                "concolic_solves",
                "One record per solve_branch call: branch, constraint slice, solver tier, model, validation outcome.",
            ),
            "exprs.jsonl" => (
                "concolic_exprs",
                "Interned Expr DAG nodes for constraint reconstruction (dedup by NodeId).",
            ),
            "branches.jsonl" => (
                "concolic_branches",
                "Observed branch events with concrete LHS/RHS NodeIds.",
            ),
            "traces.jsonl" => (
                "concolic_traces",
                "Per-execution symbolic path traces.",
            ),
            "coverage.jsonl" => (
                "concolic_coverage",
                "New-coverage events from confirmed model validations.",
            ),
            "smt2" => (
                "concolic_smt2_dir",
                "Directory of replayable SMT-LIB v2.6 dumps (record_count = file count).",
            ),
            _ => ("concolic_artifact", "Concolic artifact"),
        };
        let (status_field, include) = match entry.status {
            ArtifactStatus::Complete => (None, true),
            ArtifactStatus::Partial => (Some("partial".to_string()), true),
            ArtifactStatus::Failed | ArtifactStatus::Skipped => (None, false),
        };
        if !include {
            continue;
        }
        out.push(ArtifactIndexRecord {
            path: format!("concolic/{name}"),
            kind: kind.to_string(),
            description: desc.to_string(),
            record_count: entry.records as usize,
            status: status_field,
        });
    }

    out
}

/// Build [`ArtifactIndexRecord`]s for the dynamic-trace pipeline's
/// artifact family based on `out/dynamic_trace/run_status.json`.
/// Mirrors [`fuzzer_artifact_index_entries`] and
/// [`concolic_artifact_index_entries`] semantics exactly: same
/// gating, same Complete/Partial/Failed/Skipped discipline.
///
/// Returns an empty Vec when:
/// - `mode == "off"` (dynamic-trace was not requested), OR
/// - `run_status.json` is missing or unparseable.
///
/// v1 registers up to 7 artifacts:
/// - `run_status.json` (always first, the ledger itself)
/// - `events.ndjson` (canonical event stream)
/// - `entity_graph.json` (process/file/network nodes + edges)
/// - `behavior_facts.jsonl` (runtime-observed facts)
/// - `behavior_fact_union.jsonl` (static + dynamic union envelope)
/// - `evidence_pack.json` (LLM-facing top-N + summary)
/// - `trace.sqlite` (durable cross-run query store)
#[cfg(feature = "dynamic-trace")]
pub fn dynamic_trace_artifact_index_entries(
    dynamic_trace_dir: &std::path::Path,
    mode: &str,
) -> Vec<ArtifactIndexRecord> {
    if mode == "off" {
        return Vec::new();
    }
    let status_path = dynamic_trace_dir.join("run_status.json");
    let status =
        match crate::dynamic_trace::dyn_run_status::read_dynamic_trace_run_status(&status_path) {
            Some(s) => s,
            None => return Vec::new(),
        };

    let mut out = Vec::with_capacity(status.base.artifacts.len() + 1);
    out.push(ArtifactIndexRecord {
        path: "dynamic_trace/run_status.json".to_string(),
        kind: "dynamic_trace_run_status".to_string(),
        description: "Per-artifact finalization ledger for the dynamic-trace pipeline; read this first. Includes run_meta with events_dropped count, loss_policy, capability_probe result.".to_string(),
        record_count: 1,
        status: None,
    });

    use crate::run_status::ArtifactStatus;
    for (name, entry) in &status.base.artifacts {
        let (kind, desc): (&str, &str) = match name.as_str() {
            "events.ndjson" => (
                "dynamic_trace_events",
                "Canonical event stream: one NDJSON record per captured kernel-ETW event (file/registry/network/DNS/process/image_load).",
            ),
            "entity_graph.json" => (
                "dynamic_trace_entity_graph",
                "Process/file/network/registry/socket nodes and the typed edges (write/read/connect/...) between them.",
            ),
            "behavior_facts.jsonl" => (
                "dynamic_trace_behavior_facts",
                "Runtime-observed behavior facts (persistence, defense_evasion, exfil_staging, discovery, service_creation, browser_credential_access).",
            ),
            "behavior_fact_union.jsonl" => (
                "dynamic_trace_behavior_fact_union",
                "Common envelope around static BehaviorDossierRecord AND dynamic DynamicBehaviorFactRecord so the LLM sees one fact stream.",
            ),
            "evidence_pack.json" => (
                "dynamic_trace_evidence_pack",
                "LLM-facing top-N events + summary sentences + uncertainties. Negative claims suppressed when events_dropped > 0.",
            ),
            "trace.sqlite" => (
                "dynamic_trace_store",
                "Durable SQLite store of events/entities/edges/behavior_facts for ad-hoc cross-run queries.",
            ),
            _ => ("dynamic_trace_artifact", "Dynamic-trace artifact"),
        };
        let (status_field, include) = match entry.status {
            ArtifactStatus::Complete => (None, true),
            ArtifactStatus::Partial => (Some("partial".to_string()), true),
            ArtifactStatus::Failed | ArtifactStatus::Skipped => (None, false),
        };
        if !include {
            continue;
        }
        out.push(ArtifactIndexRecord {
            path: format!("dynamic_trace/{name}"),
            kind: kind.to_string(),
            description: desc.to_string(),
            record_count: entry.records as usize,
            status: status_field,
        });
    }

    out
}

/// Build [`ArtifactIndexRecord`]s for the vuln-discovery pipeline
/// (v1.0 + v1.1 combined) based on `out/vuln/run_status.json`.
/// Mirrors the fuzzer and concolic helpers exactly:
/// Complete/Partial/Failed/Skipped gating.
///
/// v1.0 ships 5 artifact kinds (`vuln_findings`, `vuln_chain_graph`,
/// `vuln_evidence_bundle`, `vuln_findings_store`, plus the
/// `vuln_run_status` ledger). v1.1 adds 4 more kinds when their
/// respective features / flags emit:
/// - `vuln_harnesses_dir` — `harnesses/` directory with per-chain
///   `.skeleton.md` (and `.runnable.rs` for verification-PASSED
///   harnesses).
/// - `vuln_patch_suggestions` — pure-Rust template-based patch
///   suggestions, one per line.
/// - `vuln_test_suggestions` — pure-Rust template-based test
///   suggestions, one per line.
/// - `vuln_lifetime_candidates` — Candidate-tier UAF / double-free
///   findings (separate from the default `findings.jsonl` per
///   Codex finding 3).
#[cfg(feature = "vuln-discovery")]
pub fn vuln_artifact_index_entries(
    vuln_dir: &std::path::Path,
    mode: &str,
) -> Vec<ArtifactIndexRecord> {
    if mode == "off" {
        return Vec::new();
    }
    let status_path = vuln_dir.join("run_status.json");
    let status = match crate::vuln::vuln_run_status::read_vuln_run_status(&status_path) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(status.base.artifacts.len() + 1);
    out.push(ArtifactIndexRecord {
        path: "vuln/run_status.json".to_string(),
        kind: "vuln_run_status".to_string(),
        description: "Per-artifact finalization ledger for vuln-discovery (v1.0 + v1.1); read this first. run_meta tracks templates_loaded, chains_discovered, chains_above_threshold, scoring_calibrated.".to_string(),
        record_count: 1,
        status: None,
    });
    use crate::run_status::ArtifactStatus;
    for (name, entry) in &status.base.artifacts {
        let (kind, desc): (&str, &str) = match name.as_str() {
            // v1.0 artifacts
            "findings.jsonl" => (
                "vuln_findings",
                "One vulnerability finding per line: bug class, source/sink chain, scoring factors, uncertainties. v1.1 records may include a `dynamic_evidence` block when ConfirmedTrigger/ReachedOnly evidence attached.",
            ),
            "chain_graph.json" => (
                "vuln_chain_graph",
                "Node/edge view of all discovered chains so the LLM can pivot from a function to every chain that touches it.",
            ),
            "evidence_bundle.json" => (
                "vuln_evidence_bundle",
                "Top-N findings ranked by risk + summary sentences + uncertainties (read this after run_status). v1.1 bundle EXCLUDES lifetime candidates from top-N per Codex finding 3.",
            ),
            "findings.sqlite" => (
                "vuln_findings_store",
                "Durable SQLite store of every finding for cross-run queries and differential analysis.",
            ),
            // v1.1 artifacts
            "harnesses" => (
                "vuln_harnesses_dir",
                "Per-chain harness artifacts: {harness_id}.skeleton.md always written; {harness_id}.runnable.rs only when verify_runnable() PASSED for that chain (Codex finding 2 enforcement).",
            ),
            "patch_suggestions.jsonl" => (
                "vuln_patch_suggestions",
                "Pure-Rust template-based patch suggestions, one per line (source: \"template\"). Not live-LLM output; review before applying.",
            ),
            "test_suggestions.jsonl" => (
                "vuln_test_suggestions",
                "Pure-Rust template-based test suggestions, one per line (source: \"template\"). Construct these as smoke / regression tests for the suspected vulnerability.",
            ),
            "lifetime_candidates.jsonl" => (
                "vuln_lifetime_candidates",
                "Candidate-tier UAF / double-free findings (--vuln-include-lifetime). Hard-capped at 0.65 confidence. EXCLUDED from findings.jsonl and from evidence_bundle.json::top_findings per Codex finding 3.",
            ),
            _ => ("vuln_artifact", "Vuln-discovery artifact"),
        };
        let (status_field, include) = match entry.status {
            ArtifactStatus::Complete => (None, true),
            ArtifactStatus::Partial => (Some("partial".to_string()), true),
            ArtifactStatus::Failed | ArtifactStatus::Skipped => (None, false),
        };
        if !include {
            continue;
        }
        out.push(ArtifactIndexRecord {
            path: format!("vuln/{name}"),
            kind: kind.to_string(),
            description: desc.to_string(),
            record_count: entry.records as usize,
            status: status_field,
        });
    }
    out
}

/// Manifest helper for the Aurora unpacker. Reads
/// `out/unpack/run_status.json` and emits one
/// `ArtifactIndexRecord` per Complete or Partial entry, plus
/// the run-status entry itself. Returns an empty Vec when:
///
/// - `mode == "off"` (Aurora was not requested), OR
/// - the run_status file is missing (Aurora didn't finish
///   cleanly enough to advertise its artifacts).
///
/// Recognized artifact names (other names fall back to a
/// generic description so a future Aurora version's new
/// artifacts still appear):
///
/// - `unpack_provenance.json` — snapshot manifest (the
///   contract `PEImage::from_snapshot()` reads).
/// - `regions/region_NN.bin` — captured memory blobs that the
///   manifest's `regions[].blob_path` points to.
/// - `entropy_curve.jsonl` — per-region entropy time-series.
/// - `guard_page_log.jsonl` — per-page write trace.
/// - `oep_candidates.jsonl` — 4-signal corroboration scoring.
#[cfg(feature = "unpack")]
pub fn unpack_artifact_index_entries(
    unpack_dir: &std::path::Path,
    mode: &str,
) -> Vec<ArtifactIndexRecord> {
    if mode == "off" {
        return Vec::new();
    }
    let status_path = unpack_dir.join("run_status.json");
    let status = match crate::run_status::read_run_status(&status_path) {
        Some(s) => s,
        None => return Vec::new(),
    };
    let mut out = Vec::with_capacity(status.artifacts.len() + 1);
    out.push(ArtifactIndexRecord {
        path: "unpack/run_status.json".to_string(),
        kind: "unpack_run_status".to_string(),
        description: "Per-artifact finalization ledger for the Aurora unpacker. run_meta tracks tracer_mode, hook counts, OEP top confidence, regions_dumped.".to_string(),
        record_count: 1,
        status: None,
    });
    use crate::run_status::ArtifactStatus;
    for (name, entry) in &status.artifacts {
        let (kind, desc): (&str, &str) = match name.as_str() {
            "unpack_provenance.json" => (
                "unpack_snapshot_manifest",
                "Snapshot manifest (schema vuln_discovery.unpack_snapshot.v1) — the contract consumed by PEImage::from_snapshot(). Lists captured regions, OEP candidates with 4-signal corroboration, anti-VM profile, execution provenance.",
            ),
            "entropy_curve.jsonl" => (
                "unpack_entropy_curve",
                "Per-region Shannon entropy time-series. A sharp drop in the same region between two consecutive samples is the canonical 'packer just decoded' signal.",
            ),
            "guard_page_log.jsonl" => (
                "unpack_guard_page_log",
                "Per-page write trace via PAGE_GUARD violations. Bounded ring buffer; if dropped_count > 0 the manifest's uncertainties field flags the truncation.",
            ),
            "oep_candidates.jsonl" => (
                "unpack_oep_candidates",
                "Original Entry Point candidates ranked by 4-signal corroboration (entropy_drop, execute_from_newly_allocated, function_prologue_match, iat_call_pattern). confidence_score = signals_present / 4.",
            ),
            other if other.starts_with("regions/") => (
                "unpack_region_blob",
                "Raw memory blob captured by ReadProcessMemory. Address layout + permissions are in unpack_provenance.json::regions; consume both together via PEImage::from_snapshot().",
            ),
            _ => ("unpack_artifact", "Aurora unpacker artifact"),
        };
        let (status_field, include) = match entry.status {
            ArtifactStatus::Complete => (None, true),
            ArtifactStatus::Partial => (Some("partial".to_string()), true),
            ArtifactStatus::Failed | ArtifactStatus::Skipped => (None, false),
        };
        if !include {
            continue;
        }
        out.push(ArtifactIndexRecord {
            path: format!("unpack/{name}"),
            kind: kind.to_string(),
            description: desc.to_string(),
            record_count: entry.records as usize,
            status: status_field,
        });
    }
    out
}

#[derive(Clone, Serialize)]
pub struct LlmArtifactSummary {
    pub schema: String,
    pub nodes: usize,
    pub edges: usize,
    pub review_packs: usize,
    pub decompiled_sources: usize,
    pub unsupported_lifter: bool,
    pub artifacts: Vec<ArtifactIndexRecord>,
}

#[derive(Clone, Serialize)]
pub struct AnalysisManifestRecord {
    pub schema: String,
    pub sha256: String,
    pub source_path: String,
    pub format: String,
    pub machine: u16,
    pub llm_artifacts_mode: String,
    pub review_packs_mode: String,
    pub decompile_source_mode: String,
    pub deterministic: bool,
    pub model_free: bool,
    pub source_of_truth: String,
    pub artifact_index: Vec<ArtifactIndexRecord>,
    pub counts: BTreeMap<String, usize>,
    pub recommended_reading_order: Vec<String>,
    pub limitations: Vec<String>,
    pub caps_hit: Value,
}

pub struct LlmArtifactInput<'a> {
    pub sha256: &'a str,
    pub source_path: &'a str,
    pub format_label: &'a str,
    pub machine: u16,
    pub out_dir: &'a Path,
    pub llm_artifacts_mode: &'a str,
    pub review_packs_mode: &'a str,
    pub decompile_source_mode: &'a str,
    pub disasm_capped: bool,
    pub semantic_caps_hit: Value,
    pub functions: &'a [FunctionRecord],
    pub cfg: &'a [CfgRecord],
    pub instructions: &'a [InstructionRecord],
    pub ir: &'a [IrInstruction],
    pub imports: &'a [ImportRecord],
    pub strings: &'a [StringRecord],
    pub xrefs: &'a [XrefRecord],
    pub callgraph: &'a [CallGraphRecord],
    pub value_graph: &'a [ValueGraphRecord],
    pub ssa_values: &'a [SsaValueRecord],
    pub dataflow_edges: &'a [DataflowEdgeRecord],
    pub structured_flow: &'a [StructuredFlowRecord],
    pub type_hints: &'a [TypeHintRecord],
    pub api_flows: &'a [ApiFlowRecord],
    pub pseudo_ir: &'a [PseudoIrRecord],
    pub function_dossiers: &'a [FunctionDossierRecord],
    pub behavior_dossiers: &'a [BehaviorDossierRecord],
    pub vuln_candidates: &'a [VulnCandidateRecord],
    pub decompiled_c: &'a [DecompiledCRecord],
    pub uncertainties: &'a [UncertaintyRecord],
    pub debug_modules: &'a [DebugModuleRecord],
    pub debug_identities: &'a [DebugIdentityRecord],
    pub debug_symbols: &'a [DebugSymbolRecord],
    pub source_files: &'a [SourceFileRecord],
    pub line_entries: &'a [LineEntryRecord],
    pub inline_scopes: &'a [InlineScopeRecord],
    pub debug_types: &'a [DebugTypeRecord],
    pub symbol_uncertainties: &'a [SymbolUncertaintyRecord],
    pub symbol_graph_rows: &'a [SymbolGraphRecord],
    pub symbol_packet_count: usize,
    pub switches: &'a [crate::switches::SwitchFact],
    pub eh_facts: &'a [crate::eh::EhFunctionFact],
    pub class_facts: &'a [crate::cpp_classes::ClassFact],
}

pub fn write_llm_artifacts(
    input: LlmArtifactInput<'_>,
) -> Result<LlmArtifactSummary, Box<dyn Error>> {
    if input.llm_artifacts_mode == "off" {
        return Ok(LlmArtifactSummary {
            schema: "llm_artifacts/1".to_string(),
            nodes: 0,
            edges: 0,
            review_packs: 0,
            decompiled_sources: 0,
            unsupported_lifter: false,
            artifacts: Vec::new(),
        });
    }

    let (nodes, node_ids, import_nodes, string_nodes, block_nodes, op_nodes, ssa_nodes) =
        build_nodes(&input);
    let edges = build_edges(
        &input,
        &node_ids,
        &import_nodes,
        &string_nodes,
        &block_nodes,
        &op_nodes,
        &ssa_nodes,
    );
    let sources = build_source_views(&input);
    let review_pack_count = write_llm_review_packs(&input)?;

    let graph_dir = input.out_dir.join("graph");
    fs::create_dir_all(&graph_dir)?;
    write_jsonl(graph_dir.join("nodes.jsonl"), &nodes)?;
    write_jsonl(graph_dir.join("edges.jsonl"), &edges)?;
    write_jsonl(input.out_dir.join("decompiled_source.jsonl"), &sources)?;

    let artifacts = artifact_index(
        &input,
        nodes.len(),
        edges.len(),
        review_pack_count,
        sources.len(),
    );
    let manifest = build_manifest(
        &input,
        artifacts.clone(),
        nodes.len(),
        edges.len(),
        review_pack_count,
        sources.len(),
    );
    write_json(
        input.out_dir.join("analysis_manifest.json"),
        &serde_json::to_value(&manifest)?,
    )?;

    Ok(LlmArtifactSummary {
        schema: "llm_artifacts/1".to_string(),
        nodes: nodes.len(),
        edges: edges.len(),
        review_packs: review_pack_count,
        decompiled_sources: sources.len(),
        unsupported_lifter: true,
        artifacts,
    })
}

type NodeBuildResult = (
    Vec<GraphNodeRecord>,
    BTreeSet<String>,
    BTreeMap<String, String>,
    BTreeMap<u64, String>,
    BTreeMap<(u64, u64), String>,
    BTreeMap<u64, String>,
    BTreeMap<String, String>,
);

fn build_nodes(input: &LlmArtifactInput<'_>) -> NodeBuildResult {
    let mut nodes = Vec::new();
    let mut ids = BTreeSet::new();

    push_node(
        &mut nodes,
        &mut ids,
        GraphNodeRecord {
            id: "lifter:sleigh:unsupported".to_string(),
            kind: "unsupported_lifter".to_string(),
            label: "SLEIGH lifter adapter not yet integrated".to_string(),
            function: None,
            va: None,
            end_va: None,
            confidence: "high".to_string(),
            source: "llm_artifacts".to_string(),
            evidence: input
                .functions
                .first()
                .map(|row| vec![row.start])
                .unwrap_or_default(),
            attributes: json!({
                "requested_lifter": "sleigh",
                "status": "unsupported_lifter",
                "semantic_truth": "legacy deterministic IR is exported, but not promoted as SLEIGH p-code",
            }),
        },
    );

    for module in input.debug_modules {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: module.module_id.clone(),
                kind: "debug_module".to_string(),
                label: module.source_path.clone(),
                function: None,
                va: Some(module.image_base),
                end_va: None,
                confidence: "high".to_string(),
                source: "debug_symbols".to_string(),
                evidence: Vec::new(),
                attributes: json!({
                    "format": module.format,
                    "machine": module.machine,
                    "image_base": module.image_base,
                    "entry_rva": module.entry_rva,
                    "address_size": module.address_size,
                    "section_count": module.section_count,
                    "symbol_mode": module.symbol_mode,
                    "cache_key": module.cache_key,
                }),
            },
        );
    }

    for identity in input.debug_identities {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: identity.identity_id.clone(),
                kind: "debug_identity".to_string(),
                label: identity
                    .path_hint
                    .clone()
                    .or_else(|| identity.build_id.clone())
                    .or_else(|| identity.guid.clone())
                    .unwrap_or_else(|| identity.identity_kind.clone()),
                function: None,
                va: None,
                end_va: None,
                confidence: identity.confidence.clone(),
                source: identity.provider.clone(),
                evidence: identity.evidence.clone(),
                attributes: json!({
                    "module_id": identity.module_id,
                    "provider": identity.provider,
                    "identity_kind": identity.identity_kind,
                    "path_hint": identity.path_hint,
                    "build_id": identity.build_id,
                    "guid": identity.guid,
                    "age": identity.age,
                    "debuglink": identity.debuglink,
                    "uuid": identity.uuid,
                    "found_path": identity.found_path,
                }),
            },
        );
    }

    let image_base = debug_image_base(input);
    for symbol in input.debug_symbols {
        let start_va = image_base.saturating_add(symbol.start_rva);
        let end_va = image_base.saturating_add(symbol.end_rva);
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: symbol.symbol_id.clone(),
                kind: "symbol".to_string(),
                label: symbol.name.clone(),
                function: function_for(input.functions, start_va),
                va: Some(start_va),
                end_va: Some(end_va),
                confidence: symbol.confidence.clone(),
                source: symbol.provider.clone(),
                evidence: symbol.evidence.clone(),
                attributes: json!({
                    "module_id": symbol.module_id,
                    "provider": symbol.provider,
                    "name": symbol.name,
                    "linkage_name": symbol.linkage_name,
                    "kind": symbol.kind,
                    "start_rva": symbol.start_rva,
                    "end_rva": symbol.end_rva,
                    "function": symbol.function,
                }),
            },
        );
    }

    for file in input.source_files {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: file.file_id.clone(),
                kind: "source_file".to_string(),
                label: file.path.clone(),
                function: None,
                va: None,
                end_va: None,
                confidence: file.confidence.clone(),
                source: file.provider.clone(),
                evidence: file.evidence.clone(),
                attributes: json!({
                    "module_id": file.module_id,
                    "provider": file.provider,
                    "path": file.path,
                    "checksum": file.checksum,
                }),
            },
        );
    }

    for line in input.line_entries {
        let start_va = image_base.saturating_add(line.start_rva);
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: line.line_id.clone(),
                kind: "line_entry".to_string(),
                label: format!("{}:{}", line.file_id, line.line),
                function: function_for(input.functions, start_va),
                va: Some(start_va),
                end_va: Some(image_base.saturating_add(line.end_rva)),
                confidence: line.confidence.clone(),
                source: line.provider.clone(),
                evidence: line.evidence.clone(),
                attributes: json!({
                    "module_id": line.module_id,
                    "provider": line.provider,
                    "start_rva": line.start_rva,
                    "end_rva": line.end_rva,
                    "file_id": line.file_id,
                    "line": line.line,
                    "column": line.column,
                    "flags": line.flags,
                }),
            },
        );
    }

    for scope in input.inline_scopes {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: scope.scope_id.clone(),
                kind: "inline_scope".to_string(),
                label: scope
                    .function_ref
                    .clone()
                    .unwrap_or_else(|| "inline_scope".to_string()),
                function: function_for(input.functions, image_base.saturating_add(scope.start_rva)),
                va: Some(image_base.saturating_add(scope.start_rva)),
                end_va: Some(image_base.saturating_add(scope.end_rva)),
                confidence: scope.confidence.clone(),
                source: scope.provider.clone(),
                evidence: scope.evidence.clone(),
                attributes: json!({
                    "module_id": scope.module_id,
                    "provider": scope.provider,
                    "function_ref": scope.function_ref,
                    "start_rva": scope.start_rva,
                    "end_rva": scope.end_rva,
                    "call_file_id": scope.call_file_id,
                    "call_line": scope.call_line,
                }),
            },
        );
    }

    for ty in input.debug_types {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: ty.type_id.clone(),
                kind: "debug_type".to_string(),
                label: ty.name.clone().unwrap_or_else(|| ty.kind.clone()),
                function: None,
                va: None,
                end_va: None,
                confidence: ty.confidence.clone(),
                source: ty.provider.clone(),
                evidence: ty.evidence.clone(),
                attributes: json!({
                    "module_id": ty.module_id,
                    "provider": ty.provider,
                    "namespace": ty.namespace,
                    "raw_key": ty.raw_key,
                    "kind": ty.kind,
                    "name": ty.name,
                    "size": ty.size,
                }),
            },
        );
    }

    for uncertainty in input.symbol_uncertainties {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: uncertainty.uncertainty_id.clone(),
                kind: "symbol_uncertainty".to_string(),
                label: uncertainty.code.clone(),
                function: None,
                va: None,
                end_va: None,
                confidence: uncertainty.severity.clone(),
                source: uncertainty.provider.clone(),
                evidence: uncertainty.evidence.clone(),
                attributes: json!({
                    "module_id": uncertainty.module_id,
                    "provider": uncertainty.provider,
                    "code": uncertainty.code,
                    "message": uncertainty.message,
                    "recommended_action": uncertainty.recommended_action,
                    "severity": uncertainty.severity,
                }),
            },
        );
    }

    for row in input.symbol_graph_rows {
        let start_va = row.rva_start.map(|rva| image_base.saturating_add(rva));
        let end_va = row.rva_end.map(|rva| image_base.saturating_add(rva));
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: symbol_graph_node_id(&row.id),
                kind: row.kind.clone(),
                label: row.label.clone(),
                function: start_va.and_then(|va| function_for(input.functions, va)),
                va: start_va,
                end_va,
                confidence: row.confidence.clone(),
                source: "symbol_graph".to_string(),
                evidence: parse_symbol_graph_evidence(&row.evidence),
                attributes: json!({
                    "raw_symbol_graph_id": row.id,
                    "artifact_id": row.artifact_id,
                    "provider": row.provider,
                    "rva_start": row.rva_start,
                    "rva_end": row.rva_end,
                    "source_file": row.source_file,
                    "line_start": row.line_start,
                    "line_end": row.line_end,
                    "related": row.related,
                    "attributes": row.attributes,
                }),
            },
        );
    }

    for function in input.functions {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: function_id(function.start),
                kind: "function".to_string(),
                label: format!("function_{:016X}", function.start),
                function: Some(function.start),
                va: Some(function.start),
                end_va: Some(function.end),
                confidence: "medium".to_string(),
                source: function.source.clone(),
                evidence: vec![function.start],
                attributes: json!({
                    "size": function.size,
                    "source": function.source,
                    "calls": function.calls,
                    "imports": function.calls_imports,
                    "strings": function.strings,
                    "xrefs": function.xrefs,
                }),
            },
        );
    }

    let mut block_nodes = BTreeMap::new();
    for cfg in input.cfg {
        for block in &cfg.blocks {
            let id = block_id(cfg.function, block.start);
            block_nodes.insert((cfg.function, block.start), id.clone());
            push_node(
                &mut nodes,
                &mut ids,
                GraphNodeRecord {
                    id,
                    kind: "block".to_string(),
                    label: format!("block_{:016X}", block.start),
                    function: Some(cfg.function),
                    va: Some(block.start),
                    end_va: Some(block.end),
                    confidence: "medium".to_string(),
                    source: "cfg".to_string(),
                    evidence: vec![block.start],
                    attributes: json!({
                        "instruction_count": block.instruction_count,
                    }),
                },
            );
        }
    }

    let mut op_nodes = BTreeMap::new();
    for ir in input.ir {
        let id = op_id(ir.address);
        op_nodes.insert(ir.address, id.clone());
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id,
                kind: "pcode_op".to_string(),
                label: format!("{}_{:016X}", ir.mnemonic, ir.address),
                function: function_for(input.functions, ir.address),
                va: Some(ir.address),
                end_va: Some(ir.address.saturating_add(ir.size as u64)),
                confidence: "low".to_string(),
                source: "legacy_ir_until_sleigh_adapter".to_string(),
                evidence: vec![ir.address],
                attributes: json!({
                    "mnemonic": ir.mnemonic,
                    "write_reg": ir.write_reg,
                    "read_regs": ir.read_regs,
                    "immediate": ir.immediate,
                    "rip_target": ir.rip_target,
                    "memory_base": ir.memory_base,
                    "memory_index": ir.memory_index,
                    "memory_scale": ir.memory_scale,
                    "memory_displacement": ir.memory_displacement,
                    "operand_width": ir.operand_width,
                    "memory_read": ir.memory_read,
                    "memory_write": ir.memory_write,
                    "direct_target": ir.direct_target,
                    "is_call": ir.is_call,
                    "is_jump": ir.is_jump,
                    "semantic_source_status": "not_sleigh_pcode",
                }),
            },
        );
    }

    let mut import_nodes = BTreeMap::new();
    for (index, import) in input.imports.iter().enumerate() {
        let id = format!("import:{index:04X}:{}", safe_file_component(&import.symbol));
        import_nodes.insert(import.symbol.clone(), id.clone());
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id,
                kind: "import".to_string(),
                label: import.symbol.clone(),
                function: None,
                va: Some(import.va),
                end_va: None,
                confidence: "high".to_string(),
                source: "loader".to_string(),
                evidence: (import.va != 0).then_some(import.va).into_iter().collect(),
                attributes: json!({
                    "dll": import.dll,
                    "name": import.name,
                    "rva": import.rva,
                    "categories": import.categories,
                }),
            },
        );
    }

    let mut string_nodes = BTreeMap::new();
    for string in input.strings {
        let id = format!("string:{:016X}", string.va);
        string_nodes.insert(string.va, id.clone());
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id,
                kind: "string".to_string(),
                label: truncate_label(&string.text, 80),
                function: None,
                va: Some(string.va),
                end_va: Some(string.va.saturating_add(string.size as u64)),
                confidence: "high".to_string(),
                source: "strings".to_string(),
                evidence: vec![string.va],
                attributes: json!({
                    "encoding": string.encoding,
                    "size": string.size,
                    "classifiers": string.classifiers,
                    "section": string.section,
                    "text": string.text,
                }),
            },
        );
    }

    for value in input.value_graph {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: value.value_id.clone(),
                kind: "value".to_string(),
                label: format!("{} {}", value.location, value.inferred_type),
                function: Some(value.function),
                va: Some(value.source_instruction),
                end_va: None,
                confidence: value.confidence.clone(),
                source: "value_graph".to_string(),
                evidence: value.evidence.clone(),
                attributes: json!({
                    "location": value.location,
                    "inferred_type": value.inferred_type,
                    "value": value.value,
                    "target_va": value.target_va,
                }),
            },
        );
    }

    let mut ssa_nodes = BTreeMap::new();
    let mut var_nodes = BTreeSet::new();
    for value in input.ssa_values {
        ssa_nodes.insert(value.ssa_id.clone(), value.ssa_id.clone());
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: value.ssa_id.clone(),
                kind: "ssa_value".to_string(),
                label: format!("{}@v{}", value.storage, value.version),
                function: Some(value.function),
                va: Some(value.site_va),
                end_va: None,
                confidence: value.confidence.clone(),
                source: "ssa".to_string(),
                evidence: value.evidence.clone(),
                attributes: json!({
                    "block": value.block,
                    "storage": value.storage,
                    "version": value.version,
                    "value_kind": value.kind,
                    "source": value.source,
                    "value": value.value,
                }),
            },
        );
        let var_id = recovered_var_id(value.function, &value.storage);
        if var_nodes.insert(var_id.clone()) {
            push_node(
                &mut nodes,
                &mut ids,
                GraphNodeRecord {
                    id: var_id,
                    kind: if value.storage == "mem" || value.storage.starts_with("stack[") {
                        "memory_location"
                    } else {
                        "recovered_var"
                    }
                    .to_string(),
                    label: value.storage.clone(),
                    function: Some(value.function),
                    va: None,
                    end_va: None,
                    confidence: "medium".to_string(),
                    source: "ssa_storage".to_string(),
                    evidence: value.evidence.clone(),
                    attributes: json!({
                        "storage": value.storage,
                        "storage_class": storage_class(&value.storage),
                    }),
                },
            );
        }
    }

    for hint in input.type_hints {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: hint.type_id.clone(),
                kind: "type".to_string(),
                label: format!("{}: {}", hint.location, hint.type_tag),
                function: Some(hint.function),
                va: Some(hint.site_va),
                end_va: None,
                confidence: hint.confidence.clone(),
                source: hint.source.clone(),
                evidence: hint.evidence.clone(),
                attributes: json!({
                    "location": hint.location,
                    "type_tag": hint.type_tag,
                }),
            },
        );
    }

    for flow in input.api_flows {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: flow.flow_id.clone(),
                kind: "api_flow".to_string(),
                label: format!("{} {}", flow.api, flow.argument),
                function: Some(flow.function),
                va: Some(flow.callsite),
                end_va: None,
                confidence: flow.confidence.clone(),
                source: "api_flow".to_string(),
                evidence: flow.evidence.clone(),
                attributes: json!({
                    "api": flow.api,
                    "normalized_api": flow.normalized_api,
                    "api_family": flow.api_family,
                    "api_categories": flow.api_categories,
                    "argument": flow.argument,
                    "argument_register": flow.argument_register,
                    "argument_index": flow.argument_index,
                    "argument_name": flow.argument_name,
                    "value": flow.value,
                    "value_tags": flow.value_tags,
                    "mode": flow.mode,
                    "resolved_api": flow.resolved_api,
                }),
            },
        );
    }

    for behavior in input.behavior_dossiers {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: behavior.behavior_id.clone(),
                kind: "behavior".to_string(),
                label: behavior.title.clone(),
                function: Some(behavior.function),
                va: Some(behavior.function),
                end_va: None,
                confidence: confidence_label(behavior.confidence),
                source: "behavior_dossier".to_string(),
                evidence: behavior.evidence_vas.clone(),
                attributes: json!({
                    "capability": behavior.capability,
                    "supporting_features": behavior.supporting_features,
                    "api_flow_ids": behavior.api_flow_ids,
                    "recovered_string_ids": behavior.recovered_string_ids,
                    "type_hint_ids": behavior.type_hint_ids,
                    "uncertainty": behavior.uncertainty,
                }),
            },
        );
    }

    for candidate in input.vuln_candidates {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: candidate.candidate_id.clone(),
                kind: "vuln_lead".to_string(),
                label: candidate.summary.clone(),
                function: candidate.function,
                va: candidate.site_va,
                end_va: None,
                confidence: candidate.confidence.clone(),
                source: "deterministic_vuln_leads".to_string(),
                evidence: candidate.evidence.clone(),
                attributes: json!({
                    "kind": candidate.kind,
                    "summary": candidate.summary,
                    "fuzz_harness_ref": candidate.fuzz_harness_ref,
                }),
            },
        );
    }

    for uncertainty in input.uncertainties {
        push_node(
            &mut nodes,
            &mut ids,
            GraphNodeRecord {
                id: uncertainty.uncertainty_id.clone(),
                kind: "uncertainty".to_string(),
                label: uncertainty.reason.clone(),
                function: Some(uncertainty.function),
                va: uncertainty.site_va,
                end_va: None,
                confidence: uncertainty.severity_hint.clone(),
                source: "uncertainty".to_string(),
                evidence: uncertainty.evidence.clone(),
                attributes: json!({
                    "reason": uncertainty.reason,
                    "details": uncertainty.details,
                    "tried": uncertainty.tried,
                    "recommended_action": uncertainty.recommended_action,
                    "severity_hint": uncertainty.severity_hint,
                }),
            },
        );
    }

    (
        nodes,
        ids,
        import_nodes,
        string_nodes,
        block_nodes,
        op_nodes,
        ssa_nodes,
    )
}

fn build_edges(
    input: &LlmArtifactInput<'_>,
    node_ids: &BTreeSet<String>,
    import_nodes: &BTreeMap<String, String>,
    string_nodes: &BTreeMap<u64, String>,
    block_nodes: &BTreeMap<(u64, u64), String>,
    op_nodes: &BTreeMap<u64, String>,
    ssa_nodes: &BTreeMap<String, String>,
) -> Vec<GraphEdgeRecord> {
    let mut edges = Vec::new();
    let mut edge_index = 0usize;

    for cfg in input.cfg {
        let function = function_id(cfg.function);
        for block in &cfg.blocks {
            if let Some(block_id) = block_nodes.get(&(cfg.function, block.start)) {
                push_edge(
                    &mut edges,
                    &mut edge_index,
                    node_ids,
                    "contains",
                    &function,
                    block_id,
                    Some(cfg.function),
                    Some(block.start),
                    "cfg",
                    vec![cfg.function, block.start],
                    json!({}),
                );
            }
        }
        for edge in &cfg.edges {
            let from_block = block_for_address(cfg, edge.from).unwrap_or(edge.from);
            let to_block = block_for_address(cfg, edge.to).unwrap_or(edge.to);
            if let (Some(from), Some(to)) = (
                block_nodes.get(&(cfg.function, from_block)),
                block_nodes.get(&(cfg.function, to_block)),
            ) {
                push_edge(
                    &mut edges,
                    &mut edge_index,
                    node_ids,
                    "control_flow",
                    from,
                    to,
                    Some(cfg.function),
                    Some(edge.from),
                    "cfg",
                    vec![edge.from, edge.to],
                    json!({ "edge_type": edge.edge_type }),
                );
            }
        }
    }

    for ir in input.ir {
        let Some(op) = op_nodes.get(&ir.address) else {
            continue;
        };
        if let Some(function) = function_for(input.functions, ir.address) {
            if let Some(cfg) = input.cfg.iter().find(|row| row.function == function) {
                if let Some(block) = block_for_address(cfg, ir.address)
                    .and_then(|block| block_nodes.get(&(function, block)))
                {
                    push_edge(
                        &mut edges,
                        &mut edge_index,
                        node_ids,
                        "contains",
                        block,
                        op,
                        Some(function),
                        Some(ir.address),
                        "legacy_ir",
                        vec![ir.address],
                        json!({ "semantic_source_status": "not_sleigh_pcode" }),
                    );
                }
            }
        }
    }

    for xref in input.xrefs {
        let Some(op) = op_nodes.get(&xref.from) else {
            continue;
        };
        if let Some(symbol) = &xref.symbol {
            if let Some(import_id) = import_nodes.get(symbol) {
                push_edge(
                    &mut edges,
                    &mut edge_index,
                    node_ids,
                    "xref",
                    op,
                    import_id,
                    function_for(input.functions, xref.from),
                    Some(xref.from),
                    "xrefs",
                    vec![xref.from, xref.target],
                    json!({ "xref_kind": xref.kind, "role": xref.role }),
                );
            }
        } else if let Some(string_id) = string_nodes.get(&xref.target) {
            push_edge(
                &mut edges,
                &mut edge_index,
                node_ids,
                "xref",
                op,
                string_id,
                function_for(input.functions, xref.from),
                Some(xref.from),
                "xrefs",
                vec![xref.from, xref.target],
                json!({ "xref_kind": xref.kind, "role": xref.role }),
            );
        }
    }

    let image_base = debug_image_base(input);
    for identity in input.debug_identities {
        push_edge(
            &mut edges,
            &mut edge_index,
            node_ids,
            "has_debug_identity",
            &identity.module_id,
            &identity.identity_id,
            None,
            None,
            "debug_symbols",
            identity.evidence.clone(),
            json!({ "provider": identity.provider, "identity_kind": identity.identity_kind }),
        );
    }

    for symbol in input.debug_symbols {
        push_edge(
            &mut edges,
            &mut edge_index,
            node_ids,
            "defines_symbol",
            &symbol.module_id,
            &symbol.symbol_id,
            None,
            Some(image_base.saturating_add(symbol.start_rva)),
            "debug_symbols",
            symbol.evidence.clone(),
            json!({ "provider": symbol.provider, "kind": symbol.kind }),
        );
        let symbol_start = image_base.saturating_add(symbol.start_rva);
        let symbol_end = image_base.saturating_add(symbol.end_rva);
        for function in input.functions {
            if ranges_overlap(function.start, function.end, symbol_start, symbol_end) {
                push_edge(
                    &mut edges,
                    &mut edge_index,
                    node_ids,
                    "resolves_symbol",
                    &function_id(function.start),
                    &symbol.symbol_id,
                    Some(function.start),
                    Some(function.start.max(symbol_start)),
                    "debug_symbols",
                    merged_evidence(vec![function.start], &symbol.evidence),
                    json!({
                        "symbol_name": symbol.name,
                        "provider": symbol.provider,
                        "start_rva": symbol.start_rva,
                        "end_rva": symbol.end_rva,
                    }),
                );
            }
        }
    }

    for line in input.line_entries {
        push_edge(
            &mut edges,
            &mut edge_index,
            node_ids,
            "symbol_source_file",
            &line.line_id,
            &line.file_id,
            function_for(input.functions, image_base.saturating_add(line.start_rva)),
            Some(image_base.saturating_add(line.start_rva)),
            "debug_symbols",
            line.evidence.clone(),
            json!({ "line": line.line, "column": line.column }),
        );
        let line_start = image_base.saturating_add(line.start_rva);
        let line_end = image_base.saturating_add(line.end_rva);
        for function in input.functions {
            if ranges_overlap(function.start, function.end, line_start, line_end) {
                push_edge(
                    &mut edges,
                    &mut edge_index,
                    node_ids,
                    "has_source_line",
                    &function_id(function.start),
                    &line.line_id,
                    Some(function.start),
                    Some(line_start),
                    "debug_symbols",
                    merged_evidence(vec![function.start], &line.evidence),
                    json!({ "line": line.line, "file_id": line.file_id }),
                );
            }
        }
    }

    for uncertainty in input.symbol_uncertainties {
        push_edge(
            &mut edges,
            &mut edge_index,
            node_ids,
            "symbol_uncertainty",
            &uncertainty.module_id,
            &uncertainty.uncertainty_id,
            None,
            None,
            "debug_symbols",
            uncertainty.evidence.clone(),
            json!({ "code": uncertainty.code, "provider": uncertainty.provider }),
        );
    }

    for row in input.symbol_graph_rows {
        let row_node_id = symbol_graph_node_id(&row.id);
        for related in &row.related {
            let related_node_id = symbol_graph_node_id(related);
            push_edge(
                &mut edges,
                &mut edge_index,
                node_ids,
                "symbol_graph_related",
                &row_node_id,
                &related_node_id,
                row.rva_start
                    .map(|rva| image_base.saturating_add(rva))
                    .and_then(|va| function_for(input.functions, va)),
                row.rva_start.map(|rva| image_base.saturating_add(rva)),
                "symbol_graph",
                parse_symbol_graph_evidence(&row.evidence),
                json!({
                    "raw_from": row.id,
                    "raw_to": related,
                    "provider": row.provider,
                }),
            );
        }

        match row.kind.as_str() {
            "function_symbol" | "data_symbol" => {
                let Some(symbol_start) = row.rva_start.map(|rva| image_base.saturating_add(rva))
                else {
                    continue;
                };
                let symbol_end = row
                    .rva_end
                    .map(|rva| image_base.saturating_add(rva))
                    .unwrap_or_else(|| symbol_start.saturating_add(1));
                for function in input.functions {
                    if ranges_overlap(function.start, function.end, symbol_start, symbol_end) {
                        push_edge(
                            &mut edges,
                            &mut edge_index,
                            node_ids,
                            "symbol_graph_resolves",
                            &function_id(function.start),
                            &row_node_id,
                            Some(function.start),
                            Some(function.start.max(symbol_start)),
                            "symbol_graph",
                            merged_evidence(
                                vec![function.start],
                                &parse_symbol_graph_evidence(&row.evidence),
                            ),
                            json!({
                                "symbol_name": row.label,
                                "provider": row.provider,
                                "rva_start": row.rva_start,
                                "rva_end": row.rva_end,
                            }),
                        );
                    }
                }
            }
            "line_row" => {
                let Some(line_start) = row.rva_start.map(|rva| image_base.saturating_add(rva))
                else {
                    continue;
                };
                let line_end = row
                    .rva_end
                    .map(|rva| image_base.saturating_add(rva))
                    .unwrap_or_else(|| line_start.saturating_add(1));
                for function in input.functions {
                    if ranges_overlap(function.start, function.end, line_start, line_end) {
                        push_edge(
                            &mut edges,
                            &mut edge_index,
                            node_ids,
                            "symbol_graph_source_line",
                            &function_id(function.start),
                            &row_node_id,
                            Some(function.start),
                            Some(line_start),
                            "symbol_graph",
                            merged_evidence(
                                vec![function.start],
                                &parse_symbol_graph_evidence(&row.evidence),
                            ),
                            json!({
                                "source_file": row.source_file,
                                "line_start": row.line_start,
                                "line_end": row.line_end,
                            }),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    for call in input.callgraph {
        let from = function_id(call.caller);
        if let Some(callee) = call.callee {
            push_edge(
                &mut edges,
                &mut edge_index,
                node_ids,
                "call",
                &from,
                &function_id(callee),
                Some(call.caller),
                Some(call.callsite),
                "callgraph",
                vec![call.callsite],
                json!({
                    "call_kind": call.call_kind,
                    "resolved_api": call.resolved_api,
                    "wrapper_chain": call.wrapper_chain,
                }),
            );
        }
        if let Some(import) = &call.import {
            if let Some(import_id) = import_nodes.get(import) {
                push_edge(
                    &mut edges,
                    &mut edge_index,
                    node_ids,
                    "call_import",
                    &from,
                    import_id,
                    Some(call.caller),
                    Some(call.callsite),
                    "callgraph",
                    vec![call.callsite],
                    json!({
                        "call_kind": call.call_kind,
                        "resolved_api": call.resolved_api,
                        "wrapper_chain": call.wrapper_chain,
                    }),
                );
            }
        }
    }

    for edge in input.dataflow_edges {
        let Some(to) = ssa_nodes.get(&edge.to_value) else {
            continue;
        };
        if let Some(from_value) = &edge.from_value {
            if let Some(from) = ssa_nodes.get(from_value) {
                push_edge(
                    &mut edges,
                    &mut edge_index,
                    node_ids,
                    &edge.edge_kind,
                    from,
                    to,
                    Some(edge.function),
                    Some(edge.to_va),
                    "ssa_dataflow",
                    edge.evidence.clone(),
                    json!({
                        "from_storage": edge.from_storage,
                        "to_storage": edge.to_storage,
                        "type_tag": edge.type_tag,
                    }),
                );
            }
        }
    }

    for value in input.ssa_values {
        let var_id = recovered_var_id(value.function, &value.storage);
        push_edge(
            &mut edges,
            &mut edge_index,
            node_ids,
            "storage_instance",
            &var_id,
            &value.ssa_id,
            Some(value.function),
            Some(value.site_va),
            "ssa_storage",
            value.evidence.clone(),
            json!({ "storage": value.storage, "version": value.version }),
        );
    }

    for hint in input.type_hints {
        push_edge(
            &mut edges,
            &mut edge_index,
            node_ids,
            "type_constraint",
            &hint.type_id,
            &recovered_var_id(hint.function, &hint.location),
            Some(hint.function),
            Some(hint.site_va),
            &hint.source,
            hint.evidence.clone(),
            json!({ "type_tag": hint.type_tag }),
        );
    }

    for flow in input.api_flows {
        if let Some(function) = node_ids.get(&function_id(flow.function)) {
            push_edge(
                &mut edges,
                &mut edge_index,
                node_ids,
                "api_flow",
                function,
                &flow.flow_id,
                Some(flow.function),
                Some(flow.callsite),
                "api_flow",
                flow.evidence.clone(),
                json!({ "api": flow.api, "argument": flow.argument }),
            );
        }
    }

    for behavior in input.behavior_dossiers {
        push_edge(
            &mut edges,
            &mut edge_index,
            node_ids,
            "behavior_evidence",
            &function_id(behavior.function),
            &behavior.behavior_id,
            Some(behavior.function),
            Some(behavior.function),
            "behavior_dossier",
            behavior.evidence_vas.clone(),
            json!({ "capability": behavior.capability }),
        );
    }

    for candidate in input.vuln_candidates {
        if let Some(function) = candidate.function {
            push_edge(
                &mut edges,
                &mut edge_index,
                node_ids,
                "vuln_lead",
                &function_id(function),
                &candidate.candidate_id,
                Some(function),
                candidate.site_va,
                "deterministic_vuln_leads",
                candidate.evidence.clone(),
                json!({ "kind": candidate.kind }),
            );
        }
    }

    for uncertainty in input.uncertainties {
        push_edge(
            &mut edges,
            &mut edge_index,
            node_ids,
            "uncertainty",
            &function_id(uncertainty.function),
            &uncertainty.uncertainty_id,
            Some(uncertainty.function),
            uncertainty.site_va,
            "uncertainty",
            uncertainty.evidence.clone(),
            json!({ "reason": uncertainty.reason }),
        );
    }

    for flow in input.structured_flow {
        for natural_loop in &flow.natural_loops {
            let from_block = block_for_structured(flow, natural_loop.from);
            let to_block = block_for_structured(flow, natural_loop.to);
            if let (Some(from), Some(to)) = (
                from_block.and_then(|block| block_nodes.get(&(flow.function, block))),
                to_block.and_then(|block| block_nodes.get(&(flow.function, block))),
            ) {
                push_edge(
                    &mut edges,
                    &mut edge_index,
                    node_ids,
                    "loop_backedge",
                    from,
                    to,
                    Some(flow.function),
                    Some(natural_loop.from),
                    "structured_flow",
                    vec![natural_loop.from, natural_loop.to],
                    json!({ "edge_type": natural_loop.edge_type }),
                );
            }
        }
    }

    edges
}

fn build_source_views(input: &LlmArtifactInput<'_>) -> Vec<DecompiledSourceRecord> {
    if input.decompile_source_mode == "off" {
        return Vec::new();
    }
    let limit = if input.decompile_source_mode == "all" {
        usize::MAX
    } else {
        16
    };
    let pseudo_by_function: BTreeMap<u64, &PseudoIrRecord> = input
        .pseudo_ir
        .iter()
        .map(|row| (row.function, row))
        .collect();
    let c_by_function: BTreeMap<u64, &DecompiledCRecord> = input
        .decompiled_c
        .iter()
        .map(|row| (row.function, row))
        .collect();
    let mut selected = input
        .function_dossiers
        .iter()
        .map(|row| row.function)
        .collect::<Vec<_>>();
    if selected.is_empty() {
        selected = input.functions.iter().map(|row| row.start).collect();
    }
    selected.sort_unstable();
    selected.dedup();

    let mut rows = Vec::new();
    for function in selected.into_iter().take(limit) {
        let mut lines = Vec::new();
        lines.push("// LLM source view generated from deterministic graph artifacts.".to_string());
        lines.push("// Source of truth: graph/nodes.jsonl and graph/edges.jsonl.".to_string());
        lines.push(format!("fn function_{function:016X}() {{"));
        if let Some(pseudo) = pseudo_by_function.get(&function) {
            for line in pseudo.lines.iter().take(80) {
                lines.push(format!("    // {}", line.replace('\n', " ")));
            }
        } else if let Some(c) = c_by_function.get(&function) {
            for line in c.lines.iter().take(80) {
                lines.push(format!("    // {}", line.replace('\n', " ")));
            }
        } else {
            lines.push(
                "    // no pseudo-IR was available at the current semantic depth".to_string(),
            );
        }
        lines.push("}".to_string());

        let relative =
            PathBuf::from("decompiled_rust").join(format!("function_{function:016X}.rs"));
        let path = input.out_dir.join(&relative);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&path, format!("{}\n", lines.join("\n")));
        rows.push(DecompiledSourceRecord {
            source_id: format!("source:rustlike:{function:016X}"),
            function,
            language: "rustlike".to_string(),
            status: "generated_from_graph_view".to_string(),
            output_path: relative.to_string_lossy().replace('\\', "/"),
            source_of_truth: "graph".to_string(),
            confidence: "low".to_string(),
            evidence: vec![function],
            lines,
        });
    }
    rows
}

fn write_llm_review_packs(input: &LlmArtifactInput<'_>) -> Result<usize, Box<dyn Error>> {
    if input.review_packs_mode == "off" {
        return Ok(0);
    }
    let limit = if input.review_packs_mode == "all" {
        128
    } else {
        32
    };
    let review_dir = input.out_dir.join("review_packs");
    fs::create_dir_all(&review_dir)?;
    let mut ranked = input.function_dossiers.iter().collect::<Vec<_>>();
    ranked.sort_by_key(|row| std::cmp::Reverse(row.score));
    let pseudo_by_function: BTreeMap<u64, &PseudoIrRecord> = input
        .pseudo_ir
        .iter()
        .map(|row| (row.function, row))
        .collect();
    let flow_by_function = group_by_function(input.api_flows.iter().map(|row| (row.function, row)));
    let vuln_by_function = group_by_function(
        input
            .vuln_candidates
            .iter()
            .filter_map(|row| row.function.map(|f| (f, row))),
    );
    let uncertainty_by_function =
        group_by_function(input.uncertainties.iter().map(|row| (row.function, row)));
    let image_base = debug_image_base(input);

    let mut packs = Vec::new();
    for (index, dossier) in ranked.into_iter().take(limit).enumerate() {
        let file = format!("llm_{index:03}_0x{:016X}.json", dossier.function);
        let symbols = input
            .debug_symbols
            .iter()
            .filter(|symbol| {
                let start = image_base.saturating_add(symbol.start_rva);
                let end = image_base.saturating_add(symbol.end_rva);
                ranges_overlap(
                    dossier.function,
                    dossier.function.saturating_add(1),
                    start,
                    end,
                ) || input
                    .functions
                    .iter()
                    .find(|function| function.start == dossier.function)
                    .is_some_and(|function| {
                        ranges_overlap(function.start, function.end, start, end)
                    })
            })
            .collect::<Vec<_>>();
        let lines = input
            .line_entries
            .iter()
            .filter(|line| {
                let start = image_base.saturating_add(line.start_rva);
                input
                    .functions
                    .iter()
                    .find(|function| function.start == dossier.function)
                    .is_some_and(|function| function.start <= start && start < function.end)
            })
            .take(64)
            .collect::<Vec<_>>();
        let payload = json!({
            "schema": "llm_review_pack/1",
            "pack_kind": "function",
            "function": dossier.function,
            "score": dossier.score,
            "dossier": dossier,
            "symbols": symbols,
            "source_lines": lines,
            "pseudo_ir": pseudo_by_function.get(&dossier.function),
            "api_flows": flow_by_function.get(&dossier.function).cloned().unwrap_or_default(),
            "vuln_leads": vuln_by_function.get(&dossier.function).cloned().unwrap_or_default(),
            "uncertainties": uncertainty_by_function.get(&dossier.function).cloned().unwrap_or_default(),
            "graph_entrypoints": {
                "function_node": function_id(dossier.function),
                "nodes": "graph/nodes.jsonl",
                "edges": "graph/edges.jsonl"
            }
        });
        write_json(review_dir.join(&file), &payload)?;
        packs.push(json!({
            "file": file,
            "kind": "function",
            "function": dossier.function,
            "score": dossier.score,
        }));
    }

    for (index, candidate) in input.vuln_candidates.iter().take(32).enumerate() {
        let file = format!(
            "llm_vuln_{index:03}_{}.json",
            safe_file_component(&candidate.candidate_id)
        );
        let payload = json!({
            "schema": "llm_review_pack/1",
            "pack_kind": "vuln_lead",
            "candidate": candidate,
            "graph_entrypoints": {
                "vuln_node": candidate.candidate_id,
                "function_node": candidate.function.map(function_id),
                "nodes": "graph/nodes.jsonl",
                "edges": "graph/edges.jsonl"
            }
        });
        write_json(review_dir.join(&file), &payload)?;
        packs.push(json!({
            "file": file,
            "kind": "vuln_lead",
            "function": candidate.function,
            "score": 0,
        }));
    }

    write_json(
        review_dir.join("llm_manifest.json"),
        &json!({
            "schema": "llm_review_pack_manifest/1",
            "debug_symbols": {
                "symbols": input.debug_symbols.len(),
                "source_files": input.source_files.len(),
                "line_entries": input.line_entries.len(),
                "symbol_uncertainties": input.symbol_uncertainties.len(),
            },
            "symbol_graph": {
                "records": input.symbol_graph_rows.len(),
                "packets": input.symbol_packet_count,
            },
            "packs": packs,
        }),
    )?;
    Ok(packs.len())
}

fn build_manifest(
    input: &LlmArtifactInput<'_>,
    artifacts: Vec<ArtifactIndexRecord>,
    nodes: usize,
    edges: usize,
    review_packs: usize,
    sources: usize,
) -> AnalysisManifestRecord {
    let mut counts = BTreeMap::new();
    counts.insert("functions".to_string(), input.functions.len());
    counts.insert(
        "blocks".to_string(),
        input.cfg.iter().map(|row| row.blocks.len()).sum(),
    );
    counts.insert("instructions".to_string(), input.instructions.len());
    counts.insert("legacy_ir_ops".to_string(), input.ir.len());
    counts.insert("imports".to_string(), input.imports.len());
    counts.insert("strings".to_string(), input.strings.len());
    counts.insert("ssa_values".to_string(), input.ssa_values.len());
    counts.insert("dataflow_edges".to_string(), input.dataflow_edges.len());
    counts.insert("api_flows".to_string(), input.api_flows.len());
    counts.insert("vuln_leads".to_string(), input.vuln_candidates.len());
    counts.insert("uncertainties".to_string(), input.uncertainties.len());
    counts.insert("debug_modules".to_string(), input.debug_modules.len());
    counts.insert("debug_identities".to_string(), input.debug_identities.len());
    counts.insert("symbols".to_string(), input.debug_symbols.len());
    counts.insert("source_files".to_string(), input.source_files.len());
    counts.insert("line_entries".to_string(), input.line_entries.len());
    counts.insert("inline_scopes".to_string(), input.inline_scopes.len());
    counts.insert("debug_types".to_string(), input.debug_types.len());
    counts.insert(
        "symbol_uncertainties".to_string(),
        input.symbol_uncertainties.len(),
    );
    counts.insert(
        "symbol_graph_records".to_string(),
        input.symbol_graph_rows.len(),
    );
    counts.insert("symbol_packets".to_string(), input.symbol_packet_count);
    counts.insert("graph_nodes".to_string(), nodes);
    counts.insert("graph_edges".to_string(), edges);
    counts.insert("review_packs".to_string(), review_packs);
    counts.insert("decompiled_sources".to_string(), sources);

    AnalysisManifestRecord {
        schema: "llm_analysis_manifest/1".to_string(),
        sha256: input.sha256.to_string(),
        source_path: input.source_path.to_string(),
        format: input.format_label.to_string(),
        machine: input.machine,
        llm_artifacts_mode: input.llm_artifacts_mode.to_string(),
        review_packs_mode: input.review_packs_mode.to_string(),
        decompile_source_mode: input.decompile_source_mode.to_string(),
        deterministic: true,
        model_free: true,
        source_of_truth: "graph/nodes.jsonl + graph/edges.jsonl".to_string(),
        artifact_index: artifacts,
        counts,
        recommended_reading_order: vec![
            "analysis_manifest.json".to_string(),
            "symbol_packets/manifest.json".to_string(),
            "symbol_graph.jsonl".to_string(),
            "symbol_indexes.json".to_string(),
            "symbols.jsonl".to_string(),
            "debug_identities.jsonl".to_string(),
            "graph/nodes.jsonl".to_string(),
            "graph/edges.jsonl".to_string(),
            "review_packs/llm_manifest.json".to_string(),
            "function_dossiers.jsonl".to_string(),
            "behavior_dossiers.jsonl".to_string(),
            "vuln_candidates.jsonl".to_string(),
            "uncertainty.jsonl".to_string(),
            "decompiled_source.jsonl".to_string(),
            "switches.jsonl".to_string(),
            "eh.jsonl".to_string(),
            "classes.jsonl".to_string(),
        ],
        limitations: vec![
            "axe is deterministic and model-free; external LLMs consume these artifacts after analysis".to_string(),
            "debug symbols are local-only and Rust-only; missing PDB/DWARF files become symbol_uncertainty records".to_string(),
            "SLEIGH p-code lifter adapter is not integrated in this slice; legacy deterministic IR is marked as not_sleigh_pcode".to_string(),
            "source views are lossy hints and are not the source of truth".to_string(),
        ],
        caps_hit: json!({
            "disassembly": input.disasm_capped,
            "semantic": input.semantic_caps_hit,
        }),
    }
}

fn artifact_index(
    input: &LlmArtifactInput<'_>,
    nodes: usize,
    edges: usize,
    review_packs: usize,
    sources: usize,
) -> Vec<ArtifactIndexRecord> {
    vec![
        ArtifactIndexRecord {
            path: "debug_modules.jsonl".to_string(),
            kind: "debug_modules".to_string(),
            description: "Normalized loaded-module records used by the Rust-only debug symbol layer".to_string(),
            record_count: input.debug_modules.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "debug_identities.jsonl".to_string(),
            kind: "debug_identities".to_string(),
            description: "PDB RSDS, ELF build-id/debuglink, embedded DWARF, and dSYM locator identities".to_string(),
            record_count: input.debug_identities.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "symbols.jsonl".to_string(),
            kind: "symbols".to_string(),
            description: "Normalized function/data/public symbols from object, DWARF, PDB, or function recovery providers".to_string(),
            record_count: input.debug_symbols.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "source_files.jsonl".to_string(),
            kind: "source_files".to_string(),
            description: "Normalized source file records from local debug information".to_string(),
            record_count: input.source_files.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "line_entries.jsonl".to_string(),
            kind: "line_entries".to_string(),
            description: "Normalized source line ranges resolved from local debug information".to_string(),
            record_count: input.line_entries.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "inline_scopes.jsonl".to_string(),
            kind: "inline_scopes".to_string(),
            description: "Normalized inline scope records from local debug information".to_string(),
            record_count: input.inline_scopes.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "debug_types.jsonl".to_string(),
            kind: "debug_types".to_string(),
            description: "Lazy provider-local debug type references, normalized above raw DWARF/PDB keys".to_string(),
            record_count: input.debug_types.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "symbol_uncertainty.jsonl".to_string(),
            kind: "symbol_uncertainty".to_string(),
            description: "Typed symbol/debug-info failures and partial-result records".to_string(),
            record_count: input.symbol_uncertainties.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "symbol_graph.jsonl".to_string(),
            kind: "symbol_graph".to_string(),
            description: "Canonical SymbolGraph IR rows normalized from object, DWARF, PDB, and recovered analysis facts".to_string(),
            record_count: input.symbol_graph_rows.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "symbol_indexes.json".to_string(),
            kind: "symbol_indexes".to_string(),
            description: "Deterministic address, name, source, type, compile-unit, and evidence indexes over SymbolGraph rows".to_string(),
            record_count: input.symbol_graph_rows.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "symbol_packets/manifest.json".to_string(),
            kind: "symbol_packet_manifest".to_string(),
            description: "Compact address-backed SymbolGraph packets intended for external LLM context windows".to_string(),
            record_count: input.symbol_packet_count,
            status: None,
        },
        ArtifactIndexRecord {
            path: "graph/nodes.jsonl".to_string(),
            kind: "graph_nodes".to_string(),
            description: "Entity nodes for functions, blocks, ops, values, memory, types, APIs, behaviors, vuln leads, and uncertainties".to_string(),
            record_count: nodes,
            status: None,
        },
        ArtifactIndexRecord {
            path: "graph/edges.jsonl".to_string(),
            kind: "graph_edges".to_string(),
            description: "Relationship edges for containment, CFG, calls, xrefs, dataflow, type constraints, vuln evidence, and uncertainties".to_string(),
            record_count: edges,
            status: None,
        },
        ArtifactIndexRecord {
            path: "review_packs/llm_manifest.json".to_string(),
            kind: "review_pack_manifest".to_string(),
            description: "Compact context-window packs for external LLM review".to_string(),
            record_count: review_packs,
            status: None,
        },
        ArtifactIndexRecord {
            path: "decompiled_source.jsonl".to_string(),
            kind: "source_view".to_string(),
            description: "Optional Rust-like source views generated from deterministic artifacts".to_string(),
            record_count: sources,
            status: None,
        },
        ArtifactIndexRecord {
            path: "switches.jsonl".to_string(),
            kind: "switches".to_string(),
            description: "Recovered switch statements: index expr, range guard, default target, per-case (value, target_va), and lowering classification (MSVC absolute/RVA, PIC offset, compare-tree, bit-test, â€¦)".to_string(),
            record_count: input.switches.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "eh.jsonl".to_string(),
            kind: "eh".to_string(),
            description: "Normalized exception-handling facts: try regions, catch handlers (with type names), cleanup actions; ABI-tagged (MSVC FH3/FH4/SEH, Itanium .eh_frame+LSDA)".to_string(),
            record_count: input.eh_facts.len(),
            status: None,
        },
        ArtifactIndexRecord {
            path: "classes.jsonl".to_string(),
            kind: "cpp_classes".to_string(),
            description: "Reconstructed C++ class facts: demangled name, size, ABI, vtables, base classes, fields, methods, constructors/destructors; per-field Claim<T> with source attribution (PDB/DWARF/RTTI/Heuristic)".to_string(),
            record_count: input.class_facts.len(),
            status: None,
        },
    ]
}

fn push_node(nodes: &mut Vec<GraphNodeRecord>, ids: &mut BTreeSet<String>, node: GraphNodeRecord) {
    if ids.insert(node.id.clone()) {
        nodes.push(node);
    }
}

fn symbol_graph_node_id(raw_id: &str) -> String {
    format!("symbol_graph:{raw_id}")
}

fn parse_symbol_graph_evidence(evidence: &[String]) -> Vec<u64> {
    evidence
        .iter()
        .filter_map(|value| {
            value
                .strip_prefix("rva_or_va:")
                .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                .or_else(|| value.parse::<u64>().ok())
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push_edge(
    edges: &mut Vec<GraphEdgeRecord>,
    edge_index: &mut usize,
    node_ids: &BTreeSet<String>,
    kind: &str,
    from: &str,
    to: &str,
    function: Option<u64>,
    va: Option<u64>,
    source: &str,
    mut evidence: Vec<u64>,
    attributes: Value,
) {
    if !node_ids.contains(from) || !node_ids.contains(to) || from == to {
        return;
    }
    evidence.sort_unstable();
    evidence.dedup();
    let id = format!("edge:{kind}:{:08X}", *edge_index);
    *edge_index += 1;
    edges.push(GraphEdgeRecord {
        id,
        kind: kind.to_string(),
        from: from.to_string(),
        to: to.to_string(),
        function,
        va,
        confidence: "medium".to_string(),
        source: source.to_string(),
        evidence,
        attributes,
    });
}

fn write_json(path: PathBuf, value: &Value) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    serde_json::to_writer_pretty(BufWriter::new(file), value)?;
    Ok(())
}

fn write_jsonl<T: Serialize>(path: PathBuf, rows: &[T]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut writer = BufWriter::with_capacity(256 * 1024, File::create(path)?);
    for row in rows {
        serde_json::to_writer(&mut writer, row)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

fn group_by_function<'a, T, I>(rows: I) -> BTreeMap<u64, Vec<&'a T>>
where
    I: IntoIterator<Item = (u64, &'a T)>,
{
    let mut grouped: BTreeMap<u64, Vec<&T>> = BTreeMap::new();
    for (function, row) in rows {
        grouped.entry(function).or_default().push(row);
    }
    grouped
}

fn function_for(functions: &[FunctionRecord], va: u64) -> Option<u64> {
    functions
        .iter()
        .find(|row| row.start <= va && va < row.end)
        .map(|row| row.start)
}

fn debug_image_base(input: &LlmArtifactInput<'_>) -> u64 {
    input
        .debug_modules
        .first()
        .map(|module| module.image_base)
        .unwrap_or(0)
}

fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    let a_end = a_end.max(a_start.saturating_add(1));
    let b_end = b_end.max(b_start.saturating_add(1));
    a_start < b_end && b_start < a_end
}

fn merged_evidence(mut primary: Vec<u64>, secondary: &[u64]) -> Vec<u64> {
    primary.extend_from_slice(secondary);
    primary.sort_unstable();
    primary.dedup();
    primary
}

fn block_for_address(cfg: &CfgRecord, address: u64) -> Option<u64> {
    cfg.blocks
        .iter()
        .find(|block| block.start <= address && address < block.end)
        .map(|block| block.start)
        .or_else(|| {
            cfg.blocks
                .iter()
                .any(|block| block.start == address)
                .then_some(address)
        })
}

fn block_for_structured(flow: &StructuredFlowRecord, address: u64) -> Option<u64> {
    flow.block_order
        .iter()
        .copied()
        .filter(|block| *block <= address)
        .max()
}

fn function_id(va: u64) -> String {
    format!("function:{va:016X}")
}

fn block_id(function: u64, va: u64) -> String {
    format!("block:{function:016X}:{va:016X}")
}

fn op_id(va: u64) -> String {
    format!("op:{va:016X}")
}

fn recovered_var_id(function: u64, storage: &str) -> String {
    format!(
        "var:{function:016X}:{}",
        safe_file_component(&storage.to_ascii_lowercase())
    )
}

fn storage_class(storage: &str) -> &'static str {
    if storage == "mem" {
        "unknown_memory"
    } else if storage.starts_with("stack[") {
        "stack"
    } else if matches!(storage, "zf" | "sf" | "of" | "cf" | "pf" | "af") {
        "flag"
    } else {
        "register"
    }
}

fn confidence_label(score: f64) -> String {
    if score >= 0.7 {
        "high"
    } else if score >= 0.4 {
        "medium"
    } else {
        "low"
    }
    .to_string()
}

fn truncate_label(value: &str, max: usize) -> String {
    let mut out = value.chars().take(max).collect::<String>();
    if value.chars().count() > max {
        out.push_str("...");
    }
    out
}
