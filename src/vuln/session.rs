//! v1.0 session orchestrator.
//!
//! Sequence: ingest existing analyses → build EvidenceGraph → load
//! templates → propagate taint → discover chains → score → emit 4
//! LLM artifacts → finalize ledger.
//!
//! The session takes pre-built axe analysis records as input — it
//! does NOT re-run the static analysis. Callers (typically `axe`'s
//! CLI in `bin/axe.rs`) pass the records they already have.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::attack::AttackTechniqueRecord;
use crate::pe::{
    ApiFlowRecord, BehaviorDossierRecord, CfgRecord, DataflowEdgeRecord, FunctionRecord,
    ImportRecord, SsaValueRecord, ValueGraphRecord, VsaValueRecord, XrefRecord,
};

use crate::vuln::bug_class::TemplateRegistry;
use crate::vuln::call_summaries::compute_summaries;
use crate::vuln::confirmation::{aggregate_for_chain, ChainConfirmation};
use crate::vuln::dynamic_attempt::{attempts_from_dynamic_evidence, emit_dynamic_attempts_jsonl};
use crate::vuln::dynamic_evidence::DynamicEvidence;
use crate::vuln::dynamic_orchestrator::{
    orchestrate, DynamicOrchestratorInput, DynamicOrchestratorOptions,
};
use crate::vuln::finding::{attach_v1_1_context, emit_finding, FindingRecord, FindingStore};
use crate::vuln::graph::EvidenceGraph;
use crate::vuln::graph_builder::{
    ingest_api_flows, ingest_attack, ingest_behavior_dossiers, ingest_callsite_ssa_bridge,
    ingest_cfg, ingest_dataflow, ingest_functions, ingest_imports, ingest_local_sink_wrappers,
    ingest_ssa, ingest_value_graph, ingest_vsa, ingest_xrefs,
};
use crate::vuln::harness_synth::{default_kind_for_chain, synthesize, Harness};
use crate::vuln::llm_analyst::{suggest_patches, suggest_tests};
use crate::vuln::llm_pack::{
    emit_chain_graph_json, emit_evidence_bundle_json, emit_evidence_bundle_json_v1_1,
    emit_findings_jsonl, emit_harness_artifacts, emit_lifetime_candidates_jsonl,
    emit_patch_suggestions_jsonl, emit_test_suggestions_jsonl, is_lifetime_bug_class,
    split_findings_by_lifetime,
};
use crate::vuln::proof_packet::{emit_proof_packets, ProofPacketInput};
use crate::vuln::query::{discover_chains, CandidateChain};
use crate::vuln::scoring::{score_chain, score_chain_v1_1, FindingScore};
use crate::vuln::sinks::SinkCatalog;
use crate::vuln::sources::SourceCatalog;
use crate::vuln::taint::propagate;
use crate::vuln::vuln_run_status::{RunMeta, VulnRunStatusLedger};
use crate::vuln::{HarnessTierMode, VulnError, VulnOptions, VulnReport};

/// Pre-computed analysis inputs that the session ingests into the
/// EvidenceGraph. The caller (typically the CLI in `bin/axe.rs`)
/// passes the records its earlier analysis pass produced.
#[derive(Default)]
pub struct VulnInputs<'a> {
    pub run_id: &'a str,
    pub source_path: Option<&'a str>,
    pub functions: &'a [FunctionRecord],
    pub cfgs: &'a [CfgRecord],
    pub xrefs: &'a [XrefRecord],
    pub ssa: &'a [SsaValueRecord],
    pub dataflow: &'a [DataflowEdgeRecord],
    pub value_graph: &'a [ValueGraphRecord],
    pub vsa: &'a [VsaValueRecord],
    pub attack: &'a [AttackTechniqueRecord],
    pub behavior_dossiers: &'a [BehaviorDossierRecord],
    pub api_flows: &'a [ApiFlowRecord],
    pub imports: &'a [ImportRecord],
}

pub fn run(opts: &VulnOptions, inputs: &VulnInputs<'_>) -> Result<VulnReport, VulnError> {
    let started = now_ms();
    std::fs::create_dir_all(&opts.out_dir)?;

    let mut ledger = VulnRunStatusLedger::create(&opts.out_dir, inputs.run_id, started);

    // ----- Build graph -----
    let mut graph = EvidenceGraph::new();
    ingest_functions(&mut graph, inputs.functions);
    ingest_cfg(&mut graph, inputs.cfgs);
    ingest_xrefs(&mut graph, inputs.xrefs);
    let ssa_index = ingest_ssa(&mut graph, inputs.ssa);
    ingest_dataflow(&mut graph, inputs.dataflow, &ssa_index);
    ingest_value_graph(&mut graph, inputs.value_graph, &ssa_index);
    ingest_vsa(&mut graph, inputs.vsa);
    ingest_attack(&mut graph, inputs.attack);
    ingest_behavior_dossiers(&mut graph, inputs.behavior_dossiers);
    ingest_api_flows(&mut graph, inputs.api_flows);
    ingest_local_sink_wrappers(&mut graph, inputs.functions, inputs.xrefs);
    ingest_imports(&mut graph, inputs.imports);
    // v1.0.1: bridge CallSites to SSA values at shared VAs so taint
    // can propagate across call boundaries. Without this, the 10
    // tainted-arg templates fire zero times on real binaries.
    ingest_callsite_ssa_bridge(&mut graph, inputs.api_flows, inputs.ssa, &ssa_index);

    // ----- Load templates + catalogs -----
    let source_catalog = SourceCatalog::v1_0();
    let sink_catalog = SinkCatalog::v1_0();
    let templates = TemplateRegistry::load_v1_0();
    let templates_filtered = templates.filter_csv(&opts.templates);

    // ----- Taint + summaries -----
    let summaries = compute_summaries(&graph);
    let taint = propagate(&graph, &source_catalog, &summaries);

    // ----- Discover chains -----
    let mut chains = discover_chains(&graph, &taint, &source_catalog, &sink_catalog, &templates);

    // v1.1: append lifetime candidates when opt-in is on AND the
    // feature is compiled. Lifetime chains carry distinct
    // template_id strings so the routing in split_findings_by_lifetime
    // (Step 34) handles them correctly.
    if opts.enable_v1_1 && opts.include_lifetime {
        chains.extend(discover_lifetime_when_enabled(&graph));
    }

    // ----- v1.1: build per-chain harnesses (when enabled) -----
    let harnesses_by_chain: BTreeMap<String, Harness> = if opts.enable_v1_1 {
        chains
            .iter()
            .map(|c| {
                let kind = default_kind_for_chain(c);
                (c.chain_id.clone(), synthesize(c, &sink_catalog, kind))
            })
            .collect()
    } else {
        BTreeMap::new()
    };
    let dynamic_evidence = if opts.enable_v1_1 {
        let mut explicit_dynamic = opts.dynamic_evidence.clone();
        explicit_dynamic.extend(crate::vuln::controlled_confirm::confirm_controlled_fixture(
            inputs.source_path,
            &chains,
            &harnesses_by_chain,
        ));
        orchestrate(
            &harnesses_by_chain,
            DynamicOrchestratorInput {
                source_path: inputs.source_path,
                explicit_evidence: &explicit_dynamic,
            },
            DynamicOrchestratorOptions {
                requested_sources: &opts.dynamic_confirmation_sources,
                include_controlled_fixture: true,
            },
        )
        .evidence
    } else {
        Vec::new()
    };
    let confirmations_by_chain: BTreeMap<String, ChainConfirmation> = if opts.enable_v1_1 {
        harnesses_by_chain
            .values()
            .filter_map(|harness| {
                aggregate_for_chain(harness, &dynamic_evidence)
                    .map(|confirmation| (harness.chain_id.clone(), confirmation))
            })
            .collect()
    } else {
        BTreeMap::new()
    };

    // ----- Score + filter -----
    let mut findings: Vec<FindingRecord> = Vec::new();
    let mut chains_above_threshold = 0u64;
    let mut finding_counter: u32 = 0;
    for chain in &chains {
        let template_in_filtered = templates_filtered
            .iter()
            .find(|t| t.id == chain.template_id);
        // Lifetime templates aren't in the v1.0 filtered registry but
        // we still want to score them when enable_v1_1 + include_lifetime
        // is on. Synthesize a minimal BugClass on the fly via the
        // lifetime-template metadata if needed.
        let template_owned: Option<crate::vuln::bug_class::BugClass> =
            if template_in_filtered.is_none() && is_lifetime_bug_class(&chain.template_id) {
                Some(lifetime_template_for(&chain.template_id))
            } else {
                None
            };
        let template_ref: &crate::vuln::bug_class::BugClass =
            match (template_in_filtered, template_owned.as_ref()) {
                (Some(t), _) => t,
                (None, Some(t)) => t,
                (None, None) => continue,
            };

        // v1.1: build confirmation for this chain from pre-collected
        // dynamic evidence and re-score via score_chain_v1_1 (which
        // returns base score when confirmation is None or doesn't
        // contribute).
        let score: FindingScore = if opts.enable_v1_1 {
            let confirmation = confirmations_by_chain.get(&chain.chain_id);
            score_chain_v1_1(chain, template_ref, &source_catalog, confirmation)
        } else {
            score_chain(chain, template_ref, &source_catalog)
        };
        if score.confidence < opts.confidence_threshold {
            continue;
        }
        finding_counter += 1;
        let id = format!("F-{:06}", finding_counter);
        let mut finding = emit_finding(
            inputs.run_id,
            &id,
            chain,
            template_ref,
            &score,
            &source_catalog,
        );
        if opts.enable_v1_1 {
            attach_v1_1_context(
                &mut finding,
                chain,
                harnesses_by_chain.get(&chain.chain_id),
                confirmations_by_chain.get(&chain.chain_id),
            );
        }
        chains_above_threshold += 1;
        findings.push(finding);
    }

    // ----- v1.1: split lifetime findings into separate stream -----
    let (default_findings, lifetime_findings) = if opts.enable_v1_1 {
        split_findings_by_lifetime(&findings)
    } else {
        (findings.clone(), Vec::new())
    };

    // ----- Persist to SQLite store (only the default stream; lifetime
    // ----- candidates are intentionally outside the canonical store) -----
    let store_path = opts.out_dir.join("findings.sqlite");
    let mut store = FindingStore::open(&store_path)
        .map_err(|e| VulnError::Io(std::io::Error::other(format!("{e}"))))?;
    for f in &default_findings {
        store
            .insert(f)
            .map_err(|e| VulnError::Io(std::io::Error::other(format!("{e}"))))?;
    }
    let store_bytes = std::fs::metadata(&store_path).map(|m| m.len()).unwrap_or(0);
    ledger.mark_complete(
        "findings.sqlite",
        store_bytes,
        default_findings.len() as u64,
    );

    // ----- Emit v1.0 LLM artifacts -----
    let findings_path = opts.out_dir.join("findings.jsonl");
    let chain_graph_path = opts.out_dir.join("chain_graph.json");
    let bundle_path = opts.out_dir.join("evidence_bundle.json");
    let findings_bytes = emit_findings_jsonl(&findings_path, &default_findings)?;
    let chain_graph_bytes =
        emit_chain_graph_json(&chain_graph_path, inputs.run_id, &default_findings)?;
    ledger.mark_complete(
        "findings.jsonl",
        findings_bytes,
        default_findings.len() as u64,
    );
    ledger.mark_complete("chain_graph.json", chain_graph_bytes, 1);

    let bundle_bytes = if opts.enable_v1_1 {
        emit_evidence_bundle_json_v1_1(&bundle_path, inputs.run_id, &findings, 10)?
    } else {
        emit_evidence_bundle_json(&bundle_path, inputs.run_id, &default_findings, 10)?
    };
    ledger.mark_complete("evidence_bundle.json", bundle_bytes, 1);

    // ----- v1.1: emit additional artifacts -----
    if opts.enable_v1_1 {
        // harnesses/ directory — skeleton always; runnable only when
        // tier is Both AND harness was promoted to Runnable.
        let harnesses_dir = opts.out_dir.join("harnesses");
        // Filter runnable_rust visibility per HarnessTierMode. For
        // SkeletonOnly mode we strip runnable_rust before emission so
        // emit_harness_artifacts never writes a .runnable.rs (Codex
        // finding 2 strict default).
        let harnesses_for_emit: Vec<Harness> = harnesses_by_chain
            .values()
            .cloned()
            .map(|mut h| {
                if opts.harness_tier == HarnessTierMode::SkeletonOnly {
                    h.runnable_rust = None;
                }
                h
            })
            .collect();
        let files_written = emit_harness_artifacts(&harnesses_dir, &harnesses_for_emit)?;
        ledger.mark_complete(
            "harnesses",
            harnesses_dir_bytes(&harnesses_dir),
            files_written as u64,
        );
        let dynamic_evidence_path = opts.out_dir.join("dynamic_evidence.jsonl");
        let dynamic_evidence_bytes =
            emit_dynamic_evidence_jsonl(&dynamic_evidence_path, &dynamic_evidence)?;
        ledger.mark_complete(
            "dynamic_evidence.jsonl",
            dynamic_evidence_bytes,
            dynamic_evidence.len() as u64,
        );
        let dynamic_attempts =
            attempts_from_dynamic_evidence(&harnesses_by_chain, &dynamic_evidence);
        let dynamic_attempts_path = opts.out_dir.join("dynamic_attempts.jsonl");
        let dynamic_attempts_bytes =
            emit_dynamic_attempts_jsonl(&dynamic_attempts_path, &dynamic_attempts)?;
        ledger.mark_complete(
            "dynamic_attempts.jsonl",
            dynamic_attempts_bytes,
            dynamic_attempts.len() as u64,
        );

        // patch_suggestions.jsonl + test_suggestions.jsonl — derived
        // from the default findings (lifetime suggestions are
        // intentionally NOT included here; Step 33's analyst handles
        // them via fall-through but we exclude lifetime from the
        // default-stream suggestion artifact to mirror Codex
        // finding 3's separation).
        let proof_packets = emit_proof_packets(
            &opts.out_dir,
            ProofPacketInput {
                run_id: inputs.run_id,
                findings: &default_findings,
                chains: &chains,
                harnesses_by_chain: &harnesses_by_chain,
                confirmations_by_chain: &confirmations_by_chain,
                api_flows: inputs.api_flows,
            },
        )?;
        ledger.mark_complete(
            "vuln_packets",
            proof_packets.bytes_written,
            proof_packets.packet_count as u64,
        );

        let mut patch_suggestions = Vec::new();
        let mut test_suggestions = Vec::new();
        for f in &default_findings {
            patch_suggestions.extend(suggest_patches(f));
            test_suggestions.extend(suggest_tests(f));
        }
        let patch_path = opts.out_dir.join("patch_suggestions.jsonl");
        let test_path = opts.out_dir.join("test_suggestions.jsonl");
        let patch_bytes = emit_patch_suggestions_jsonl(&patch_path, &patch_suggestions)?;
        let test_bytes = emit_test_suggestions_jsonl(&test_path, &test_suggestions)?;
        ledger.mark_complete(
            "patch_suggestions.jsonl",
            patch_bytes,
            patch_suggestions.len() as u64,
        );
        ledger.mark_complete(
            "test_suggestions.jsonl",
            test_bytes,
            test_suggestions.len() as u64,
        );

        // lifetime_candidates.jsonl — only when include_lifetime is on
        // AND we have lifetime findings. Codex finding 3 enforcement:
        // separate from findings.jsonl.
        if opts.include_lifetime && !lifetime_findings.is_empty() {
            let lifetime_path = opts.out_dir.join("lifetime_candidates.jsonl");
            let lifetime_bytes =
                emit_lifetime_candidates_jsonl(&lifetime_path, &lifetime_findings)?;
            ledger.mark_complete(
                "lifetime_candidates.jsonl",
                lifetime_bytes,
                lifetime_findings.len() as u64,
            );
        }
    }

    // ----- Finalize ledger -----
    let phase = if opts.enable_v1_1 {
        "v1.1_dynamic_confirmation"
    } else {
        "v1.0_static"
    };
    ledger.set_run_meta(RunMeta {
        phase: phase.into(),
        templates_loaded: templates_filtered.len() as u32,
        chains_discovered: chains.len() as u64,
        chains_above_threshold,
        scoring_calibrated: false,
    });
    let run_status_path = opts.out_dir.join("run_status.json");
    ledger.finalize_atomic(now_ms())?;

    Ok(VulnReport {
        run_id: inputs.run_id.to_string(),
        chains_discovered: chains.len() as u64,
        chains_above_threshold,
        findings_emitted: findings.len() as u64,
        templates_loaded: templates_filtered.len() as u32,
        run_status_path: Some(run_status_path),
    })
}

/// Approximate the byte size of a harnesses directory by summing
/// file sizes. Used only for the ledger record-bytes field.
fn harnesses_dir_bytes(dir: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in rd.flatten() {
        if let Ok(meta) = entry.metadata() {
            total += meta.len();
        }
    }
    total
}

fn emit_dynamic_evidence_jsonl(path: &Path, rows: &[DynamicEvidence]) -> Result<u64, VulnError> {
    let file = std::fs::File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);
    for row in rows {
        serde_json::to_writer(&mut writer, row)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(std::fs::metadata(path).map(|m| m.len()).unwrap_or(0))
}

/// Synthesize a minimal [`crate::vuln::bug_class::BugClass`] for a
/// lifetime template id. Used when the v1.0 filtered template
/// registry doesn't include the lifetime template (which it never
/// does, since lifetime templates have empty source_kinds /
/// sink_apis and are skipped by `discover_chains`). Without this,
/// lifetime candidates would never be scored or emitted.
fn lifetime_template_for(template_id: &str) -> crate::vuln::bug_class::BugClass {
    use crate::vuln::bug_class::{
        BugClass, EvidenceTier, GuardRequirement, IntegerPatternRequirement, SinkArgRequirement,
    };
    let (id, name, description) = match template_id {
        "uaf_candidate" => (
            "uaf_candidate",
            "Use-after-free candidate",
            "Pointer used after a free()-class call (SSA-equality alias only; intentionally limited per Codex finding 3).",
        ),
        "double_free_candidate" => (
            "double_free_candidate",
            "Double-free candidate",
            "Same pointer passed to a free()-class call twice (SSA-equality alias only; intentionally limited per Codex finding 3).",
        ),
        _ => unreachable!("lifetime_template_for called with non-lifetime id: {template_id}"),
    };
    BugClass {
        id,
        name,
        category: "lifetime",
        source_kinds: &[],
        sink_apis: &[],
        sink_requirement: SinkArgRequirement::AnyCall,
        guard_requirement: GuardRequirement::DontCare,
        integer_pattern: IntegerPatternRequirement::DontCare,
        evidence_tier: EvidenceTier::Candidate,
        confidence_cap: Some(0.65),
        description,
    }
}

#[cfg(feature = "vuln-discovery-lifetime")]
fn discover_lifetime_when_enabled(graph: &EvidenceGraph) -> Vec<CandidateChain> {
    crate::vuln::templates::lifetime::discover_lifetime_candidates(graph)
}

#[cfg(not(feature = "vuln-discovery-lifetime"))]
fn discover_lifetime_when_enabled(_graph: &EvidenceGraph) -> Vec<CandidateChain> {
    // Feature not compiled — silently skip. The
    // include_lifetime flag is a no-op in this build.
    Vec::new()
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn empty_inputs_produces_empty_report_with_run_status() {
        let tmp = TempDir::new().unwrap();
        let opts = VulnOptions {
            out_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let inputs = VulnInputs {
            run_id: "test-run",
            ..Default::default()
        };
        let report = run(&opts, &inputs).unwrap();
        assert_eq!(report.chains_discovered, 0);
        assert_eq!(report.findings_emitted, 0);
        assert!(report.run_status_path.unwrap().exists());
        // Manifest files exist even with zero findings.
        assert!(tmp.path().join("findings.jsonl").exists());
        assert!(tmp.path().join("chain_graph.json").exists());
        assert!(tmp.path().join("evidence_bundle.json").exists());
    }

    #[test]
    fn recv_plus_deletefile_fires_missing_caller_validation_via_anycall_template() {
        // Synthetic fixture: one function, two api_flows (recv +
        // DeleteFile), no SSA/DataFlow records, no CFG. Taint cannot
        // propagate (no DataFlow edges) so the TaintedArgRole
        // templates skip. But missing_caller_validation has
        // sink_requirement = AnyCall + guard_requirement =
        // NoDominatingGuard; with no CFG there are zero guards, so it
        // fires on the (network_recv source, memcpy sink) pair.
        //
        // Per-template positive + negative coverage lives in
        // tests/vuln_template_coverage.rs; this session-level test
        // verifies the orchestrator wires through to a real finding +
        // writes the ledger.
        let tmp = TempDir::new().unwrap();
        let opts = VulnOptions {
            out_dir: tmp.path().to_path_buf(),
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
        let report = run(&opts, &inputs).unwrap();
        assert!(report.chains_discovered >= 1, "expected ≥1 chain");
        assert!(
            report.findings_emitted >= 1,
            "expected ≥1 finding above threshold"
        );
        assert!(report.run_status_path.is_some());
        assert!(tmp.path().join("run_status.json").exists());
    }
}
