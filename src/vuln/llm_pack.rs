//! v1.0 LLM-pack emitters.
//!
//! Three artifacts:
//! - `findings.jsonl` — one [`FindingRecord`] per line.
//! - `chain_graph.json` — node/edge view of the chains so the LLM
//!   can pivot from a function to all chains that touch it.
//! - `evidence_bundle.json` — top-N findings + summary sentences +
//!   uncertainties (mirrors dynamic-trace's evidence pack pattern).

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;

use crate::atomic_write::AtomicWriter;
use crate::vuln::finding::FindingRecord;
use crate::vuln::harness_synth::{Harness, HarnessTier};
use crate::vuln::llm_analyst::{PatchSuggestion, TestSuggestion};

pub const GRAPH_SCHEMA: &str = "vuln_discovery.chain_graph.v1";
pub const BUNDLE_SCHEMA: &str = "vuln_discovery.evidence_bundle.v1";
pub const BUNDLE_SCHEMA_V1_1: &str = "vuln_discovery.evidence_bundle.v1_1";
pub const LIFETIME_CANDIDATES_SCHEMA: &str = "vuln_discovery.lifetime_candidates.v1";

/// Bug-class ids that route to `lifetime_candidates.jsonl` rather
/// than `findings.jsonl`. Mirrors the constant in
/// `templates::lifetime::V1_1_LIFETIME_ALIAS_LIMITED_DETECTORS`,
/// but lives here too so this module can do its routing without
/// requiring the `vuln-discovery-lifetime` feature.
pub const LIFETIME_BUG_CLASS_IDS: &[&str] = &["uaf_candidate", "double_free_candidate"];

/// `true` iff `bug_class` is a lifetime template that must NOT
/// land in `findings.jsonl` or in `evidence_bundle.json::top_findings`.
pub fn is_lifetime_bug_class(bug_class: &str) -> bool {
    LIFETIME_BUG_CLASS_IDS.contains(&bug_class)
}

pub fn emit_findings_jsonl(path: &Path, findings: &[FindingRecord]) -> io::Result<u64> {
    let mut w = AtomicWriter::create(path)?;
    let mut bytes = 0u64;
    for f in findings {
        let line = serde_json::to_vec(f).map_err(io::Error::other)?;
        w.write_all(&line)?;
        w.write_all(b"\n")?;
        bytes += line.len() as u64 + 1;
    }
    w.finalize()?;
    Ok(bytes)
}

// ---------- chain_graph.json --------------------------------------

#[derive(Serialize, Clone, Debug)]
struct ChainGraph<'a> {
    schema: &'a str,
    run_id: &'a str,
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
}

#[derive(Serialize, Clone, Debug)]
struct GraphNode {
    id: String,
    kind: String,
    label: String,
}

#[derive(Serialize, Clone, Debug)]
struct GraphEdge {
    from: String,
    to: String,
    edge_type: String,
    finding_id: String,
}

pub fn emit_chain_graph_json(
    path: &Path,
    run_id: &str,
    findings: &[FindingRecord],
) -> io::Result<u64> {
    let mut nodes: BTreeMap<String, GraphNode> = BTreeMap::new();
    let mut edges: Vec<GraphEdge> = Vec::new();
    for f in findings {
        let src_id = format!("function:{}", f.source.function_va);
        let snk_id = format!("function:{}", f.sink.function_va);
        nodes.entry(src_id.clone()).or_insert_with(|| GraphNode {
            id: src_id.clone(),
            kind: "function".into(),
            label: format!("source@{}", f.source.function_va),
        });
        nodes.entry(snk_id.clone()).or_insert_with(|| GraphNode {
            id: snk_id.clone(),
            kind: "function".into(),
            label: format!("sink@{}", f.sink.function_va),
        });
        edges.push(GraphEdge {
            from: src_id,
            to: snk_id,
            edge_type: f.bug_class.clone(),
            finding_id: f.finding_id.clone(),
        });
    }
    let g = ChainGraph {
        schema: GRAPH_SCHEMA,
        run_id,
        nodes: nodes.into_values().collect(),
        edges,
    };
    let bytes = serde_json::to_vec_pretty(&g).map_err(io::Error::other)?;
    let len = bytes.len() as u64;
    let mut w = AtomicWriter::create(path)?;
    w.write_all(&bytes)?;
    w.finalize()?;
    Ok(len)
}

// ---------- evidence_bundle.json ----------------------------------

#[derive(Serialize, Clone, Debug)]
struct EvidenceBundle<'a> {
    schema: &'a str,
    run_id: &'a str,
    phase: &'a str,
    top_findings: Vec<String>,
    summary: Vec<String>,
    uncertainties: Vec<String>,
}

pub fn emit_evidence_bundle_json(
    path: &Path,
    run_id: &str,
    findings: &[FindingRecord],
    top_n: usize,
) -> io::Result<u64> {
    let mut by_risk: Vec<&FindingRecord> = findings.iter().collect();
    by_risk.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
    let top: Vec<String> = by_risk
        .iter()
        .take(top_n)
        .map(|f| f.finding_id.clone())
        .collect();
    let summary = build_summary(findings);
    let uncertainties = vec![
        "v1.0 has NOT been dynamically confirmed; all findings are static-only.".into(),
        "Scoring weights calibrated 2026-05-17 (calibrated_v1_0_2): toctou_file_access, missing_bounds_check_var_mismatch, and auth_check_after_action require argument facts, call order, and path/lock evidence before scoring. See docs/vuln-calibration.md.".into(),
        "Interprocedural taint uses summary-based propagation; chains crossing >3 call boundaries have lower confidence. Cross-function (source-fn != sink-fn) findings should be treated as coarse interprocedural extensions, not proven taint paths.".into(),
        "Lifetime templates (UAF, double-free) are not enabled in v1.0; v1.1 adds them as opt-in only.".into(),
        "Source trust classification is direction-blind in v1.0: 'com_server_ingress' / 'ioctl_input_buffer' fire whether the binary CALLS or HOSTS the API. Discount findings where the binary appears to be the API client rather than the server.".into(),
    ];
    let b = EvidenceBundle {
        schema: BUNDLE_SCHEMA,
        run_id,
        phase: "v1.0_static",
        top_findings: top,
        summary,
        uncertainties,
    };
    let bytes = serde_json::to_vec_pretty(&b).map_err(io::Error::other)?;
    let len = bytes.len() as u64;
    let mut w = AtomicWriter::create(path)?;
    w.write_all(&bytes)?;
    w.finalize()?;
    Ok(len)
}

// =====================================================================
// v1.1 emitters (Step 34)
// =====================================================================

/// Emit `lifetime_candidates.jsonl` — Codex finding 3 separate
/// artifact for lifetime templates. Caller passes the subset of
/// findings whose `bug_class` is in [`LIFETIME_BUG_CLASS_IDS`];
/// this function does NOT do the filtering (use
/// [`split_findings_by_lifetime`] for that).
pub fn emit_lifetime_candidates_jsonl(
    path: &Path,
    lifetime_findings: &[FindingRecord],
) -> io::Result<u64> {
    // Same wire shape as findings.jsonl — one record per line — but
    // explicitly separated so the LLM consumer never confuses
    // candidate-tier with ground-truth.
    emit_findings_jsonl(path, lifetime_findings)
}

/// Partition findings into `(default, lifetime)` based on
/// `bug_class`. The caller passes `default` to
/// [`emit_findings_jsonl`] and `lifetime` to
/// [`emit_lifetime_candidates_jsonl`].
pub fn split_findings_by_lifetime(
    findings: &[FindingRecord],
) -> (Vec<FindingRecord>, Vec<FindingRecord>) {
    let mut default = Vec::new();
    let mut lifetime = Vec::new();
    for f in findings {
        if is_lifetime_bug_class(&f.bug_class) {
            lifetime.push(f.clone());
        } else {
            default.push(f.clone());
        }
    }
    (default, lifetime)
}

/// Emit `patch_suggestions.jsonl` — one suggestion per line.
pub fn emit_patch_suggestions_jsonl(
    path: &Path,
    suggestions: &[PatchSuggestion],
) -> io::Result<u64> {
    let mut w = AtomicWriter::create(path)?;
    let mut bytes = 0u64;
    for s in suggestions {
        let line = serde_json::to_vec(s).map_err(io::Error::other)?;
        w.write_all(&line)?;
        w.write_all(b"\n")?;
        bytes += line.len() as u64 + 1;
    }
    w.finalize()?;
    Ok(bytes)
}

/// Emit `test_suggestions.jsonl` — one suggestion per line.
pub fn emit_test_suggestions_jsonl(path: &Path, suggestions: &[TestSuggestion]) -> io::Result<u64> {
    let mut w = AtomicWriter::create(path)?;
    let mut bytes = 0u64;
    for s in suggestions {
        let line = serde_json::to_vec(s).map_err(io::Error::other)?;
        w.write_all(&line)?;
        w.write_all(b"\n")?;
        bytes += line.len() as u64 + 1;
    }
    w.finalize()?;
    Ok(bytes)
}

/// Write per-harness artifacts under `harnesses_dir`:
/// - `{harness_id}.skeleton.md` — always written (every harness has
///   a Markdown skeleton with chain provenance + setup notes).
/// - `{harness_id}.runnable.rs` — written ONLY when the harness's
///   `tier == Runnable` AND `runnable_rust.is_some()`. Codex finding 2
///   enforcement: a Skeleton-tier harness MUST NOT have a runnable
///   file on disk (otherwise downstream consumers might invoke it
///   without verification).
///
/// Returns the count of artifact files written.
pub fn emit_harness_artifacts(harnesses_dir: &Path, harnesses: &[Harness]) -> io::Result<usize> {
    std::fs::create_dir_all(harnesses_dir)?;
    let mut count = 0;
    for h in harnesses {
        let skeleton_path = harnesses_dir.join(format!("{}.skeleton.md", h.harness_id));
        let mut w = AtomicWriter::create(&skeleton_path)?;
        w.write_all(h.skeleton_markdown.as_bytes())?;
        w.finalize()?;
        count += 1;
        if h.tier == HarnessTier::Runnable {
            if let Some(runnable_rust) = h.runnable_rust.as_ref() {
                let runnable_path = harnesses_dir.join(format!("{}.runnable.rs", h.harness_id));
                let mut w = AtomicWriter::create(&runnable_path)?;
                w.write_all(runnable_rust.as_bytes())?;
                w.finalize()?;
                count += 1;
            }
        }
    }
    Ok(count)
}

/// v1.1 evidence-bundle emitter. **Excludes lifetime findings from
/// `top_findings` and from the bug-class summary** (Codex finding 3
/// separate-artifact enforcement). Replaces v1.0's static-only
/// disclaimers with v1.1-aware text.
pub fn emit_evidence_bundle_json_v1_1(
    path: &Path,
    run_id: &str,
    findings: &[FindingRecord],
    top_n: usize,
) -> io::Result<u64> {
    // Filter out lifetime findings BEFORE ranking — top_findings
    // never references a Candidate-tier lifetime fact id.
    let default: Vec<&FindingRecord> = findings
        .iter()
        .filter(|f| !is_lifetime_bug_class(&f.bug_class))
        .collect();
    let mut by_risk: Vec<&&FindingRecord> = default.iter().collect();
    by_risk.sort_by(|a, b| b.risk_score.partial_cmp(&a.risk_score).unwrap());
    let top: Vec<String> = by_risk
        .iter()
        .take(top_n)
        .map(|f| f.finding_id.clone())
        .collect();
    let summary = build_summary_excluding_lifetime(findings);
    let uncertainties = vec![
        "v1.1 dynamic confirmation: only findings with attached DynamicEvidence (status confirmed_trigger or reached_only) have been dynamically corroborated; remainder are static-only.".into(),
        "Scoring weights calibrated 2026-05-17 (calibrated_v1_0_2): toctou_file_access, missing_bounds_check_var_mismatch, and auth_check_after_action require argument facts, call order, and path/lock evidence before scoring. See docs/vuln-calibration.md.".into(),
        "Interprocedural taint uses summary-based propagation; chains crossing >3 call boundaries have lower confidence. Cross-function (source-fn != sink-fn) findings should be treated as coarse interprocedural extensions, not proven taint paths.".into(),
        "Lifetime templates (UAF, double-free) emit to lifetime_candidates.jsonl when --vuln-include-lifetime is on; they are EXCLUDED from this top-N selection by construction (Codex finding 3).".into(),
        "Source trust classification is direction-blind in v1.0: 'com_server_ingress' / 'ioctl_input_buffer' fire whether the binary CALLS or HOSTS the API. Discount findings where the binary appears to be the API client rather than the server.".into(),
        "Patch and test suggestions in patch_suggestions.jsonl and test_suggestions.jsonl are pure-Rust templates (source: \"template\"); they are not live-LLM output and should be reviewed before applying.".into(),
    ];
    let b = EvidenceBundle {
        schema: BUNDLE_SCHEMA_V1_1,
        run_id,
        phase: "v1.1_dynamic_confirmation",
        top_findings: top,
        summary,
        uncertainties,
    };
    let bytes = serde_json::to_vec_pretty(&b).map_err(io::Error::other)?;
    let len = bytes.len() as u64;
    let mut w = AtomicWriter::create(path)?;
    w.write_all(&bytes)?;
    w.finalize()?;
    Ok(len)
}

fn build_summary_excluding_lifetime(findings: &[FindingRecord]) -> Vec<String> {
    let default: Vec<&FindingRecord> = findings
        .iter()
        .filter(|f| !is_lifetime_bug_class(&f.bug_class))
        .collect();
    let lifetime_count = findings.len() - default.len();
    let mut out = build_summary_from_refs(&default);
    if lifetime_count > 0 {
        out.push(format!(
            "{} lifetime candidate(s) routed to lifetime_candidates.jsonl (not counted above).",
            lifetime_count
        ));
    }
    out
}

fn build_summary_from_refs(findings: &[&FindingRecord]) -> Vec<String> {
    if findings.is_empty() {
        return vec!["No vulnerability chains discovered.".into()];
    }
    let mut by_severity: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_bug_class: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        *by_severity.entry(f.severity_guess.as_str()).or_insert(0) += 1;
        *by_bug_class.entry(f.bug_class.clone()).or_insert(0) += 1;
    }
    let mut out = Vec::new();
    out.push(format!(
        "{} candidate vulnerability chain(s) discovered.",
        findings.len()
    ));
    for (sev, n) in &by_severity {
        out.push(format!("{} severity_guess: {} findings.", sev, n));
    }
    let top_class = by_bug_class.iter().max_by_key(|(_, n)| **n);
    if let Some((bc, n)) = top_class {
        out.push(format!("Most common bug class: {} ({} findings).", bc, n));
    }
    out
}

fn build_summary(findings: &[FindingRecord]) -> Vec<String> {
    if findings.is_empty() {
        return vec!["No vulnerability chains discovered.".into()];
    }
    let mut by_severity: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_bug_class: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings {
        *by_severity.entry(f.severity_guess.as_str()).or_insert(0) += 1;
        *by_bug_class.entry(f.bug_class.clone()).or_insert(0) += 1;
    }
    let mut out = Vec::new();
    out.push(format!(
        "{} candidate vulnerability chain(s) discovered.",
        findings.len()
    ));
    for (sev, n) in &by_severity {
        out.push(format!("{} severity_guess: {} findings.", sev, n));
    }
    let top_class = by_bug_class.iter().max_by_key(|(_, n)| **n);
    if let Some((bc, n)) = top_class {
        out.push(format!("Most common bug class: {} ({} findings).", bc, n));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::confidence::Confidence;
    use crate::vuln::bug_class::EvidenceTier;
    use crate::vuln::finding::{
        FindingSink, FindingSource, FindingStore, ScoringFactors, FINDING_SCHEMA,
    };
    use crate::vuln::taint::PropagationMode;
    use tempfile::TempDir;

    fn make_finding(id: &str, bug_class: &str, risk: f32) -> FindingRecord {
        FindingRecord {
            schema: FINDING_SCHEMA.into(),
            finding_id: id.into(),
            run_id: "run-1".into(),
            bug_class: bug_class.into(),
            evidence_tier: EvidenceTier::GroundTruth,
            phase: "v1.0_static".into(),
            chain_id: None,
            harness: None,
            dynamic_evidence: None,
            severity_guess: if risk >= 7.0 {
                "high".into()
            } else {
                "low".into()
            },
            risk_score: risk,
            confidence: Confidence::from_score(0.85),
            trust_boundary: "remote_unauth".into(),
            source_to_sink_summary: "test".into(),
            source: FindingSource {
                kind: "network_recv".into(),
                function_va: "0x0000000000401000".into(),
                site_va: "0x0000000000401100".into(),
            },
            sink: FindingSink {
                api: "memcpy".into(),
                function_va: "0x0000000000402000".into(),
                site_va: "0x0000000000402200".into(),
            },
            propagation_mode: PropagationMode::Exact,
            dominating_guard_count: 0,
            matched_integer_pattern: false,
            scoring: ScoringFactors {
                source_trust: 1.0,
                sink_danger: 1.0,
                taint_confidence: 1.0,
                missing_mitigation: 1.0,
                reachability: 1.0,
                exploitability_prior: 1.0,
                false_positive_penalty: 0.0,
                weights_calibration: "uncalibrated_v1_0_baseline".into(),
            },
            uncertainties: vec!["test_uncertainty".into()],
            provenance: Vec::new(),
        }
    }

    #[test]
    fn findings_jsonl_writes_one_line_per_record() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("findings.jsonl");
        let findings = vec![
            make_finding("F-1", "unchecked_copy_length", 8.5),
            make_finding("F-2", "format_string_controlled", 6.0),
        ];
        emit_findings_jsonl(&path, &findings).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
        for line in content.lines() {
            let _: FindingRecord = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn chain_graph_collapses_duplicate_function_nodes() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("chain_graph.json");
        let findings = vec![
            make_finding("F-1", "unchecked_copy_length", 8.5),
            make_finding("F-2", "format_string_controlled", 6.0),
        ];
        emit_chain_graph_json(&path, "run-1", &findings).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let nodes = parsed["nodes"].as_array().unwrap();
        let edges = parsed["edges"].as_array().unwrap();
        // Both findings share source/sink VAs → 2 nodes total.
        assert_eq!(nodes.len(), 2);
        assert_eq!(edges.len(), 2);
    }

    #[test]
    fn evidence_bundle_top_n_ranks_by_risk_desc() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("evidence_bundle.json");
        let findings = vec![
            make_finding("F-LOW", "unchecked_copy_length", 2.0),
            make_finding("F-HIGH", "unchecked_copy_length", 9.0),
            make_finding("F-MID", "unchecked_copy_length", 5.5),
        ];
        emit_evidence_bundle_json(&path, "run-1", &findings, 2).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let top: Vec<String> = parsed["top_findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert_eq!(top, vec!["F-HIGH".to_string(), "F-MID".to_string()]);
    }

    #[test]
    fn evidence_bundle_warns_v1_0_is_static_only() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("evidence_bundle.json");
        emit_evidence_bundle_json(&path, "run-1", &[], 10).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("NOT been dynamically confirmed"));
        assert!(content.contains("calibrated 2026-05-17"));
        assert!(content.contains("argument facts, call order, and path/lock evidence"));
    }

    // =====================================================================
    // v1.1 emitter tests (Step 34)
    // =====================================================================

    use crate::vuln::harness_synth::{synthesize, HarnessKind};
    use crate::vuln::llm_analyst::{suggest_patches, suggest_tests};
    use crate::vuln::query::CandidateChain;
    use crate::vuln::sinks::SinkCatalog;

    #[test]
    fn split_findings_routes_lifetime_to_separate_partition() {
        let findings = vec![
            make_finding("F-1", "unchecked_copy_length", 8.0),
            make_finding("F-2", "uaf_candidate", 5.5),
            make_finding("F-3", "tainted_allocation_size", 7.0),
            make_finding("F-4", "double_free_candidate", 4.0),
        ];
        let (default, lifetime) = split_findings_by_lifetime(&findings);
        assert_eq!(default.len(), 2);
        assert_eq!(lifetime.len(), 2);
        assert!(default.iter().all(|f| !is_lifetime_bug_class(&f.bug_class)));
        assert!(lifetime.iter().all(|f| is_lifetime_bug_class(&f.bug_class)));
    }

    #[test]
    fn is_lifetime_bug_class_matches_both_lifetime_templates() {
        assert!(is_lifetime_bug_class("uaf_candidate"));
        assert!(is_lifetime_bug_class("double_free_candidate"));
        assert!(!is_lifetime_bug_class("unchecked_copy_length"));
        assert!(!is_lifetime_bug_class("tainted_allocation_size"));
    }

    #[test]
    fn emit_lifetime_candidates_jsonl_writes_one_line_per_record() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("lifetime_candidates.jsonl");
        let lifetime = vec![
            make_finding("L-1", "uaf_candidate", 4.5),
            make_finding("L-2", "double_free_candidate", 3.5),
        ];
        emit_lifetime_candidates_jsonl(&path, &lifetime).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
    }

    #[test]
    fn evidence_bundle_v1_1_excludes_lifetime_from_top_findings() {
        // Codex finding 3 separate-artifact enforcement: even if a
        // lifetime finding has the HIGHEST risk_score, it MUST NOT
        // appear in top_findings of the v1.1 bundle.
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("evidence_bundle.json");
        let findings = vec![
            make_finding("F-LOW-MEM", "unchecked_copy_length", 4.0),
            make_finding("F-HIGH-LIFETIME", "uaf_candidate", 9.5),
            make_finding("F-MID-MEM", "tainted_allocation_size", 6.0),
        ];
        emit_evidence_bundle_json_v1_1(&path, "run-1", &findings, 10).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        let top: Vec<String> = parsed["top_findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        // F-HIGH-LIFETIME has the highest risk but MUST be excluded.
        assert_eq!(top, vec!["F-MID-MEM".to_string(), "F-LOW-MEM".to_string()]);
    }

    #[test]
    fn evidence_bundle_v1_1_notes_lifetime_routing_in_summary() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("evidence_bundle.json");
        let findings = vec![
            make_finding("F-1", "unchecked_copy_length", 8.0),
            make_finding("L-1", "uaf_candidate", 5.0),
            make_finding("L-2", "double_free_candidate", 4.5),
        ];
        emit_evidence_bundle_json_v1_1(&path, "run-1", &findings, 5).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("2 lifetime candidate(s) routed to lifetime_candidates.jsonl"));
        assert!(content.contains("BUNDLE_SCHEMA_V1_1") || content.contains("evidence_bundle.v1_1"));
    }

    #[test]
    fn evidence_bundle_v1_1_disclaimers_mention_dynamic_confirmation_status() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("evidence_bundle.json");
        emit_evidence_bundle_json_v1_1(&path, "run-1", &[], 5).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("v1.1 dynamic confirmation"));
        assert!(content.contains("DynamicEvidence"));
        // The v1.0 disclaimer text should NOT appear (we replaced it).
        assert!(!content.contains("v1.0 has NOT been dynamically confirmed"));
        // Lifetime disclaimer is present.
        assert!(content.contains("lifetime_candidates.jsonl"));
        // Patch / test suggestion source caveat.
        assert!(content.contains("patch_suggestions"));
    }

    #[test]
    fn emit_patch_suggestions_jsonl_writes_one_line_per_record() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("patch_suggestions.jsonl");
        let f1 = make_finding("F-1", "unchecked_copy_length", 8.0);
        let f2 = make_finding("F-2", "format_string_controlled", 5.0);
        let mut all = Vec::new();
        all.extend(suggest_patches(&f1));
        all.extend(suggest_patches(&f2));
        emit_patch_suggestions_jsonl(&path, &all).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
        for line in content.lines() {
            let _: PatchSuggestion = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn emit_test_suggestions_jsonl_writes_one_line_per_record() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("test_suggestions.jsonl");
        let f = make_finding("F-1", "auth_check_after_action", 6.0);
        let suggestions = suggest_tests(&f);
        emit_test_suggestions_jsonl(&path, &suggestions).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 1);
        let parsed: TestSuggestion = serde_json::from_str(content.lines().next().unwrap()).unwrap();
        assert_eq!(parsed.bug_class, "auth_check_after_action");
    }

    fn fixture_harness_v1_1(chain_id: &str) -> crate::vuln::harness_synth::Harness {
        synthesize(
            &CandidateChain {
                chain_id: chain_id.into(),
                template_id: "unchecked_copy_length".into(),
                source_kind: "network_recv".into(),
                source_function_va: 0x140001000,
                source_site_va: 0x140001100,
                sink_api: "memcpy".into(),
                sink_function_va: 0x140002000,
                sink_site_va: 0x1400022a4,
                propagation_mode: crate::vuln::taint::PropagationMode::Exact,
                hop_count: 0,
                dominating_guard_count: 0,
                matched_integer_pattern: false,
            },
            &SinkCatalog::v1_0(),
            HarnessKind::SourceAvailableFnByteSlice,
        )
    }

    #[test]
    fn emit_harness_artifacts_writes_skeleton_for_every_harness() {
        let tmp = TempDir::new().unwrap();
        let harnesses_dir = tmp.path().join("harnesses");
        let harnesses = vec![fixture_harness_v1_1("C-1"), fixture_harness_v1_1("C-2")];
        let count = emit_harness_artifacts(&harnesses_dir, &harnesses).unwrap();
        assert_eq!(count, 2);
        assert!(harnesses_dir.join("H-C-1.skeleton.md").exists());
        assert!(harnesses_dir.join("H-C-2.skeleton.md").exists());
        // Skeleton-only harnesses do NOT have .runnable.rs files.
        assert!(!harnesses_dir.join("H-C-1.runnable.rs").exists());
        assert!(!harnesses_dir.join("H-C-2.runnable.rs").exists());
    }

    #[test]
    fn emit_harness_artifacts_writes_runnable_only_when_tier_runnable() {
        // Codex finding 2 enforcement at the wire-shape boundary: a
        // .runnable.rs file appears on disk ONLY when verification
        // has PASSED.
        let tmp = TempDir::new().unwrap();
        let harnesses_dir = tmp.path().join("harnesses");
        let mut h_runnable = fixture_harness_v1_1("C-R");
        h_runnable.tier = HarnessTier::Runnable;
        let h_skeleton = fixture_harness_v1_1("C-S");
        let count = emit_harness_artifacts(&harnesses_dir, &[h_runnable, h_skeleton]).unwrap();
        // 2 skeleton.md + 1 runnable.rs (only for the Runnable tier).
        assert_eq!(count, 3);
        assert!(harnesses_dir.join("H-C-R.skeleton.md").exists());
        assert!(harnesses_dir.join("H-C-R.runnable.rs").exists());
        assert!(harnesses_dir.join("H-C-S.skeleton.md").exists());
        assert!(!harnesses_dir.join("H-C-S.runnable.rs").exists());
    }

    #[test]
    fn emit_harness_artifacts_skips_runnable_when_runnable_rust_is_none() {
        // Defense in depth: a BinaryOnlyPeEntry harness that's
        // somehow flipped to Runnable tier (which the structural
        // check in harness_verify forbids) STILL won't get a
        // .runnable.rs because runnable_rust is None.
        let tmp = TempDir::new().unwrap();
        let harnesses_dir = tmp.path().join("harnesses");
        let mut h = synthesize(
            &CandidateChain {
                chain_id: "C-BO".into(),
                template_id: "unchecked_copy_length".into(),
                source_kind: "network_recv".into(),
                source_function_va: 0x140001000,
                source_site_va: 0x140001100,
                sink_api: "memcpy".into(),
                sink_function_va: 0x140002000,
                sink_site_va: 0x1400022a4,
                propagation_mode: crate::vuln::taint::PropagationMode::Exact,
                hop_count: 0,
                dominating_guard_count: 0,
                matched_integer_pattern: false,
            },
            &SinkCatalog::v1_0(),
            HarnessKind::BinaryOnlyPeEntry,
        );
        // Forge tier as Runnable (this would never happen via the
        // sanctioned promotion path, but we defend anyway).
        h.tier = HarnessTier::Runnable;
        let count = emit_harness_artifacts(&harnesses_dir, &[h]).unwrap();
        assert_eq!(count, 1); // only the .skeleton.md
        assert!(harnesses_dir.join("H-C-BO.skeleton.md").exists());
        assert!(!harnesses_dir.join("H-C-BO.runnable.rs").exists());
    }

    #[test]
    fn skeleton_md_contains_chain_id_and_sink_va() {
        let tmp = TempDir::new().unwrap();
        let harnesses_dir = tmp.path().join("harnesses");
        let h = fixture_harness_v1_1("C-X");
        emit_harness_artifacts(&harnesses_dir, &[h]).unwrap();
        let content = std::fs::read_to_string(harnesses_dir.join("H-C-X.skeleton.md")).unwrap();
        assert!(content.contains("C-X"));
        // Sink site VA in canonical 16-hex form.
        assert!(content.contains("0x00000001400022a4"));
    }

    #[test]
    fn store_top_n_round_trips_with_llm_pack() {
        let mut store = FindingStore::open_in_memory().unwrap();
        for f in [
            make_finding("F-1", "unchecked_copy_length", 8.5),
            make_finding("F-2", "format_string_controlled", 6.0),
        ] {
            store.insert(&f).unwrap();
        }
        let top = store.top_n_by_risk(10).unwrap();
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("findings.jsonl");
        emit_findings_jsonl(&path, &top).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 2);
    }
}
