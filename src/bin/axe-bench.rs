use anyhow::{anyhow, Context, Result};
use axe_core::vuln::dynamic_evidence::DynamicEvidence;
use axe_core::AnalysisOptions;
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "axe-bench",
    version,
    about = "Run ground-truth-backed axe benchmark manifests"
)]
struct Args {
    #[arg(long, value_name = "FILE")]
    manifest: PathBuf,

    #[arg(long, value_name = "DIR")]
    out: PathBuf,

    #[arg(long, value_parser = ["real-5", "real-8", "real-9"], default_value = "real-5")]
    preset: String,

    /// Build manifest-declared source fixtures before analysis.
    #[arg(long)]
    build_fixtures: bool,

    /// Output directory for built source fixtures.
    #[arg(long, value_name = "DIR")]
    fixture_out: Option<PathBuf>,

    /// Real-9 fixture build policy. `missing` builds only absent outputs.
    #[arg(long, value_parser = ["never", "missing", "always"], default_value = "never")]
    real9_build: String,

    /// Real-9 external source staging mode. `fetch` checks out pinned source only.
    #[arg(long, value_parser = ["off", "fetch", "build"], default_value = "off")]
    real9_stage: String,

    /// Directory for Real-9 pinned source checkouts.
    #[arg(long, value_name = "DIR")]
    real9_source_root: Option<PathBuf>,

    /// Dynamic job selector for Real-9 repro work.
    #[arg(long, default_value = "off")]
    dynamic_jobs: String,

    /// Per-case dynamic job budget in seconds.
    #[arg(long, default_value_t = 60)]
    dynamic_budget_secs: u64,

    /// Required before Real-9 executes crashable vulnerable fixtures.
    #[arg(long)]
    allow_vulnerable_fixtures: bool,

    /// Emit benchmark-level repro packets for ranked findings.
    #[arg(long)]
    emit_repro_packets: bool,
}

#[derive(Debug, Deserialize)]
struct BenchmarkManifest {
    schema: String,
    cases: Vec<BenchmarkCase>,
}

#[derive(Debug, Deserialize)]
struct BenchmarkCase {
    id: String,
    path: PathBuf,
    corpus: String,
    expected_clean: bool,
    #[serde(default)]
    build: Option<FixtureBuild>,
    #[serde(default)]
    dynamic_probe: Option<DynamicProbe>,
    #[serde(default)]
    dynamic_jobs: Vec<DynamicJob>,
    #[serde(default)]
    expected_signatures: Vec<String>,
    #[serde(default)]
    expected_findings: Vec<ExpectedFinding>,
    #[serde(default)]
    vuln_id: Option<String>,
    #[serde(default)]
    source_url: Option<String>,
    #[serde(default)]
    source_ref: Option<String>,
    #[serde(default)]
    fixture_subdir: Option<String>,
    #[serde(default)]
    fixture_build_kind: Option<String>,
    #[serde(default)]
    repro_seed: Option<String>,
    #[serde(default)]
    allowed_misses: Option<usize>,
    #[serde(default)]
    false_positive_cap: Option<usize>,
    #[serde(default)]
    require_dynamic_confirmation: bool,
    #[serde(default)]
    require_proof_packets: bool,
    #[serde(default = "default_top_k")]
    top_k: usize,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct FixtureBuild {
    source: PathBuf,
    #[serde(default)]
    output: Option<PathBuf>,
    #[serde(default)]
    compiler: Option<String>,
    #[serde(default)]
    cflags: Vec<String>,
    #[serde(default)]
    ldflags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct DynamicProbe {
    #[serde(default)]
    argv: Vec<String>,
    #[serde(default)]
    stdin: Option<String>,
    #[serde(default = "default_probe_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_probe_evidence_source")]
    evidence_source: String,
    #[serde(default = "default_probe_status")]
    status: String,
    #[serde(default)]
    expect_stdout_contains: Vec<String>,
    #[serde(default)]
    observed: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct DynamicJob {
    #[serde(default = "default_dynamic_job_kind")]
    kind: String,
    #[serde(default)]
    argv: Vec<String>,
    #[serde(default)]
    stdin: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    evidence_source: Option<String>,
    #[serde(default = "default_probe_status")]
    status: String,
    #[serde(default)]
    expect_stdout_contains: Vec<String>,
    #[serde(default)]
    observed: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeEvidencePolicy {
    AllowProbeStatusOnly,
    RequireObservedSinkPc,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ExpectedFinding {
    #[serde(default)]
    id: Option<String>,
    bug_class: String,
    #[serde(default)]
    source_kind: Option<String>,
    #[serde(default)]
    sink_api: Option<String>,
    #[serde(default)]
    min_dynamic_status: Option<String>,
    #[serde(default)]
    require_proof_packet: bool,
    #[serde(default)]
    required_evidence_source: Option<String>,
    #[serde(default)]
    min_rank: Option<usize>,
    #[serde(default)]
    collapse_key: Option<String>,
    #[serde(default = "default_allow_duplicate_matches")]
    allow_duplicate_matches: bool,
    #[serde(default)]
    expected_missed_ok: bool,
}

#[derive(Debug, Serialize)]
struct CaseResult {
    schema: &'static str,
    id: String,
    corpus: String,
    path: String,
    status: String,
    expected_clean: bool,
    vuln_id: Option<String>,
    source_url: Option<String>,
    source_ref: Option<String>,
    expected_signatures: Vec<String>,
    expected_findings: Vec<ExpectedFinding>,
    matched_signatures: Vec<String>,
    matched_expected_findings: usize,
    missed_expected_findings: Vec<String>,
    false_positive_findings: Vec<String>,
    duplicate_matches: Vec<String>,
    collapsed_precision: f64,
    gate_reasons: Vec<String>,
    top_k: usize,
    findings_considered: usize,
    proof_packets_present: usize,
    repro_packets_present: usize,
    dynamic_confirmed_findings: usize,
    non_controlled_dynamic_confirmed_findings: usize,
    dynamic_evidence_source_counts: BTreeMap<String, usize>,
    requirements_met: bool,
    true_positives: usize,
    false_positives: usize,
    precision: f64,
    recall: f64,
    precision_grade_1_to_5: f64,
    estimated_level: f64,
    notes: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct FindingResult {
    schema: &'static str,
    case_id: String,
    rank: usize,
    finding_id: String,
    signature: String,
    source_kind: String,
    sink_api: String,
    risk_score: f64,
    confidence: f64,
    matched_expected_signature: bool,
    matched_expected_finding: bool,
    proof_packet_present: bool,
    dynamic_status: Option<String>,
    evidence_sources: Vec<String>,
    counted_as_dynamic_confirmation: bool,
    repro_packet_present: bool,
}

#[derive(Debug, Serialize)]
struct ReproPacket {
    schema: &'static str,
    case_id: String,
    finding_id: String,
    chain_id: Option<String>,
    bug_class: String,
    runner_command: Vec<String>,
    seed: Option<String>,
    expected_sink_pc: Option<String>,
    observed_status: Option<String>,
    observed_pc: Option<String>,
    evidence_sources: Vec<String>,
    proof_packet_id: Option<String>,
    artifact_provenance: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Real9StageReport {
    schema: &'static str,
    mode: String,
    status: String,
    source_root: Option<String>,
    case_count: usize,
    pinned_source_count: usize,
    ready_source_count: usize,
    manual_source_ref_count: usize,
    failed_source_count: usize,
    cases: Vec<Real9StageCase>,
    warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct Real9StageCase {
    case_id: String,
    vuln_id: Option<String>,
    source_url: Option<String>,
    source_ref: Option<String>,
    fixture_subdir: Option<String>,
    fixture_build_kind: Option<String>,
    source_dir: Option<String>,
    fixture_path: String,
    status: String,
    reason: Option<String>,
    checked_out_ref: Option<String>,
    build_plan: Option<Real9BuildPlan>,
}

#[derive(Clone, Debug, Serialize)]
struct Real9BuildPlan {
    schema: &'static str,
    case_id: String,
    fixture_subdir: String,
    build_script: String,
    working_dir: String,
    expected_binary: String,
    fixture_output: String,
    build_command: Vec<String>,
    executed: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    run(args)
}

fn run(args: Args) -> Result<()> {
    let manifest_text = fs::read_to_string(&args.manifest)
        .with_context(|| format!("read manifest {}", args.manifest.display()))?;
    let manifest: BenchmarkManifest = serde_json::from_str(&manifest_text)
        .with_context(|| format!("parse manifest {}", args.manifest.display()))?;
    if manifest.schema != "axe_benchmark_manifest/1" {
        return Err(anyhow!(
            "unsupported benchmark manifest schema {:?}; expected axe_benchmark_manifest/1",
            manifest.schema
        ));
    }
    fs::create_dir_all(&args.out)
        .with_context(|| format!("create benchmark out dir {}", args.out.display()))?;

    let manifest_dir = args
        .manifest
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let real9_stage_report = real9_stage_report(&args, &manifest_dir, &manifest)?;
    if args.preset == "real-9" {
        write_json(
            args.out.join("real9_stage.json"),
            &serde_json::to_value(&real9_stage_report)?,
        )?;
    }
    let mut case_results = Vec::new();
    let mut finding_results = Vec::new();

    for case in &manifest.cases {
        let case_out = args.out.join("cases").join(safe_component(&case.id));
        let analysis_out = case_out.join("analysis");
        let nominal_input_path = resolve_manifest_path(&manifest_dir, &case.path);
        let prepared_input = prepare_case_input(&args, &manifest_dir, case, &case_out);
        let input_path = prepared_input
            .as_ref()
            .cloned()
            .unwrap_or_else(|_| nominal_input_path.clone());
        let dynamic_execution_blocked = real_9_dynamic_execution_blocked(&args, case);
        let mut result = CaseResult {
            schema: "axe_benchmark_case/1",
            id: case.id.clone(),
            corpus: case.corpus.clone(),
            path: input_path.display().to_string(),
            status: "completed".to_string(),
            expected_clean: case.expected_clean,
            vuln_id: case.vuln_id.clone(),
            source_url: case.source_url.clone(),
            source_ref: case.source_ref.clone(),
            expected_signatures: case.expected_signatures.clone(),
            expected_findings: case.expected_findings.clone(),
            matched_signatures: Vec::new(),
            matched_expected_findings: 0,
            missed_expected_findings: Vec::new(),
            false_positive_findings: Vec::new(),
            duplicate_matches: Vec::new(),
            collapsed_precision: 0.0,
            gate_reasons: Vec::new(),
            top_k: case.top_k,
            findings_considered: 0,
            proof_packets_present: 0,
            repro_packets_present: 0,
            dynamic_confirmed_findings: 0,
            non_controlled_dynamic_confirmed_findings: 0,
            dynamic_evidence_source_counts: BTreeMap::new(),
            requirements_met: true,
            true_positives: 0,
            false_positives: 0,
            precision: 0.0,
            recall: 0.0,
            precision_grade_1_to_5: 1.0,
            estimated_level: 1.0,
            notes: case.notes.clone(),
            error: None,
        };

        if let Err(err) = prepared_input {
            result.status = if case.build.is_some() && args.build_fixtures {
                "build_failed".to_string()
            } else {
                "input_prepare_failed".to_string()
            };
            result.error = Some(err.to_string());
            case_results.push(result);
            continue;
        }

        if !input_path.exists() {
            result.status = "skipped_missing_input".to_string();
            result.error = Some(format!("input not found: {}", input_path.display()));
            case_results.push(result);
            continue;
        }

        let mut options = options_for_preset(&args.preset)?;
        options.precomputed_sha256 = None;
        options.progress_path = None;
        let analysis_result = if matches!(args.preset.as_str(), "real-8" | "real-9")
            && dynamic_execution_requested(case, &args)
            && !dynamic_execution_blocked
        {
            let static_out = case_out.join("analysis_static");
            run_analysis(&input_path, &static_out, options.clone()).and_then(|_| {
                let static_findings = read_findings(&static_out, case.top_k)?;
                let static_proof_packets = read_proof_packets(&static_out)?;
                let policy = if args.preset == "real-9" {
                    ProbeEvidencePolicy::RequireObservedSinkPc
                } else {
                    ProbeEvidencePolicy::AllowProbeStatusOnly
                };
                let mut dynamic_evidence = Vec::new();
                if let Some(probe) = &case.dynamic_probe {
                    let (probe_succeeded, probe_report) = run_dynamic_probe(&input_path, probe)?;
                    write_json(case_out.join("dynamic_probe.json"), &probe_report)?;
                    if probe_succeeded {
                        dynamic_evidence.extend(synthesize_probe_evidence_with_policy(
                            &case.id,
                            &static_findings,
                            &static_proof_packets,
                            &case.expected_findings,
                            probe,
                            policy,
                        ));
                    }
                }
                let job_reports = run_dynamic_jobs(
                    &input_path,
                    case,
                    &args,
                    &static_findings,
                    &static_proof_packets,
                    policy,
                    &mut dynamic_evidence,
                )?;
                if !job_reports.is_empty() {
                    write_jsonl(case_out.join("dynamic_jobs.jsonl"), &job_reports)?;
                }
                if !dynamic_evidence.is_empty() {
                    options.vuln_dynamic_evidence = dynamic_evidence;
                }
                run_analysis(&input_path, &analysis_out, options)
            })
        } else {
            run_analysis(&input_path, &analysis_out, options)
        };
        if let Err(err) = analysis_result {
            result.status = "analysis_failed".to_string();
            result.error = Some(err.to_string());
            case_results.push(result);
            continue;
        }

        let findings = read_findings(&analysis_out, case.top_k)?;
        let proof_packets = read_proof_packets(&analysis_out)?;
        let expected: BTreeSet<String> = case.expected_signatures.iter().cloned().collect();
        let mut matched = BTreeSet::new();
        let mut expected_match_counts = vec![0usize; case.expected_findings.len()];
        let mut finding_expected_matches: Vec<Vec<usize>> = Vec::new();
        for (rank, finding) in findings.iter().enumerate() {
            let finding_id = finding_id(finding).to_string();
            let proof_packet = proof_packets.get(finding_id.as_str());
            let signature = finding_signature(finding);
            let matched_expected = expected.contains(&signature);
            let rank_one_based = rank + 1;
            let expected_matches: Vec<usize> = case
                .expected_findings
                .iter()
                .enumerate()
                .filter_map(|(idx, expected)| {
                    expected_finding_matches(finding, proof_packet, expected, rank_one_based)
                        .then_some(idx)
                })
                .collect();
            for idx in &expected_matches {
                expected_match_counts[*idx] += 1;
            }
            let matched_expected_finding = !expected_matches.is_empty();
            let dynamic_status = dynamic_status_for(finding, proof_packet);
            let counted_dynamic = dynamic_status_counts_as_confirmation(dynamic_status.as_deref());
            let evidence_sources = evidence_sources_for(finding, proof_packet);
            if matched_expected {
                matched.insert(signature.clone());
            }
            if proof_packet.is_some() {
                result.proof_packets_present += 1;
            }
            let repro_packet_present = if args.emit_repro_packets {
                emit_repro_packet(
                    &args,
                    case,
                    &input_path,
                    &analysis_out,
                    &case_out,
                    rank_one_based,
                    finding,
                    proof_packet,
                )?
                .is_some()
            } else {
                false
            };
            if repro_packet_present {
                result.repro_packets_present += 1;
            }
            if counted_dynamic {
                result.dynamic_confirmed_findings += 1;
                if evidence_sources
                    .iter()
                    .any(|source| !source.eq_ignore_ascii_case("controlled_fixture"))
                {
                    result.non_controlled_dynamic_confirmed_findings += 1;
                }
            }
            for source in &evidence_sources {
                *result
                    .dynamic_evidence_source_counts
                    .entry(source.clone())
                    .or_insert(0) += 1;
            }
            finding_results.push(FindingResult {
                schema: "axe_benchmark_finding/1",
                case_id: case.id.clone(),
                rank: rank + 1,
                finding_id,
                signature,
                source_kind: finding
                    .pointer("/source/kind")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                sink_api: finding
                    .pointer("/sink/api")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                risk_score: finding
                    .get("risk_score")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0),
                confidence: finding
                    .pointer("/confidence/score")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0),
                matched_expected_signature: matched_expected,
                matched_expected_finding,
                proof_packet_present: proof_packet.is_some(),
                dynamic_status,
                evidence_sources,
                counted_as_dynamic_confirmation: counted_dynamic,
                repro_packet_present,
            });
            finding_expected_matches.push(expected_matches);
        }
        result.findings_considered = findings.len();
        result.matched_signatures = matched.iter().cloned().collect();
        result.matched_expected_findings = case
            .expected_findings
            .iter()
            .enumerate()
            .filter(|(idx, _)| expected_match_counts[*idx] > 0)
            .count();
        result.missed_expected_findings = case
            .expected_findings
            .iter()
            .enumerate()
            .filter(|(idx, expected)| {
                expected_match_counts[*idx] == 0 && !expected.expected_missed_ok
            })
            .map(|(_, expected)| expected_label(expected))
            .collect();
        for (idx, expected) in case.expected_findings.iter().enumerate() {
            if expected_match_counts[idx] > 1 {
                result.duplicate_matches.push(format!(
                    "{}:{}",
                    expected_label(expected),
                    expected_match_counts[idx]
                ));
            }
        }
        result.false_positive_findings = findings
            .iter()
            .enumerate()
            .filter(|(idx, finding)| {
                if case.expected_clean {
                    return true;
                }
                let signature = finding_signature(finding);
                !expected.contains(&signature)
                    && finding_expected_matches[*idx].is_empty()
                    && !case
                        .expected_findings
                        .iter()
                        .any(|expected| expected_finding_shape_matches(finding, expected))
            })
            .map(|(_, finding)| finding_id(finding).to_string())
            .collect();
        result.requirements_met = (!case.require_dynamic_confirmation
            || result.dynamic_confirmed_findings > 0)
            && (!case.require_proof_packets || result.proof_packets_present > 0);
        if case.require_dynamic_confirmation && result.dynamic_confirmed_findings == 0 {
            result
                .gate_reasons
                .push("missing_required_dynamic_confirmation".to_string());
        }
        if dynamic_execution_blocked {
            result
                .gate_reasons
                .push("vulnerable_fixture_execution_not_allowed".to_string());
        }
        if case.require_proof_packets && result.proof_packets_present == 0 {
            result
                .gate_reasons
                .push("missing_required_proof_packets".to_string());
        }
        for missed in &result.missed_expected_findings {
            result
                .gate_reasons
                .push(format!("missed_expected_finding:{missed}"));
        }
        for (idx, expected) in case.expected_findings.iter().enumerate() {
            if expected_match_counts[idx] > 1 && !expected.allow_duplicate_matches {
                result.gate_reasons.push(format!(
                    "duplicate_expected_match:{}",
                    expected_label(expected)
                ));
            }
        }
        if case.expected_clean && !result.false_positive_findings.is_empty() {
            result
                .gate_reasons
                .push("expected_clean_had_findings".to_string());
        }
        if let Some(allowed_misses) = case.allowed_misses {
            if result.missed_expected_findings.len() > allowed_misses {
                result.gate_reasons.push(format!(
                    "missed_expected_findings_above_allowed:{}>{}",
                    result.missed_expected_findings.len(),
                    allowed_misses
                ));
            }
        }
        if let Some(false_positive_cap) = case.false_positive_cap {
            if result.false_positive_findings.len() > false_positive_cap {
                result.gate_reasons.push(format!(
                    "false_positive_findings_above_cap:{}>{}",
                    result.false_positive_findings.len(),
                    false_positive_cap
                ));
            }
        }
        result.requirements_met = result.requirements_met && result.gate_reasons.is_empty();
        result.true_positives = if case.expected_clean {
            0
        } else {
            result.matched_signatures.len()
                + case
                    .expected_findings
                    .iter()
                    .enumerate()
                    .filter(|(idx, expected)| {
                        !expected.expected_missed_ok && expected_match_counts[*idx] > 0
                    })
                    .count()
        };
        result.false_positives = result.false_positive_findings.len();
        let denom = result.true_positives + result.false_positives;
        result.precision = if denom == 0 {
            if case.expected_clean {
                1.0
            } else {
                0.0
            }
        } else {
            result.true_positives as f64 / denom as f64
        };
        let collapsed_denom =
            result.matched_expected_findings + result.false_positive_findings.len();
        result.collapsed_precision = if collapsed_denom == 0 {
            if case.expected_clean {
                1.0
            } else {
                0.0
            }
        } else {
            result.matched_expected_findings as f64 / collapsed_denom as f64
        };
        let case_expected_total = case.expected_signatures.len()
            + case
                .expected_findings
                .iter()
                .filter(|expected| !expected.expected_missed_ok)
                .count();
        result.recall = if case_expected_total == 0 {
            if case.expected_clean {
                1.0
            } else {
                0.0
            }
        } else {
            result.true_positives as f64 / case_expected_total as f64
        };
        result.precision_grade_1_to_5 = 1.0 + 4.0 * result.precision;
        result.estimated_level = if result.recall >= 1.0 {
            result.precision_grade_1_to_5
        } else {
            result.precision_grade_1_to_5.min(4.0)
        };
        if !result.requirements_met {
            result.estimated_level = result.estimated_level.min(4.0);
        }
        case_results.push(result);
    }

    let completed_cases: Vec<&CaseResult> = case_results
        .iter()
        .filter(|case| case.status == "completed")
        .collect();
    let mean_precision_grade = mean(
        completed_cases
            .iter()
            .map(|case| case.precision_grade_1_to_5),
    );
    let mean_estimated_level = mean(completed_cases.iter().map(|case| case.estimated_level));
    let expected_total = completed_cases
        .iter()
        .map(|case| {
            case.expected_signatures.len()
                + case
                    .expected_findings
                    .iter()
                    .filter(|expected| !expected.expected_missed_ok)
                    .count()
        })
        .sum::<usize>();
    let expected_matched = completed_cases
        .iter()
        .map(|case| {
            let matched_expected = case
                .expected_findings
                .iter()
                .filter(|expected| !expected.expected_missed_ok)
                .filter(|expected| {
                    !case
                        .missed_expected_findings
                        .contains(&expected_label(expected))
                })
                .count();
            case.matched_signatures.len() + matched_expected
        })
        .sum::<usize>();
    let expected_recall = if expected_total == 0 {
        1.0
    } else {
        expected_matched as f64 / expected_total as f64
    };
    let false_positives_per_binary = if completed_cases.is_empty() {
        0.0
    } else {
        completed_cases
            .iter()
            .map(|case| case.false_positives)
            .sum::<usize>() as f64
            / completed_cases.len() as f64
    };
    let collapsed_precision_mean =
        mean(completed_cases.iter().map(|case| case.collapsed_precision));
    let missed_expected_findings_count = completed_cases
        .iter()
        .map(|case| case.missed_expected_findings.len())
        .sum::<usize>();
    let false_positive_findings_count = completed_cases
        .iter()
        .map(|case| case.false_positive_findings.len())
        .sum::<usize>();
    let duplicate_match_count = completed_cases
        .iter()
        .map(|case| case.duplicate_matches.len())
        .sum::<usize>();
    let skipped_dynamic_counted = finding_results.iter().any(|finding| {
        finding.counted_as_dynamic_confirmation && finding.signature == "dynamic_unavailable"
    });
    let mut dynamic_evidence_source_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut controlled_dynamic_confirmed_findings = 0usize;
    let mut non_controlled_dynamic_confirmed_findings = 0usize;
    for finding in &finding_results {
        if !finding.counted_as_dynamic_confirmation {
            continue;
        }
        let mut has_controlled = false;
        let mut has_non_controlled = false;
        for source in &finding.evidence_sources {
            *dynamic_evidence_source_counts
                .entry(source.clone())
                .or_insert(0) += 1;
            if source.eq_ignore_ascii_case("controlled_fixture") {
                has_controlled = true;
            } else {
                has_non_controlled = true;
            }
        }
        if has_controlled {
            controlled_dynamic_confirmed_findings += 1;
        }
        if has_non_controlled {
            non_controlled_dynamic_confirmed_findings += 1;
        }
    }
    let requirement_failures = completed_cases
        .iter()
        .filter(|case| !case.requirements_met)
        .count();
    let real_5_gate = if !completed_cases.is_empty()
        && expected_total > 0
        && mean_estimated_level >= 5.0
        && mean_precision_grade >= 3.5
        && expected_recall >= 1.0
        && requirement_failures == 0
        && !skipped_dynamic_counted
    {
        "pass"
    } else {
        "fail"
    };
    let mut real_8_gate_reasons = Vec::new();
    if completed_cases.len() < 5 {
        real_8_gate_reasons.push("min_completed_cases");
    }
    if expected_total < 5 {
        real_8_gate_reasons.push("min_expected_findings");
    }
    if mean_estimated_level < 5.0 {
        real_8_gate_reasons.push("mean_estimated_level_below_5");
    }
    if mean_precision_grade < 4.5 {
        real_8_gate_reasons.push("precision_grade_below_4_5");
    }
    if expected_recall < 1.0 {
        real_8_gate_reasons.push("expected_recall_below_1");
    }
    if collapsed_precision_mean < 0.9 {
        real_8_gate_reasons.push("collapsed_precision_below_0_9");
    }
    if false_positives_per_binary > 0.25 {
        real_8_gate_reasons.push("false_positives_per_binary_above_0_25");
    }
    if requirement_failures != 0 {
        real_8_gate_reasons.push("requirement_failures");
    }
    if skipped_dynamic_counted {
        real_8_gate_reasons.push("skipped_dynamic_source_counted");
    }
    if non_controlled_dynamic_confirmed_findings == 0 {
        real_8_gate_reasons.push("missing_non_controlled_dynamic_confirmation");
    }
    let real_8_gate = if args.preset == "real-8" && real_8_gate_reasons.is_empty() {
        "pass"
    } else {
        "fail"
    };
    let mut real_9_gate_reasons = real_8_gate_reasons.clone();
    real_9_gate_reasons.extend(real_9_dynamic_source_reasons(
        &dynamic_evidence_source_counts,
    ));
    real_9_gate_reasons.extend(real_9_stage_gate_reasons(&real9_stage_report));
    if completed_cases.iter().any(|case| {
        case.gate_reasons
            .iter()
            .any(|reason| reason == "vulnerable_fixture_execution_not_allowed")
    }) {
        real_9_gate_reasons.push("vulnerable_fixture_execution_not_allowed");
    }
    let real_9_gate = if args.preset == "real-9" && real_9_gate_reasons.is_empty() {
        "pass"
    } else {
        "fail"
    };
    let operational_scale_estimate = if real_9_gate == "pass" {
        9.0
    } else if real_8_gate == "pass" {
        8.0
    } else if real_5_gate == "pass" {
        5.5
    } else if !completed_cases.is_empty() {
        mean_estimated_level.min(5.0)
    } else {
        0.0
    };
    let real9_stage_value = serde_json::to_value(&real9_stage_report)?;

    let summary = json!({
        "schema": "axe_benchmark_summary/1",
        "preset": args.preset,
        "case_count": case_results.len(),
        "completed_case_count": completed_cases.len(),
        "top_k_precision_grade_mean": mean_precision_grade,
        "expected_signature_recall": expected_recall,
        "false_positives_per_binary": false_positives_per_binary,
        "collapsed_precision_mean": collapsed_precision_mean,
        "missed_expected_findings_count": missed_expected_findings_count,
        "false_positive_findings_count": false_positive_findings_count,
        "duplicate_match_count": duplicate_match_count,
        "mean_estimated_level": mean_estimated_level,
        "operational_scale_estimate_0_to_10": operational_scale_estimate,
        "real_5_gate": real_5_gate,
        "real_8_gate": real_8_gate,
        "real_8_gate_reasons": real_8_gate_reasons,
        "real_9_gate": real_9_gate,
        "real_9_gate_reasons": real_9_gate_reasons,
        "requirement_failures": requirement_failures,
        "controlled_dynamic_confirmed_findings": controlled_dynamic_confirmed_findings,
        "non_controlled_dynamic_confirmed_findings": non_controlled_dynamic_confirmed_findings,
        "dynamic_evidence_source_counts": dynamic_evidence_source_counts,
        "real9_stage": real9_stage_value.clone(),
        "repro_packets_present": case_results
            .iter()
            .map(|case| case.repro_packets_present)
            .sum::<usize>(),
        "skipped_dynamic_source_counted_as_confirmation": skipped_dynamic_counted,
    });

    write_json(args.out.join("benchmark_summary.json"), &summary)?;
    if args.preset == "real-9" {
        write_json(
            args.out.join("real9_grade.json"),
            &json!({
                "schema": "axe_real9_grade/1",
                "gate": summary["real_9_gate"],
                "gate_reasons": summary["real_9_gate_reasons"],
                "completed_case_count": summary["completed_case_count"],
                "expected_recall": summary["expected_signature_recall"],
                "collapsed_precision_mean": summary["collapsed_precision_mean"],
                "missed_expected_findings_count": summary["missed_expected_findings_count"],
                "false_positive_findings_count": summary["false_positive_findings_count"],
                "non_controlled_dynamic_confirmed_findings": summary["non_controlled_dynamic_confirmed_findings"],
                "dynamic_evidence_source_counts": summary["dynamic_evidence_source_counts"],
                "source_stage": real9_stage_value,
                "repro_packets_present": summary["repro_packets_present"],
            }),
        )?;
    }
    write_jsonl(args.out.join("benchmark_cases.jsonl"), &case_results)?;
    write_jsonl(args.out.join("benchmark_findings.jsonl"), &finding_results)?;
    fs::write(
        args.out.join("benchmark_report.md"),
        report_markdown(&summary, &case_results),
    )?;
    println!("{}", args.out.display());
    Ok(())
}

fn default_top_k() -> usize {
    10
}

fn default_probe_timeout_ms() -> u64 {
    2_000
}

fn default_probe_evidence_source() -> String {
    "safe_fixture_probe".to_string()
}

fn default_probe_status() -> String {
    "reached_only".to_string()
}

fn default_dynamic_job_kind() -> String {
    "debug_probe".to_string()
}

fn default_allow_duplicate_matches() -> bool {
    true
}

fn resolve_manifest_path(manifest_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        manifest_dir.join(path)
    }
}

fn real9_stage_report(
    args: &Args,
    manifest_dir: &Path,
    manifest: &BenchmarkManifest,
) -> Result<Real9StageReport> {
    if args.preset != "real-9" {
        return Ok(Real9StageReport {
            schema: "axe_real9_stage/1",
            mode: args.real9_stage.clone(),
            status: "not_applicable".to_string(),
            source_root: None,
            case_count: 0,
            pinned_source_count: 0,
            ready_source_count: 0,
            manual_source_ref_count: 0,
            failed_source_count: 0,
            cases: Vec::new(),
            warnings: Vec::new(),
        });
    }

    let source_root = args
        .real9_source_root
        .clone()
        .unwrap_or_else(|| PathBuf::from("out").join("real9_sources"));
    let mut cases = Vec::new();
    let mut staged_sources: BTreeMap<(String, String), Real9StageCase> = BTreeMap::new();
    let mut warnings = Vec::new();
    if args.real9_stage == "build" {
        warnings.push(
            "build mode stages pinned source and emits non-executing build plans when fixture_subdir/build.sh exists; it does not build or run fixtures"
                .to_string(),
        );
    }

    for case in &manifest.cases {
        let fixture_path = resolve_manifest_path(manifest_dir, &case.path);
        let Some(source_url) = case.source_url.clone() else {
            cases.push(Real9StageCase {
                case_id: case.id.clone(),
                vuln_id: case.vuln_id.clone(),
                source_url: None,
                source_ref: case.source_ref.clone(),
                fixture_subdir: case.fixture_subdir.clone(),
                fixture_build_kind: case.fixture_build_kind.clone(),
                source_dir: None,
                fixture_path: fixture_path.display().to_string(),
                status: "no_external_source_metadata".to_string(),
                reason: Some("case has no source_url metadata".to_string()),
                checked_out_ref: None,
                build_plan: None,
            });
            continue;
        };
        let Some(source_ref) = case.source_ref.clone() else {
            cases.push(Real9StageCase {
                case_id: case.id.clone(),
                vuln_id: case.vuln_id.clone(),
                source_url: Some(source_url),
                source_ref: None,
                fixture_subdir: case.fixture_subdir.clone(),
                fixture_build_kind: case.fixture_build_kind.clone(),
                source_dir: None,
                fixture_path: fixture_path.display().to_string(),
                status: "no_source_ref".to_string(),
                reason: Some("case has source_url but no pinned source_ref".to_string()),
                checked_out_ref: None,
                build_plan: None,
            });
            continue;
        };
        let source_dir = real9_source_dir_for(&source_root, &source_url, &source_ref);
        if args.real9_stage == "off" {
            cases.push(Real9StageCase {
                case_id: case.id.clone(),
                vuln_id: case.vuln_id.clone(),
                source_url: Some(source_url),
                source_ref: Some(source_ref),
                fixture_subdir: case.fixture_subdir.clone(),
                fixture_build_kind: case.fixture_build_kind.clone(),
                source_dir: Some(source_dir.display().to_string()),
                fixture_path: fixture_path.display().to_string(),
                status: "not_requested".to_string(),
                reason: Some("run with --real9-stage fetch to check out pinned source".to_string()),
                checked_out_ref: None,
                build_plan: None,
            });
            continue;
        }
        if !is_full_git_sha(&source_ref) {
            cases.push(Real9StageCase {
                case_id: case.id.clone(),
                vuln_id: case.vuln_id.clone(),
                source_url: Some(source_url),
                source_ref: Some(source_ref),
                fixture_subdir: case.fixture_subdir.clone(),
                fixture_build_kind: case.fixture_build_kind.clone(),
                source_dir: Some(source_dir.display().to_string()),
                fixture_path: fixture_path.display().to_string(),
                status: "manual_source_ref".to_string(),
                reason: Some(
                    "source_ref must be an immutable 40-character git SHA for automated staging"
                        .to_string(),
                ),
                checked_out_ref: None,
                build_plan: None,
            });
            continue;
        }

        let key = (source_url.clone(), source_ref.clone());
        let source_stage = if let Some(existing) = staged_sources.get(&key) {
            existing.clone()
        } else {
            let staged = stage_real9_git_source(&source_url, &source_ref, &source_dir);
            staged_sources.insert(key, staged.clone());
            staged
        };
        let (status, reason, build_plan) = real9_case_stage_status_for_mode(
            args.real9_stage.as_str(),
            case,
            &source_stage,
            &fixture_path,
        );
        cases.push(Real9StageCase {
            case_id: case.id.clone(),
            vuln_id: case.vuln_id.clone(),
            source_url: Some(source_url),
            source_ref: Some(source_ref),
            fixture_subdir: case.fixture_subdir.clone(),
            fixture_build_kind: case.fixture_build_kind.clone(),
            source_dir: source_stage.source_dir,
            fixture_path: fixture_path.display().to_string(),
            status,
            reason,
            checked_out_ref: source_stage.checked_out_ref,
            build_plan,
        });
    }

    let case_count = cases.len();
    let pinned_source_count = cases
        .iter()
        .filter(|case| case.source_ref.as_deref().is_some_and(is_full_git_sha))
        .count();
    let ready_source_count = cases
        .iter()
        .filter(|case| real9_stage_status_ready(&case.status))
        .count();
    let manual_source_ref_count = cases
        .iter()
        .filter(|case| case.status == "manual_source_ref")
        .count();
    let failed_source_count = cases
        .iter()
        .filter(|case| real9_stage_status_failed(&case.status))
        .count();
    let status = real9_overall_stage_status(
        args.real9_stage.as_str(),
        case_count,
        pinned_source_count,
        ready_source_count,
        manual_source_ref_count,
        failed_source_count,
    );

    Ok(Real9StageReport {
        schema: "axe_real9_stage/1",
        mode: args.real9_stage.clone(),
        status,
        source_root: Some(source_root.display().to_string()),
        case_count,
        pinned_source_count,
        ready_source_count,
        manual_source_ref_count,
        failed_source_count,
        cases,
        warnings,
    })
}

fn real9_case_stage_status_for_mode(
    mode: &str,
    case: &BenchmarkCase,
    source_stage: &Real9StageCase,
    fixture_path: &Path,
) -> (String, Option<String>, Option<Real9BuildPlan>) {
    if mode != "build" || !real9_stage_status_ready(&source_stage.status) {
        return (
            source_stage.status.clone(),
            source_stage.reason.clone(),
            None,
        );
    }
    let Some(source_dir) = source_stage.source_dir.as_deref().map(PathBuf::from) else {
        return (
            "source_ready_build_not_configured".to_string(),
            Some(
                "pinned source is ready but source_dir is missing from the stage report"
                    .to_string(),
            ),
            None,
        );
    };
    if let Some(build_plan) = real9_build_plan_for_case(&case.id, &source_dir, case, fixture_path) {
        return (
            "build_recipe_ready".to_string(),
            Some(
                "build recipe found; staging did not execute the build script or the fixture binary"
                    .to_string(),
            ),
            Some(build_plan),
        );
    }
    if case.fixture_subdir.is_some() {
        return (
            "build_recipe_missing".to_string(),
            Some("fixture_subdir is declared but no build.sh exists at that path".to_string()),
            None,
        );
    }
    (
        "source_ready_build_not_configured".to_string(),
        Some(
            "pinned source is ready; no external fixture build recipe is declared for this case"
                .to_string(),
        ),
        None,
    )
}

fn real9_build_plan_for_case(
    case_id: &str,
    source_dir: &Path,
    case: &BenchmarkCase,
    fixture_path: &Path,
) -> Option<Real9BuildPlan> {
    real9_fts_build_plan(
        case_id,
        source_dir,
        case.fixture_subdir.as_deref(),
        fixture_path,
    )
    .or_else(|| {
        case.fixture_build_kind.as_deref().and_then(|kind| {
            real9_cmake_baseline_build_plan(case_id, kind, source_dir, fixture_path)
        })
    })
}

fn real9_fts_build_plan(
    case_id: &str,
    source_dir: &Path,
    fixture_subdir: Option<&str>,
    fixture_path: &Path,
) -> Option<Real9BuildPlan> {
    let fixture_subdir = fixture_subdir?;
    let build_script = source_dir.join(fixture_subdir).join("build.sh");
    if !build_script.is_file() {
        return None;
    }
    let working_dir = fixture_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("build");
    let expected_binary = working_dir.join(format!("{fixture_subdir}-fsanitize_fuzzer"));
    let command = format!(
        "mkdir -p {} && cd {} && FUZZING_ENGINE=fsanitize_fuzzer {} && cp {} {}",
        bash_quote_path(&working_dir),
        bash_quote_path(&working_dir),
        bash_quote_path(&build_script),
        bash_quote_path(&expected_binary),
        bash_quote_path(fixture_path)
    );
    Some(Real9BuildPlan {
        schema: "axe_real9_build_plan/1",
        case_id: case_id.to_string(),
        fixture_subdir: fixture_subdir.to_string(),
        build_script: build_script.display().to_string(),
        working_dir: working_dir.display().to_string(),
        expected_binary: expected_binary.display().to_string(),
        fixture_output: fixture_path.display().to_string(),
        build_command: vec!["bash".to_string(), "-lc".to_string(), command],
        executed: false,
    })
}

fn real9_cmake_baseline_build_plan(
    case_id: &str,
    kind: &str,
    source_dir: &Path,
    fixture_path: &Path,
) -> Option<Real9BuildPlan> {
    if !source_dir.join("CMakeLists.txt").is_file() {
        return None;
    }
    let working_dir = fixture_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("build");
    let (cmake_options, expected_binary_name) = match kind {
        "cmake_cares_aresfuzz" => (
            "-DCARES_STATIC=ON -DCARES_BUILD_TESTS=ON -DCARES_BUILD_TOOLS=ON -DBUILD_SHARED_LIBS=OFF",
            PathBuf::from("test").join("aresfuzz"),
        ),
        "cmake_libxml2_xmllint" => (
            "-DBUILD_SHARED_LIBS=OFF -DLIBXML2_WITH_PYTHON=OFF -DLIBXML2_WITH_ZLIB=OFF -DLIBXML2_WITH_LZMA=OFF -DLIBXML2_WITH_ICONV=OFF -DLIBXML2_WITH_PROGRAMS=ON",
            PathBuf::from("xmllint"),
        ),
        _ => return None,
    };
    let expected_binary = working_dir.join(expected_binary_name);
    let command = format!(
        "mkdir -p {} && cmake -S {} -B {} {} && cmake --build {} --config Release && cp {} {}",
        bash_quote_path(&working_dir),
        bash_quote_path(source_dir),
        bash_quote_path(&working_dir),
        cmake_options,
        bash_quote_path(&working_dir),
        bash_quote_path(&expected_binary),
        bash_quote_path(fixture_path)
    );
    Some(Real9BuildPlan {
        schema: "axe_real9_build_plan/1",
        case_id: case_id.to_string(),
        fixture_subdir: kind.to_string(),
        build_script: source_dir.join("CMakeLists.txt").display().to_string(),
        working_dir: working_dir.display().to_string(),
        expected_binary: expected_binary.display().to_string(),
        fixture_output: fixture_path.display().to_string(),
        build_command: vec!["bash".to_string(), "-lc".to_string(), command],
        executed: false,
    })
}

fn bash_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'\''"#))
}

fn bash_quote_path(path: &Path) -> String {
    bash_quote(&path.display().to_string().replace('\\', "/"))
}

fn real9_overall_stage_status(
    mode: &str,
    case_count: usize,
    pinned_source_count: usize,
    ready_source_count: usize,
    manual_source_ref_count: usize,
    failed_source_count: usize,
) -> String {
    if case_count == 0 {
        return "no_cases".to_string();
    }
    if mode == "off" {
        return "not_requested".to_string();
    }
    if failed_source_count > 0 {
        return "partial".to_string();
    }
    if manual_source_ref_count > 0 {
        return "manual_action_required".to_string();
    }
    if pinned_source_count > 0 && ready_source_count == pinned_source_count {
        return "ready".to_string();
    }
    "partial".to_string()
}

fn real_9_stage_gate_reasons(report: &Real9StageReport) -> Vec<&'static str> {
    if report.status == "not_applicable" || report.case_count == 0 {
        return Vec::new();
    }
    if report.status == "ready" {
        return Vec::new();
    }
    if report.mode == "build" {
        return vec!["external_fixture_builds_not_ready"];
    }
    vec!["external_sources_not_staged"]
}

fn stage_real9_git_source(source_url: &str, source_ref: &str, source_dir: &Path) -> Real9StageCase {
    let source_dir_string = source_dir.display().to_string();
    if Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return Real9StageCase {
            case_id: String::new(),
            vuln_id: None,
            source_url: Some(source_url.to_string()),
            source_ref: Some(source_ref.to_string()),
            fixture_subdir: None,
            fixture_build_kind: None,
            source_dir: Some(source_dir_string),
            fixture_path: String::new(),
            status: "toolchain_unavailable".to_string(),
            reason: Some("git is not available on PATH".to_string()),
            checked_out_ref: None,
            build_plan: None,
        };
    }

    if source_dir.exists() && !source_dir.join(".git").is_dir() {
        return Real9StageCase {
            case_id: String::new(),
            vuln_id: None,
            source_url: Some(source_url.to_string()),
            source_ref: Some(source_ref.to_string()),
            fixture_subdir: None,
            fixture_build_kind: None,
            source_dir: Some(source_dir_string),
            fixture_path: String::new(),
            status: "source_dir_not_git".to_string(),
            reason: Some("source directory exists but is not a git checkout".to_string()),
            checked_out_ref: None,
            build_plan: None,
        };
    }

    if source_dir.join(".git").is_dir() {
        if let Some(head) = git_rev_parse_head(source_dir) {
            if head.eq_ignore_ascii_case(source_ref) {
                return Real9StageCase {
                    case_id: String::new(),
                    vuln_id: None,
                    source_url: Some(source_url.to_string()),
                    source_ref: Some(source_ref.to_string()),
                    fixture_subdir: None,
                    fixture_build_kind: None,
                    source_dir: Some(source_dir_string),
                    fixture_path: String::new(),
                    status: "ready".to_string(),
                    reason: None,
                    checked_out_ref: Some(head),
                    build_plan: None,
                };
            }
        }
    } else if let Some(parent) = source_dir.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            return Real9StageCase {
                case_id: String::new(),
                vuln_id: None,
                source_url: Some(source_url.to_string()),
                source_ref: Some(source_ref.to_string()),
                fixture_subdir: None,
                fixture_build_kind: None,
                source_dir: Some(source_dir_string),
                fixture_path: String::new(),
                status: "source_root_create_failed".to_string(),
                reason: Some(err.to_string()),
                checked_out_ref: None,
                build_plan: None,
            };
        }
        let clone = Command::new("git")
            .arg("clone")
            .arg("--filter=blob:none")
            .arg("--no-checkout")
            .arg(source_url)
            .arg(source_dir)
            .output();
        match clone {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                return Real9StageCase {
                    case_id: String::new(),
                    vuln_id: None,
                    source_url: Some(source_url.to_string()),
                    source_ref: Some(source_ref.to_string()),
                    fixture_subdir: None,
                    fixture_build_kind: None,
                    source_dir: Some(source_dir_string),
                    fixture_path: String::new(),
                    status: "fetch_failed".to_string(),
                    reason: Some(format!(
                        "git clone failed: {}",
                        one_line_command_stderr(&output.stderr)
                    )),
                    checked_out_ref: None,
                    build_plan: None,
                };
            }
            Err(err) => {
                return Real9StageCase {
                    case_id: String::new(),
                    vuln_id: None,
                    source_url: Some(source_url.to_string()),
                    source_ref: Some(source_ref.to_string()),
                    fixture_subdir: None,
                    fixture_build_kind: None,
                    source_dir: Some(source_dir_string),
                    fixture_path: String::new(),
                    status: "fetch_failed".to_string(),
                    reason: Some(format!("spawn git clone: {err}")),
                    checked_out_ref: None,
                    build_plan: None,
                };
            }
        }
    }

    let fetch = Command::new("git")
        .arg("-C")
        .arg(source_dir)
        .arg("fetch")
        .arg("--depth")
        .arg("1")
        .arg("origin")
        .arg(source_ref)
        .output();
    let fetch_ok = match fetch {
        Ok(output) if output.status.success() => true,
        Ok(_) | Err(_) => Command::new("git")
            .arg("-C")
            .arg(source_dir)
            .arg("fetch")
            .arg("origin")
            .arg(source_ref)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success()),
    };
    if !fetch_ok {
        return Real9StageCase {
            case_id: String::new(),
            vuln_id: None,
            source_url: Some(source_url.to_string()),
            source_ref: Some(source_ref.to_string()),
            fixture_subdir: None,
            fixture_build_kind: None,
            source_dir: Some(source_dir_string),
            fixture_path: String::new(),
            status: "fetch_failed".to_string(),
            reason: Some("git fetch could not retrieve the pinned source_ref".to_string()),
            checked_out_ref: None,
            build_plan: None,
        };
    }

    let checkout = Command::new("git")
        .arg("-C")
        .arg(source_dir)
        .arg("checkout")
        .arg("--detach")
        .arg(source_ref)
        .output();
    match checkout {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            return Real9StageCase {
                case_id: String::new(),
                vuln_id: None,
                source_url: Some(source_url.to_string()),
                source_ref: Some(source_ref.to_string()),
                fixture_subdir: None,
                fixture_build_kind: None,
                source_dir: Some(source_dir_string),
                fixture_path: String::new(),
                status: "checkout_failed".to_string(),
                reason: Some(format!(
                    "git checkout failed: {}",
                    one_line_command_stderr(&output.stderr)
                )),
                checked_out_ref: None,
                build_plan: None,
            };
        }
        Err(err) => {
            return Real9StageCase {
                case_id: String::new(),
                vuln_id: None,
                source_url: Some(source_url.to_string()),
                source_ref: Some(source_ref.to_string()),
                fixture_subdir: None,
                fixture_build_kind: None,
                source_dir: Some(source_dir_string),
                fixture_path: String::new(),
                status: "checkout_failed".to_string(),
                reason: Some(format!("spawn git checkout: {err}")),
                checked_out_ref: None,
                build_plan: None,
            };
        }
    }

    let head = git_rev_parse_head(source_dir);
    if !head
        .as_deref()
        .is_some_and(|head| head.eq_ignore_ascii_case(source_ref))
    {
        return Real9StageCase {
            case_id: String::new(),
            vuln_id: None,
            source_url: Some(source_url.to_string()),
            source_ref: Some(source_ref.to_string()),
            fixture_subdir: None,
            fixture_build_kind: None,
            source_dir: Some(source_dir_string),
            fixture_path: String::new(),
            status: "ref_mismatch".to_string(),
            reason: Some("checked-out HEAD did not match source_ref".to_string()),
            checked_out_ref: head,
            build_plan: None,
        };
    }

    Real9StageCase {
        case_id: String::new(),
        vuln_id: None,
        source_url: Some(source_url.to_string()),
        source_ref: Some(source_ref.to_string()),
        fixture_subdir: None,
        fixture_build_kind: None,
        source_dir: Some(source_dir_string),
        fixture_path: String::new(),
        status: "fetched".to_string(),
        reason: None,
        checked_out_ref: head,
        build_plan: None,
    }
}

fn git_rev_parse_head(source_dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(source_dir)
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let head = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!head.is_empty()).then_some(head)
}

fn one_line_command_stderr(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    let mut line = text.lines().next().unwrap_or("").trim().to_string();
    if line.len() > 240 {
        line.truncate(240);
        line.push_str("...");
    }
    if line.is_empty() {
        "no stderr".to_string()
    } else {
        line
    }
}

fn real9_stage_status_ready(status: &str) -> bool {
    matches!(status, "ready" | "fetched" | "build_recipe_ready")
}

fn real9_stage_status_failed(status: &str) -> bool {
    matches!(
        status,
        "toolchain_unavailable"
            | "source_dir_not_git"
            | "source_root_create_failed"
            | "fetch_failed"
            | "checkout_failed"
            | "ref_mismatch"
            | "build_recipe_missing"
    )
}

fn is_full_git_sha(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn real9_source_dir_for(source_root: &Path, source_url: &str, source_ref: &str) -> PathBuf {
    let repo = source_url
        .trim_end_matches('/')
        .rsplit(['/', ':'])
        .next()
        .unwrap_or("source")
        .trim_end_matches(".git");
    let ref_prefix: String = source_ref.chars().take(12).collect();
    source_root.join(safe_component(&format!("{repo}-{ref_prefix}")))
}

fn prepare_case_input(
    args: &Args,
    manifest_dir: &Path,
    case: &BenchmarkCase,
    case_out: &Path,
) -> Result<PathBuf> {
    let Some(build) = &case.build else {
        return Ok(resolve_manifest_path(manifest_dir, &case.path));
    };
    let source = resolve_manifest_path(manifest_dir, &build.source);
    let fixture_root = args
        .fixture_out
        .clone()
        .unwrap_or_else(|| args.out.join("fixtures"));
    let output = match &build.output {
        Some(path) if path.is_absolute() => path.clone(),
        Some(path) => fixture_root.join(path),
        None => fixture_root.join(safe_component(&case.id)).join(format!(
            "{}{}",
            source
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("fixture"),
            std::env::consts::EXE_SUFFIX
        )),
    };
    let should_build = should_build_fixture(args, &output);
    if !should_build {
        return Ok(resolve_manifest_path(manifest_dir, &case.path));
    }
    if args.real9_build == "missing" && output.is_file() {
        return Ok(output);
    }

    if !source.is_file() {
        return Err(anyhow!("fixture source not found: {}", source.display()));
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create fixture output dir {}", parent.display()))?;
    }
    fs::create_dir_all(case_out)
        .with_context(|| format!("create case output dir {}", case_out.display()))?;
    let compiler = select_c_compiler(build.compiler.as_deref())?;
    let mut command = Command::new(&compiler);
    for flag in ["-O0", "-g", "-fno-stack-protector"] {
        command.arg(flag);
    }
    for flag in &build.cflags {
        command.arg(flag);
    }
    command.arg(&source).arg("-o").arg(&output);
    for flag in &build.ldflags {
        command.arg(flag);
    }
    let compile_output = command
        .output()
        .with_context(|| format!("spawn fixture compiler {compiler}"))?;
    let compile_report = json!({
        "schema": "axe_benchmark_fixture_build/1",
        "case_id": case.id,
        "source": source.to_string_lossy(),
        "output": output.to_string_lossy(),
        "compiler": compiler,
        "status": compile_output.status.code(),
        "success": compile_output.status.success(),
        "stdout": String::from_utf8_lossy(&compile_output.stdout),
        "stderr": String::from_utf8_lossy(&compile_output.stderr),
    });
    write_json(case_out.join("fixture_build.json"), &compile_report)?;
    if !compile_output.status.success() {
        return Err(anyhow!(
            "fixture build failed for {} with compiler {}",
            source.display(),
            compiler
        ));
    }
    if !output.is_file() {
        return Err(anyhow!(
            "fixture compiler succeeded but output is missing: {}",
            output.display()
        ));
    }
    Ok(output)
}

fn should_build_fixture(args: &Args, output: &Path) -> bool {
    if args.build_fixtures {
        return true;
    }
    if args.preset != "real-9" {
        return false;
    }
    match args.real9_build.as_str() {
        "always" => true,
        "missing" => !output.is_file(),
        _ => false,
    }
}

fn real_9_dynamic_execution_blocked(args: &Args, case: &BenchmarkCase) -> bool {
    args.preset == "real-9"
        && !args.allow_vulnerable_fixtures
        && dynamic_execution_requested(case, args)
}

fn select_c_compiler(explicit: Option<&str>) -> Result<String> {
    if let Some(compiler) = explicit {
        return Ok(compiler.to_string());
    }
    for candidate in ["x86_64-w64-mingw32-gcc", "gcc", "cc"] {
        if Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return Ok(candidate.to_string());
        }
    }
    Err(anyhow!(
        "no C compiler found; set build.compiler or install x86_64-w64-mingw32-gcc/gcc"
    ))
}

fn options_for_preset(preset: &str) -> Result<AnalysisOptions> {
    match preset {
        "real-5" => Ok(AnalysisOptions::real_5_preset()),
        "real-8" => Ok(AnalysisOptions::real_8_preset()),
        "real-9" => Ok(AnalysisOptions::real_9_preset()),
        other => Err(anyhow!("unsupported preset {other:?}")),
    }
}

fn run_analysis(input_path: &Path, analysis_out: &Path, options: AnalysisOptions) -> Result<()> {
    axe_core::analyze_path(
        input_path
            .to_str()
            .ok_or_else(|| anyhow!("input path is not valid UTF-8: {}", input_path.display()))?,
        analysis_out
            .to_str()
            .ok_or_else(|| anyhow!("out path is not valid UTF-8: {}", analysis_out.display()))?,
        options,
    )
    .map(|_| ())
    .map_err(|err| anyhow!(err.to_string()))
}

fn run_dynamic_probe(input_path: &Path, probe: &DynamicProbe) -> Result<(bool, Value)> {
    let mut command = Command::new(input_path);
    command
        .args(&probe.argv)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if probe.stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn dynamic probe {}", input_path.display()))?;
    if let Some(stdin_text) = &probe.stdin {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_text.as_bytes())?;
        }
    }

    let started = Instant::now();
    let timeout = Duration::from_millis(probe.timeout_ms);
    let mut timed_out = false;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let stdout_ok = probe
        .expect_stdout_contains
        .iter()
        .all(|needle| stdout.contains(needle));
    let succeeded = !timed_out && output.status.success() && stdout_ok;
    Ok((
        succeeded,
        json!({
            "schema": "axe_benchmark_dynamic_probe/1",
            "input": input_path.to_string_lossy(),
            "argv": probe.argv,
            "timeout_ms": probe.timeout_ms,
            "timed_out": timed_out,
            "status": output.status.code(),
            "success": succeeded,
            "evidence_source": probe.evidence_source,
            "stdout_contains_ok": stdout_ok,
            "stdout": stdout,
            "stderr": stderr,
        }),
    ))
}

fn run_dynamic_jobs(
    input_path: &Path,
    case: &BenchmarkCase,
    args: &Args,
    static_findings: &[Value],
    static_proof_packets: &BTreeMap<String, Value>,
    policy: ProbeEvidencePolicy,
    dynamic_evidence: &mut Vec<DynamicEvidence>,
) -> Result<Vec<Value>> {
    let mut reports = Vec::new();
    for job in &case.dynamic_jobs {
        if !dynamic_job_selected(&args.dynamic_jobs, job) {
            continue;
        }
        let probe = dynamic_job_as_probe(job, args.dynamic_budget_secs);
        let (succeeded, mut report) = run_dynamic_probe(input_path, &probe)?;
        if let Some(obj) = report.as_object_mut() {
            obj.insert("job_kind".to_string(), json!(job.kind));
            obj.insert("case_id".to_string(), json!(case.id));
        }
        if succeeded {
            dynamic_evidence.extend(synthesize_probe_evidence_with_policy(
                &case.id,
                static_findings,
                static_proof_packets,
                &case.expected_findings,
                &probe,
                policy,
            ));
        }
        reports.push(report);
    }
    Ok(reports)
}

fn dynamic_job_as_probe(job: &DynamicJob, budget_secs: u64) -> DynamicProbe {
    DynamicProbe {
        argv: job.argv.clone(),
        stdin: job.stdin.clone(),
        timeout_ms: job
            .timeout_ms
            .unwrap_or_else(|| budget_secs.saturating_mul(1_000))
            .max(1),
        evidence_source: job
            .evidence_source
            .clone()
            .unwrap_or_else(|| job.kind.clone()),
        status: job.status.clone(),
        expect_stdout_contains: job.expect_stdout_contains.clone(),
        observed: job.observed.clone(),
    }
}

fn dynamic_job_selected(selector: &str, job: &DynamicJob) -> bool {
    match selector {
        "off" => false,
        "auto" | "all" => true,
        value => value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .any(|part| {
                part.eq_ignore_ascii_case(&job.kind)
                    || job
                        .evidence_source
                        .as_deref()
                        .is_some_and(|source| part.eq_ignore_ascii_case(source))
            }),
    }
}

fn dynamic_execution_requested(case: &BenchmarkCase, args: &Args) -> bool {
    case.dynamic_probe.is_some()
        || case
            .dynamic_jobs
            .iter()
            .any(|job| dynamic_job_selected(&args.dynamic_jobs, job))
}

fn synthesize_probe_evidence_with_policy(
    case_id: &str,
    findings: &[Value],
    proof_packets: &BTreeMap<String, Value>,
    expected_findings: &[ExpectedFinding],
    probe: &DynamicProbe,
    policy: ProbeEvidencePolicy,
) -> Vec<DynamicEvidence> {
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for (rank, finding) in findings.iter().enumerate() {
        let proof_packet = proof_packets.get(finding_id(finding));
        let rank_one_based = rank + 1;
        let Some(expected) = expected_findings.iter().find(|expected| {
            !expected.expected_missed_ok
                && expected
                    .required_evidence_source
                    .as_deref()
                    .is_none_or(|source| source.eq_ignore_ascii_case(&probe.evidence_source))
                && expected
                    .min_rank
                    .is_none_or(|min_rank| rank_one_based <= min_rank)
                && expected_finding_shape_matches(finding, expected)
        }) else {
            continue;
        };
        let Some(chain_id) = finding.pointer("/chain_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(sink_va) = finding
            .pointer("/sink/site_va")
            .and_then(Value::as_str)
            .and_then(parse_hex_va)
            .or_else(|| {
                proof_packet
                    .and_then(|packet| {
                        packet
                            .pointer("/source_to_sink_chain/sink_site_va")
                            .and_then(Value::as_str)
                    })
                    .and_then(parse_hex_va)
            })
        else {
            continue;
        };
        if !probe_satisfies_policy(probe, sink_va, policy) {
            continue;
        }
        let key = format!("{}:{}:{}", probe.evidence_source, chain_id, sink_va);
        if !seen.insert(key) {
            continue;
        }
        let harness_id = finding
            .pointer("/harness/harness_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("H-{chain_id}"));
        let mut observed = probe.observed.clone();
        observed.insert("case_id".to_string(), json!(case_id));
        observed.insert("finding_id".to_string(), json!(finding_id(finding)));
        observed.insert(
            "expected_finding".to_string(),
            json!(expected_label(expected)),
        );
        observed.insert("probe_status".to_string(), json!(probe.status));
        let reproducer = format!(
            "{}:{}:{}",
            probe.evidence_source,
            case_id,
            expected_label(expected)
        );
        let sink_pc = DynamicEvidence::format_sink_pc(sink_va);
        let row = match probe.status.as_str() {
            "confirmed_trigger" => DynamicEvidence::confirmed_trigger(
                chain_id.to_string(),
                harness_id,
                sink_pc,
                observed,
                reproducer,
            ),
            "not_observed" => {
                DynamicEvidence::not_observed(chain_id.to_string(), harness_id, sink_pc)
            }
            _ => DynamicEvidence::reached_only(
                chain_id.to_string(),
                harness_id,
                sink_pc,
                observed,
                reproducer,
            ),
        }
        .with_evidence_source(probe.evidence_source.clone());
        rows.push(row);
    }
    rows
}

fn probe_satisfies_policy(probe: &DynamicProbe, sink_va: u64, policy: ProbeEvidencePolicy) -> bool {
    match policy {
        ProbeEvidencePolicy::AllowProbeStatusOnly => true,
        ProbeEvidencePolicy::RequireObservedSinkPc => observed_sink_pc(probe) == Some(sink_va),
    }
}

fn observed_sink_pc(probe: &DynamicProbe) -> Option<u64> {
    for key in ["sink_pc", "sink_va", "observed_sink_pc", "observed_sink_va"] {
        let Some(value) = probe.observed.get(key) else {
            continue;
        };
        if let Some(raw) = value.as_str().and_then(parse_hex_va) {
            return Some(raw);
        }
        if let Some(raw) = value.as_u64() {
            return Some(raw);
        }
    }
    None
}

fn real_9_dynamic_source_reasons(source_counts: &BTreeMap<String, usize>) -> Vec<&'static str> {
    let mut reasons = Vec::new();
    if source_counts
        .iter()
        .any(|(source, count)| *count > 0 && source.eq_ignore_ascii_case("safe_fixture_probe"))
    {
        reasons.push("safe_fixture_probe_disallowed");
    }
    let has_verified_source = source_counts.iter().any(|(source, count)| {
        *count > 0
            && matches!(
                source.as_str(),
                "debug_probe" | "fuzz" | "trace" | "concolic"
            )
    });
    if !has_verified_source {
        reasons.push("missing_verified_dynamic_source");
    }
    reasons
}

fn parse_hex_va(value: &str) -> Option<u64> {
    let normalized = value
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    u64::from_str_radix(normalized, 16).ok()
}

fn read_findings(analysis_out: &Path, top_k: usize) -> Result<Vec<Value>> {
    let path = analysis_out.join("vuln").join("findings.jsonl");
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let mut rows = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        rows.push(serde_json::from_str::<Value>(line)?);
    }
    rows.sort_by(|left, right| {
        right
            .get("risk_score")
            .and_then(Value::as_f64)
            .partial_cmp(&left.get("risk_score").and_then(Value::as_f64))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows.truncate(top_k);
    Ok(rows)
}

fn read_proof_packets(analysis_out: &Path) -> Result<BTreeMap<String, Value>> {
    let manifest_path = analysis_out
        .join("vuln")
        .join("vuln_packets")
        .join("manifest.json");
    if !manifest_path.is_file() {
        return Ok(BTreeMap::new());
    }
    let manifest: Value = serde_json::from_slice(
        &fs::read(&manifest_path).with_context(|| format!("read {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parse {}", manifest_path.display()))?;
    let mut out = BTreeMap::new();
    let Some(entries) = manifest.get("packets").and_then(Value::as_array) else {
        return Ok(out);
    };
    for entry in entries {
        let Some(rel_path) = entry.get("path").and_then(Value::as_str) else {
            continue;
        };
        let packet_path = analysis_out.join("vuln").join(rel_path);
        if !packet_path.is_file() {
            continue;
        }
        let packet: Value = serde_json::from_slice(
            &fs::read(&packet_path).with_context(|| format!("read {}", packet_path.display()))?,
        )
        .with_context(|| format!("parse {}", packet_path.display()))?;
        if let Some(finding_id) = packet.get("finding_id").and_then(Value::as_str) {
            out.insert(finding_id.to_string(), packet);
        }
    }
    Ok(out)
}

fn finding_id(finding: &Value) -> &str {
    finding
        .get("finding_id")
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn finding_signature(finding: &Value) -> String {
    finding
        .get("bug_class")
        .and_then(Value::as_str)
        .or_else(|| finding.get("signature").and_then(Value::as_str))
        .unwrap_or("unknown")
        .to_string()
}

fn expected_finding_matches(
    finding: &Value,
    proof_packet: Option<&Value>,
    expected: &ExpectedFinding,
    rank: usize,
) -> bool {
    if expected.min_rank.is_some_and(|min_rank| rank > min_rank) {
        return false;
    }
    if finding_signature(finding) != expected.bug_class {
        return false;
    }
    if let Some(source_kind) = expected.source_kind.as_deref() {
        if !case_insensitive_eq(
            finding
                .pointer("/source/kind")
                .and_then(Value::as_str)
                .unwrap_or(""),
            source_kind,
        ) {
            return false;
        }
    }
    if let Some(sink_api) = expected.sink_api.as_deref() {
        if !case_insensitive_contains(
            finding
                .pointer("/sink/api")
                .and_then(Value::as_str)
                .unwrap_or(""),
            sink_api,
        ) {
            return false;
        }
    }
    if expected.require_proof_packet && proof_packet.is_none() {
        return false;
    }
    if let Some(min_status) = expected.min_dynamic_status.as_deref() {
        let Some(status) = dynamic_status_for(finding, proof_packet) else {
            return false;
        };
        if dynamic_status_rank(&status) < dynamic_status_rank(min_status) {
            return false;
        }
    }
    if let Some(required_source) = expected.required_evidence_source.as_deref() {
        if !evidence_sources_for(finding, proof_packet)
            .iter()
            .any(|source| source.eq_ignore_ascii_case(required_source))
        {
            return false;
        }
    }
    true
}

fn expected_finding_shape_matches(finding: &Value, expected: &ExpectedFinding) -> bool {
    if finding_signature(finding) != expected.bug_class {
        return false;
    }
    if let Some(source_kind) = expected.source_kind.as_deref() {
        if !case_insensitive_eq(
            finding
                .pointer("/source/kind")
                .and_then(Value::as_str)
                .unwrap_or(""),
            source_kind,
        ) {
            return false;
        }
    }
    if let Some(sink_api) = expected.sink_api.as_deref() {
        if !case_insensitive_contains(
            finding
                .pointer("/sink/api")
                .and_then(Value::as_str)
                .unwrap_or(""),
            sink_api,
        ) {
            return false;
        }
    }
    true
}

fn expected_label(expected: &ExpectedFinding) -> String {
    expected
        .id
        .clone()
        .or_else(|| expected.collapse_key.clone())
        .unwrap_or_else(|| {
            format!(
                "{}:{}:{}",
                expected.bug_class,
                expected.source_kind.as_deref().unwrap_or("*"),
                expected.sink_api.as_deref().unwrap_or("*")
            )
        })
}

fn dynamic_status_for(finding: &Value, proof_packet: Option<&Value>) -> Option<String> {
    finding
        .pointer("/dynamic_evidence/status")
        .and_then(Value::as_str)
        .or_else(|| {
            proof_packet.and_then(|packet| {
                packet
                    .pointer("/dynamic_confirmation/status")
                    .and_then(Value::as_str)
            })
        })
        .map(str::to_string)
}

fn evidence_sources_for(finding: &Value, proof_packet: Option<&Value>) -> Vec<String> {
    let mut out = Vec::new();
    collect_string_array(
        finding.pointer("/dynamic_evidence/evidence_sources"),
        &mut out,
    );
    collect_string_value(
        finding.pointer("/dynamic_evidence/evidence_source"),
        &mut out,
    );
    if let Some(packet) = proof_packet {
        collect_string_array(
            packet.pointer("/dynamic_confirmation/evidence_sources"),
            &mut out,
        );
        collect_string_value(
            packet.pointer("/dynamic_confirmation/evidence_source"),
            &mut out,
        );
    }
    out.sort();
    out.dedup();
    out
}

fn emit_repro_packet(
    args: &Args,
    case: &BenchmarkCase,
    input_path: &Path,
    analysis_out: &Path,
    case_out: &Path,
    rank: usize,
    finding: &Value,
    proof_packet: Option<&Value>,
) -> Result<Option<PathBuf>> {
    let finding_id = finding_id(finding);
    if finding_id.is_empty() {
        return Ok(None);
    }
    let packet = ReproPacket {
        schema: "axe_benchmark_repro_packet/1",
        case_id: case.id.clone(),
        finding_id: finding_id.to_string(),
        chain_id: finding
            .get("chain_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        bug_class: finding_signature(finding),
        runner_command: runner_command_for_case(args, case, input_path),
        seed: case.repro_seed.clone().or_else(|| {
            case.dynamic_probe
                .as_ref()
                .and_then(|probe| probe.stdin.clone())
                .map(|stdin| format!("stdin:{}", short_hash(stdin.as_bytes())))
        }),
        expected_sink_pc: finding
            .pointer("/sink/site_va")
            .and_then(Value::as_str)
            .or_else(|| {
                proof_packet.and_then(|packet| {
                    packet
                        .pointer("/source_to_sink_chain/sink_site_va")
                        .and_then(Value::as_str)
                })
            })
            .map(str::to_string),
        observed_status: dynamic_status_for(finding, proof_packet),
        observed_pc: finding
            .pointer("/dynamic_evidence/sink_pc")
            .and_then(Value::as_str)
            .or_else(|| {
                proof_packet.and_then(|packet| {
                    packet
                        .pointer("/dynamic_confirmation/sink_pc")
                        .and_then(Value::as_str)
                })
            })
            .map(str::to_string),
        evidence_sources: evidence_sources_for(finding, proof_packet),
        proof_packet_id: proof_packet
            .and_then(|packet| packet.get("packet_id").and_then(Value::as_str))
            .map(str::to_string),
        artifact_provenance: vec![
            format!("benchmark_case:{}", case.id),
            format!("analysis_out:{}", analysis_out.display()),
            format!("finding_rank:{rank}"),
        ],
    };
    let path = case_out
        .join("repro_packets")
        .join(format!("{rank:03}_{}.json", safe_component(finding_id)));
    write_json(path.clone(), &serde_json::to_value(packet)?)?;
    Ok(Some(path))
}

fn runner_command_for_case(args: &Args, case: &BenchmarkCase, input_path: &Path) -> Vec<String> {
    let mut command = vec![input_path.display().to_string()];
    if let Some(probe) = &case.dynamic_probe {
        command.extend(probe.argv.clone());
        return command;
    }
    if let Some(job) = case
        .dynamic_jobs
        .iter()
        .find(|job| dynamic_job_selected(&args.dynamic_jobs, job))
    {
        command.extend(job.argv.clone());
    }
    command
}

fn short_hash(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn collect_string_array(value: Option<&Value>, out: &mut Vec<String>) {
    let Some(values) = value.and_then(Value::as_array) else {
        return;
    };
    for value in values {
        collect_string_value(Some(value), out);
    }
}

fn collect_string_value(value: Option<&Value>, out: &mut Vec<String>) {
    let Some(value) = value.and_then(Value::as_str) else {
        return;
    };
    if !value.is_empty() {
        out.push(value.to_string());
    }
}

fn dynamic_status_counts_as_confirmation(status: Option<&str>) -> bool {
    let Some(status) = status else {
        return false;
    };
    matches!(status, "confirmed_trigger" | "reached_only")
}

fn dynamic_status_rank(status: &str) -> u8 {
    match status {
        "confirmed_trigger" => 2,
        "reached_only" => 1,
        _ => 0,
    }
}

fn case_insensitive_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn case_insensitive_contains(value: &str, needle: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_finding() -> Value {
        json!({
            "finding_id": "F-000001",
            "bug_class": "unchecked_copy_length",
            "chain_id": "C-000001",
            "source": { "kind": "network_recv" },
            "sink": { "api": "memcpy", "site_va": "0x0000000014001234" },
            "harness": { "harness_id": "H-C-000001" }
        })
    }

    fn fixture_expected() -> ExpectedFinding {
        ExpectedFinding {
            id: Some("expected_memcpy".to_string()),
            bug_class: "unchecked_copy_length".to_string(),
            source_kind: Some("network_recv".to_string()),
            sink_api: Some("memcpy".to_string()),
            min_dynamic_status: Some("reached_only".to_string()),
            require_proof_packet: false,
            required_evidence_source: Some("debug_probe".to_string()),
            min_rank: Some(1),
            collapse_key: None,
            allow_duplicate_matches: true,
            expected_missed_ok: false,
        }
    }

    fn fixture_probe(observed_sink_pc: Option<&str>, evidence_source: &str) -> DynamicProbe {
        let mut observed = BTreeMap::new();
        if let Some(sink_pc) = observed_sink_pc {
            observed.insert("sink_pc".to_string(), json!(sink_pc));
        }
        DynamicProbe {
            argv: Vec::new(),
            stdin: None,
            timeout_ms: 100,
            evidence_source: evidence_source.to_string(),
            status: "reached_only".to_string(),
            expect_stdout_contains: Vec::new(),
            observed,
        }
    }

    #[test]
    fn real_9_probe_evidence_requires_observed_sink_pc_match() {
        let findings = vec![fixture_finding()];
        let proof_packets = BTreeMap::new();
        let expected = vec![fixture_expected()];

        let missing_marker = fixture_probe(None, "debug_probe");
        let rows = synthesize_probe_evidence_with_policy(
            "case-1",
            &findings,
            &proof_packets,
            &expected,
            &missing_marker,
            ProbeEvidencePolicy::RequireObservedSinkPc,
        );
        assert!(
            rows.is_empty(),
            "real-9 evidence must not be synthesized from a generic successful probe"
        );

        let wrong_marker = fixture_probe(Some("0x0000000014009999"), "debug_probe");
        let rows = synthesize_probe_evidence_with_policy(
            "case-1",
            &findings,
            &proof_packets,
            &expected,
            &wrong_marker,
            ProbeEvidencePolicy::RequireObservedSinkPc,
        );
        assert!(
            rows.is_empty(),
            "real-9 evidence must match the exact sink PC for the chain"
        );

        let matching_marker = fixture_probe(Some("0x0000000014001234"), "debug_probe");
        let rows = synthesize_probe_evidence_with_policy(
            "case-1",
            &findings,
            &proof_packets,
            &expected,
            &matching_marker,
            ProbeEvidencePolicy::RequireObservedSinkPc,
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].evidence_source, "debug_probe");
        assert_eq!(rows[0].sink_pc, "0x0000000014001234");
    }

    #[test]
    fn real_9_dynamic_sources_exclude_safe_fixture_probe() {
        let sources = BTreeMap::from([
            ("debug_probe".to_string(), 3usize),
            ("safe_fixture_probe".to_string(), 9usize),
        ]);
        let reasons = real_9_dynamic_source_reasons(&sources);
        assert!(
            reasons.contains(&"safe_fixture_probe_disallowed"),
            "real-9 must make synthetic fixture probes visible as a gate failure"
        );
        assert!(
            !reasons.contains(&"missing_verified_dynamic_source"),
            "debug_probe should satisfy the verified-source requirement"
        );
    }

    #[test]
    fn real_9_build_plan_is_non_executing_and_targets_fixture_path() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let source_dir = tmp.path().join("fuzzer-test-suite");
        let fixture_subdir = source_dir.join("c-ares-CVE-2016-5180");
        fs::create_dir_all(&fixture_subdir).expect("create fixture subdir");
        fs::write(fixture_subdir.join("build.sh"), "#!/bin/bash\n").expect("write build script");
        let fixture_path = tmp.path().join("fixtures").join("case").join("target.bin");

        let plan = real9_fts_build_plan(
            "case",
            &source_dir,
            Some("c-ares-CVE-2016-5180"),
            &fixture_path,
        )
        .expect("build plan");

        assert_eq!(plan.executed, false);
        assert!(
            plan.build_script
                .ends_with("c-ares-CVE-2016-5180\\build.sh")
                || plan.build_script.ends_with("c-ares-CVE-2016-5180/build.sh")
        );
        assert!(plan
            .expected_binary
            .ends_with("c-ares-CVE-2016-5180-fsanitize_fuzzer"));
        assert_eq!(plan.fixture_output, fixture_path.display().to_string());
        assert_eq!(plan.build_command.first().map(String::as_str), Some("bash"));
    }

    #[test]
    fn real_9_cmake_baseline_plan_is_non_executing() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let source_dir = tmp.path().join("libxml2");
        fs::create_dir_all(&source_dir).expect("create source dir");
        fs::write(
            source_dir.join("CMakeLists.txt"),
            "cmake_minimum_required(VERSION 3.18)\n",
        )
        .expect("write cmake");
        let fixture_path = tmp
            .path()
            .join("fixtures")
            .join("baseline")
            .join("target.bin");

        let plan = real9_cmake_baseline_build_plan(
            "baseline",
            "cmake_libxml2_xmllint",
            &source_dir,
            &fixture_path,
        )
        .expect("baseline build plan");

        assert_eq!(plan.executed, false);
        assert_eq!(plan.fixture_output, fixture_path.display().to_string());
        assert!(plan.expected_binary.ends_with("xmllint"));
        assert!(plan
            .build_command
            .get(2)
            .is_some_and(|cmd| cmd.contains("cmake -S")));
    }
}

fn mean(values: impl Iterator<Item = f64>) -> f64 {
    let mut count = 0usize;
    let mut total = 0.0;
    for value in values {
        count += 1;
        total += value;
    }
    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}

fn write_json(path: PathBuf, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    serde_json::to_writer_pretty(BufWriter::new(file), value)?;
    Ok(())
}

fn write_jsonl<T: Serialize>(path: PathBuf, rows: &[T]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut writer = BufWriter::new(File::create(path)?);
    for row in rows {
        serde_json::to_writer(&mut writer, row)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

fn report_markdown(summary: &Value, cases: &[CaseResult]) -> String {
    let mut lines = Vec::new();
    lines.push("# axe benchmark report".to_string());
    lines.push(String::new());
    lines.push(format!(
        "real_5_gate: `{}`",
        summary["real_5_gate"].as_str().unwrap_or("fail")
    ));
    lines.push(format!(
        "real_8_gate: `{}`",
        summary["real_8_gate"].as_str().unwrap_or("fail")
    ));
    lines.push(format!(
        "mean_estimated_level: {:.2}",
        summary["mean_estimated_level"].as_f64().unwrap_or(0.0)
    ));
    lines.push(format!(
        "expected_signature_recall: {:.3}",
        summary["expected_signature_recall"].as_f64().unwrap_or(0.0)
    ));
    lines.push(format!(
        "collapsed_precision_mean: {:.3}",
        summary["collapsed_precision_mean"].as_f64().unwrap_or(0.0)
    ));
    lines.push(format!(
        "non_controlled_dynamic_confirmed_findings: {}",
        summary["non_controlled_dynamic_confirmed_findings"]
            .as_u64()
            .unwrap_or(0)
    ));
    lines.push(String::new());
    lines.push(
        "| case | status | precision | collapsed precision | recall | false positives | missed | dynamic | proof packets | repro packets | requirements |"
            .to_string(),
    );
    lines.push(
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |".to_string(),
    );
    for case in cases {
        lines.push(format!(
            "| {} | {} | {:.3} | {:.3} | {:.3} | {} | {} | {} | {} | {} | {} |",
            case.id,
            case.status,
            case.precision,
            case.collapsed_precision,
            case.recall,
            case.false_positives,
            case.missed_expected_findings.len(),
            case.dynamic_confirmed_findings,
            case.proof_packets_present,
            case.repro_packets_present,
            if case.requirements_met {
                "met"
            } else {
                "failed"
            }
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn safe_component(value: &str) -> String {
    let safe: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        "case".to_string()
    } else {
        safe
    }
}
