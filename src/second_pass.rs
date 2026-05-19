use crate::ir::IrInstruction;
use crate::pe::{
    ApiFlowRecord, FunctionDossierRecord, FunctionRecord, ObfuscationHintRecord,
    RecoveredStringRecord, ResolvedCallRecord, SecondPassSummaryRecord, SecondPassTargetRecord,
    StructuredFlowRecord, UncertaintyRecord, XrefRecord,
};
use crate::semantic_index::FunctionSemanticIndex;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

pub struct SecondPassInput<'a> {
    pub policy: &'a str,
    pub budget_name: &'a str,
    pub functions: &'a [FunctionRecord],
    pub semantic_index: &'a FunctionSemanticIndex,
    pub ir: &'a [IrInstruction],
    pub xrefs: &'a [XrefRecord],
    pub api_flows: &'a [ApiFlowRecord],
    pub function_dossiers: &'a [FunctionDossierRecord],
    pub obfuscation_hints: &'a [ObfuscationHintRecord],
    pub recovered_strings: &'a [RecoveredStringRecord],
    pub resolved_calls: &'a [ResolvedCallRecord],
    pub structured_flow: &'a [StructuredFlowRecord],
}

pub struct SecondPassResult {
    pub summary: SecondPassSummaryRecord,
    pub targets: Vec<SecondPassTargetRecord>,
    pub uncertainties: Vec<UncertaintyRecord>,
    pub profile: BTreeMap<String, f64>,
}

#[derive(Clone)]
struct Candidate {
    function: u64,
    reason: String,
    priority_score: i64,
    pass1_uncertainty: String,
    evidence: Vec<u64>,
    site_va: Option<u64>,
    uncertainty_reason: Option<String>,
}

pub fn run_second_pass(input: SecondPassInput<'_>) -> SecondPassResult {
    let total_started = Instant::now();
    let mut profile = BTreeMap::new();
    if input.policy == "off" {
        return SecondPassResult {
            summary: SecondPassSummaryRecord {
                status: "disabled".to_string(),
                eligible_functions: 0,
                analyzed_functions: 0,
                skipped_by_budget: 0,
                reason_counts: BTreeMap::new(),
                elapsed_seconds: total_started.elapsed().as_secs_f64(),
                caps_hit: false,
                vsa_values: 0,
                resolved_jump_tables: 0,
                resolved_hashes: 0,
                decoded_strings: 0,
                type_hints: 0,
                structured_refinements: 0,
                rtti_ownership_refinements: 0,
                resolved_virtual_calls: 0,
                ssa_values: 0,
                dataflow_edges: 0,
                behavior_dossiers: 0,
            },
            targets: Vec::new(),
            uncertainties: Vec::new(),
            profile,
        };
    }

    let select_started = Instant::now();
    let mut candidates = if input.policy == "all" {
        all_function_candidates(input.functions)
    } else {
        auto_candidates(&input)
    };
    candidates.sort_by(|left, right| {
        right
            .priority_score
            .cmp(&left.priority_score)
            .then_with(|| left.function.cmp(&right.function))
            .then_with(|| left.reason.cmp(&right.reason))
            .then_with(|| left.site_va.cmp(&right.site_va))
    });
    profile.insert(
        "target_selection".to_string(),
        select_started.elapsed().as_secs_f64(),
    );

    let eligible_functions = candidates
        .iter()
        .map(|row| row.function)
        .collect::<BTreeSet<_>>()
        .len();
    let target_cap = second_pass_target_cap(input.budget_name);
    let caps_hit = candidates.len() > target_cap;
    candidates.truncate(target_cap);

    let analyze_started = Instant::now();
    let mut reason_counts = BTreeMap::new();
    let mut targets = Vec::with_capacity(candidates.len());
    let mut uncertainties = Vec::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        *reason_counts.entry(candidate.reason.clone()).or_insert(0) += 1;
        let target_id = format!(
            "second-pass:{:016X}:{}:{:04X}",
            candidate.function, candidate.reason, index
        );
        targets.push(SecondPassTargetRecord {
            target_id,
            function: candidate.function,
            reason: candidate.reason.clone(),
            priority_score: candidate.priority_score,
            pass1_uncertainty: candidate.pass1_uncertainty.clone(),
            result_status: "analyzed".to_string(),
            evidence: candidate.evidence.clone(),
        });
        if let Some(reason) = candidate.uncertainty_reason {
            uncertainties.push(UncertaintyRecord {
                uncertainty_id: format!(
                    "uncertainty:{:016X}:{}:{:04X}",
                    candidate.function,
                    reason,
                    uncertainties.len()
                ),
                function: candidate.function,
                site_va: candidate.site_va,
                reason,
                details: candidate.pass1_uncertainty,
                tried: tried_for_reason(&candidate.reason),
                recommended_action: "manual review".to_string(),
                severity_hint: severity_for_reason(&candidate.reason),
                evidence: candidate.evidence,
            });
        }
    }
    profile.insert(
        "bounded_analysis".to_string(),
        analyze_started.elapsed().as_secs_f64(),
    );

    let status = if caps_hit {
        "completed_with_caps"
    } else {
        "completed"
    };
    let analyzed_functions = targets
        .iter()
        .map(|row| row.function)
        .collect::<BTreeSet<_>>()
        .len();
    let skipped_by_budget = if caps_hit {
        eligible_functions.saturating_sub(analyzed_functions)
    } else {
        0
    };
    let elapsed_seconds = total_started.elapsed().as_secs_f64();
    profile.insert("total".to_string(), elapsed_seconds);
    SecondPassResult {
        summary: SecondPassSummaryRecord {
            status: status.to_string(),
            eligible_functions,
            analyzed_functions,
            skipped_by_budget,
            reason_counts,
            elapsed_seconds,
            caps_hit,
            vsa_values: 0,
            resolved_jump_tables: 0,
            resolved_hashes: 0,
            decoded_strings: 0,
            type_hints: 0,
            structured_refinements: 0,
            rtti_ownership_refinements: 0,
            resolved_virtual_calls: 0,
            ssa_values: 0,
            dataflow_edges: 0,
            behavior_dossiers: 0,
        },
        targets,
        uncertainties,
        profile,
    }
}

fn auto_candidates(input: &SecondPassInput<'_>) -> Vec<Candidate> {
    let mut rows = Vec::new();
    rows.extend(unresolved_indirect_candidates(input));
    rows.extend(obfuscation_candidates(input));
    rows.extend(behavior_flow_candidates(input));
    rows.extend(low_confidence_high_value_candidates(input));
    rows.extend(class_dispatch_candidates(input));
    dedupe_candidates(rows)
}

fn all_function_candidates(functions: &[FunctionRecord]) -> Vec<Candidate> {
    functions
        .iter()
        .map(|function| Candidate {
            function: function.start,
            reason: "policy_all".to_string(),
            priority_score: 1,
            pass1_uncertainty: "second-pass all policy requested".to_string(),
            evidence: vec![function.start],
            site_va: None,
            uncertainty_reason: None,
        })
        .collect()
}

fn unresolved_indirect_candidates(input: &SecondPassInput<'_>) -> Vec<Candidate> {
    let import_call_sites: BTreeSet<u64> = input
        .xrefs
        .iter()
        .filter(|xref| xref.kind == "import" && xref.role == "call")
        .map(|xref| xref.from)
        .collect();
    let resolved_call_sites: BTreeSet<u64> = input
        .resolved_calls
        .iter()
        .map(|row| row.callsite)
        .collect();
    let mut rows = Vec::new();
    for slice in &input.semantic_index.slices {
        for ins in &input.ir[slice.ir_range.clone()] {
            if !(ins.is_call || ins.is_jump) || ins.direct_target.is_some() {
                continue;
            }
            if import_call_sites.contains(&ins.address)
                || resolved_call_sites.contains(&ins.address)
            {
                continue;
            }
            let reason = if ins.is_call {
                "unresolved_indirect_call"
            } else {
                "unresolved_indirect_jump"
            };
            rows.push(Candidate {
                function: slice.function_start,
                reason: reason.to_string(),
                priority_score: if ins.is_call { 100 } else { 90 },
                pass1_uncertainty: format!(
                    "{} at 0x{:016X} still lacks a static target after pass 1",
                    reason, ins.address
                ),
                evidence: vec![ins.address],
                site_va: Some(ins.address),
                uncertainty_reason: Some(if ins.is_call {
                    "indirect_call_unresolved".to_string()
                } else {
                    "indirect_jump_unresolved".to_string()
                }),
            });
        }
    }
    rows
}

fn obfuscation_candidates(input: &SecondPassInput<'_>) -> Vec<Candidate> {
    let mut rows = Vec::new();
    for hint in input.obfuscation_hints {
        let reason = match hint.candidate_kind.as_str() {
            "api_hash_candidate" => "api_hash_candidate",
            "encoded_blob_hint" => "encoded_blob_hint",
            other => other,
        };
        rows.push(Candidate {
            function: hint.function,
            reason: reason.to_string(),
            priority_score: if reason == "api_hash_candidate" {
                95
            } else {
                55
            },
            pass1_uncertainty: hint.uncertainty_reason.clone(),
            evidence: hint.evidence.clone(),
            site_va: hint.evidence.first().copied(),
            uncertainty_reason: Some(match reason {
                "api_hash_candidate" => "api_hash_unresolved".to_string(),
                "encoded_blob_hint" => "packed_or_encoded_blob".to_string(),
                _ => "obfuscation_candidate_unresolved".to_string(),
            }),
        });
    }
    rows
}

fn behavior_flow_candidates(input: &SecondPassInput<'_>) -> Vec<Candidate> {
    let malware_categories = [
        "process",
        "registry",
        "network",
        "crypto",
        "anti_debug",
        "service",
        "memory",
        "module",
    ];
    let mut rows = Vec::new();
    for flow in input.api_flows {
        if !flow
            .api_categories
            .iter()
            .any(|category| malware_categories.contains(&category.as_str()))
        {
            continue;
        }
        let priority = match flow.semantic_relevance.as_str() {
            "high" => 85,
            "medium" => 70,
            _ => 45,
        };
        rows.push(Candidate {
            function: flow.function,
            reason: "malware_relevant_api_flow".to_string(),
            priority_score: priority,
            pass1_uncertainty: format!(
                "{} flow into {} needs second-pass corroboration",
                flow.argument, flow.normalized_api
            ),
            evidence: flow.evidence.clone(),
            site_va: Some(flow.callsite),
            uncertainty_reason: None,
        });
    }
    rows
}

fn low_confidence_high_value_candidates(input: &SecondPassInput<'_>) -> Vec<Candidate> {
    input
        .function_dossiers
        .iter()
        .filter(|row| row.confidence == "low" && row.score >= 50)
        .map(|row| Candidate {
            function: row.function,
            reason: "high_priority_low_confidence".to_string(),
            priority_score: row.score,
            pass1_uncertainty:
                "function dossier ranked high but boundary/semantic confidence is low".to_string(),
            evidence: vec![row.function],
            site_va: None,
            uncertainty_reason: None,
        })
        .collect()
}

fn class_dispatch_candidates(input: &SecondPassInput<'_>) -> Vec<Candidate> {
    let recovered_functions: BTreeSet<u64> = input
        .recovered_strings
        .iter()
        .map(|row| row.function)
        .collect();
    input
        .structured_flow
        .iter()
        .filter(|row| !row.switch_candidates.is_empty())
        .map(|row| Candidate {
            function: row.function,
            reason: "unclear_dispatch_structure".to_string(),
            priority_score: if recovered_functions.contains(&row.function) {
                75
            } else {
                60
            },
            pass1_uncertainty:
                "structured flow contains switch/dispatch candidates requiring refinement"
                    .to_string(),
            evidence: row.switch_candidates.clone(),
            site_va: row.switch_candidates.first().copied(),
            uncertainty_reason: None,
        })
        .collect()
}

fn dedupe_candidates(rows: Vec<Candidate>) -> Vec<Candidate> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for row in rows {
        let key = (row.function, row.reason.clone(), row.site_va);
        if seen.insert(key) {
            deduped.push(row);
        }
    }
    deduped
}

fn second_pass_target_cap(budget_name: &str) -> usize {
    match budget_name {
        "max" => usize::MAX,
        "high" => 2048,
        _ => 512,
    }
}

fn tried_for_reason(reason: &str) -> Vec<String> {
    match reason {
        "unresolved_indirect_call" | "unresolved_indirect_jump" => vec![
            "pass1_cfg".to_string(),
            "wrapper_collapse".to_string(),
            "bounded_static_resolution".to_string(),
        ],
        "api_hash_candidate" => vec![
            "hash_pattern_scan".to_string(),
            "import_resolution_context".to_string(),
            "static_hash_lookup_pending".to_string(),
        ],
        _ => vec!["pass1_static_evidence".to_string()],
    }
}

fn severity_for_reason(reason: &str) -> String {
    match reason {
        "unresolved_indirect_call" | "api_hash_candidate" => "high",
        "unresolved_indirect_jump" | "malware_relevant_api_flow" => "medium",
        _ => "low",
    }
    .to_string()
}
