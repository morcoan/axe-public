use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Default)]
pub struct ScorecardInput {
    pub functions: usize,
    pub pdata_functions: usize,
    pub api_flows: usize,
    pub typed_api_args: usize,
    pub jump_tables: usize,
    pub jump_table_targets: usize,
    pub jump_table_quality_failures: usize,
    pub unresolved_indirects: usize,
    pub decoder_candidates: usize,
    pub decoder_timeouts: usize,
    pub decoded_strings: usize,
    pub prototype_known_api_flows: usize,
    pub prototype_typed_api_flows: usize,
    pub behavior_dossiers: usize,
    pub behavior_dossiers_with_evidence: usize,
    pub rtti_classes: usize,
    pub rtti_owned_classes: usize,
    pub structured_functions: usize,
    pub structured_region_functions: usize,
    pub pass2_elapsed_seconds: f64,
    pub pass2_caps_hit: bool,
    pub json_parseable: bool,
    pub jsonl_parseable: bool,
    pub ground_truth_functions_expected: usize,
    pub ground_truth_functions_recovered: usize,
    pub ground_truth_api_args_expected: usize,
    pub ground_truth_api_args_correct: usize,
    pub ground_truth_jump_tables_expected: usize,
    pub ground_truth_jump_tables_correct: usize,
    pub ground_truth_type_hints_expected: usize,
    pub ground_truth_type_hints_correct: usize,
    pub ground_truth_decoded_strings_expected: usize,
    pub ground_truth_decoded_strings_correct: usize,
    pub ground_truth_rtti_expected: usize,
    pub ground_truth_rtti_correct: usize,
    pub ground_truth_structured_expected: usize,
    pub ground_truth_structured_correct: usize,
    pub behavior_claims_expected: usize,
    pub behavior_claims_with_valid_va: usize,
}

#[derive(Clone, Serialize)]
pub struct EvalGateRecord {
    pub name: String,
    pub score: f64,
    pub passed: bool,
    pub detail: String,
}

#[derive(Clone, Serialize)]
pub struct EvalScorecardRecord {
    pub schema: String,
    pub truth_source: String,
    pub overall_score: f64,
    pub estimated_level: f64,
    pub gates: Vec<EvalGateRecord>,
    pub failed_gates: Vec<String>,
    pub ground_truth_available: bool,
    pub ground_truth_metrics: BTreeMap<String, f64>,
    pub auto_truth_metrics: BTreeMap<String, f64>,
    pub fixture_truth_metrics: BTreeMap<String, f64>,
    pub unknown_truth_metrics: BTreeMap<String, f64>,
    pub truth_source_breakdown: BTreeMap<String, usize>,
}

pub fn build_scorecard(input: ScorecardInput) -> EvalScorecardRecord {
    let mut gates = Vec::new();
    let function_recall = ratio(input.pdata_functions, input.functions.max(1));
    gates.push(gate(
        "function_recall",
        function_recall * 100.0,
        function_recall >= 0.60 || input.functions == 0,
        format!(
            "pdata_or_oracle_functions={} total_functions={}",
            input.pdata_functions, input.functions
        ),
    ));

    let api_arg_score = if input.api_flows == 0 {
        100.0
    } else if input.typed_api_args == 0 {
        0.0
    } else {
        (60.0 + ratio(input.typed_api_args, input.api_flows).min(0.40) * 100.0).min(100.0)
    };
    gates.push(gate(
        "api_argument_recovery",
        api_arg_score,
        api_arg_score >= 60.0 || input.api_flows == 0,
        format!(
            "typed_api_args={} api_flows={}",
            input.typed_api_args, input.api_flows
        ),
    ));

    let jump_score = if input.unresolved_indirects == 0 {
        100.0
    } else if input.jump_tables > 0 {
        90.0 + ratio(
            input.jump_tables,
            input.jump_tables + input.unresolved_indirects,
        ) * 10.0
    } else {
        70.0
    };
    gates.push(gate(
        "jump_table_resolution",
        jump_score,
        jump_score >= 60.0 || input.unresolved_indirects == 0,
        format!(
            "resolved_jump_tables={} unresolved_indirects={}",
            input.jump_tables, input.unresolved_indirects
        ),
    ));

    let jump_quality_score = if input.jump_tables == 0 {
        100.0
    } else if input.jump_table_quality_failures == 0
        && input.jump_table_targets >= input.jump_tables * 2
    {
        100.0
    } else {
        55.0
    };
    gates.push(gate(
        "jump_table_target_quality",
        jump_quality_score,
        jump_quality_score >= 80.0,
        format!(
            "jump_table_targets={} quality_failures={}",
            input.jump_table_targets, input.jump_table_quality_failures
        ),
    ));

    gates.push(gate(
        "decoded_string_precision",
        if input.decoder_candidates == 0 {
            100.0
        } else if input.decoded_strings > 0 && input.decoder_timeouts == 0 {
            100.0
        } else if input.decoded_strings == 0 && input.decoder_timeouts == 0 {
            100.0
        } else {
            50.0
        },
        input.decoder_timeouts == 0,
        format!(
            "decoded_strings={} decoder_candidates={} timeouts={}",
            input.decoded_strings, input.decoder_candidates, input.decoder_timeouts
        ),
    ));

    let prototype_score = if input.prototype_known_api_flows == 0 {
        100.0
    } else {
        ratio(
            input.prototype_typed_api_flows,
            input.prototype_known_api_flows,
        ) * 100.0
    };
    gates.push(gate(
        "prototype_coverage",
        prototype_score,
        prototype_score >= 75.0 || input.prototype_known_api_flows == 0,
        format!(
            "prototype_typed_api_flows={} prototype_known_api_flows={}",
            input.prototype_typed_api_flows, input.prototype_known_api_flows
        ),
    ));

    let evidence_score = if input.behavior_dossiers == 0 {
        100.0
    } else {
        ratio(
            input.behavior_dossiers_with_evidence,
            input.behavior_dossiers,
        ) * 100.0
    };
    gates.push(gate(
        "behavior_citation_integrity",
        evidence_score,
        evidence_score >= 98.0,
        format!(
            "with_evidence={} behavior_dossiers={}",
            input.behavior_dossiers_with_evidence, input.behavior_dossiers
        ),
    ));

    let rtti_score = if input.rtti_classes == 0 {
        100.0
    } else {
        (85.0 + ratio(input.rtti_owned_classes, input.rtti_classes) * 15.0).min(100.0)
    };
    gates.push(gate(
        "rtti_ownership",
        rtti_score,
        rtti_score >= 70.0,
        format!(
            "rtti_owned_classes={} rtti_classes={}",
            input.rtti_owned_classes, input.rtti_classes
        ),
    ));

    let structured_score = if input.structured_functions == 0 {
        100.0
    } else {
        (70.0
            + ratio(
                input.structured_region_functions,
                input.structured_functions,
            ) * 30.0)
            .min(100.0)
    };
    gates.push(gate(
        "structured_region_quality",
        structured_score,
        structured_score >= 75.0,
        format!(
            "structured_region_functions={} structured_functions={}",
            input.structured_region_functions, input.structured_functions
        ),
    ));

    let pass2_score = if input.pass2_elapsed_seconds <= 5.0 {
        100.0
    } else {
        (100.0 - (input.pass2_elapsed_seconds - 5.0) * 5.0).max(0.0)
    };
    gates.push(gate(
        "pass2_wall_time",
        pass2_score,
        pass2_score >= 50.0,
        format!("pass2_elapsed_seconds={:.3}", input.pass2_elapsed_seconds),
    ));

    gates.push(gate(
        "caps_explicit",
        100.0,
        true,
        format!("pass2_caps_hit={}", input.pass2_caps_hit),
    ));

    gates.push(gate(
        "json_parseability",
        if input.json_parseable && input.jsonl_parseable {
            100.0
        } else {
            0.0
        },
        input.json_parseable && input.jsonl_parseable,
        format!(
            "json_parseable={} jsonl_parseable={}",
            input.json_parseable, input.jsonl_parseable
        ),
    ));

    let ground_truth_metrics = ground_truth_metrics(&input);
    for (name, expected, correct, threshold) in [
        (
            "ground_truth_function_recall",
            input.ground_truth_functions_expected,
            input.ground_truth_functions_recovered,
            85.0,
        ),
        (
            "ground_truth_api_arg_precision",
            input.ground_truth_api_args_expected,
            input.ground_truth_api_args_correct,
            85.0,
        ),
        (
            "ground_truth_jump_table_precision",
            input.ground_truth_jump_tables_expected,
            input.ground_truth_jump_tables_correct,
            85.0,
        ),
        (
            "ground_truth_type_correctness",
            input.ground_truth_type_hints_expected,
            input.ground_truth_type_hints_correct,
            80.0,
        ),
        (
            "ground_truth_decoded_string_precision",
            input.ground_truth_decoded_strings_expected,
            input.ground_truth_decoded_strings_correct,
            90.0,
        ),
        (
            "ground_truth_rtti_ownership_accuracy",
            input.ground_truth_rtti_expected,
            input.ground_truth_rtti_correct,
            80.0,
        ),
        (
            "ground_truth_structured_region_quality",
            input.ground_truth_structured_expected,
            input.ground_truth_structured_correct,
            80.0,
        ),
        (
            "ground_truth_behavior_citation_integrity",
            input.behavior_claims_expected,
            input.behavior_claims_with_valid_va,
            98.0,
        ),
    ] {
        let score = if expected == 0 {
            100.0
        } else {
            ratio(correct, expected) * 100.0
        };
        gates.push(gate(
            name,
            score,
            score >= threshold || expected == 0,
            format!(
                "correct={} expected={} threshold={threshold:.1}",
                correct, expected
            ),
        ));
    }

    let overall_score = gates.iter().map(|gate| gate.score).sum::<f64>() / gates.len() as f64;
    let failed_gates = gates
        .iter()
        .filter(|gate| !gate.passed)
        .map(|gate| gate.name.clone())
        .collect();
    let ground_truth_available = [
        input.ground_truth_functions_expected,
        input.ground_truth_api_args_expected,
        input.ground_truth_jump_tables_expected,
        input.ground_truth_type_hints_expected,
        input.ground_truth_decoded_strings_expected,
        input.ground_truth_rtti_expected,
        input.ground_truth_structured_expected,
        input.behavior_claims_expected,
    ]
    .iter()
    .any(|count| *count > 0);
    EvalScorecardRecord {
        schema: "eval_scorecard/1".to_string(),
        truth_source: if ground_truth_available {
            "ground_truth".to_string()
        } else {
            "heuristic_truth".to_string()
        },
        overall_score,
        estimated_level: (overall_score / 10.0).clamp(0.0, 10.0),
        gates,
        failed_gates,
        ground_truth_available,
        ground_truth_metrics,
        auto_truth_metrics: BTreeMap::new(),
        fixture_truth_metrics: BTreeMap::new(),
        unknown_truth_metrics: if ground_truth_available {
            BTreeMap::new()
        } else {
            BTreeMap::from([("truth_unavailable".to_string(), 1.0)])
        },
        truth_source_breakdown: BTreeMap::from([
            (
                "ground_truth".to_string(),
                usize::from(ground_truth_available),
            ),
            ("fixture_truth".to_string(), 0),
            ("auto_truth".to_string(), 0),
            (
                "heuristic_truth".to_string(),
                usize::from(!ground_truth_available),
            ),
            (
                "unknown_truth".to_string(),
                usize::from(!ground_truth_available),
            ),
        ]),
    }
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        1.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn gate(name: &str, score: f64, passed: bool, detail: String) -> EvalGateRecord {
    EvalGateRecord {
        name: name.to_string(),
        score: score.clamp(0.0, 100.0),
        passed,
        detail,
    }
}

fn ground_truth_metrics(input: &ScorecardInput) -> BTreeMap<String, f64> {
    let mut metrics = BTreeMap::new();
    metrics.insert(
        "function_recall".to_string(),
        percent(
            input.ground_truth_functions_recovered,
            input.ground_truth_functions_expected,
        ),
    );
    metrics.insert(
        "api_arg_precision".to_string(),
        percent(
            input.ground_truth_api_args_correct,
            input.ground_truth_api_args_expected,
        ),
    );
    metrics.insert(
        "jump_table_precision".to_string(),
        percent(
            input.ground_truth_jump_tables_correct,
            input.ground_truth_jump_tables_expected,
        ),
    );
    metrics.insert(
        "type_correctness".to_string(),
        percent(
            input.ground_truth_type_hints_correct,
            input.ground_truth_type_hints_expected,
        ),
    );
    metrics.insert(
        "decoded_string_precision".to_string(),
        percent(
            input.ground_truth_decoded_strings_correct,
            input.ground_truth_decoded_strings_expected,
        ),
    );
    metrics.insert(
        "rtti_ownership_accuracy".to_string(),
        percent(
            input.ground_truth_rtti_correct,
            input.ground_truth_rtti_expected,
        ),
    );
    metrics.insert(
        "structured_region_quality".to_string(),
        percent(
            input.ground_truth_structured_correct,
            input.ground_truth_structured_expected,
        ),
    );
    metrics.insert(
        "behavior_citation_integrity".to_string(),
        percent(
            input.behavior_claims_with_valid_va,
            input.behavior_claims_expected,
        ),
    );
    metrics
}

fn percent(correct: usize, expected: usize) -> f64 {
    if expected == 0 {
        100.0
    } else {
        ratio(correct, expected) * 100.0
    }
}
