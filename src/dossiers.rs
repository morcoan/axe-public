use crate::pe::{
    ApiFlowRecord, ApiFlowSummaryRecord, BehaviorDossierRecord, CfgRecord, ClaimEvidenceRecord,
    ClassDossierRecord, FunctionDossierRecord, FunctionQualityRecord, FunctionRecord,
    PseudoIrRecord, RecoveredStringRecord, RecoveredStringSummaryRecord, ResolvedApiSummaryRecord,
    ResolvedCallRecord, StructuredFlowRecord, TypeHintRecord, TypeSummaryRecord, VTableRecord,
};
use crate::semantic_index::{FunctionSemanticIndex, SemanticBudget, SemanticCapsHit};
use crate::strings::{classify_string, import_categories};
use std::collections::{BTreeMap, BTreeSet};

pub fn build_function_dossiers(
    sha256: &str,
    functions: &[FunctionRecord],
    cfg: &[CfgRecord],
    semantic_index: &FunctionSemanticIndex,
    api_flows: &[ApiFlowRecord],
    recovered_strings: &[RecoveredStringRecord],
    resolved_calls: &[ResolvedCallRecord],
    structured_flow: &[StructuredFlowRecord],
    pseudo_ir: &[PseudoIrRecord],
    behavior_dossiers: &[BehaviorDossierRecord],
    type_hints: &[TypeHintRecord],
    class_dossiers: &[ClassDossierRecord],
    semantic_focus: &str,
    budget: &SemanticBudget,
    caps_hit: &mut SemanticCapsHit,
) -> Vec<FunctionDossierRecord> {
    let mut flows_by_function: BTreeMap<u64, Vec<&ApiFlowRecord>> = BTreeMap::new();
    for flow in api_flows {
        flows_by_function
            .entry(flow.function)
            .or_default()
            .push(flow);
    }
    let mut recovered_by_function: BTreeMap<u64, Vec<&RecoveredStringRecord>> = BTreeMap::new();
    for row in recovered_strings {
        recovered_by_function
            .entry(row.function)
            .or_default()
            .push(row);
    }
    let mut resolved_by_function: BTreeMap<u64, Vec<&ResolvedCallRecord>> = BTreeMap::new();
    for row in resolved_calls {
        resolved_by_function
            .entry(row.caller)
            .or_default()
            .push(row);
    }
    let structured_by_function: BTreeMap<u64, &StructuredFlowRecord> = structured_flow
        .iter()
        .map(|row| (row.function, row))
        .collect();
    let pseudo_by_function: BTreeMap<u64, &PseudoIrRecord> =
        pseudo_ir.iter().map(|row| (row.function, row)).collect();
    let mut behaviors_by_function: BTreeMap<u64, Vec<&BehaviorDossierRecord>> = BTreeMap::new();
    for row in behavior_dossiers {
        behaviors_by_function
            .entry(row.function)
            .or_default()
            .push(row);
    }
    let mut types_by_function: BTreeMap<u64, Vec<&TypeHintRecord>> = BTreeMap::new();
    for row in type_hints {
        types_by_function.entry(row.function).or_default().push(row);
    }
    let mut classes_by_method: BTreeMap<u64, Vec<&ClassDossierRecord>> = BTreeMap::new();
    for row in class_dossiers {
        for method in &row.methods {
            classes_by_method.entry(*method).or_default().push(row);
        }
    }
    functions
        .iter()
        .enumerate()
        .map(|(idx, function)| {
            let slice = semantic_index.slices.get(idx);
            let cfg_record =
                slice.and_then(|row| row.cfg_index.and_then(|cfg_idx| cfg.get(cfg_idx)));
            let score = function_score(function);
            let function_flows = flows_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default();
            let mut prioritized_flows = function_flows.clone();
            prioritized_flows.sort_by_key(|flow| {
                (
                    focus_rank(semantic_focus, flow),
                    relevance_rank(&flow.semantic_relevance),
                    tier_rank(&flow.api_tier),
                    flow.callsite,
                )
            });
            let deobfuscation = recovered_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default();
            if function_flows.len() > budget.dossier_links_per_function
                || deobfuscation.len() > budget.dossier_links_per_function
            {
                caps_hit.dossier_links = true;
            }
            let api_flow_ids: Vec<String> = function_flows
                .iter()
                .take(budget.dossier_links_per_function)
                .map(|flow| flow.flow_id.clone())
                .collect();
            let recovered_string_ids: Vec<String> = deobfuscation
                .iter()
                .take(budget.dossier_links_per_function)
                .map(|row| row.recovered_id.clone())
                .collect();
            let api_flow_summaries: Vec<ApiFlowSummaryRecord> = prioritized_flows
                .iter()
                .take(budget.dossier_summaries_per_function)
                .map(|flow| ApiFlowSummaryRecord {
                    flow_id: flow.flow_id.clone(),
                    callsite: flow.callsite,
                    api: flow.normalized_api.clone(),
                    value: flow.value.chars().take(160).collect(),
                    value_tags: flow.value_tags.iter().take(8).cloned().collect(),
                    argument: flow.argument.clone(),
                    confidence: flow.confidence.clone(),
                    mode: flow.mode.clone(),
                })
                .collect();
            let recovered_string_summaries: Vec<RecoveredStringSummaryRecord> = deobfuscation
                .iter()
                .take(budget.dossier_summaries_per_function)
                .map(|row| RecoveredStringSummaryRecord {
                    recovered_id: row.recovered_id.clone(),
                    kind: row.kind.clone(),
                    text: row.text.chars().take(160).collect(),
                    tags: row.tags.iter().take(8).cloned().collect(),
                    confidence: row.confidence.clone(),
                })
                .collect();
            let semantic_tags = semantic_tags(function, &function_flows, &deobfuscation);
            let resolved_api_summaries: Vec<ResolvedApiSummaryRecord> = resolved_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(16)
                .map(|row| ResolvedApiSummaryRecord {
                    callsite: row.callsite,
                    resolved_api: row.resolved_api.clone(),
                    chain_depth: row.chain_depth,
                    confidence: row.confidence.clone(),
                })
                .collect();
            let side_effects = side_effects(&prioritized_flows);
            let inputs = inputs(&prioritized_flows);
            let outputs = outputs(function, &prioritized_flows);
            let pseudo_ir_id = pseudo_by_function
                .get(&function.start)
                .map(|row| row.pseudo_ir_id.clone());
            let structured_flow_id = structured_by_function
                .get(&function.start)
                .map(|row| row.structured_flow_id.clone());
            let intent_summary =
                intent_summary(function, &prioritized_flows, &resolved_api_summaries);
            let behavior_refs: Vec<String> = behaviors_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(16)
                .map(|row| row.behavior_id.clone())
                .collect();
            let type_summaries: Vec<TypeSummaryRecord> = types_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(16)
                .map(|row| TypeSummaryRecord {
                    type_id: row.type_id.clone(),
                    location: row.location.clone(),
                    type_tag: row.type_tag.clone(),
                    confidence: row.confidence.clone(),
                })
                .collect();
            let class_refs: Vec<String> = classes_by_method
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(8)
                .map(|row| row.class_id.clone())
                .collect();
            let mut claim_evidence = Vec::new();
            for behavior in behaviors_by_function
                .get(&function.start)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(8)
            {
                claim_evidence.push(ClaimEvidenceRecord {
                    claim: behavior.title.clone(),
                    evidence_vas: behavior.evidence_vas.iter().copied().take(16).collect(),
                    confidence: format!("{:.2}", behavior.confidence),
                });
            }
            if let Some(pseudo) = pseudo_by_function.get(&function.start) {
                if !pseudo.evidence.is_empty() {
                    claim_evidence.push(ClaimEvidenceRecord {
                        claim: "pseudo-IR summary is backed by static evidence".to_string(),
                        evidence_vas: pseudo.evidence.iter().copied().take(16).collect(),
                        confidence: pseudo.confidence.clone(),
                    });
                }
            }
            let dossier_quality = dossier_quality(
                &claim_evidence,
                &type_summaries,
                &behavior_refs,
                &class_refs,
            );
            FunctionDossierRecord {
                id: format!(
                    "{}:{:016x}",
                    &sha256[..sha256.len().min(16)],
                    function.start
                ),
                sample_sha256: sha256.to_string(),
                function: function.start,
                end: function.end,
                size: function.size,
                source: function.source.clone(),
                score,
                confidence: if ["pdata", "entry", "export"].contains(&function.source.as_str()) {
                    "medium".to_string()
                } else {
                    "low".to_string()
                },
                calls: function.calls.iter().copied().take(128).collect(),
                imports: function.calls_imports.iter().take(128).cloned().collect(),
                strings: function.strings.iter().take(128).cloned().collect(),
                xrefs: function.xrefs,
                cfg_blocks: cfg_record.map(|row| row.blocks.len()).unwrap_or(0),
                cfg_edges: cfg_record.map(|row| row.edges.len()).unwrap_or(0),
                tags: function_tags(function),
                semantic_tags: semantic_tags.clone(),
                behavior_summary: behavior_summary(function, &semantic_tags, &function_flows),
                intent_summary,
                side_effects,
                inputs,
                outputs,
                resolved_api_summaries,
                pseudo_ir_id,
                structured_flow_id,
                api_flow_ids,
                api_flow_summaries,
                recovered_string_ids,
                recovered_string_summaries,
                behavior_refs,
                type_summaries,
                class_refs,
                claim_evidence,
                dossier_quality,
                function_quality: function_quality(function, slice),
            }
        })
        .collect()
}

pub fn interesting_functions(dossiers: &[FunctionDossierRecord]) -> Vec<FunctionDossierRecord> {
    let mut rows = dossiers.to_vec();
    rows.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.function.cmp(&right.function))
    });
    rows.truncate(500);
    rows
}

pub fn build_class_dossiers(vtables: &[VTableRecord]) -> Vec<ClassDossierRecord> {
    vtables
        .iter()
        .map(|table| ClassDossierRecord {
            class_id: format!("class:{:016X}", table.va),
            vtable: table.va,
            vftable_va: table.va,
            probable_class: table.probable_class.clone(),
            base_classes: table.base_classes.clone(),
            method_count: table.method_count,
            methods: table.methods.clone(),
            constructors: table.constructor_candidates.clone(),
            col_va: table.col_va,
            ownership_confidence: table.ownership_confidence.clone(),
            confidence: if table.probable_class.is_some() {
                "medium".to_string()
            } else {
                "low".to_string()
            },
        })
        .collect()
}

fn dossier_quality(
    evidence: &[ClaimEvidenceRecord],
    types: &[TypeSummaryRecord],
    behaviors: &[String],
    classes: &[String],
) -> String {
    if !evidence.is_empty() && (!types.is_empty() || !behaviors.is_empty() || !classes.is_empty()) {
        "evidence_backed".to_string()
    } else if !evidence.is_empty() {
        "basic_evidence".to_string()
    } else {
        "low_context".to_string()
    }
}

pub fn flow_summary(flows: &[ApiFlowRecord]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for flow in flows {
        for category in &flow.api_categories {
            *counts.entry(category.clone()).or_insert(0) += 1;
        }
    }
    counts
}

fn function_score(function: &FunctionRecord) -> i64 {
    (function.calls_imports.len() as i64 * 8)
        + (function.strings.len() as i64 * 3)
        + function.calls.len() as i64
        + function.xrefs.min(25) as i64
}

fn function_tags(function: &FunctionRecord) -> Vec<String> {
    let mut tags = BTreeSet::new();
    for symbol in &function.calls_imports {
        for tag in import_categories(symbol) {
            tags.insert(tag);
        }
    }
    for text in &function.strings {
        for tag in classify_string(text) {
            tags.insert(tag);
        }
    }
    tags.into_iter().collect()
}

fn relevance_rank(value: &str) -> u8 {
    match value {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    }
}

fn focus_rank(focus: &str, flow: &ApiFlowRecord) -> u8 {
    match focus {
        "all" => 0,
        "os" => {
            if flow.api_tier == "os_api" {
                0
            } else {
                1
            }
        }
        "malware" => {
            if flow.api_tier == "os_api" && flow.semantic_relevance == "high" {
                0
            } else if flow.api_tier == "os_api" {
                1
            } else if flow.api_tier == "internal_api" && flow.semantic_relevance != "low" {
                2
            } else if flow.semantic_relevance == "high" {
                3
            } else {
                4
            }
        }
        _ => 0,
    }
}

fn tier_rank(value: &str) -> u8 {
    match value {
        "os_api" => 0,
        "internal_api" => 1,
        _ => 2,
    }
}

fn side_effects(flows: &[&ApiFlowRecord]) -> Vec<String> {
    let mut rows = BTreeSet::new();
    for flow in flows {
        if flow.semantic_relevance == "low" {
            continue;
        }
        rows.insert(format!("{}:{}", flow.api_tier, flow.api_family));
    }
    rows.into_iter().take(16).collect()
}

fn inputs(flows: &[&ApiFlowRecord]) -> Vec<String> {
    let mut rows = BTreeSet::new();
    for flow in flows {
        if flow.value.is_empty() || flow.semantic_relevance == "low" {
            continue;
        }
        rows.insert(format!(
            "{}={}",
            flow.argument,
            flow.value.chars().take(120).collect::<String>()
        ));
    }
    rows.into_iter().take(16).collect()
}

fn outputs(function: &FunctionRecord, flows: &[&ApiFlowRecord]) -> Vec<String> {
    let mut rows = BTreeSet::new();
    if !flows.is_empty() {
        rows.insert("api_call_side_effects".to_string());
    }
    if !function.calls.is_empty() {
        rows.insert("local_call_results_unknown".to_string());
    }
    rows.into_iter().collect()
}

fn intent_summary(
    function: &FunctionRecord,
    flows: &[&ApiFlowRecord],
    resolved: &[ResolvedApiSummaryRecord],
) -> String {
    if let Some(flow) = flows.iter().find(|flow| flow.semantic_relevance == "high") {
        return format!(
            "Function 0x{:016X} passes recovered {} value into {} ({})",
            function.start, flow.argument, flow.normalized_api, flow.api_family
        );
    }
    if let Some(call) = resolved.first() {
        return format!(
            "Function 0x{:016X} calls wrapper resolved to {}",
            function.start, call.resolved_api
        );
    }
    if !flows.is_empty() {
        return format!(
            "Function 0x{:016X} has API argument evidence, mostly low-priority runtime/internal calls",
            function.start
        );
    }
    format!(
        "Function 0x{:016X} has no high-confidence semantic intent recovered",
        function.start
    )
}

fn semantic_tags(
    function: &FunctionRecord,
    flows: &[&ApiFlowRecord],
    recovered: &[&RecoveredStringRecord],
) -> Vec<String> {
    let mut tags = BTreeSet::new();
    for tag in function_tags(function) {
        tags.insert(tag);
    }
    for flow in flows {
        for tag in &flow.api_categories {
            tags.insert(tag.clone());
        }
        for tag in &flow.value_tags {
            tags.insert(tag.clone());
        }
    }
    for row in recovered {
        tags.insert(row.kind.clone());
        for tag in &row.tags {
            tags.insert(tag.clone());
        }
    }
    tags.into_iter().collect()
}

fn behavior_summary(
    function: &FunctionRecord,
    semantic_tags: &[String],
    flows: &[&ApiFlowRecord],
) -> String {
    if flows.iter().any(|flow| flow.mode == "proven") {
        let apis: Vec<String> = flows
            .iter()
            .filter(|flow| flow.mode == "proven")
            .map(|flow| flow.api.clone())
            .take(5)
            .collect();
        return format!(
            "Evidence-backed API argument flow in function 0x{:016X}: {}",
            function.start,
            apis.join(", ")
        );
    }
    if !semantic_tags.is_empty() {
        return format!(
            "Heuristic semantic signals in function 0x{:016X}: {}",
            function.start,
            semantic_tags
                .iter()
                .take(8)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    format!(
        "No high-signal semantic behavior recovered for function 0x{:016X}",
        function.start
    )
}

fn function_quality(
    function: &FunctionRecord,
    slice: Option<&crate::semantic_index::FunctionSemanticSlice>,
) -> FunctionQualityRecord {
    let has_return = slice.map(|row| row.has_return).unwrap_or(false);
    let overlaps_known_function = slice
        .map(|row| row.overlaps_known_function)
        .unwrap_or(false);
    let has_pdata = function.source == "pdata";
    FunctionQualityRecord {
        boundary_source: function.source.clone(),
        has_pdata,
        has_return,
        overlaps_known_function,
        confidence: if has_pdata && !overlaps_known_function {
            "high".to_string()
        } else if has_return && !overlaps_known_function {
            "medium".to_string()
        } else {
            "low".to_string()
        },
    }
}
