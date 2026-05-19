use crate::image::BinaryImage;
use crate::ir::IrInstruction;
use crate::pe::{FunctionRecord, ObfuscationHintRecord, RecoveredStringRecord};
use crate::semantic_index::{
    recovered_id, FunctionSemanticIndex, SemanticBudget, SemanticCapsHit, SemanticCounters,
};
use crate::strings::classify_string;
use std::collections::BTreeMap;

pub fn recover_strings(
    _image: &dyn BinaryImage,
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    budget: &SemanticBudget,
    counters: &mut SemanticCounters,
    caps_hit: &mut SemanticCapsHit,
) -> Vec<RecoveredStringRecord> {
    let mut rows = Vec::new();
    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        let mut stores: BTreeMap<i64, (Vec<u8>, Vec<u64>)> = BTreeMap::new();
        for ins in &ir[slice.ir_range.clone()] {
            if ins.mnemonic != "mov" || !ins.memory_write {
                continue;
            }
            let (Some(slot), Some(value)) = (ins.stack_slot, ins.immediate) else {
                continue;
            };
            let bytes = immediate_bytes(value);
            if bytes.iter().all(|byte| *byte == 0) {
                continue;
            }
            if !stores.contains_key(&slot) && stores.len() >= budget.stack_store_slots_per_function
            {
                caps_hit.stack_store_slots = true;
                continue;
            }
            stores
                .entry(slot)
                .or_insert_with(|| (Vec::new(), Vec::new()))
                .0
                .extend(bytes);
            stores
                .entry(slot)
                .or_insert_with(|| (Vec::new(), Vec::new()))
                .1
                .push(ins.address);
        }
        let mut merged = Vec::new();
        let mut evidence = Vec::new();
        for (_slot, (mut bytes, mut ev)) in stores {
            trim_zero_tail(&mut bytes);
            if bytes.len() >= 3 {
                merged.extend(bytes);
                evidence.append(&mut ev);
            }
        }
        if let Some(text) = printable_text(&merged) {
            if text.len() >= 5 {
                let index = rows.len();
                rows.push(RecoveredStringRecord {
                    recovered_id: recovered_id(function.start, "stack_string", index),
                    function: function.start,
                    kind: "stack_string".to_string(),
                    text: text.clone(),
                    tags: classify_string(&text),
                    confidence: "medium".to_string(),
                    evidence,
                });
                counters.stack_strings_recovered += 1;
            }
        }
    }
    rows
}

pub fn packed_or_obfuscated(
    image: &dyn BinaryImage,
    recovered: &[RecoveredStringRecord],
    hints: &[ObfuscationHintRecord],
) -> serde_json::Value {
    let mut reasons = Vec::new();
    let mut obfuscation_hints = Vec::new();
    if image
        .sections()
        .iter()
        .any(|section| section.executable && section.entropy >= 7.2)
    {
        reasons.push("high_entropy_executable_section");
    }
    if image
        .sections()
        .iter()
        .any(|section| section.name.to_ascii_lowercase().contains("upx"))
    {
        reasons.push("upx_section_name");
    }
    if hints
        .iter()
        .any(|row| row.candidate_kind == "api_hash_candidate")
    {
        obfuscation_hints.push("api_hash_constants");
    }
    serde_json::json!({
        "packed_like": !reasons.is_empty(),
        "reasons": reasons,
        "obfuscated_like": !obfuscation_hints.is_empty(),
        "obfuscation_hints": obfuscation_hints,
        "recovered_string_count": recovered.iter().filter(|row| row.kind == "stack_string").count(),
        "obfuscation_hint_count": hints.len(),
    })
}

pub fn obfuscation_hints(
    image: &dyn BinaryImage,
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    budget: &SemanticBudget,
    counters: &mut SemanticCounters,
    caps_hit: &mut SemanticCapsHit,
) -> Vec<ObfuscationHintRecord> {
    let mut rows =
        api_hash_candidates(functions, semantic_index, ir, budget, counters, caps_hit, 0);
    let encoded_start = rows.len();
    rows.extend(encoded_blob_hints(
        image,
        budget,
        counters,
        caps_hit,
        encoded_start,
    ));
    rows
}

fn api_hash_candidates(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    ir: &[IrInstruction],
    budget: &SemanticBudget,
    counters: &mut SemanticCounters,
    caps_hit: &mut SemanticCapsHit,
    start_index: usize,
) -> Vec<ObfuscationHintRecord> {
    let mut rows = Vec::new();
    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        let mut constants = Vec::new();
        let mut evidence = Vec::new();
        let mut has_rotate = false;
        let mut hash_ops = 0usize;
        for ins in &ir[slice.ir_range.clone()] {
            if matches!(ins.mnemonic.as_str(), "ror" | "rol") {
                has_rotate = true;
            }
            if matches!(
                ins.mnemonic.as_str(),
                "imul" | "xor" | "add" | "sub" | "ror" | "rol"
            ) {
                hash_ops += 1;
            }
            if matches!(ins.mnemonic.as_str(), "imul" | "xor" | "add" | "sub")
                && ins.immediate.unwrap_or(0) > 0xffff
            {
                if constants.len() >= budget.api_hash_constants_per_function {
                    caps_hit.api_hash_constants = true;
                    continue;
                }
                constants.push(format!("0x{:X}", ins.immediate.unwrap_or(0)));
                evidence.push(ins.address);
            }
        }
        let import_resolution_context = function.calls_imports.iter().any(|symbol| {
            let lower = symbol.to_ascii_lowercase();
            lower.contains("getprocaddress")
                || lower.contains("loadlibrary")
                || lower.contains("ldrgetprocedureaddress")
        }) || function.strings.iter().any(|text| {
            let lower = text.to_ascii_lowercase();
            lower.contains("kernel32") || lower.contains("ntdll") || lower.contains("advapi32")
        });
        if has_rotate && hash_ops >= 6 && constants.len() >= 2 && import_resolution_context {
            let index = start_index + rows.len();
            rows.push(ObfuscationHintRecord {
                hint_id: recovered_id(function.start, "api_hash_candidate", index),
                function: function.start,
                candidate_kind: "api_hash_candidate".to_string(),
                description: constants.join(","),
                tags: vec!["api_hash".to_string()],
                confidence: "low".to_string(),
                evidence,
                uncertainty_reason:
                    "hash-like arithmetic with import-resolution context; static candidate only"
                        .to_string(),
            });
            counters.api_hash_candidates += 1;
        }
    }
    rows
}

fn encoded_blob_hints(
    image: &dyn BinaryImage,
    budget: &SemanticBudget,
    counters: &mut SemanticCounters,
    caps_hit: &mut SemanticCapsHit,
    start_index: usize,
) -> Vec<ObfuscationHintRecord> {
    let mut rows = Vec::new();
    for section in image.sections() {
        if section.executable || section.entropy < 7.5 || section.data_size < 512 {
            continue;
        }
        if rows.len() >= budget.encoded_blob_hints {
            caps_hit.encoded_blob_hints = true;
            break;
        }
        let index = start_index + rows.len();
        rows.push(ObfuscationHintRecord {
            hint_id: recovered_id(0, "encoded_blob_hint", index),
            function: 0,
            candidate_kind: "encoded_blob_hint".to_string(),
            description: format!("section {} entropy {:.4}", section.name, section.entropy),
            tags: vec!["encoded_blob".to_string()],
            confidence: "low".to_string(),
            evidence: vec![section.va],
            uncertainty_reason: "high entropy non-executable section; static hint only".to_string(),
        });
        counters.encoded_blob_hints += 1;
    }
    rows
}

fn immediate_bytes(value: u64) -> Vec<u8> {
    value
        .to_le_bytes()
        .into_iter()
        .take_while(|byte| *byte != 0)
        .collect()
}

fn trim_zero_tail(bytes: &mut Vec<u8>) {
    while matches!(bytes.last(), Some(0)) {
        bytes.pop();
    }
}

fn printable_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    if bytes
        .iter()
        .all(|byte| *byte == 9 || *byte == 10 || *byte == 13 || (0x20..=0x7e).contains(byte))
    {
        return Some(String::from_utf8_lossy(bytes).to_string());
    }
    None
}
