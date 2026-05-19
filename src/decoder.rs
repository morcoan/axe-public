use crate::pe::{ObfuscationHintRecord, RecoveredStringRecord};
use crate::semantic_index::recovered_id;
use crate::strings::classify_string;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct DecodedTransform {
    pub text: String,
    pub operation: String,
    pub key: u8,
    pub steps: usize,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct DecodeError {
    pub reason: String,
    pub steps: usize,
}

#[allow(dead_code)]
pub fn decode_xor_ascii(bytes: &[u8], key: u8, step_cap: usize) -> Option<String> {
    let decoded: Vec<u8> = bytes.iter().take(step_cap).map(|byte| byte ^ key).collect();
    printable_ascii(&decoded)
}

pub fn decode_transform_ascii(
    bytes: &[u8],
    operation: &str,
    key: u8,
    step_cap: usize,
) -> Result<DecodedTransform, DecodeError> {
    if bytes.len() > step_cap {
        return Err(DecodeError {
            reason: "timeout".to_string(),
            steps: step_cap,
        });
    }
    let decoded: Vec<u8> = bytes
        .iter()
        .map(|byte| match operation {
            "xor" => byte ^ key,
            "add" => byte.wrapping_sub(key),
            "sub" => byte.wrapping_add(key),
            "rol" => byte.rotate_right((key & 7) as u32),
            "ror" => byte.rotate_left((key & 7) as u32),
            _ => *byte,
        })
        .collect();
    let Some(text) = printable_ascii(&decoded) else {
        return Err(DecodeError {
            reason: "non_printable".to_string(),
            steps: bytes.len(),
        });
    };
    Ok(DecodedTransform {
        text,
        operation: operation.to_string(),
        key,
        steps: bytes.len(),
    })
}

pub fn recover_decoded_strings(
    image: &dyn crate::image::BinaryImage,
    hints: &[ObfuscationHintRecord],
    budget_name: &str,
) -> Vec<RecoveredStringRecord> {
    let cap = match budget_name {
        "max" => 512,
        "high" => 128,
        _ => 32,
    };
    let mut rows = Vec::new();
    for hint in hints
        .iter()
        .filter(|row| row.candidate_kind == "encoded_blob_hint")
    {
        if rows.len() >= cap {
            break;
        }
        let Some(section_va) = hint.evidence.first().copied() else {
            continue;
        };
        let Some(section) = image.section_for_va(section_va) else {
            continue;
        };
        let data = section.data(image.bytes());
        let window = &data[..data.len().min(4096)];
        if let Some(decoded) = best_transform(window, 4096) {
            let index = rows.len();
            rows.push(RecoveredStringRecord {
                recovered_id: recovered_id(hint.function, "decoded_string", index),
                function: hint.function,
                kind: if hint.function == 0 {
                    "decoded_string".to_string()
                } else {
                    "tight_string".to_string()
                },
                text: decoded.text.clone(),
                tags: classify_string(&decoded.text),
                confidence: "medium".to_string(),
                evidence: vec![section_va, decoded.key as u64, decoded.steps as u64],
            });
        }
    }
    rows
}

fn best_transform(bytes: &[u8], step_cap: usize) -> Option<DecodedTransform> {
    ["xor", "add", "sub", "rol", "ror"]
        .into_iter()
        .flat_map(|operation| {
            (1_u8..=255).filter_map(move |key| {
                decode_transform_ascii(bytes.get(..bytes.len().min(512))?, operation, key, step_cap)
                    .ok()
            })
        })
        .filter(|decoded| decoded.text.len() >= 5)
        .max_by_key(|decoded| printable_score(&decoded.text))
}

fn printable_ascii(bytes: &[u8]) -> Option<String> {
    let trimmed = trim_nul_tail(bytes);
    if trimmed.len() < 5 {
        return None;
    }
    if trimmed.iter().all(|byte| {
        *byte == b'\t' || *byte == b'\n' || *byte == b'\r' || (0x20..=0x7e).contains(byte)
    }) {
        return Some(String::from_utf8_lossy(trimmed).to_string());
    }
    None
}

fn trim_nul_tail(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len();
    while end > 0 && bytes[end - 1] == 0 {
        end -= 1;
    }
    &bytes[..end]
}

fn printable_score(text: &str) -> usize {
    text.bytes()
        .filter(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(*byte, b'.' | b'_' | b'/' | b'\\' | b':' | b'-')
        })
        .count()
}
