use crate::ir::IrInstruction;
use crate::pe::{ApiFlowRecord, SecondPassTargetRecord, TypeHintRecord};
use crate::winapi;
use std::collections::{BTreeMap, BTreeSet};

#[allow(dead_code)]
pub fn infer_type_hints(api_flows: &[ApiFlowRecord], ir: &[IrInstruction]) -> Vec<TypeHintRecord> {
    let mut rows = Vec::new();
    for flow in api_flows {
        let Some(location) = flow.argument_register.clone() else {
            continue;
        };
        if let Some(type_tag) = winapi_arg_type(&flow.api, &flow.argument, flow.argument_index) {
            rows.push(TypeHintRecord {
                type_id: format!(
                    "type:{:016X}:{:016X}:{}:{}",
                    flow.function,
                    flow.callsite,
                    location,
                    rows.len()
                ),
                function: flow.function,
                site_va: flow.callsite,
                location,
                type_tag,
                source: "winapi_prototype".to_string(),
                confidence: "high".to_string(),
                evidence: flow.evidence.clone(),
            });
        }
        if let Some(return_type) = winapi::prototype(&flow.api).map(|proto| proto.return_type) {
            rows.push(TypeHintRecord {
                type_id: format!(
                    "type:{:016X}:{:016X}:rax:{}",
                    flow.function,
                    flow.callsite,
                    rows.len()
                ),
                function: flow.function,
                site_va: flow.callsite,
                location: "rax".to_string(),
                type_tag: return_type.to_string(),
                source: "winapi_return_prototype".to_string(),
                confidence: "medium".to_string(),
                evidence: flow.evidence.clone(),
            });
        }
    }

    let default_function = api_flows.first().map(|row| row.function).unwrap_or(0);
    for ins in ir {
        if matches!(ins.mnemonic.as_str(), "test" | "cmp")
            && ins.read_regs.iter().any(|reg| reg == "rax" || reg == "eax")
        {
            rows.push(TypeHintRecord {
                type_id: format!("type:{default_function:016X}:{:016X}:HRESULT", ins.address),
                function: default_function,
                site_va: ins.address,
                location: "rax".to_string(),
                type_tag: "HRESULT".to_string(),
                source: "hresult_sign_or_zero_test".to_string(),
                confidence: "low".to_string(),
                evidence: vec![ins.address],
            });
        }
    }

    rows.sort_by(|left, right| {
        left.function
            .cmp(&right.function)
            .then_with(|| left.site_va.cmp(&right.site_va))
            .then_with(|| left.location.cmp(&right.location))
            .then_with(|| left.type_tag.cmp(&right.type_tag))
    });
    rows.dedup_by(|left, right| {
        left.function == right.function
            && left.site_va == right.site_va
            && left.location == right.location
            && left.type_tag == right.type_tag
    });
    rows
}

pub fn infer_type_hints_for_targets(
    api_flows: &[ApiFlowRecord],
    targets: &[SecondPassTargetRecord],
    budget_name: &str,
) -> Vec<TypeHintRecord> {
    let selected: BTreeSet<u64> = targets.iter().map(|row| row.function).collect();
    if selected.is_empty() {
        return Vec::new();
    }
    let per_function_cap = match budget_name {
        "max" => 128,
        "high" => 96,
        _ => 64,
    };
    let mut emitted_by_function: BTreeMap<u64, usize> = BTreeMap::new();
    let mut rows = Vec::new();
    for flow in api_flows {
        if !selected.contains(&flow.function) {
            continue;
        }
        let count = emitted_by_function.entry(flow.function).or_default();
        if *count >= per_function_cap {
            continue;
        }
        let Some(location) = flow.argument_register.clone() else {
            continue;
        };
        if let Some(type_tag) = winapi_arg_type(&flow.api, &flow.argument, flow.argument_index) {
            rows.push(TypeHintRecord {
                type_id: format!(
                    "type:{:016X}:{:016X}:{}:{}",
                    flow.function,
                    flow.callsite,
                    location,
                    rows.len()
                ),
                function: flow.function,
                site_va: flow.callsite,
                location,
                type_tag,
                source: "winapi_prototype".to_string(),
                confidence: "high".to_string(),
                evidence: flow.evidence.clone(),
            });
            *count += 1;
        }
        if *count < per_function_cap {
            if let Some(return_type) = winapi::prototype(&flow.api).map(|proto| proto.return_type) {
                rows.push(TypeHintRecord {
                    type_id: format!(
                        "type:{:016X}:{:016X}:rax:{}",
                        flow.function,
                        flow.callsite,
                        rows.len()
                    ),
                    function: flow.function,
                    site_va: flow.callsite,
                    location: "rax".to_string(),
                    type_tag: return_type.to_string(),
                    source: "winapi_return_prototype".to_string(),
                    confidence: "medium".to_string(),
                    evidence: flow.evidence.clone(),
                });
                *count += 1;
            }
        }
    }
    rows
}

fn winapi_arg_type(api: &str, argument: &str, index: Option<usize>) -> Option<String> {
    if let Some(index) = index {
        if let Some(proto) = winapi::prototype(api) {
            if let Some(tag) = proto.args.get(index) {
                return Some((*tag).to_string());
            }
        }
    }
    let lower_api = api.to_ascii_lowercase();
    let lower_arg = argument.to_ascii_lowercase();
    if lower_api.contains("createfilew") && index == Some(0) {
        return Some("LPCWSTR".to_string());
    }
    if lower_api.contains("createfilea") && index == Some(0) {
        return Some("LPCSTR".to_string());
    }
    if lower_arg.contains("filename") || lower_arg.contains("path") {
        if lower_api.ends_with('w') {
            return Some("LPCWSTR".to_string());
        }
        if lower_api.ends_with('a') {
            return Some("LPCSTR".to_string());
        }
    }
    if lower_arg.contains("handle")
        || lower_arg == "file"
        || lower_api.contains("readfile") && index == Some(0)
        || lower_api.contains("writefile") && index == Some(0)
    {
        return Some("HANDLE".to_string());
    }
    if lower_arg.contains("buffer")
        || lower_arg.contains("base")
        || lower_arg.contains("address")
        || lower_api.contains("virtualalloc")
    {
        return Some("LPVOID".to_string());
    }
    if lower_arg.contains("size") || lower_arg.contains("bytes") {
        return Some("SIZE_T".to_string());
    }
    if lower_arg.contains("flags") || lower_arg.contains("protect") || lower_arg.contains("access")
    {
        return Some("DWORD".to_string());
    }
    None
}
