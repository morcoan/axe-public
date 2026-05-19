use crate::pe::{FunctionRecord, ResolvedCallRecord, XrefRecord};
use crate::semantic_index::FunctionSemanticIndex;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
enum WrapperTarget {
    Import(String),
    Function(u64),
}

pub fn resolve_calls(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    xrefs: &[XrefRecord],
    max_depth: usize,
) -> Vec<ResolvedCallRecord> {
    let wrappers = discover_wrappers(functions, semantic_index, xrefs);
    let mut rows = Vec::new();
    for slice in &semantic_index.slices {
        let Some(caller) = functions.get(slice.function_index) else {
            continue;
        };
        for xref in &xrefs[slice.xref_range.clone()] {
            if xref.kind != "code" || xref.role != "call" {
                continue;
            }
            if let Some((resolved_api, wrapper_chain)) =
                resolve_target(xref.target, &wrappers, max_depth)
            {
                rows.push(ResolvedCallRecord {
                    caller: caller.start,
                    callsite: xref.from,
                    original_callee: xref.target,
                    chain_depth: wrapper_chain.len(),
                    resolved_api,
                    wrapper_chain,
                    confidence: "high".to_string(),
                    resolution_kind: Some("wrapper_collapse".to_string()),
                    class_id: None,
                    vtable_va: None,
                    vtable_slot: None,
                    target: None,
                    candidate_targets: Vec::new(),
                    candidate_classes: Vec::new(),
                });
            }
        }
    }
    rows
}

fn discover_wrappers(
    functions: &[FunctionRecord],
    semantic_index: &FunctionSemanticIndex,
    xrefs: &[XrefRecord],
) -> BTreeMap<u64, WrapperTarget> {
    let mut wrappers = BTreeMap::new();
    for slice in &semantic_index.slices {
        let Some(function) = functions.get(slice.function_index) else {
            continue;
        };
        let calls: Vec<&XrefRecord> = xrefs[slice.xref_range.clone()]
            .iter()
            .filter(|xref| xref.role == "call" || xref.role == "branch")
            .collect();
        if calls.len() != 1 {
            continue;
        }
        let call = calls[0];
        if call.kind == "import" {
            if let Some(symbol) = &call.symbol {
                wrappers.insert(function.start, WrapperTarget::Import(symbol.clone()));
            }
        } else if call.kind == "code" {
            wrappers.insert(function.start, WrapperTarget::Function(call.target));
        }
    }
    wrappers
}

fn resolve_target(
    target: u64,
    wrappers: &BTreeMap<u64, WrapperTarget>,
    max_depth: usize,
) -> Option<(String, Vec<u64>)> {
    let mut chain = Vec::new();
    let mut current = target;
    let mut seen = BTreeSet::new();
    for _ in 0..max_depth {
        if !seen.insert(current) {
            return None;
        }
        match wrappers.get(&current)? {
            WrapperTarget::Import(symbol) => {
                chain.push(current);
                return Some((symbol.clone(), chain));
            }
            WrapperTarget::Function(next) => {
                chain.push(current);
                current = *next;
            }
        }
    }
    None
}
