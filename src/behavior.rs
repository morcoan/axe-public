use crate::pe::{
    ApiFlowRecord, ApiHashResolutionRecord, BehaviorDossierRecord, BehaviorFeatureRecord,
    RecoveredStringRecord, TypeHintRecord,
};
use std::collections::{BTreeMap, BTreeSet};

pub fn build_behavior_dossiers(
    sha256: &str,
    api_flows: &[ApiFlowRecord],
    recovered_strings: &[RecoveredStringRecord],
    type_hints: &[TypeHintRecord],
    api_hashes: &[ApiHashResolutionRecord],
    budget_name: &str,
) -> Vec<BehaviorDossierRecord> {
    let cap = match budget_name {
        "max" => usize::MAX,
        "high" => 2048,
        _ => 512,
    };
    let mut flows_by_function: BTreeMap<u64, Vec<&ApiFlowRecord>> = BTreeMap::new();
    for flow in api_flows {
        flows_by_function
            .entry(flow.function)
            .or_default()
            .push(flow);
    }
    let strings_by_function = group_recovered_strings(recovered_strings);
    let types_by_function = group_type_hints(type_hints);
    let hashes_by_function = group_api_hashes(api_hashes);

    let mut rows = Vec::new();
    for (function, flows) in flows_by_function {
        for spec in capability_specs() {
            if rows.len() >= cap {
                return rows;
            }
            let matched: Vec<&ApiFlowRecord> = flows
                .iter()
                .copied()
                .filter(|flow| spec.matches(flow))
                .collect();
            if matched.len() < spec.minimum_hits {
                continue;
            }
            let mut features = Vec::new();
            let mut api_flow_ids = Vec::new();
            let mut evidence = BTreeSet::new();
            for flow in matched.iter().take(16) {
                api_flow_ids.push(flow.flow_id.clone());
                for va in &flow.evidence {
                    evidence.insert(*va);
                }
                evidence.insert(flow.callsite);
                features.push(BehaviorFeatureRecord {
                    feature: "api".to_string(),
                    name: flow.normalized_api.clone(),
                    va: Some(flow.callsite),
                    evidence: flow.evidence.clone(),
                });
            }
            let recovered_refs = strings_by_function
                .get(&function)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(8)
                .map(|row| {
                    for va in &row.evidence {
                        evidence.insert(*va);
                    }
                    row.recovered_id.clone()
                })
                .collect::<Vec<_>>();
            let type_refs = types_by_function
                .get(&function)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(8)
                .map(|row| {
                    for va in &row.evidence {
                        evidence.insert(*va);
                    }
                    row.type_id.clone()
                })
                .collect::<Vec<_>>();
            let hash_refs = hashes_by_function
                .get(&function)
                .cloned()
                .unwrap_or_default();
            if !hash_refs.is_empty() && spec.capability == "load-code/runtime-api-resolution" {
                for hash in hash_refs {
                    for va in &hash.evidence {
                        evidence.insert(*va);
                    }
                    features.push(BehaviorFeatureRecord {
                        feature: "api_hash".to_string(),
                        name: hash.resolved_api.clone(),
                        va: hash.site_va,
                        evidence: hash.evidence.clone(),
                    });
                }
            }

            if features.iter().any(|feature| feature.va.is_none()) || evidence.is_empty() {
                continue;
            }
            let evidence_vas: Vec<u64> = evidence.into_iter().collect();
            rows.push(BehaviorDossierRecord {
                behavior_id: format!("beh:{sha}:{function:016X}:{}", rows.len(), sha=&sha256[..sha256.len().min(12)]),
                sample_sha256: sha256.to_string(),
                function,
                capability: spec.capability.to_string(),
                title: spec.title.to_string(),
                supporting_features: features,
                api_flow_ids,
                recovered_string_ids: recovered_refs,
                type_hint_ids: type_refs,
                confidence: confidence_for(&spec, matched.len(), evidence_vas.len()),
                uncertainty: (matched.len() == spec.minimum_hits).then(|| {
                    "minimum evidence threshold met; static-only behavior requires analyst confirmation"
                        .to_string()
                }),
                evidence_vas,
            });
        }
    }

    for hash in api_hashes {
        if rows.len() >= cap {
            break;
        }
        if rows.iter().any(|row| {
            row.function == hash.function && row.capability == "load-code/runtime-api-resolution"
        }) {
            continue;
        }
        if hash.evidence.is_empty() {
            continue;
        }
        rows.push(BehaviorDossierRecord {
            behavior_id: format!(
                "beh:{sha}:{:016X}:{}",
                hash.function,
                rows.len(),
                sha = &sha256[..sha256.len().min(12)]
            ),
            sample_sha256: sha256.to_string(),
            function: hash.function,
            capability: "load-code/runtime-api-resolution".to_string(),
            title: "Runtime API resolution".to_string(),
            supporting_features: vec![BehaviorFeatureRecord {
                feature: "api_hash".to_string(),
                name: hash.resolved_api.clone(),
                va: hash.site_va,
                evidence: hash.evidence.clone(),
            }],
            api_flow_ids: Vec::new(),
            recovered_string_ids: Vec::new(),
            type_hint_ids: Vec::new(),
            evidence_vas: hash.evidence.clone(),
            confidence: 0.82,
            uncertainty: None,
        });
    }

    rows.sort_by(|left, right| {
        left.function
            .cmp(&right.function)
            .then_with(|| left.capability.cmp(&right.capability))
    });
    rows
}

struct CapabilitySpec {
    capability: &'static str,
    title: &'static str,
    categories: &'static [&'static str],
    api_needles: &'static [&'static str],
    minimum_hits: usize,
}

impl CapabilitySpec {
    fn matches(&self, flow: &ApiFlowRecord) -> bool {
        let api = flow.normalized_api.to_ascii_lowercase();
        flow.api_categories
            .iter()
            .any(|category| self.categories.contains(&category.as_str()))
            || self
                .api_needles
                .iter()
                .any(|needle| api.contains(&needle.to_ascii_lowercase()))
    }
}

fn capability_specs() -> Vec<CapabilitySpec> {
    vec![
        CapabilitySpec {
            capability: "host-interaction/process/inject",
            title: "Process injection candidate",
            categories: &["process", "memory", "thread"],
            api_needles: &[
                "virtualallocex",
                "writeprocessmemory",
                "createremotethread",
                "ntcreatethreadex",
            ],
            minimum_hits: 2,
        },
        CapabilitySpec {
            capability: "persistence/registry",
            title: "Registry persistence or configuration",
            categories: &["registry"],
            api_needles: &["regsetvalue", "regcreatekey", "regopenkey"],
            minimum_hits: 1,
        },
        CapabilitySpec {
            capability: "communication/network",
            title: "Network communication",
            categories: &["network"],
            api_needles: &["winhttp", "internet", "connect", "send"],
            minimum_hits: 1,
        },
        CapabilitySpec {
            capability: "data-manipulation/crypto",
            title: "Cryptographic operation",
            categories: &["crypto"],
            api_needles: &["crypt", "bcrypt"],
            minimum_hits: 1,
        },
        CapabilitySpec {
            capability: "anti-analysis/anti-debugging",
            title: "Anti-debugging check",
            categories: &["anti_debug"],
            api_needles: &[
                "isdebuggerpresent",
                "ntqueryinformationprocess",
                "checkremotedebuggerpresent",
            ],
            minimum_hits: 1,
        },
        CapabilitySpec {
            capability: "persistence/service",
            title: "Service control or installation",
            categories: &["service"],
            api_needles: &["createservice", "openscmanager", "startservice"],
            minimum_hits: 1,
        },
        CapabilitySpec {
            capability: "load-code/runtime-api-resolution",
            title: "Runtime API loading or resolution",
            categories: &["module"],
            api_needles: &["loadlibrary", "getprocaddress", "ldrgetprocedureaddress"],
            minimum_hits: 1,
        },
    ]
}

fn confidence_for(spec: &CapabilitySpec, hits: usize, evidence_count: usize) -> f64 {
    let base = if spec.minimum_hits >= 2 { 0.82 } else { 0.72 };
    let bonus = (hits.saturating_sub(spec.minimum_hits).min(3) as f64 * 0.04)
        + (evidence_count.min(6) as f64 * 0.01);
    (base + bonus).min(0.96)
}

fn group_recovered_strings(
    rows: &[RecoveredStringRecord],
) -> BTreeMap<u64, Vec<&RecoveredStringRecord>> {
    let mut map = BTreeMap::new();
    for row in rows {
        map.entry(row.function).or_insert_with(Vec::new).push(row);
    }
    map
}

fn group_type_hints(rows: &[TypeHintRecord]) -> BTreeMap<u64, Vec<&TypeHintRecord>> {
    let mut map = BTreeMap::new();
    for row in rows {
        map.entry(row.function).or_insert_with(Vec::new).push(row);
    }
    map
}

fn group_api_hashes(
    rows: &[ApiHashResolutionRecord],
) -> BTreeMap<u64, Vec<&ApiHashResolutionRecord>> {
    let mut map = BTreeMap::new();
    for row in rows {
        map.entry(row.function).or_insert_with(Vec::new).push(row);
    }
    map
}
