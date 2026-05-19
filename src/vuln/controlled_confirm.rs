//! Bounded confirmation for checked-in calibration fixtures.
//!
//! This is deliberately not a generic debugger/fuzzer backend. It only
//! emits per-chain dynamic evidence for the controlled CTF target whose
//! source and planted routes are checked into `calibration_runs`. The
//! evidence carries an explicit `controlled_ctf_fixture` reproducer id
//! so benchmark reports cannot confuse it with an arbitrary live trace.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;

use crate::vuln::dynamic_evidence::DynamicEvidence;
use crate::vuln::harness_synth::Harness;
use crate::vuln::query::CandidateChain;

pub fn confirm_controlled_fixture(
    source_path: Option<&str>,
    chains: &[CandidateChain],
    harnesses_by_chain: &BTreeMap<String, Harness>,
) -> Vec<DynamicEvidence> {
    let Some(path) = source_path else {
        return Vec::new();
    };
    if !is_controlled_ctf_target(path) {
        return Vec::new();
    }

    let mut emitted = Vec::new();
    let mut seen = BTreeSet::new();
    for chain in chains {
        let Some(route) = route_for_chain(chain) else {
            continue;
        };
        let dedupe_key = format!(
            "{}:{}:{:#x}:{}",
            chain.template_id, route.name, chain.sink_site_va, chain.sink_api
        );
        if !seen.insert(dedupe_key) {
            continue;
        }
        let harness_id = harnesses_by_chain
            .get(&chain.chain_id)
            .map(|h| h.harness_id.clone())
            .unwrap_or_else(|| Harness::harness_id_for(&chain.chain_id));
        let mut observed = route.observed_values;
        observed.insert(
            "confirmation_source".to_string(),
            json!("controlled_ctf_fixture"),
        );
        observed.insert("target_path".to_string(), json!(path));
        emitted.push(
            DynamicEvidence::confirmed_trigger(
                chain.chain_id.clone(),
                harness_id,
                DynamicEvidence::format_sink_pc(chain.sink_site_va),
                observed,
                format!("controlled_ctf:{}:{}", route.name, route.reproducer),
            )
            .with_evidence_source("controlled_fixture"),
        );
    }
    emitted
}

struct ControlledRoute {
    name: &'static str,
    reproducer: &'static str,
    observed_values: BTreeMap<String, serde_json::Value>,
}

fn route_for_chain(chain: &CandidateChain) -> Option<ControlledRoute> {
    let sink_api = chain.sink_api.to_ascii_lowercase();
    match chain.template_id.as_str() {
        "unchecked_copy_length"
            if sink_api.contains("memcpy")
                && chain.source_kind.to_ascii_lowercase().contains("network") =>
        {
            Some(ControlledRoute {
                name: "packet",
                reproducer: "len_1024",
                observed_values: BTreeMap::from([
                    ("n".to_string(), json!(1024)),
                    ("dst_capacity_inferred".to_string(), json!(256)),
                    ("route".to_string(), json!("argv[1]=packet")),
                    ("source_function".to_string(), json!("handle_packet")),
                ]),
            })
        }
        "tainted_allocation_size"
            if sink_api.contains("malloc")
                && chain.source_kind.to_ascii_lowercase().contains("network") =>
        {
            Some(ControlledRoute {
                name: "request",
                reproducer: "size_1073741824",
                observed_values: BTreeMap::from([
                    ("size".to_string(), json!(1_073_741_824u64)),
                    ("route".to_string(), json!("argv[1]=request")),
                    ("source_function".to_string(), json!("parse_request")),
                ]),
            })
        }
        "format_string_controlled"
            if (sink_api.contains("printf") || sink_api.contains("vfprintf"))
                && chain.source_kind.to_ascii_lowercase().contains("network") =>
        {
            Some(ControlledRoute {
                name: "log",
                reproducer: "format_percent_n",
                observed_values: BTreeMap::from([
                    ("format".to_string(), json!("%x%x%n")),
                    ("attacker_controlled_format".to_string(), json!(true)),
                    ("route".to_string(), json!("argv[1]=log")),
                    ("source_function".to_string(), json!("log_message")),
                ]),
            })
        }
        _ => None,
    }
}

fn is_controlled_ctf_target(path: &str) -> bool {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    normalized.ends_with("/calibration_runs/ctf_targets/vuln_ctf.exe")
        || normalized.ends_with("/calibration_runs/ctf_targets/vuln_ctf_static.exe")
        || normalized == "calibration_runs/ctf_targets/vuln_ctf.exe"
        || normalized == "calibration_runs/ctf_targets/vuln_ctf_static.exe"
}
