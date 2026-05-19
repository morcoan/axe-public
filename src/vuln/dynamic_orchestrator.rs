//! Dynamic confirmation orchestration chokepoint.
//!
//! This module owns the session-level truthfulness policy for dynamic
//! evidence: only requested sources may flow through, and scoring
//! evidence must match the target harness's exact sink PC before it is
//! passed to the confirmation aggregator.

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::vuln::dynamic_evidence::DynamicEvidence;
use crate::vuln::harness_synth::Harness;

#[derive(Clone, Debug)]
pub struct DynamicOrchestratorInput<'a> {
    pub source_path: Option<&'a str>,
    pub explicit_evidence: &'a [DynamicEvidence],
}

#[derive(Clone, Copy, Debug)]
pub struct DynamicOrchestratorOptions<'a> {
    pub requested_sources: &'a str,
    pub include_controlled_fixture: bool,
}

#[derive(Clone, Debug, Default)]
pub struct DynamicOrchestratorReport {
    pub evidence: Vec<DynamicEvidence>,
}

pub fn orchestrate(
    harnesses_by_chain: &BTreeMap<String, Harness>,
    input: DynamicOrchestratorInput<'_>,
    options: DynamicOrchestratorOptions<'_>,
) -> DynamicOrchestratorReport {
    let requested = requested_dynamic_sources(
        options.requested_sources,
        options.include_controlled_fixture,
    );
    if requested.is_empty() && input.explicit_evidence.is_empty() {
        return DynamicOrchestratorReport::default();
    }

    let mut evidence = Vec::new();
    for row in input.explicit_evidence {
        if !requested.is_empty()
            && !row.evidence_source.is_empty()
            && !source_requested(&requested, &row.evidence_source)
        {
            continue;
        }
        let Some(harness) = harnesses_by_chain.get(&row.chain_id) else {
            continue;
        };
        if !row.sink_pc_matches(harness.intended_sink_va) {
            continue;
        }
        evidence.push(row.clone());
    }

    if !requested.is_empty() {
        for harness in harnesses_by_chain.values() {
            for source in &requested {
                let already_has_source = evidence.iter().any(|row| {
                    row.chain_id == harness.chain_id
                        && row.evidence_source.eq_ignore_ascii_case(source)
                        && row.sink_pc_matches(harness.intended_sink_va)
                });
                if already_has_source {
                    continue;
                }
                let mut unavailable = DynamicEvidence::unavailable(
                    harness.chain_id.clone(),
                    DynamicEvidence::format_sink_pc(harness.intended_sink_va),
                );
                unavailable.harness_id = harness.harness_id.clone();
                unavailable.evidence_source = (*source).to_string();
                unavailable.reproducer_id = format!("source_unavailable:{source}");
                evidence.push(unavailable);
            }
        }
    }

    let _ = input.source_path;
    DynamicOrchestratorReport { evidence }
}

fn requested_dynamic_sources(
    selector: &str,
    include_controlled_fixture: bool,
) -> Vec<&'static str> {
    let mut sources = match selector {
        "debug_probe" => vec!["debug_probe"],
        "fuzz" => vec!["fuzz"],
        "trace" => vec!["trace"],
        "concolic" => vec!["concolic"],
        "both" => vec!["fuzz", "trace"],
        "all" => vec!["debug_probe", "fuzz", "trace", "concolic"],
        _ => Vec::new(),
    };
    if include_controlled_fixture && !sources.is_empty() {
        sources.push("controlled_fixture");
        sources.push("safe_fixture_probe");
    }
    sources.sort_unstable();
    sources.dedup();
    sources
}

fn source_requested(requested: &[&str], source: &str) -> bool {
    !source.is_empty()
        && requested
            .iter()
            .any(|requested| source.eq_ignore_ascii_case(requested))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use serde_json::json;

    use crate::vuln::dynamic_evidence::{DynamicEvidence, DynamicStatus};
    use crate::vuln::harness_synth::{synthesize, Harness};
    use crate::vuln::query::CandidateChain;
    use crate::vuln::sinks::SinkCatalog;
    use crate::vuln::taint::PropagationMode;

    use super::{orchestrate, DynamicOrchestratorInput, DynamicOrchestratorOptions};

    fn chain(chain_id: &str, sink_site_va: u64) -> CandidateChain {
        CandidateChain {
            chain_id: chain_id.to_string(),
            template_id: "unchecked_copy_length".to_string(),
            source_kind: "network_recv".to_string(),
            source_function_va: 0x140001000,
            source_site_va: 0x140001100,
            sink_api: "memcpy".to_string(),
            sink_function_va: 0x140001000,
            sink_site_va,
            propagation_mode: PropagationMode::Exact,
            hop_count: 0,
            dominating_guard_count: 0,
            matched_integer_pattern: false,
        }
    }

    fn harnesses(chains: &[CandidateChain]) -> BTreeMap<String, Harness> {
        let sinks = SinkCatalog::v1_0();
        chains
            .iter()
            .map(|chain| {
                let harness = synthesize(
                    chain,
                    &sinks,
                    crate::vuln::harness_synth::HarnessKind::BinaryOnlyPeEntry,
                );
                (chain.chain_id.clone(), harness)
            })
            .collect()
    }

    #[test]
    fn orchestrator_drops_scoring_evidence_with_wrong_sink_pc() {
        let chains = vec![chain("C-1", 0x140001234)];
        let harnesses = harnesses(&chains);
        let explicit = vec![DynamicEvidence::confirmed_trigger(
            "C-1",
            "H-C-1",
            DynamicEvidence::format_sink_pc(0x140009999),
            BTreeMap::from([("n".to_string(), json!(4096))]),
            "crash-1",
        )
        .with_evidence_source("fuzz")];

        let report = orchestrate(
            &harnesses,
            DynamicOrchestratorInput {
                source_path: None,
                explicit_evidence: &explicit,
            },
            DynamicOrchestratorOptions {
                requested_sources: "fuzz",
                include_controlled_fixture: false,
            },
        );

        assert!(
            report
                .evidence
                .iter()
                .all(|row| row.status != DynamicStatus::ConfirmedTrigger),
            "wrong-sink evidence must not be allowed into session scoring inputs"
        );
        assert!(
            report
                .evidence
                .iter()
                .any(|row| row.status == DynamicStatus::Unavailable
                    && row.evidence_source == "fuzz"
                    && row.chain_id == "C-1"),
            "requested but unmatched sources should be visible as unavailable attempts"
        );
    }

    #[test]
    fn orchestrator_keeps_only_requested_dynamic_sources() {
        let chains = vec![chain("C-1", 0x140001234)];
        let harnesses = harnesses(&chains);
        let explicit = vec![
            DynamicEvidence::reached_only(
                "C-1",
                "H-C-1",
                DynamicEvidence::format_sink_pc(0x140001234),
                BTreeMap::new(),
                "trace-1",
            )
            .with_evidence_source("trace"),
            DynamicEvidence::reached_only(
                "C-1",
                "H-C-1",
                DynamicEvidence::format_sink_pc(0x140001234),
                BTreeMap::new(),
                "probe-1",
            )
            .with_evidence_source("safe_fixture_probe"),
        ];

        let report = orchestrate(
            &harnesses,
            DynamicOrchestratorInput {
                source_path: None,
                explicit_evidence: &explicit,
            },
            DynamicOrchestratorOptions {
                requested_sources: "trace",
                include_controlled_fixture: false,
            },
        );

        let sources: BTreeSet<_> = report
            .evidence
            .iter()
            .map(|row| row.evidence_source.as_str())
            .collect();
        assert!(sources.contains("trace"));
        assert!(!sources.contains("safe_fixture_probe"));
    }

    #[test]
    fn orchestrator_accepts_manifest_safe_probe_when_all_sources_requested() {
        let chains = vec![chain("C-1", 0x140001234)];
        let harnesses = harnesses(&chains);
        let explicit = vec![DynamicEvidence::reached_only(
            "C-1",
            "H-C-1",
            DynamicEvidence::format_sink_pc(0x140001234),
            BTreeMap::new(),
            "probe-1",
        )
        .with_evidence_source("safe_fixture_probe")];

        let report = orchestrate(
            &harnesses,
            DynamicOrchestratorInput {
                source_path: None,
                explicit_evidence: &explicit,
            },
            DynamicOrchestratorOptions {
                requested_sources: "all",
                include_controlled_fixture: true,
            },
        );

        assert!(report.evidence.iter().any(|row| {
            row.status == DynamicStatus::ReachedOnly && row.evidence_source == "safe_fixture_probe"
        }));
    }
}
