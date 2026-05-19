//! LLM-ready vulnerability proof packets.
//!
//! The canonical finding stream is intentionally compact. These
//! packets give review tooling a deterministic, provenance-heavy view
//! of one ranked finding: why it matters, the source-to-sink path, the
//! API evidence touching the sink, dynamic confirmation status, harness
//! reference, remaining uncertainty, and the next dynamic check to run.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::pe::ApiFlowRecord;
use crate::vuln::confirmation::ChainConfirmation;
use crate::vuln::dynamic_evidence::DynamicStatus;
use crate::vuln::finding::FindingRecord;
use crate::vuln::harness_synth::{Harness, HarnessKind, HarnessTier};
use crate::vuln::query::CandidateChain;
use crate::vuln::taint::PropagationMode;
use crate::vuln::VulnError;

pub const PROOF_PACKET_SCHEMA: &str = "vuln_discovery.proof_packet.v1";
pub const PROOF_PACKET_MANIFEST_SCHEMA: &str = "vuln_discovery.proof_packet_manifest.v1";

pub struct ProofPacketInput<'a> {
    pub run_id: &'a str,
    pub findings: &'a [FindingRecord],
    pub chains: &'a [CandidateChain],
    pub harnesses_by_chain: &'a BTreeMap<String, Harness>,
    pub confirmations_by_chain: &'a BTreeMap<String, ChainConfirmation>,
    pub api_flows: &'a [ApiFlowRecord],
}

#[derive(Clone, Debug)]
pub struct ProofPacketEmitReport {
    pub manifest_path: PathBuf,
    pub packet_count: usize,
    pub files_written: usize,
    pub bytes_written: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofPacketManifest {
    pub schema: String,
    pub run_id: String,
    pub packet_count: usize,
    pub packets: Vec<ProofPacketManifestEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofPacketManifestEntry {
    pub packet_id: String,
    pub finding_id: String,
    pub chain_id: String,
    pub bug_class: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_status: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VulnProofPacket {
    pub schema: String,
    pub packet_id: String,
    pub run_id: String,
    pub finding_id: String,
    pub chain_id: String,
    pub bug_class: String,
    pub why_this_function_matters: Vec<String>,
    pub source_to_sink_chain: PacketSourceToSink,
    pub all_evidence_touching_this_sink: Vec<PacketApiEvidence>,
    pub cross_folder_api_pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_confirmation: Option<PacketDynamicConfirmation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<PacketHarness>,
    pub uncertainties_blocking_confidence: Vec<String>,
    pub what_to_verify_dynamically_next: Vec<String>,
    pub provenance: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketSourceToSink {
    pub summary: String,
    pub source_kind: String,
    pub source_function_va: String,
    pub source_site_va: String,
    pub sink_api: String,
    pub sink_function_va: String,
    pub sink_site_va: String,
    pub propagation_mode: String,
    pub hop_count: u32,
    pub dominating_guard_count: usize,
    pub matched_integer_pattern: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketApiEvidence {
    pub flow_id: String,
    pub api: String,
    pub normalized_api: String,
    pub function_va: String,
    pub callsite_va: String,
    pub argument: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argument_register: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argument_index: Option<usize>,
    pub semantic_relevance: String,
    pub provenance: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketDynamicConfirmation {
    pub status: DynamicStatus,
    pub sink_pc: String,
    pub harness_id: String,
    pub observed_argument_values: BTreeMap<String, serde_json::Value>,
    pub reproducer_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_sources: Vec<String>,
    pub confidence_delta: f32,
    pub source_evidence_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PacketHarness {
    pub harness_id: String,
    pub kind: String,
    pub tier: String,
    pub runnable_verification: String,
    pub skeleton_path: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub setup_notes: Vec<String>,
}

pub fn emit_proof_packets(
    out_dir: &Path,
    input: ProofPacketInput<'_>,
) -> Result<ProofPacketEmitReport, VulnError> {
    let packets_dir = out_dir.join("vuln_packets");
    std::fs::create_dir_all(&packets_dir)?;

    let chains_by_id: BTreeMap<&str, &CandidateChain> = input
        .chains
        .iter()
        .map(|chain| (chain.chain_id.as_str(), chain))
        .collect();
    let mut manifest_entries = Vec::new();
    let mut bytes_written = 0u64;
    let mut files_written = 0usize;

    for finding in input.findings {
        let Some(chain_id) = finding.chain_id.as_deref() else {
            continue;
        };
        let Some(chain) = chains_by_id.get(chain_id).copied() else {
            continue;
        };
        let confirmation = input.confirmations_by_chain.get(chain_id);
        let harness = input.harnesses_by_chain.get(chain_id);
        let packet_id = format!("P-{}", finding.finding_id);
        let file_name = format!(
            "{}_{}.json",
            safe_component(&finding.finding_id),
            safe_component(chain_id)
        );
        let relative_path = format!("vuln_packets/{file_name}");
        let packet_path = packets_dir.join(&file_name);
        let packet = build_packet(
            input.run_id,
            &packet_id,
            finding,
            chain,
            harness,
            confirmation,
            input.api_flows,
        );
        let file = std::fs::File::create(&packet_path)?;
        let mut writer = std::io::BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &packet)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        bytes_written += std::fs::metadata(&packet_path)
            .map(|meta| meta.len())
            .unwrap_or(0);
        files_written += 1;
        manifest_entries.push(ProofPacketManifestEntry {
            packet_id,
            finding_id: finding.finding_id.clone(),
            chain_id: chain_id.to_string(),
            bug_class: finding.bug_class.clone(),
            path: relative_path,
            dynamic_status: confirmation.map(|c| dynamic_status_label(c.status).to_string()),
        });
    }

    let manifest = ProofPacketManifest {
        schema: PROOF_PACKET_MANIFEST_SCHEMA.to_string(),
        run_id: input.run_id.to_string(),
        packet_count: manifest_entries.len(),
        packets: manifest_entries,
    };
    let manifest_path = packets_dir.join("manifest.json");
    let file = std::fs::File::create(&manifest_path)?;
    let mut writer = std::io::BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, &manifest)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    bytes_written += std::fs::metadata(&manifest_path)
        .map(|meta| meta.len())
        .unwrap_or(0);
    files_written += 1;

    Ok(ProofPacketEmitReport {
        manifest_path,
        packet_count: manifest.packet_count,
        files_written,
        bytes_written,
    })
}

fn build_packet(
    run_id: &str,
    packet_id: &str,
    finding: &FindingRecord,
    chain: &CandidateChain,
    harness: Option<&Harness>,
    confirmation: Option<&ChainConfirmation>,
    api_flows: &[ApiFlowRecord],
) -> VulnProofPacket {
    let dynamic_confirmation = confirmation.map(|c| PacketDynamicConfirmation {
        status: c.status,
        sink_pc: c.sink_pc.clone(),
        harness_id: c.harness_id.clone(),
        observed_argument_values: c.merged_observed_argument_values.clone(),
        reproducer_ids: c.reproducer_ids.clone(),
        evidence_sources: c.evidence_sources.clone(),
        confidence_delta: c.confidence_delta,
        source_evidence_count: c.source_evidence_count,
    });
    let packet_harness = harness.map(|h| PacketHarness {
        harness_id: h.harness_id.clone(),
        kind: harness_kind_label(h.kind).to_string(),
        tier: harness_tier_label(h.tier).to_string(),
        runnable_verification: h.verification.wire_label().to_string(),
        skeleton_path: format!("harnesses/{}.skeleton.md", h.harness_id),
        setup_notes: h.setup_notes.clone(),
    });

    VulnProofPacket {
        schema: PROOF_PACKET_SCHEMA.to_string(),
        packet_id: packet_id.to_string(),
        run_id: run_id.to_string(),
        finding_id: finding.finding_id.clone(),
        chain_id: chain.chain_id.clone(),
        bug_class: finding.bug_class.clone(),
        why_this_function_matters: why_this_function_matters(finding, chain, confirmation),
        source_to_sink_chain: PacketSourceToSink {
            summary: finding.source_to_sink_summary.clone(),
            source_kind: chain.source_kind.clone(),
            source_function_va: hex_va(chain.source_function_va),
            source_site_va: hex_va(chain.source_site_va),
            sink_api: chain.sink_api.clone(),
            sink_function_va: hex_va(chain.sink_function_va),
            sink_site_va: hex_va(chain.sink_site_va),
            propagation_mode: propagation_label(chain.propagation_mode).to_string(),
            hop_count: chain.hop_count,
            dominating_guard_count: chain.dominating_guard_count,
            matched_integer_pattern: chain.matched_integer_pattern,
        },
        all_evidence_touching_this_sink: api_evidence_for_sink(chain, api_flows),
        cross_folder_api_pattern: format!(
            "{} -> {} in function {}",
            chain.source_kind,
            chain.sink_api,
            hex_va(chain.sink_function_va)
        ),
        dynamic_confirmation,
        harness: packet_harness,
        uncertainties_blocking_confidence: uncertainties(finding, confirmation),
        what_to_verify_dynamically_next: verify_next(chain, harness, confirmation),
        provenance: provenance(finding, chain, harness, confirmation),
    }
}

fn why_this_function_matters(
    finding: &FindingRecord,
    chain: &CandidateChain,
    confirmation: Option<&ChainConfirmation>,
) -> Vec<String> {
    let mut out = vec![
        format!(
            "{} source reaches {} sink in function {}",
            chain.source_kind,
            chain.sink_api,
            hex_va(chain.sink_function_va)
        ),
        format!(
            "ranked as {} risk {:.2} with confidence {:.2}",
            finding.severity_guess, finding.risk_score, finding.confidence.score
        ),
    ];
    if chain.matched_integer_pattern {
        out.push("integer/length pattern matched the sink argument shape".to_string());
    }
    if let Some(c) = confirmation {
        out.push(format!(
            "dynamic evidence status {} attaches to sink {}",
            dynamic_status_label(c.status),
            c.sink_pc
        ));
        if !c.evidence_sources.is_empty() {
            out.push(format!(
                "dynamic evidence source(s): {}",
                c.evidence_sources.join(", ")
            ));
        }
    }
    out
}

fn api_evidence_for_sink(
    chain: &CandidateChain,
    api_flows: &[ApiFlowRecord],
) -> Vec<PacketApiEvidence> {
    let sink = chain.sink_api.to_ascii_lowercase();
    let mut out = Vec::new();
    for flow in api_flows {
        let flow_api = flow.api.to_ascii_lowercase();
        let normalized_api = flow.normalized_api.to_ascii_lowercase();
        let touches_sink = flow.callsite == chain.sink_site_va
            || flow.function == chain.sink_function_va
            || flow_api.contains(&sink)
            || normalized_api.contains(&sink);
        if !touches_sink {
            continue;
        }
        out.push(PacketApiEvidence {
            flow_id: flow.flow_id.clone(),
            api: flow.api.clone(),
            normalized_api: flow.normalized_api.clone(),
            function_va: hex_va(flow.function),
            callsite_va: hex_va(flow.callsite),
            argument: flow.argument.clone(),
            argument_register: flow.argument_register.clone(),
            argument_index: flow.argument_index,
            semantic_relevance: flow.semantic_relevance.clone(),
            provenance: format!("api_flows:flow_id={}", flow.flow_id),
        });
        if out.len() >= 24 {
            break;
        }
    }
    out
}

fn uncertainties(finding: &FindingRecord, confirmation: Option<&ChainConfirmation>) -> Vec<String> {
    let mut out = finding.uncertainties.clone();
    if confirmation.is_none() {
        out.push(
            "dynamic_confirmation_missing: no contributing per-chain dynamic evidence attached"
                .to_string(),
        );
    }
    if out.is_empty() {
        out.push("no_material_uncertainty_recorded_for_this_packet".to_string());
    }
    out
}

fn verify_next(
    chain: &CandidateChain,
    harness: Option<&Harness>,
    confirmation: Option<&ChainConfirmation>,
) -> Vec<String> {
    if let Some(c) = confirmation {
        return vec![format!(
            "re-run reproducer {} and verify sink_pc {} under trace/debugger",
            c.reproducer_ids
                .first()
                .map(String::as_str)
                .unwrap_or("unknown"),
            c.sink_pc
        )];
    }
    let mut out = vec![format!(
        "drive source {} until sink {} at {} is reached",
        chain.source_kind,
        chain.sink_api,
        hex_va(chain.sink_site_va)
    )];
    if let Some(h) = harness {
        out.push(format!(
            "promote {} from {} only after runnable verification observes {}",
            h.harness_id,
            harness_tier_label(h.tier),
            hex_va(h.intended_sink_va)
        ));
    }
    out
}

fn provenance(
    finding: &FindingRecord,
    chain: &CandidateChain,
    harness: Option<&Harness>,
    confirmation: Option<&ChainConfirmation>,
) -> Vec<String> {
    let mut out = finding.provenance.clone();
    if out.is_empty() {
        out.push(format!("findings.jsonl:finding_id={}", finding.finding_id));
        out.push(format!("chain_graph.json:chain_id={}", chain.chain_id));
    }
    if let Some(h) = harness {
        let entry = format!("harnesses/{}.skeleton.md", h.harness_id);
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    if let Some(c) = confirmation {
        out.push(format!(
            "dynamic_evidence.jsonl:chain_id={} sink_pc={}",
            c.chain_id, c.sink_pc
        ));
        if !c.evidence_sources.is_empty() {
            out.push(format!(
                "dynamic_evidence.sources={}",
                c.evidence_sources.join(",")
            ));
        }
    }
    out
}

fn hex_va(value: u64) -> String {
    format!("{value:#018x}")
}

fn propagation_label(mode: PropagationMode) -> &'static str {
    match mode {
        PropagationMode::Exact => "exact",
        PropagationMode::Summary => "summary",
    }
}

fn dynamic_status_label(status: DynamicStatus) -> &'static str {
    match status {
        DynamicStatus::ConfirmedTrigger => "confirmed_trigger",
        DynamicStatus::ReachedOnly => "reached_only",
        DynamicStatus::NotObserved => "not_observed",
        DynamicStatus::Unavailable => "unavailable",
    }
}

fn harness_kind_label(kind: HarnessKind) -> &'static str {
    match kind {
        HarnessKind::BinaryOnlyPeEntry => "binary_only_pe_entry",
        HarnessKind::SourceAvailableFnByteSlice => "source_available_fn_byte_slice",
        HarnessKind::UserSuppliedEntryPoint => "user_supplied_entry_point",
    }
}

fn harness_tier_label(tier: HarnessTier) -> &'static str {
    match tier {
        HarnessTier::Skeleton => "skeleton",
        HarnessTier::Runnable => "runnable",
    }
}

fn safe_component(value: &str) -> String {
    let safe: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if safe.is_empty() {
        "packet".to_string()
    } else {
        safe
    }
}
