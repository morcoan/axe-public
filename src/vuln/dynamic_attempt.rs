//! Dynamic confirmation attempt ledger.
//!
//! `dynamic_evidence.jsonl` stays the scoring input: only records
//! with exact `chain_id` + `sink_pc` attribution can affect ranking.
//! This module emits the adjacent `dynamic_attempts.jsonl` audit log
//! so consumers can see which backend was tried, which evidence row it
//! produced, or why the backend was unavailable for a chain.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::vuln::dynamic_evidence::{DynamicEvidence, DynamicStatus};
use crate::vuln::harness_synth::{Harness, HarnessKind, HarnessVerification};
use crate::vuln::VulnError;

pub const DYNAMIC_ATTEMPT_SCHEMA: &str = "vuln_discovery.dynamic_attempt.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DynamicAttempt {
    pub schema: String,
    pub chain_id: String,
    pub harness_id: String,
    pub sink_pc: String,
    pub executor: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    pub duration_ms: u64,
}

pub fn attempts_from_dynamic_evidence(
    harnesses_by_chain: &BTreeMap<String, Harness>,
    rows: &[DynamicEvidence],
) -> Vec<DynamicAttempt> {
    rows.iter()
        .map(|row| attempt_from_evidence(harnesses_by_chain.get(&row.chain_id), row))
        .collect()
}

pub fn emit_dynamic_attempts_jsonl(path: &Path, rows: &[DynamicAttempt]) -> Result<u64, VulnError> {
    let file = std::fs::File::create(path)?;
    let mut writer = std::io::BufWriter::new(file);
    for row in rows {
        serde_json::to_writer(&mut writer, row)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(std::fs::metadata(path).map(|m| m.len()).unwrap_or(0))
}

fn attempt_from_evidence(harness: Option<&Harness>, row: &DynamicEvidence) -> DynamicAttempt {
    let executor = evidence_executor(row);
    let status = status_label(row.status).to_string();
    let is_scoring_evidence = row.status.contributes_to_score();
    DynamicAttempt {
        schema: DYNAMIC_ATTEMPT_SCHEMA.to_string(),
        chain_id: row.chain_id.clone(),
        harness_id: if row.harness_id.is_empty() {
            harness
                .map(|h| h.harness_id.clone())
                .unwrap_or_else(|| format!("H-{}", row.chain_id))
        } else {
            row.harness_id.clone()
        },
        sink_pc: row.sink_pc.clone(),
        executor: executor.clone(),
        status,
        command: command_for(row, &executor),
        reason: reason_for(harness, row, &executor),
        evidence_refs: if is_scoring_evidence {
            vec![format!(
                "dynamic_evidence.jsonl:chain_id={} sink_pc={} status={}",
                row.chain_id,
                row.sink_pc,
                status_label(row.status)
            )]
        } else {
            Vec::new()
        },
        duration_ms: 0,
    }
}

fn evidence_executor(row: &DynamicEvidence) -> String {
    if !row.evidence_source.is_empty() {
        return row.evidence_source.clone();
    }
    row.reproducer_id
        .strip_prefix("source_unavailable:")
        .map(str::to_string)
        .unwrap_or_else(|| "unknown".to_string())
}

fn command_for(row: &DynamicEvidence, executor: &str) -> Option<String> {
    if executor == "controlled_fixture" {
        return Some(format!("controlled_fixture:{}", row.reproducer_id));
    }
    match row.status {
        DynamicStatus::ConfirmedTrigger | DynamicStatus::ReachedOnly => {
            Some(format!("{executor}:{}", row.reproducer_id))
        }
        DynamicStatus::NotObserved | DynamicStatus::Unavailable => None,
    }
}

fn reason_for(harness: Option<&Harness>, row: &DynamicEvidence, executor: &str) -> Option<String> {
    match row.status {
        DynamicStatus::Unavailable => Some(match executor {
            "fuzz" => match harness {
                Some(h) if h.verification == HarnessVerification::NotAttempted => format!(
                    "{} harness is {}; no runnable fuzz harness supplied",
                    harness_kind_label(h.kind),
                    h.verification.wire_label()
                ),
                Some(h) => format!(
                    "{} harness verification is {}; fuzz evidence was not supplied",
                    harness_kind_label(h.kind),
                    h.verification.wire_label()
                ),
                None => "no harness metadata available for fuzz attempt".to_string(),
            },
            "trace" => "no per-chain trace event supplied for this sink".to_string(),
            "concolic" => "no chain-specific SAT model supplied for this sink".to_string(),
            other => format!("dynamic source unavailable: {other}"),
        }),
        DynamicStatus::NotObserved => Some(format!(
            "{executor} ran but did not observe sink {}",
            row.sink_pc
        )),
        DynamicStatus::ConfirmedTrigger | DynamicStatus::ReachedOnly => None,
    }
}

fn status_label(status: DynamicStatus) -> &'static str {
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
