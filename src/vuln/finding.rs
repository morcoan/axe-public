//! FindingRecord wire shape + rusqlite-backed FindingStore.
//!
//! `FindingRecord` is the v1.0 LLM-consumer-facing finding shape.
//! `FindingStore` durably persists every finding so cross-run
//! queries (compare runs, build differential dashboards) work
//! without re-running the analysis.

#![allow(dead_code)]

use std::collections::BTreeMap;

use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};

use crate::facts::confidence::Confidence;
use crate::vuln::bug_class::{BugClass, EvidenceTier};
use crate::vuln::confirmation::ChainConfirmation;
use crate::vuln::dynamic_evidence::DynamicStatus;
use crate::vuln::harness_synth::{Harness, HarnessKind, HarnessTier};
use crate::vuln::query::CandidateChain;
use crate::vuln::scoring::FindingScore;
use crate::vuln::sources::SourceCatalog;
use crate::vuln::taint::PropagationMode;

pub const FINDING_SCHEMA: &str = "vuln_discovery.finding.v1";
pub const STORE_SCHEMA_VERSION: i64 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingRecord {
    pub schema: String,
    pub finding_id: String,
    pub run_id: String,
    pub bug_class: String,
    pub evidence_tier: EvidenceTier,
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness: Option<FindingHarnessRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_evidence: Option<FindingDynamicEvidence>,
    pub severity_guess: String,
    pub risk_score: f32,
    pub confidence: Confidence,
    pub trust_boundary: String,
    pub source_to_sink_summary: String,
    pub source: FindingSource,
    pub sink: FindingSink,
    pub propagation_mode: PropagationMode,
    pub dominating_guard_count: usize,
    pub matched_integer_pattern: bool,
    pub scoring: ScoringFactors,
    pub uncertainties: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingSource {
    pub kind: String,
    pub function_va: String,
    pub site_va: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingSink {
    pub api: String,
    pub function_va: String,
    pub site_va: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingHarnessRef {
    pub harness_id: String,
    pub kind: String,
    pub tier: String,
    pub runnable_verification: String,
    pub skeleton_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FindingDynamicEvidence {
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
pub struct ScoringFactors {
    pub source_trust: f32,
    pub sink_danger: f32,
    pub taint_confidence: f32,
    pub missing_mitigation: f32,
    pub reachability: f32,
    pub exploitability_prior: f32,
    pub false_positive_penalty: f32,
    pub weights_calibration: String,
}

/// Build a `FindingRecord` from a chain + score + template.
pub fn emit_finding(
    run_id: &str,
    finding_id: &str,
    chain: &CandidateChain,
    template: &BugClass,
    score: &FindingScore,
    source_catalog: &SourceCatalog,
) -> FindingRecord {
    let trust_boundary = source_catalog
        .lookup(&chain.source_kind)
        .map(|s| format!("{:?}", s.trust).to_lowercase())
        .unwrap_or_else(|| "unknown".into());
    let severity_guess = severity_from_risk(score.risk);
    let summary = format!(
        "{} reaches {} via {} propagation.",
        chain.source_kind,
        chain.sink_api,
        if chain.propagation_mode == PropagationMode::Exact {
            "exact"
        } else {
            "summary"
        }
    );
    let uncertainties = build_uncertainties(chain, template);
    FindingRecord {
        schema: FINDING_SCHEMA.to_string(),
        finding_id: finding_id.to_string(),
        run_id: run_id.to_string(),
        bug_class: chain.template_id.clone(),
        evidence_tier: template.evidence_tier,
        phase: "v1.0_static".to_string(),
        chain_id: None,
        harness: None,
        dynamic_evidence: None,
        severity_guess,
        risk_score: score.risk,
        confidence: Confidence::from_score(score.confidence),
        trust_boundary,
        source_to_sink_summary: summary,
        source: FindingSource {
            kind: chain.source_kind.clone(),
            function_va: format!("{:#018x}", chain.source_function_va),
            site_va: format!("{:#018x}", chain.source_site_va),
        },
        sink: FindingSink {
            api: chain.sink_api.clone(),
            function_va: format!("{:#018x}", chain.sink_function_va),
            site_va: format!("{:#018x}", chain.sink_site_va),
        },
        propagation_mode: chain.propagation_mode,
        dominating_guard_count: chain.dominating_guard_count,
        matched_integer_pattern: chain.matched_integer_pattern,
        scoring: ScoringFactors {
            source_trust: score.source_trust,
            sink_danger: score.sink_danger,
            taint_confidence: score.taint_confidence,
            missing_mitigation: score.missing_mitigation,
            reachability: score.reachability,
            exploitability_prior: score.exploitability_prior,
            false_positive_penalty: score.false_positive_penalty,
            weights_calibration: "calibrated_v1_0_2_2026_05_17".to_string(),
        },
        uncertainties,
        provenance: Vec::new(),
    }
}

/// Attach v1.1 provenance after the session has synthesized harnesses
/// and aggregated per-chain dynamic evidence. v1.0 callers keep the
/// byte shape clean because `emit_finding` leaves these fields empty.
pub fn attach_v1_1_context(
    finding: &mut FindingRecord,
    chain: &CandidateChain,
    harness: Option<&Harness>,
    confirmation: Option<&ChainConfirmation>,
) {
    finding.phase = "v1.1_dynamic_confirmation".to_string();
    finding.chain_id = Some(chain.chain_id.clone());
    finding.harness = harness.map(|h| FindingHarnessRef {
        harness_id: h.harness_id.clone(),
        kind: harness_kind_label(h.kind).to_string(),
        tier: harness_tier_label(h.tier).to_string(),
        runnable_verification: h.verification.wire_label().to_string(),
        skeleton_path: format!("harnesses/{}.skeleton.md", h.harness_id),
    });
    finding.dynamic_evidence = confirmation.map(|c| FindingDynamicEvidence {
        status: c.status,
        sink_pc: c.sink_pc.clone(),
        harness_id: c.harness_id.clone(),
        observed_argument_values: c.merged_observed_argument_values.clone(),
        reproducer_ids: c.reproducer_ids.clone(),
        evidence_sources: c.evidence_sources.clone(),
        confidence_delta: c.confidence_delta,
        source_evidence_count: c.source_evidence_count,
    });

    let mut provenance = vec![
        format!("chain_graph.json:chain_id={}", chain.chain_id),
        format!("findings.jsonl:finding_id={}", finding.finding_id),
        format!("api_flows:source_site={:#018x}", chain.source_site_va),
        format!("api_flows:sink_site={:#018x}", chain.sink_site_va),
    ];
    if let Some(h) = harness {
        provenance.push(format!("harnesses/{}.skeleton.md", h.harness_id));
    }
    if let Some(c) = confirmation {
        provenance.push(format!(
            "dynamic_evidence.jsonl:chain_id={} sink_pc={}",
            c.chain_id, c.sink_pc
        ));
        if !c.evidence_sources.is_empty() {
            provenance.push(format!(
                "dynamic_evidence.sources={}",
                c.evidence_sources.join(",")
            ));
        }
    }
    finding.provenance = provenance;
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

fn severity_from_risk(risk: f32) -> String {
    if risk >= 7.0 {
        "high".into()
    } else if risk >= 4.0 {
        "medium".into()
    } else {
        "low".into()
    }
}

fn build_uncertainties(chain: &CandidateChain, template: &BugClass) -> Vec<String> {
    let mut out = vec![
        "scoring_weights_uncalibrated: ranks are draft until calibration on real binaries".into(),
    ];
    if chain.propagation_mode == PropagationMode::Summary {
        out.push(format!(
            "propagation_mode_summary: taint crossed {} call boundaries via approximate summaries",
            chain.hop_count
        ));
    }
    if template.evidence_tier == EvidenceTier::BestEffort {
        out.push(format!(
            "evidence_tier_best_effort: {} detector depends on type-inference heuristics",
            template.id
        ));
    }
    out
}

// ---------- FindingStore (rusqlite) -------------------------------

pub struct FindingStore {
    conn: Connection,
}

impl FindingStore {
    pub fn open(path: &std::path::Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "MEMORY")?;
        conn.pragma_update(None, "synchronous", "OFF")?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS findings (
                finding_id    TEXT PRIMARY KEY,
                run_id        TEXT NOT NULL,
                bug_class     TEXT NOT NULL,
                risk_score    REAL NOT NULL,
                confidence    REAL NOT NULL,
                payload_json  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS findings_bug_class ON findings(bug_class);
            CREATE INDEX IF NOT EXISTS findings_risk_desc ON findings(risk_score DESC);
            "#,
        )?;
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params!["schema_version", STORE_SCHEMA_VERSION.to_string()],
        )?;
        Ok(())
    }

    pub fn insert(&mut self, f: &FindingRecord) -> rusqlite::Result<()> {
        let payload = serde_json::to_string(f)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        self.conn.execute(
            r#"INSERT OR REPLACE INTO findings
                (finding_id, run_id, bug_class, risk_score, confidence, payload_json)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![
                f.finding_id,
                f.run_id,
                f.bug_class,
                f.risk_score as f64,
                f.confidence.score as f64,
                payload,
            ],
        )?;
        Ok(())
    }

    pub fn count(&self) -> rusqlite::Result<u64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| {
                r.get::<_, i64>(0).map(|n| n as u64)
            })
    }

    pub fn top_n_by_risk(&self, n: usize) -> rusqlite::Result<Vec<FindingRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM findings ORDER BY risk_score DESC LIMIT ?1")?;
        let rows = stmt.query_map(params![n as i64], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let s = row?;
            let f: FindingRecord = serde_json::from_str(&s)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            out.push(f);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::bug_class::TemplateRegistry;

    fn fixture_chain() -> CandidateChain {
        CandidateChain {
            chain_id: "C-000001".into(),
            template_id: "unchecked_copy_length".into(),
            source_kind: "network_recv".into(),
            source_function_va: 0x1000,
            source_site_va: 0x1100,
            sink_api: "memcpy".into(),
            sink_function_va: 0x2000,
            sink_site_va: 0x2200,
            propagation_mode: PropagationMode::Exact,
            hop_count: 0,
            dominating_guard_count: 0,
            matched_integer_pattern: false,
        }
    }

    #[test]
    fn finding_round_trips_through_json() {
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let chain = fixture_chain();
        let score = crate::vuln::scoring::score_chain(&chain, t, &cat);
        let f = emit_finding("run-1", "F-000001", &chain, t, &score, &cat);
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains(r#""schema":"vuln_discovery.finding.v1""#));
        let back: FindingRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(back.finding_id, "F-000001");
    }

    #[test]
    fn finding_carries_uncalibrated_disclaimer() {
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let chain = fixture_chain();
        let score = crate::vuln::scoring::score_chain(&chain, t, &cat);
        let f = emit_finding("run-1", "F-000001", &chain, t, &score, &cat);
        assert!(f.uncertainties.iter().any(|u| u.contains("uncalibrated")));
    }

    #[test]
    fn finding_summary_propagation_adds_uncertainty() {
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let mut chain = fixture_chain();
        chain.propagation_mode = PropagationMode::Summary;
        chain.hop_count = 2;
        let score = crate::vuln::scoring::score_chain(&chain, t, &cat);
        let f = emit_finding("run-1", "F-000001", &chain, t, &score, &cat);
        assert!(f
            .uncertainties
            .iter()
            .any(|u| u.contains("propagation_mode_summary")));
    }

    #[test]
    fn store_round_trips_finding() {
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let chain = fixture_chain();
        let score = crate::vuln::scoring::score_chain(&chain, t, &cat);
        let f = emit_finding("run-1", "F-000001", &chain, t, &score, &cat);
        let mut store = FindingStore::open_in_memory().unwrap();
        store.insert(&f).unwrap();
        assert_eq!(store.count().unwrap(), 1);
        let top = store.top_n_by_risk(10).unwrap();
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].finding_id, "F-000001");
    }

    #[test]
    fn store_top_n_orders_by_risk_desc() {
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let chain = fixture_chain();
        let score = crate::vuln::scoring::score_chain(&chain, t, &cat);
        let mut f_low = emit_finding("run-1", "F-LOW", &chain, t, &score, &cat);
        f_low.risk_score = 2.0;
        let mut f_high = emit_finding("run-1", "F-HIGH", &chain, t, &score, &cat);
        f_high.risk_score = 9.0;
        let mut store = FindingStore::open_in_memory().unwrap();
        store.insert(&f_low).unwrap();
        store.insert(&f_high).unwrap();
        let top = store.top_n_by_risk(10).unwrap();
        assert_eq!(top[0].finding_id, "F-HIGH");
        assert_eq!(top[1].finding_id, "F-LOW");
    }
}
