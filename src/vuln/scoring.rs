//! Multi-factor scoring formula — v1.0 static + v1.1 dynamic factor.
//!
//! See `docs/vuln-calibration.md` for the calibration procedure that
//! gates v1.1 work. v1.0 weights are uncalibrated baselines; every
//! finding carries `weights_calibration: "uncalibrated_v1_0_baseline"`
//! so the LLM consumer knows ranks are draft.
//!
//! v1.0 path: [`score_chain`] — static factors only.
//!
//! v1.1 path: [`score_chain_v1_1`] — same static factors plus an
//! optional `dynamic_evidence_score` factor from a per-chain
//! [`ChainConfirmation`] (Step 30 aggregator). **Codex finding 1
//! enforcement here is the last layer**: even with a present
//! confirmation, the score-boost depends on
//! [`DynamicStatus::contributes_to_score`] AND on the confirmation's
//! `sink_pc` matching the chain's `sink_site_va` via
//! [`DynamicEvidence::sink_pc_matches`] — mismatched evidence
//! contributes ZERO regardless of status.

#![allow(dead_code)]

use serde::Serialize;

use crate::vuln::bug_class::{BugClass, EvidenceTier};
use crate::vuln::confirmation::ChainConfirmation;
use crate::vuln::dynamic_evidence::DynamicEvidence;
use crate::vuln::query::CandidateChain;
use crate::vuln::sources::{SourceCatalog, TrustBoundary};
use crate::vuln::taint::PropagationMode;

/// Score for one chain. All sub-factors are emitted in the
/// `FindingRecord` so the LLM consumer can audit the rank.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FindingScore {
    pub risk: f32,
    pub confidence: f32,
    // Component factors (used by the LLM packet's scoring field).
    pub source_trust: f32,
    pub sink_danger: f32,
    pub taint_confidence: f32,
    pub missing_mitigation: f32,
    pub reachability: f32,
    pub exploitability_prior: f32,
    pub false_positive_penalty: f32,
}

/// Score `chain` against its template. The `source_catalog` provides
/// per-source trust weights.
pub fn score_chain(
    chain: &CandidateChain,
    template: &BugClass,
    source_catalog: &SourceCatalog,
) -> FindingScore {
    // ----- source_trust -----
    let source_trust = source_catalog
        .lookup(&chain.source_kind)
        .map(|s| s.trust.weight())
        .unwrap_or_else(|| TrustBoundary::LocalUnprivileged.weight());

    // ----- sink_danger -----
    let sink_danger = sink_danger_weight(&chain.sink_api);

    // ----- taint_confidence -----
    // exact = 1.0; summary = 0.7 with hop penalty 0.05 per hop.
    let taint_confidence = match chain.propagation_mode {
        PropagationMode::Exact => 1.0,
        PropagationMode::Summary => (0.7 - (chain.hop_count as f32) * 0.05).max(0.3),
    };

    // ----- missing_mitigation -----
    // 0 dominating guards = 1.0; ≥1 partial guard = 0.5.
    let missing_mitigation = if chain.dominating_guard_count == 0 {
        1.0
    } else {
        0.5
    };

    // ----- reachability -----
    // v1.0 stub: chains from exported entry → 1.0; we don't know
    // depth without plumbing call_distances_from into query.rs.
    // Conservative default.
    let reachability = 1.0;

    // ----- exploitability_prior (template-dependent) -----
    let exploitability_prior = match template.category {
        "memory_corruption" => 1.0,
        "auth_bypass" => 0.8,
        "deserialization" => 0.9,
        "path_injection" => 0.6,
        "race_condition" => 0.5,
        _ => 0.5,
    };

    // ----- false_positive_penalty -----
    // Best-effort tier gets a 0.1 penalty; ground-truth = 0.0.
    let false_positive_penalty = match template.evidence_tier {
        EvidenceTier::GroundTruth => 0.0,
        EvidenceTier::BestEffort => 0.1,
        EvidenceTier::Candidate => 0.3,
    };

    // ----- aggregate risk -----
    let risk = source_trust * 1.5
        + sink_danger * 1.3
        + taint_confidence * 1.0
        + missing_mitigation * 1.4
        + reachability * 1.2
        + exploitability_prior * 0.8
        - false_positive_penalty * 1.0;

    // ----- confidence -----
    let base = template.evidence_tier.confidence_base();
    let mut confidence = base
        - 0.03 // uncertainties always include calibration disclaimer
        - if chain.propagation_mode == PropagationMode::Summary { 0.05 } else { 0.0 };
    if let Some(cap) = template.confidence_cap {
        confidence = confidence.min(cap);
    }
    confidence = confidence.clamp(0.30, 0.95);

    FindingScore {
        risk,
        confidence,
        source_trust,
        sink_danger,
        taint_confidence,
        missing_mitigation,
        reachability,
        exploitability_prior,
        false_positive_penalty,
    }
}

/// v1.1 weight applied to the dynamic-evidence factor. The product
/// `dynamic_evidence_score × DYNAMIC_EVIDENCE_RISK_WEIGHT` is added
/// to `risk`. Hand-graded baseline — see `docs/vuln-calibration.md`.
pub const DYNAMIC_EVIDENCE_RISK_WEIGHT: f32 = 1.6;

/// v1.1 confidence-delta multiplier. `dynamic_evidence_score ×
/// DYNAMIC_EVIDENCE_CONFIDENCE_DELTA` is added to `confidence`
/// before the overall clamp.
pub const DYNAMIC_EVIDENCE_CONFIDENCE_DELTA: f32 = 0.10;

/// v1.1 score function: apply the dynamic-evidence factor on top of
/// the v1.0 static-only score from [`score_chain`].
///
/// When `confirmation` is `None` (or doesn't contribute to score),
/// the returned [`FindingScore`] is byte-identical to
/// `score_chain(chain, template, source_catalog)`. This means v1.0
/// callers can pass `None` to get the v1.0 behavior.
///
/// **Codex finding 1 enforcement** lives here as the last layer:
/// - Confirmations whose `sink_pc` does NOT match the chain's
///   `sink_site_va` are silently zero-weighted (defense in depth;
///   the Step 30 aggregator already filters mismatches, but a
///   misuse path could still feed us a stale confirmation).
/// - Only [`crate::vuln::dynamic_evidence::DynamicStatus::ConfirmedTrigger`]
///   and [`crate::vuln::dynamic_evidence::DynamicStatus::ReachedOnly`]
///   contribute non-zero weight; `NotObserved` and `Unavailable`
///   are explicitly zero per the v1.1 scoring formula.
pub fn score_chain_v1_1(
    chain: &CandidateChain,
    template: &BugClass,
    source_catalog: &SourceCatalog,
    confirmation: Option<&ChainConfirmation>,
) -> FindingScore {
    let mut base = score_chain(chain, template, source_catalog);
    let Some(conf) = confirmation else {
        return base;
    };
    if !conf.status.contributes_to_score() {
        return base;
    }
    // Defense in depth: even though the aggregator filters
    // mismatched evidence, re-check sink_pc here so a misuse path
    // can't accidentally apply a stale confirmation to the wrong
    // chain.
    let expected_sink_pc = DynamicEvidence::format_sink_pc(chain.sink_site_va);
    if conf.sink_pc != expected_sink_pc {
        return base;
    }
    let dyn_score = conf.status.scoring_weight();
    base.risk += dyn_score * DYNAMIC_EVIDENCE_RISK_WEIGHT;
    base.confidence =
        (base.confidence + dyn_score * DYNAMIC_EVIDENCE_CONFIDENCE_DELTA).clamp(0.30, 0.95);
    base
}

fn sink_danger_weight(api: &str) -> f32 {
    // Higher = more dangerous on average.
    let lower = api.to_lowercase();
    if lower.contains("memcpy")
        || lower.contains("memmove")
        || lower.contains("strcpy")
        || lower.contains("rtlcopymemory")
    {
        1.0
    } else if lower.contains("virtualprotect")
        || lower.contains("writeprocessmemory")
        || lower.contains("createremotethread")
    {
        1.0
    } else if lower.contains("sprintf") || lower.contains("printf") {
        0.9
    } else if lower.contains("deviceiocontrol") || lower.contains("virtualallocex") {
        0.85
    } else if lower.contains("createfile") || lower.contains("fopen") || lower.contains("open") {
        0.6
    } else {
        0.7
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::bug_class::TemplateRegistry;

    fn chain(api: &str, mode: PropagationMode, guards: usize) -> CandidateChain {
        CandidateChain {
            chain_id: "C-000001".into(),
            template_id: "unchecked_copy_length".into(),
            source_kind: "network_recv".into(),
            source_function_va: 0x1000,
            source_site_va: 0x1100,
            sink_api: api.into(),
            sink_function_va: 0x2000,
            sink_site_va: 0x2200,
            propagation_mode: mode,
            hop_count: 0,
            dominating_guard_count: guards,
            matched_integer_pattern: false,
        }
    }

    #[test]
    fn higher_source_trust_yields_higher_risk() {
        let cat_s = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let c1 = chain("memcpy", PropagationMode::Exact, 0);
        let mut c2 = c1.clone();
        c2.source_kind = "registry_value".into(); // ConfigFile trust
        let s1 = score_chain(&c1, t, &cat_s);
        let s2 = score_chain(&c2, t, &cat_s);
        assert!(s1.risk > s2.risk);
    }

    #[test]
    fn summary_propagation_lowers_taint_confidence() {
        let cat_s = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let c_exact = chain("memcpy", PropagationMode::Exact, 0);
        let c_summary = chain("memcpy", PropagationMode::Summary, 0);
        let s_exact = score_chain(&c_exact, t, &cat_s);
        let s_summary = score_chain(&c_summary, t, &cat_s);
        assert!(s_exact.taint_confidence > s_summary.taint_confidence);
        assert!(s_exact.confidence > s_summary.confidence);
    }

    #[test]
    fn dominating_guard_lowers_missing_mitigation() {
        let cat_s = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let c_no_guard = chain("memcpy", PropagationMode::Exact, 0);
        let c_with_guard = chain("memcpy", PropagationMode::Exact, 1);
        let s_no = score_chain(&c_no_guard, t, &cat_s);
        let s_with = score_chain(&c_with_guard, t, &cat_s);
        assert!(s_no.missing_mitigation > s_with.missing_mitigation);
        assert!(s_no.risk > s_with.risk);
    }

    #[test]
    fn confidence_clamped_to_band() {
        let cat_s = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let s = score_chain(&chain("memcpy", PropagationMode::Exact, 0), t, &cat_s);
        assert!(s.confidence >= 0.30);
        assert!(s.confidence <= 0.95);
    }

    // =====================================================================
    // v1.1 dynamic-evidence factor tests (Step 32)
    // =====================================================================

    use crate::vuln::confirmation::{aggregate_for_chain, ChainConfirmation};
    use crate::vuln::dynamic_evidence::{DynamicEvidence, DynamicStatus};
    use crate::vuln::harness_synth::{synthesize, HarnessKind};
    use crate::vuln::sinks::SinkCatalog;

    fn fixture_v1_1_chain() -> CandidateChain {
        CandidateChain {
            chain_id: "C-V1_1-001".into(),
            template_id: "unchecked_copy_length".into(),
            source_kind: "network_recv".into(),
            source_function_va: 0x140001000,
            source_site_va: 0x140001100,
            sink_api: "memcpy".into(),
            sink_function_va: 0x140002000,
            sink_site_va: 0x1400022a4,
            propagation_mode: PropagationMode::Exact,
            hop_count: 0,
            dominating_guard_count: 0,
            matched_integer_pattern: false,
        }
    }

    fn fixture_v1_1_confirmation(status: DynamicStatus) -> ChainConfirmation {
        let chain = fixture_v1_1_chain();
        let h = synthesize(
            &chain,
            &SinkCatalog::v1_0(),
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let ev = match status {
            DynamicStatus::ConfirmedTrigger => DynamicEvidence::confirmed_trigger(
                chain.chain_id.clone(),
                h.harness_id.clone(),
                DynamicEvidence::format_sink_pc(chain.sink_site_va),
                std::collections::BTreeMap::new(),
                "repro".to_string(),
            ),
            DynamicStatus::ReachedOnly => DynamicEvidence::reached_only(
                chain.chain_id.clone(),
                h.harness_id.clone(),
                DynamicEvidence::format_sink_pc(chain.sink_site_va),
                std::collections::BTreeMap::new(),
                "repro".to_string(),
            ),
            DynamicStatus::NotObserved => DynamicEvidence::not_observed(
                chain.chain_id.clone(),
                h.harness_id.clone(),
                DynamicEvidence::format_sink_pc(chain.sink_site_va),
            ),
            DynamicStatus::Unavailable => DynamicEvidence::unavailable(
                chain.chain_id.clone(),
                DynamicEvidence::format_sink_pc(chain.sink_site_va),
            ),
        };
        aggregate_for_chain(&h, &[ev]).expect("status must yield a confirmation")
    }

    #[test]
    fn score_v1_1_with_none_confirmation_equals_v1_0_score() {
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let c = fixture_v1_1_chain();
        let v1_0 = score_chain(&c, t, &cat);
        let v1_1 = score_chain_v1_1(&c, t, &cat, None);
        assert_eq!(v1_0.risk, v1_1.risk);
        assert_eq!(v1_0.confidence, v1_1.confidence);
    }

    #[test]
    fn confirmed_trigger_adds_1_6_to_risk_and_0_10_to_confidence() {
        // Plan formula: dyn_score=1.0 for ConfirmedTrigger →
        // risk += 1.0 × 1.6 = 1.6; confidence += 1.0 × 0.10 = 0.10.
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let c = fixture_v1_1_chain();
        let conf = fixture_v1_1_confirmation(DynamicStatus::ConfirmedTrigger);
        let base = score_chain(&c, t, &cat);
        let boosted = score_chain_v1_1(&c, t, &cat, Some(&conf));
        let risk_delta = boosted.risk - base.risk;
        let conf_delta = boosted.confidence - base.confidence;
        assert!((risk_delta - 1.6).abs() < 1e-5, "risk_delta={risk_delta}");
        // Confidence may be clamped at 0.95 if base + 0.10 > 0.95.
        let expected_conf = (base.confidence + 0.10).clamp(0.30, 0.95);
        assert!((boosted.confidence - expected_conf).abs() < 1e-5);
        let _ = conf_delta; // for diagnostic clarity, not asserted directly
    }

    #[test]
    fn reached_only_adds_0_8_to_risk_and_0_05_to_confidence() {
        // Plan formula: dyn_score=0.5 for ReachedOnly →
        // risk += 0.5 × 1.6 = 0.8; confidence += 0.5 × 0.10 = 0.05.
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let c = fixture_v1_1_chain();
        let conf = fixture_v1_1_confirmation(DynamicStatus::ReachedOnly);
        let base = score_chain(&c, t, &cat);
        let boosted = score_chain_v1_1(&c, t, &cat, Some(&conf));
        let risk_delta = boosted.risk - base.risk;
        assert!((risk_delta - 0.8).abs() < 1e-5, "risk_delta={risk_delta}");
        let expected_conf = (base.confidence + 0.05).clamp(0.30, 0.95);
        assert!((boosted.confidence - expected_conf).abs() < 1e-5);
    }

    #[test]
    fn not_observed_adds_zero_to_risk_and_zero_to_confidence() {
        // Plan formula: dyn_score=0 for NotObserved → no change.
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let c = fixture_v1_1_chain();
        let conf = fixture_v1_1_confirmation(DynamicStatus::NotObserved);
        let base = score_chain(&c, t, &cat);
        let boosted = score_chain_v1_1(&c, t, &cat, Some(&conf));
        assert_eq!(base.risk, boosted.risk);
        assert_eq!(base.confidence, boosted.confidence);
    }

    #[test]
    fn mismatched_sink_pc_contributes_zero_even_with_confirmed_trigger_status() {
        // Codex finding 1 defense in depth: if the confirmation's
        // sink_pc somehow doesn't match the chain's expected VA, the
        // dynamic factor MUST be zero regardless of status. This
        // protects against a misuse path where a stale confirmation
        // is paired with the wrong chain.
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let c = fixture_v1_1_chain();
        let mut conf = fixture_v1_1_confirmation(DynamicStatus::ConfirmedTrigger);
        // Mutate the sink_pc to a wrong value.
        conf.sink_pc = DynamicEvidence::format_sink_pc(0xdeadbeef);
        let base = score_chain(&c, t, &cat);
        let boosted = score_chain_v1_1(&c, t, &cat, Some(&conf));
        assert_eq!(base.risk, boosted.risk);
        assert_eq!(base.confidence, boosted.confidence);
    }

    #[test]
    fn confidence_boost_respects_overall_clamp_at_0_95() {
        // Even with ConfirmedTrigger, the confidence cap of 0.95
        // (from the static formula) is the hard ceiling.
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let c = fixture_v1_1_chain();
        let conf = fixture_v1_1_confirmation(DynamicStatus::ConfirmedTrigger);
        let boosted = score_chain_v1_1(&c, t, &cat, Some(&conf));
        assert!(boosted.confidence <= 0.95);
        assert!(boosted.confidence >= 0.30);
    }

    #[test]
    fn confirmed_trigger_increases_risk_more_than_reached_only() {
        // Ordinal invariant of the v1.1 formula.
        let cat = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t = templates.by_id("unchecked_copy_length").unwrap();
        let c = fixture_v1_1_chain();
        let conf_full = fixture_v1_1_confirmation(DynamicStatus::ConfirmedTrigger);
        let conf_half = fixture_v1_1_confirmation(DynamicStatus::ReachedOnly);
        let s_full = score_chain_v1_1(&c, t, &cat, Some(&conf_full));
        let s_half = score_chain_v1_1(&c, t, &cat, Some(&conf_half));
        assert!(s_full.risk > s_half.risk);
        assert!(s_full.confidence > s_half.confidence);
    }

    // ----- end v1.1 dynamic-evidence tests -----

    #[test]
    fn deserialization_template_best_effort_penalty_applied() {
        let cat_s = SourceCatalog::v1_0();
        let templates = TemplateRegistry::load_v1_0();
        let t_ground = templates.by_id("unchecked_copy_length").unwrap();
        let t_best = templates
            .by_id("deserialization_to_dangerous_type")
            .unwrap();
        let c = chain("memcpy", PropagationMode::Exact, 0);
        let s_ground = score_chain(&c, t_ground, &cat_s);
        let s_best = score_chain(&c, t_best, &cat_s);
        assert!(s_ground.false_positive_penalty < s_best.false_positive_penalty);
        assert!(s_ground.confidence > s_best.confidence);
    }
}
