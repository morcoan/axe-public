//! Concolic SAT proof → per-chain DynamicEvidence.
//!
//! **Codex round-1 finding 1 fix** for the concolic path. Same
//! invariant as `fuzz_bridge` and `trace_join`: aggregate
//! signals — "Z3 found a model for SOME branch in this binary" —
//! cannot produce confidence on a chain. Only a `SolveReport`
//! resulting from a `BranchQuery` built FROM this chain's guards +
//! sink condition counts.
//!
//! Why `ReachedOnly` (never `ConfirmedTrigger`):
//!
//! [`crate::concolic::backend::SolveStatus::Sat`] proves "there
//! exists an input that satisfies the path constraints AND reaches
//! the target branch". It does NOT prove "the input triggers the
//! bug shape at the sink" — for that you'd need the bug condition
//! (e.g. `byte_count > dst_size` for memcpy) encoded as an
//! additional assertion. The v1.1 plan defers bug-shape encoding
//! to a future enhancement, so every concolic-derived evidence is
//! [`crate::vuln::dynamic_evidence::DynamicStatus::ReachedOnly`]
//! (half weight).
//!
//! Structural defense against orchestrator drift: the attribution
//! functions take `&Harness`, not raw chain ids, so the bridge
//! fills in `chain_id` / `harness_id` / `sink_pc` from the harness
//! itself. An orchestrator that mis-routes reports between chains
//! still cannot mis-label evidence — the wire shape is anchored on
//! the harness object the caller chose.
//!
//! `Unsat` outcomes are NOT evidence. Per Codex finding 1, the
//! correct response is silence (return `None`) — fabricating a
//! `NotObserved` record from `Unsat` would conflate "the SAT
//! solver proved infeasibility" with "we tried but the sink wasn't
//! reached", which the LLM consumer would misread.

#![cfg(feature = "vuln-discovery-concolic")]
#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::concolic::backend::{SolveReport, SolveStatus};
use crate::vuln::dynamic_evidence::DynamicEvidence;
use crate::vuln::harness_synth::Harness;

/// Try to attribute one solver report to one harness's chain.
///
/// Returns `Some(reached_only)` when:
/// - `report.status == SolveStatus::Sat`
/// - `report.input_model` is `Some(_)` (Sat without a model is
///   degenerate — most likely a backend bug)
/// - `query_label` is non-empty (the orchestrator must have built
///   this query intentionally)
///
/// Returns `None` for every other status, INCLUDING `Unsat`. Unsat
/// is not evidence per Codex finding 1.
pub fn attribute_solve_report(
    harness: &Harness,
    report: &SolveReport,
    query_label: &str,
) -> Option<DynamicEvidence> {
    if query_label.is_empty() {
        return None;
    }
    if report.status != SolveStatus::Sat {
        return None;
    }
    let model_bytes = match &report.input_model {
        Some(b) if !b.is_empty() => b,
        _ => return None,
    };

    let observed_argument_values = render_model_as_observed_args(model_bytes);
    let sink_pc = DynamicEvidence::format_sink_pc(harness.intended_sink_va);
    Some(
        DynamicEvidence::reached_only(
            harness.chain_id.clone(),
            harness.harness_id.clone(),
            sink_pc,
            observed_argument_values,
            query_label.to_string(),
        )
        .with_evidence_source("concolic"),
    )
}

/// Like [`attribute_solve_report`] but with explicit argument
/// mapping. `arg_byte_ranges` specifies which slice of `input_model`
/// corresponds to each named argument; the bridge extracts each
/// range and stores it as an `0x`-prefixed lowercase hex string
/// under the argument's name in `observed_argument_values`.
///
/// Use this when the orchestrator (Step 36 session) knows the
/// chain's input layout (e.g., bytes [0..4] are `n`, bytes [4..36]
/// are `dst`). The default [`attribute_solve_report`] produces a
/// single `"input_model"` key, useful when the layout is unknown.
pub fn attribute_solve_report_with_layout(
    harness: &Harness,
    report: &SolveReport,
    query_label: &str,
    arg_byte_ranges: &[(String, std::ops::Range<usize>)],
) -> Option<DynamicEvidence> {
    if query_label.is_empty() {
        return None;
    }
    if report.status != SolveStatus::Sat {
        return None;
    }
    let model_bytes = match &report.input_model {
        Some(b) if !b.is_empty() => b,
        _ => return None,
    };

    let mut observed_argument_values: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    for (name, range) in arg_byte_ranges {
        if let Some(slice) = model_bytes.get(range.clone()) {
            observed_argument_values.insert(name.clone(), encode_bytes_as_hex_value(slice));
        }
    }
    // Always include the full model bytes so the consumer has the
    // ground truth even if the layout was wrong.
    observed_argument_values.insert("input_model".into(), encode_bytes_as_hex_value(model_bytes));

    let sink_pc = DynamicEvidence::format_sink_pc(harness.intended_sink_va);
    Some(
        DynamicEvidence::reached_only(
            harness.chain_id.clone(),
            harness.harness_id.clone(),
            sink_pc,
            observed_argument_values,
            query_label.to_string(),
        )
        .with_evidence_source("concolic"),
    )
}

/// Apply [`attribute_solve_report`] across many `(report, label)` pairs
/// for one harness.
pub fn attribute_solve_reports(
    harness: &Harness,
    reports_with_labels: &[(SolveReport, String)],
) -> Vec<DynamicEvidence> {
    reports_with_labels
        .iter()
        .filter_map(|(r, l)| attribute_solve_report(harness, r, l))
        .collect()
}

fn render_model_as_observed_args(model_bytes: &[u8]) -> BTreeMap<String, serde_json::Value> {
    let mut out = BTreeMap::new();
    out.insert(
        "input_model".to_string(),
        encode_bytes_as_hex_value(model_bytes),
    );
    out.insert(
        "input_model_len".to_string(),
        serde_json::Value::from(model_bytes.len()),
    );
    out
}

fn encode_bytes_as_hex_value(bytes: &[u8]) -> serde_json::Value {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    serde_json::Value::String(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::dynamic_evidence::DynamicStatus;
    use crate::vuln::harness_synth::{synthesize, HarnessKind};
    use crate::vuln::query::CandidateChain;
    use crate::vuln::sinks::SinkCatalog;
    use crate::vuln::taint::PropagationMode;

    fn fixture_harness() -> Harness {
        synthesize(
            &CandidateChain {
                chain_id: "C-CC-001".into(),
                template_id: "tainted_allocation_size".into(),
                source_kind: "network_recv".into(),
                source_function_va: 0x140001000,
                source_site_va: 0x140001100,
                sink_api: "malloc".into(),
                sink_function_va: 0x140005000,
                sink_site_va: 0x140005200,
                propagation_mode: PropagationMode::Exact,
                hop_count: 0,
                dominating_guard_count: 0,
                matched_integer_pattern: true,
            },
            &SinkCatalog::v1_0(),
            HarnessKind::SourceAvailableFnByteSlice,
        )
    }

    fn report(status: SolveStatus, model: Option<Vec<u8>>) -> SolveReport {
        SolveReport {
            status,
            time_ms: 12,
            input_model: model,
            smt2: "(assert true)".into(),
            reason: None,
            unsat_core: Vec::new(),
            unsat_assumptions_returned: false,
            backend: "test_backend",
        }
    }

    // ----- SAT path -----

    #[test]
    fn sat_with_model_produces_reached_only_with_input_model_in_observed_args() {
        let h = fixture_harness();
        let r = report(SolveStatus::Sat, Some(vec![0xde, 0xad, 0xbe, 0xef]));
        let ev = attribute_solve_report(&h, &r, "chain_C-CC-001_branch_0").unwrap();
        assert_eq!(ev.status, DynamicStatus::ReachedOnly);
        // ReachedOnly never carries confidence_delta (Codex finding 1
        // structural rule).
        assert_eq!(ev.confidence_delta, 0.0);
        // observed_argument_values mirrors the solver model.
        assert_eq!(
            ev.observed_argument_values.get("input_model").unwrap(),
            &serde_json::json!("0xdeadbeef")
        );
        assert_eq!(
            ev.observed_argument_values.get("input_model_len").unwrap(),
            &serde_json::json!(4)
        );
        assert_eq!(ev.reproducer_id, "chain_C-CC-001_branch_0");
    }

    #[test]
    fn sat_attribution_carries_harness_anchored_metadata() {
        // Structural defense: the bridge takes &Harness so chain_id /
        // harness_id / sink_pc come from the harness, not from caller
        // strings that could be mis-routed.
        let h = fixture_harness();
        let r = report(SolveStatus::Sat, Some(vec![1, 2, 3]));
        let ev = attribute_solve_report(&h, &r, "q").unwrap();
        assert_eq!(ev.chain_id, h.chain_id);
        assert_eq!(ev.harness_id, h.harness_id);
        assert!(ev.sink_pc_matches(h.intended_sink_va));
    }

    // ----- Non-SAT outcomes: Codex finding 1 enforcement -----

    #[test]
    fn unsat_produces_no_evidence() {
        // Unsat is NOT NotObserved. It's silence — the chain wasn't
        // attributably proven satisfiable.
        let h = fixture_harness();
        let r = report(SolveStatus::Unsat, None);
        assert!(attribute_solve_report(&h, &r, "q").is_none());
    }

    #[test]
    fn unknown_produces_no_evidence() {
        let h = fixture_harness();
        let r = report(SolveStatus::Unknown, None);
        assert!(attribute_solve_report(&h, &r, "q").is_none());
    }

    #[test]
    fn timeout_produces_no_evidence() {
        let h = fixture_harness();
        let r = report(SolveStatus::Timeout, None);
        assert!(attribute_solve_report(&h, &r, "q").is_none());
    }

    #[test]
    fn lowering_error_produces_no_evidence() {
        let h = fixture_harness();
        let r = report(SolveStatus::LoweringError, None);
        assert!(attribute_solve_report(&h, &r, "q").is_none());
    }

    // ----- Degenerate / defensive cases -----

    #[test]
    fn sat_without_input_model_produces_no_evidence() {
        // Sat without a model is most likely a backend bug; we don't
        // know what to put in observed_argument_values, so we decline
        // to attribute rather than fake it.
        let h = fixture_harness();
        let r = report(SolveStatus::Sat, None);
        assert!(attribute_solve_report(&h, &r, "q").is_none());
    }

    #[test]
    fn sat_with_empty_input_model_produces_no_evidence() {
        let h = fixture_harness();
        let r = report(SolveStatus::Sat, Some(Vec::new()));
        assert!(attribute_solve_report(&h, &r, "q").is_none());
    }

    #[test]
    fn empty_query_label_produces_no_evidence() {
        // The query_label is the reproducer_id — without it, the LLM
        // consumer can't trace evidence back to a specific solve.
        // Refuse rather than emit untraceable evidence.
        let h = fixture_harness();
        let r = report(SolveStatus::Sat, Some(vec![1, 2, 3]));
        assert!(attribute_solve_report(&h, &r, "").is_none());
    }

    // ----- Layout-aware variant -----

    #[test]
    fn layout_aware_attribution_names_argument_slices() {
        let h = fixture_harness();
        let r = report(
            SolveStatus::Sat,
            Some(vec![0x10, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd]),
        );
        let layout = vec![("n".to_string(), 0..4), ("dst".to_string(), 4..8)];
        let ev = attribute_solve_report_with_layout(&h, &r, "q-1", &layout).unwrap();
        assert_eq!(
            ev.observed_argument_values.get("n").unwrap(),
            &serde_json::json!("0x10000000")
        );
        assert_eq!(
            ev.observed_argument_values.get("dst").unwrap(),
            &serde_json::json!("0xaabbccdd")
        );
        // Full model is always preserved for auditability.
        assert_eq!(
            ev.observed_argument_values.get("input_model").unwrap(),
            &serde_json::json!("0x10000000aabbccdd")
        );
    }

    #[test]
    fn layout_aware_skips_out_of_bounds_ranges_without_failing() {
        let h = fixture_harness();
        let r = report(SolveStatus::Sat, Some(vec![1, 2, 3]));
        let layout = vec![
            ("n".to_string(), 0..2),
            ("dst".to_string(), 100..200), // OOB
        ];
        let ev = attribute_solve_report_with_layout(&h, &r, "q-2", &layout).unwrap();
        assert!(ev.observed_argument_values.contains_key("n"));
        assert!(!ev.observed_argument_values.contains_key("dst"));
        assert!(ev.observed_argument_values.contains_key("input_model"));
    }

    #[test]
    fn layout_aware_attribution_returns_none_for_unsat() {
        let h = fixture_harness();
        let r = report(SolveStatus::Unsat, None);
        let layout = vec![("n".to_string(), 0..4)];
        assert!(attribute_solve_report_with_layout(&h, &r, "q", &layout).is_none());
    }

    // ----- Multi-report aggregation -----

    #[test]
    fn attribute_solve_reports_returns_one_record_per_sat() {
        let h = fixture_harness();
        let reports = vec![
            (report(SolveStatus::Sat, Some(vec![1])), "q1".to_string()),
            (report(SolveStatus::Unsat, None), "q2".to_string()),
            (report(SolveStatus::Sat, Some(vec![2])), "q3".to_string()),
            (report(SolveStatus::Timeout, None), "q4".to_string()),
        ];
        let evs = attribute_solve_reports(&h, &reports);
        assert_eq!(evs.len(), 2);
        let labels: Vec<&str> = evs.iter().map(|e| e.reproducer_id.as_str()).collect();
        assert_eq!(labels, vec!["q1", "q3"]);
    }

    #[test]
    fn attribute_solve_reports_returns_empty_when_no_sat() {
        let h = fixture_harness();
        let reports = vec![
            (report(SolveStatus::Unsat, None), "q1".to_string()),
            (report(SolveStatus::Unknown, None), "q2".to_string()),
        ];
        let evs = attribute_solve_reports(&h, &reports);
        // Codex finding 1: no Sat → no evidence at all. NO synthesized
        // Unavailable / NotObserved fallback.
        assert!(evs.is_empty());
    }

    // ----- Helper coverage -----

    #[test]
    fn encode_bytes_as_hex_value_produces_0x_prefixed_lowercase() {
        let v = encode_bytes_as_hex_value(&[0xab, 0xcd, 0xef]);
        assert_eq!(v, serde_json::json!("0xabcdef"));
    }

    #[test]
    fn encode_bytes_as_hex_value_empty_produces_just_0x() {
        let v = encode_bytes_as_hex_value(&[]);
        assert_eq!(v, serde_json::json!("0x"));
    }
}
