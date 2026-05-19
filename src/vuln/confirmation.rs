//! Per-chain DynamicEvidence aggregator.
//!
//! Steps 27-29 produce raw [`DynamicEvidence`] records from three
//! independent sources (fuzzer crashes, ETW trace events, concolic
//! SAT proofs). One chain can receive evidence from multiple
//! sources — e.g., a fuzzer crash AND a concolic SAT proof both
//! attesting the same chain. This module is the chokepoint that
//! folds those parallel attestations into a single
//! [`ChainConfirmation`] record per chain, which the v1.1 wire shape
//! (Step 34's `llm_pack.rs` and Step 36's `session.rs`) attaches
//! to the corresponding [`FindingRecord`].
//!
//! **Codex round-1 finding 1 is the last-line-of-defense
//! invariant** enforced here:
//! - Evidence whose `sink_pc` does NOT match the chain's expected
//!   `sink_site_va` is silently dropped via
//!   [`DynamicEvidence::sink_pc_matches`]. This is the second layer
//!   of defense after the per-source attribution discipline in
//!   Steps 27-29.
//! - When no contributing evidence remains, the aggregator returns
//!   `None`. The caller MUST NOT fabricate an `Unavailable` record
//!   from that absence — silence is the honest answer.
//!
//! Aggregation rule:
//! - Status = strongest [`DynamicStatus`] across contributing
//!   records, by [`DynamicStatus::scoring_weight`].
//! - `observed_argument_values` = union of all contributing records'
//!   values (later values overwrite duplicate keys; iteration order
//!   is fuzz_bridge → trace_join → concolic_query when callers
//!   preserve source order, but this module doesn't sort).
//! - `reproducer_ids` = every contributing reproducer (so the LLM
//!   consumer can pick any to reproduce).
//! - `confidence_delta` is the status's nominal delta from
//!   [`DynamicStatus::confidence_delta`]; Step 32's v1.1 scoring
//!   formula may refine this with multi-confirmation boosts.

#![cfg(feature = "vuln-discovery")]
#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::vuln::dynamic_evidence::{DynamicEvidence, DynamicStatus};
use crate::vuln::harness_synth::Harness;

/// Aggregated dynamic confirmation for one chain.
///
/// Built by [`aggregate_for_chain`] from per-source [`DynamicEvidence`]
/// records. Step 34 (llm_pack v1.1) serializes a subset of these
/// fields into the `dynamic_evidence` block of `findings.jsonl`;
/// Step 32 (scoring v1.1) reads `status` + `confidence_delta` for
/// the v1.1 scoring formula.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ChainConfirmation {
    /// Chain identifier (from `harness.chain_id`). Codex finding 1:
    /// this field MUST match the chain the confirmation was built
    /// for; the aggregator anchors on `&Harness` so the orchestrator
    /// cannot accidentally cross-wire chains.
    pub chain_id: String,
    /// The synthesized harness id (`H-{chain_id}`).
    pub harness_id: String,
    /// Canonical hex of the sink callsite — set from
    /// `harness.intended_sink_va` via
    /// [`DynamicEvidence::format_sink_pc`].
    pub sink_pc: String,
    /// Strongest [`DynamicStatus`] observed across contributing
    /// evidence. By construction (Codex finding 1) this status
    /// implies `sink_pc_matches(harness.intended_sink_va) == true`
    /// for at least one contributing record.
    pub status: DynamicStatus,
    /// Union of every contributing record's
    /// `observed_argument_values`. Later values overwrite duplicate
    /// keys; the LLM consumer reads this as a single snapshot of
    /// runtime values observed across all confirmation sources.
    pub merged_observed_argument_values: BTreeMap<String, serde_json::Value>,
    /// Every contributing reproducer's id (corpus entry, ETW event
    /// id, concolic query label). The order matches the iteration
    /// order of the input evidence list.
    pub reproducer_ids: Vec<String>,
    /// Explicit evidence sources that contributed to this chain
    /// confirmation (`fuzz`, `trace`, `concolic`,
    /// `controlled_fixture`). Sorted and deduplicated for stable
    /// proof-packet and benchmark matching.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_sources: Vec<String>,
    /// Number of contributing evidence records. Step 32 may use
    /// this as a tie-breaker for graduated confidence boosts.
    pub source_evidence_count: usize,
    /// Pre-computed `confidence_delta` from
    /// [`DynamicStatus::confidence_delta`]. Step 32's v1.1 scoring
    /// may multiply by `source_evidence_count` for graduated boost.
    pub confidence_delta: f32,
}

/// Build a [`ChainConfirmation`] for one chain by filtering the
/// evidence list to records that:
/// - Have `chain_id == harness.chain_id`.
/// - Pass [`DynamicEvidence::sink_pc_matches`] against
///   `harness.intended_sink_va` (Codex finding 1 defensive check).
///
/// Returns `None` when no evidence survives the filter — including
/// when every contributing record is `Unavailable` (which would not
/// add information beyond what the chain already had statically).
pub fn aggregate_for_chain(
    harness: &Harness,
    evidence_list: &[DynamicEvidence],
) -> Option<ChainConfirmation> {
    let intended = harness.intended_sink_va;
    let filtered: Vec<&DynamicEvidence> = evidence_list
        .iter()
        .filter(|e| e.chain_id == harness.chain_id && e.sink_pc_matches(intended))
        .collect();
    if filtered.is_empty() {
        return None;
    }
    let strongest_status = filtered
        .iter()
        .map(|e| e.status)
        .max_by(|a, b| {
            a.scoring_weight()
                .partial_cmp(&b.scoring_weight())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap_or(DynamicStatus::Unavailable);

    // If the strongest status is Unavailable, the aggregator has
    // nothing to add — the chain stays at its static score. Returning
    // None keeps the wire shape clean (no useless dynamic_evidence
    // block in findings.jsonl).
    if strongest_status == DynamicStatus::Unavailable {
        return None;
    }

    let contributing: Vec<&DynamicEvidence> = filtered
        .iter()
        .copied()
        .filter(|ev| match strongest_status {
            DynamicStatus::ConfirmedTrigger | DynamicStatus::ReachedOnly => {
                ev.status.contributes_to_score()
            }
            DynamicStatus::NotObserved => ev.status == DynamicStatus::NotObserved,
            DynamicStatus::Unavailable => false,
        })
        .collect();

    let mut merged_observed_argument_values: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut reproducer_ids: Vec<String> = Vec::new();
    let mut evidence_sources: Vec<String> = Vec::new();
    for ev in &contributing {
        for (k, v) in &ev.observed_argument_values {
            merged_observed_argument_values.insert(k.clone(), v.clone());
        }
        if !ev.reproducer_id.is_empty() {
            reproducer_ids.push(ev.reproducer_id.clone());
        }
        if !ev.evidence_source.is_empty() && !evidence_sources.contains(&ev.evidence_source) {
            evidence_sources.push(ev.evidence_source.clone());
        }
    }
    evidence_sources.sort();

    Some(ChainConfirmation {
        chain_id: harness.chain_id.clone(),
        harness_id: harness.harness_id.clone(),
        sink_pc: DynamicEvidence::format_sink_pc(intended),
        status: strongest_status,
        merged_observed_argument_values,
        reproducer_ids,
        evidence_sources,
        source_evidence_count: contributing.len(),
        confidence_delta: strongest_status.confidence_delta(),
    })
}

/// Aggregate evidence for every harness, indexed by `chain_id`.
/// Harnesses with no surviving evidence are absent from the map.
pub fn aggregate_all(
    harnesses: &[Harness],
    evidence_list: &[DynamicEvidence],
) -> BTreeMap<String, ChainConfirmation> {
    let mut out: BTreeMap<String, ChainConfirmation> = BTreeMap::new();
    for h in harnesses {
        if let Some(conf) = aggregate_for_chain(h, evidence_list) {
            out.insert(h.chain_id.clone(), conf);
        }
    }
    out
}

/// Convenience predicate: does the aggregated confirmation
/// contribute non-zero dynamic score? Step 32's scoring formula will
/// re-derive this from `status.contributes_to_score()` but exposing
/// it here keeps callers symmetric across the v1.1 modules.
pub fn contributes_to_score(confirmation: &ChainConfirmation) -> bool {
    confirmation.status.contributes_to_score()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::harness_synth::{synthesize, HarnessKind};
    use crate::vuln::query::CandidateChain;
    use crate::vuln::sinks::SinkCatalog;
    use crate::vuln::taint::PropagationMode;

    fn fixture_chain(chain_id: &str, sink_site_va: u64) -> CandidateChain {
        CandidateChain {
            chain_id: chain_id.into(),
            template_id: "unchecked_copy_length".into(),
            source_kind: "network_recv".into(),
            source_function_va: 0x140001000,
            source_site_va: 0x140001100,
            sink_api: "memcpy".into(),
            sink_function_va: 0x140002000,
            sink_site_va,
            propagation_mode: PropagationMode::Summary,
            hop_count: 2,
            dominating_guard_count: 1,
            matched_integer_pattern: false,
        }
    }

    fn fixture_harness(chain_id: &str, sink_site_va: u64) -> Harness {
        synthesize(
            &fixture_chain(chain_id, sink_site_va),
            &SinkCatalog::v1_0(),
            HarnessKind::SourceAvailableFnByteSlice,
        )
    }

    fn confirmed(chain_id: &str, sink_va: u64, repro: &str) -> DynamicEvidence {
        let mut obs = BTreeMap::new();
        obs.insert("n".into(), serde_json::json!(4096));
        DynamicEvidence::confirmed_trigger(
            chain_id,
            format!("H-{chain_id}"),
            DynamicEvidence::format_sink_pc(sink_va),
            obs,
            repro,
        )
    }

    fn reached(chain_id: &str, sink_va: u64, repro: &str) -> DynamicEvidence {
        let mut obs = BTreeMap::new();
        obs.insert("input_model".into(), serde_json::json!("0xdeadbeef"));
        DynamicEvidence::reached_only(
            chain_id,
            format!("H-{chain_id}"),
            DynamicEvidence::format_sink_pc(sink_va),
            obs,
            repro,
        )
    }

    fn not_observed(chain_id: &str, sink_va: u64) -> DynamicEvidence {
        DynamicEvidence::not_observed(
            chain_id,
            format!("H-{chain_id}"),
            DynamicEvidence::format_sink_pc(sink_va),
        )
    }

    fn unavailable(chain_id: &str, sink_va: u64) -> DynamicEvidence {
        DynamicEvidence::unavailable(chain_id, DynamicEvidence::format_sink_pc(sink_va))
    }

    // ----- Single-source aggregation -----

    #[test]
    fn single_confirmed_trigger_yields_confirmed_trigger_with_full_delta() {
        let h = fixture_harness("C-A1", 0x140004000);
        let evs = vec![confirmed("C-A1", 0x140004000, "corpus_1")];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        assert_eq!(conf.status, DynamicStatus::ConfirmedTrigger);
        assert_eq!(conf.confidence_delta, 0.10);
        assert_eq!(conf.reproducer_ids, vec!["corpus_1"]);
        assert_eq!(conf.source_evidence_count, 1);
    }

    #[test]
    fn single_reached_only_yields_reached_only_with_zero_delta() {
        let h = fixture_harness("C-A2", 0x140004000);
        let evs = vec![reached("C-A2", 0x140004000, "evt_42")];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        assert_eq!(conf.status, DynamicStatus::ReachedOnly);
        assert_eq!(conf.confidence_delta, 0.0);
    }

    // ----- Multi-source: strongest wins -----

    #[test]
    fn confirmed_dominates_reached_when_both_present() {
        // Mix of 3 evidence types per plan validation: fuzzer
        // ConfirmedTrigger + trace ReachedOnly + concolic ReachedOnly
        // → strongest (ConfirmedTrigger) wins.
        let h = fixture_harness("C-M1", 0x140004000);
        let evs = vec![
            confirmed("C-M1", 0x140004000, "corpus_1"),
            reached("C-M1", 0x140004000, "evt_42"),
            reached("C-M1", 0x140004000, "q_3"),
        ];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        assert_eq!(conf.status, DynamicStatus::ConfirmedTrigger);
        assert_eq!(conf.confidence_delta, 0.10);
        // All three contributors recorded.
        assert_eq!(conf.source_evidence_count, 3);
        assert_eq!(conf.reproducer_ids, vec!["corpus_1", "evt_42", "q_3"]);
    }

    #[test]
    fn reached_only_wins_when_no_confirmed_present() {
        let h = fixture_harness("C-M2", 0x140004000);
        let evs = vec![
            reached("C-M2", 0x140004000, "evt_42"),
            reached("C-M2", 0x140004000, "q_7"),
        ];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        assert_eq!(conf.status, DynamicStatus::ReachedOnly);
        assert_eq!(conf.source_evidence_count, 2);
    }

    #[test]
    fn merged_observed_argument_values_unions_all_sources() {
        let h = fixture_harness("C-M3", 0x140004000);
        let mut obs1 = BTreeMap::new();
        obs1.insert("n".into(), serde_json::json!(4096));
        let mut obs2 = BTreeMap::new();
        obs2.insert("dst_capacity_inferred".into(), serde_json::json!(1024));
        let evs = vec![
            DynamicEvidence::confirmed_trigger(
                "C-M3",
                "H-C-M3",
                DynamicEvidence::format_sink_pc(0x140004000),
                obs1,
                "corpus",
            ),
            DynamicEvidence::reached_only(
                "C-M3",
                "H-C-M3",
                DynamicEvidence::format_sink_pc(0x140004000),
                obs2,
                "evt",
            ),
        ];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        // Both keys preserved.
        assert!(conf.merged_observed_argument_values.contains_key("n"));
        assert!(conf
            .merged_observed_argument_values
            .contains_key("dst_capacity_inferred"));
    }

    // ----- Codex finding 1 enforcement: sink_pc + chain_id filters -----

    #[test]
    fn evidence_with_wrong_sink_pc_is_silently_dropped() {
        let h = fixture_harness("C-CF1", 0x140004000);
        let evs = vec![
            // Wrong sink_pc — defensive filter must drop it.
            confirmed("C-CF1", 0x140009999, "corpus_wrong"),
        ];
        // Only contributing evidence had wrong sink_pc → None.
        assert!(aggregate_for_chain(&h, &evs).is_none());
    }

    #[test]
    fn wrong_sink_pc_does_not_contaminate_good_evidence() {
        let h = fixture_harness("C-CF2", 0x140004000);
        let evs = vec![
            confirmed("C-CF2", 0x140009999, "wrong"),
            reached("C-CF2", 0x140004000, "right"),
        ];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        // The wrong-sink_pc ConfirmedTrigger is dropped; only the
        // correct ReachedOnly contributes. Strongest = ReachedOnly.
        assert_eq!(conf.status, DynamicStatus::ReachedOnly);
        assert_eq!(conf.source_evidence_count, 1);
        assert_eq!(conf.reproducer_ids, vec!["right"]);
    }

    #[test]
    fn evidence_for_other_chains_is_filtered_out() {
        let h = fixture_harness("C-CF3", 0x140004000);
        let evs = vec![
            confirmed("C-OTHER", 0x140004000, "corpus_other"),
            reached("C-CF3", 0x140004000, "evt_mine"),
        ];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        assert_eq!(conf.source_evidence_count, 1);
        assert_eq!(conf.reproducer_ids, vec!["evt_mine"]);
    }

    #[test]
    fn empty_evidence_list_returns_none() {
        // Codex finding 1: silence is the honest answer when no
        // evidence is available. NO synthesized Unavailable record.
        let h = fixture_harness("C-CF4", 0x140004000);
        assert!(aggregate_for_chain(&h, &[]).is_none());
    }

    #[test]
    fn only_unavailable_evidence_returns_none() {
        // Unavailable contributes nothing on its own — the chain
        // stays at its static-only score, and the wire shape has no
        // dynamic_evidence block.
        let h = fixture_harness("C-CF5", 0x140004000);
        let evs = vec![unavailable("C-CF5", 0x140004000)];
        assert!(aggregate_for_chain(&h, &evs).is_none());
    }

    #[test]
    fn unavailable_sources_do_not_contaminate_positive_confirmation() {
        let h = fixture_harness("C-CF5B", 0x140004000);
        let evs = vec![
            reached("C-CF5B", 0x140004000, "trace_event").with_evidence_source("trace"),
            unavailable("C-CF5B", 0x140004000).with_evidence_source("debug_probe"),
            unavailable("C-CF5B", 0x140004000).with_evidence_source("fuzz"),
        ];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        assert_eq!(conf.status, DynamicStatus::ReachedOnly);
        assert_eq!(conf.evidence_sources, vec!["trace"]);
        assert_eq!(conf.source_evidence_count, 1);
        assert_eq!(conf.reproducer_ids, vec!["trace_event"]);
    }

    #[test]
    fn not_observed_alone_still_produces_a_record() {
        // NotObserved means the orchestrator TRIED but didn't reach.
        // That's information worth conveying to the LLM consumer
        // ("we ran the harness but didn't reach the sink") so we
        // produce a record. Step 32 will give it zero scoring weight.
        let h = fixture_harness("C-CF6", 0x140004000);
        let evs = vec![not_observed("C-CF6", 0x140004000)];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        assert_eq!(conf.status, DynamicStatus::NotObserved);
        assert_eq!(conf.confidence_delta, 0.0);
    }

    // ----- Sink_pc anchor verification -----

    #[test]
    fn aggregated_sink_pc_comes_from_harness_not_evidence() {
        let h = fixture_harness("C-S1", 0x140004000);
        // Build evidence with a structurally valid-but-different
        // sink_pc string (matches the va, but capitalized).
        let mut ev = confirmed("C-S1", 0x140004000, "corpus");
        ev.sink_pc = "0X140004000".to_string(); // unusual format
        let conf = aggregate_for_chain(&h, &[ev]).unwrap();
        // The aggregator emits the canonical form from the harness,
        // not whatever the evidence carried. Wire shape is uniform
        // across consumers.
        assert_eq!(conf.sink_pc, DynamicEvidence::format_sink_pc(0x140004000));
    }

    // ----- aggregate_all -----

    #[test]
    fn aggregate_all_indexes_by_chain_id() {
        let h1 = fixture_harness("C-AA1", 0x140004000);
        let h2 = fixture_harness("C-AA2", 0x140005000);
        let h3 = fixture_harness("C-AA3", 0x140006000); // no evidence
        let evs = vec![
            confirmed("C-AA1", 0x140004000, "c1"),
            reached("C-AA2", 0x140005000, "e1"),
        ];
        let map = aggregate_all(&[h1, h2, h3], &evs);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get("C-AA1").map(|c| c.status),
            Some(DynamicStatus::ConfirmedTrigger)
        );
        assert_eq!(
            map.get("C-AA2").map(|c| c.status),
            Some(DynamicStatus::ReachedOnly)
        );
        // No evidence for C-AA3 → absent from the map.
        assert!(map.get("C-AA3").is_none());
    }

    #[test]
    fn aggregate_all_does_not_cross_evidence_between_chains() {
        // Two chains, each with its own evidence — aggregate_all
        // routes correctly by chain_id and doesn't bleed evidence
        // across chains.
        let h1 = fixture_harness("C-AA4", 0x140004000);
        let h2 = fixture_harness("C-AA5", 0x140005000);
        let evs = vec![
            confirmed("C-AA4", 0x140004000, "c_for_4"),
            confirmed("C-AA5", 0x140005000, "c_for_5"),
        ];
        let map = aggregate_all(&[h1, h2], &evs);
        assert_eq!(map.get("C-AA4").unwrap().reproducer_ids, vec!["c_for_4"]);
        assert_eq!(map.get("C-AA5").unwrap().reproducer_ids, vec!["c_for_5"]);
    }

    // ----- Wire shape round-trip -----

    #[test]
    fn chain_confirmation_round_trips_through_json() {
        let h = fixture_harness("C-W1", 0x140004000);
        let evs = vec![confirmed("C-W1", 0x140004000, "corpus")];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        let s = serde_json::to_string(&conf).unwrap();
        let back: ChainConfirmation = serde_json::from_str(&s).unwrap();
        assert_eq!(back, conf);
    }

    #[test]
    fn chain_confirmation_serializes_status_as_snake_case() {
        let h = fixture_harness("C-W2", 0x140004000);
        let evs = vec![confirmed("C-W2", 0x140004000, "c")];
        let conf = aggregate_for_chain(&h, &evs).unwrap();
        let s = serde_json::to_string(&conf).unwrap();
        assert!(s.contains("\"status\":\"confirmed_trigger\""));
    }

    // ----- contributes_to_score predicate -----

    #[test]
    fn contributes_to_score_mirrors_dynamic_status_rule() {
        let h = fixture_harness("C-CS1", 0x140004000);
        let conf_confirmed =
            aggregate_for_chain(&h, &[confirmed("C-CS1", 0x140004000, "c")]).unwrap();
        assert!(contributes_to_score(&conf_confirmed));

        let conf_reached = aggregate_for_chain(&h, &[reached("C-CS1", 0x140004000, "e")]).unwrap();
        assert!(contributes_to_score(&conf_reached));

        let conf_not_observed =
            aggregate_for_chain(&h, &[not_observed("C-CS1", 0x140004000)]).unwrap();
        assert!(!contributes_to_score(&conf_not_observed));
    }
}
