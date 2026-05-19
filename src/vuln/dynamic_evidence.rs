//! Per-chain dynamic-evidence schema — **Codex round-1 finding 1 fix**.
//!
//! v1.0 emitted chains with static-only evidence. v1.1 (Steps 25-36)
//! adds dynamic confirmation via three sources:
//! - **Fuzzer crashes** (`fuzz_bridge.rs`, Step 27) — `ConfirmedTrigger`
//!   when a crash's PC matches the chain's `sink_site_va`.
//! - **ETW trace events** (`trace_join.rs`, Step 28) — `ReachedOnly`
//!   when an event's `(image_hash, function_va)` matches the chain's
//!   `sink_function`.
//! - **Concolic SAT proofs** (`concolic_query.rs`, Step 29) —
//!   `ReachedOnly` when the solver model for the chain's guards +
//!   sink condition is satisfiable, with `observed_argument_values`
//!   populated from the model.
//!
//! **The invariant** (Codex finding 1): aggregate signals — process-
//! level matches, `FuzzReport` totals, "any trace event in this
//! process" — CANNOT produce confidence. The producing code MUST
//! emit a `DynamicEvidence` record with a `chain_id` matching the
//! chain AND a `sink_pc` matching the chain's `sink_site_va`. The
//! scoring formula in Step 30 (`confirmation.rs`) validates the
//! `sink_pc` match via [`DynamicEvidence::sink_pc_matches`] before
//! applying any dynamic factor; mismatched evidence contributes
//! zero by construction.
//!
//! The four-variant [`DynamicStatus`] enum makes "no per-chain
//! attribution available" structurally distinct from "ran but didn't
//! reach the sink". Both score 0.0, but the wire shape lets the LLM
//! consumer distinguish "not tried" from "tried and failed".

#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Status of the per-chain dynamic confirmation attempt.
///
/// Scoring contribution:
/// - `ConfirmedTrigger` → `dynamic_evidence_score = 1.0`,
///   `confidence_delta = +0.10`.
/// - `ReachedOnly` → `dynamic_evidence_score = 0.5`,
///   `confidence_delta = 0.0`.
/// - `NotObserved` and `Unavailable` → both `0.0`.
///
/// `NotObserved` vs `Unavailable` are both zero-weight but carry
/// distinct meaning for the LLM consumer:
/// - `NotObserved` = a confirmation attempt was made (harness ran,
///   trace was captured, solver was queried) but the sink wasn't
///   reached / triggered.
/// - `Unavailable` = no confirmation attempt was possible (no
///   harness available for this chain, no trace data, no concolic
///   backend enabled).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DynamicStatus {
    /// Fuzzer or trace observed the sink being TRIGGERED with the
    /// expected bug shape (e.g. memcpy with `byte_count > destination_size`).
    /// Full v1.1 scoring weight.
    ConfirmedTrigger,
    /// Fuzzer / trace / concolic observed the sink being REACHED
    /// (called) but not triggered with the bug shape. Half v1.1
    /// scoring weight.
    ReachedOnly,
    /// Confirmation backend ran but the sink wasn't reached. Zero
    /// weight; recorded so the LLM consumer can distinguish
    /// "tried but didn't reach" from "didn't try".
    NotObserved,
    /// No confirmation backend was available for this chain (no
    /// harness, no trace data, no concolic). Zero weight.
    Unavailable,
}

impl DynamicStatus {
    /// v1.1 scoring weight for this status. Multiplied by the
    /// dynamic-evidence-score weight (1.6) in the v1.1 scoring
    /// formula.
    pub fn scoring_weight(&self) -> f32 {
        match self {
            Self::ConfirmedTrigger => 1.0,
            Self::ReachedOnly => 0.5,
            Self::NotObserved => 0.0,
            Self::Unavailable => 0.0,
        }
    }

    /// `true` iff this status produces a non-zero dynamic factor in
    /// the v1.1 scoring formula. False for `NotObserved` and
    /// `Unavailable`.
    pub fn contributes_to_score(&self) -> bool {
        matches!(self, Self::ConfirmedTrigger | Self::ReachedOnly)
    }

    /// v1.1 scoring `confidence_delta`: `+0.10` only for
    /// `ConfirmedTrigger`, zero otherwise. The clamp in scoring
    /// applies after this delta is added to the base confidence.
    pub fn confidence_delta(&self) -> f32 {
        match self {
            Self::ConfirmedTrigger => 0.10,
            _ => 0.0,
        }
    }
}

/// Per-chain dynamic-evidence record.
///
/// **Codex finding 1 invariant**: `sink_pc` MUST match the chain's
/// `sink_site_va` for the evidence to score. The scoring formula in
/// `confirmation.rs` calls [`Self::sink_pc_matches`] as a defensive
/// check; mismatched evidence contributes zero. Aggregate signals
/// that cannot produce a verified `sink_pc` should emit
/// [`DynamicStatus::Unavailable`] records (which always score zero)
/// rather than fake-attributing to a chain.
///
/// Serialized form (matches the plan's v1.1 wire shape on
/// `findings.jsonl`):
///
/// ```json
/// {
///   "chain_id": "F-2026-000173",
///   "harness_id": "H-F-2026-000173-runnable",
///   "sink_pc": "0x00000000004022a4",
///   "status": "confirmed_trigger",
///   "observed_argument_values": { "n": 4096, "dst_capacity_inferred": 1024 },
///   "reproducer_id": "corpus_entry_18432",
///   "confidence_delta": 0.10
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DynamicEvidence {
    /// The `CandidateChain::chain_id` this evidence attributes to.
    /// Producers MUST set this to the chain's actual id; the scoring
    /// formula uses it to look up the chain's expected sink_site_va.
    pub chain_id: String,
    /// The synthesized harness that produced the evidence (Step 26).
    /// Empty string for trace-only or concolic-only attribution
    /// where no harness was needed (the producing source provides
    /// the per-chain attribution via different means).
    pub harness_id: String,
    /// Hex-formatted VA of the sink callsite. Serialized as a
    /// `0x`-prefixed lowercase hex string for LLM consumer
    /// readability. MUST match the chain's `sink_site_va` —
    /// validated by [`Self::sink_pc_matches`].
    pub sink_pc: String,
    /// Per-status confirmation outcome.
    pub status: DynamicStatus,
    /// Explicit source of the evidence. Empty for legacy callers;
    /// current producers use values such as `fuzz`, `trace`,
    /// `concolic`, and `controlled_fixture`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub evidence_source: String,
    /// Observed argument values at the sink call. Keys are
    /// argument-role names from the chain's template (`n`,
    /// `dst_capacity_inferred`, `dst`, `path`, etc.); values are
    /// JSON-typed observations (numeric, string, boolean).
    pub observed_argument_values: BTreeMap<String, serde_json::Value>,
    /// Reference to the input that triggered the evidence:
    /// - Fuzzer crash: corpus entry id (e.g. `"corpus_entry_18432"`).
    /// - ETW trace: event id within the trace dump.
    /// - Concolic: solver-model hash or query id.
    ///
    /// Empty string when not applicable (e.g., `Unavailable`).
    pub reproducer_id: String,
    /// Pre-computed `confidence_delta` from
    /// [`DynamicStatus::confidence_delta`]. Stored here so the LLM
    /// consumer sees the same value the scoring formula used.
    pub confidence_delta: f32,
}

impl DynamicEvidence {
    /// Construct a `ConfirmedTrigger` record. Use this when the
    /// confirmation backend (typically `fuzz_bridge.rs`) observed
    /// the sink being triggered with the bug shape.
    pub fn confirmed_trigger(
        chain_id: impl Into<String>,
        harness_id: impl Into<String>,
        sink_pc: impl Into<String>,
        observed_argument_values: BTreeMap<String, serde_json::Value>,
        reproducer_id: impl Into<String>,
    ) -> Self {
        let status = DynamicStatus::ConfirmedTrigger;
        Self {
            chain_id: chain_id.into(),
            harness_id: harness_id.into(),
            sink_pc: sink_pc.into(),
            status,
            evidence_source: String::new(),
            observed_argument_values,
            reproducer_id: reproducer_id.into(),
            confidence_delta: status.confidence_delta(),
        }
    }

    /// Construct a `ReachedOnly` record. Use this when
    /// `trace_join.rs` matched an ETW event to the chain's
    /// sink_function, or when `concolic_query.rs` proved
    /// satisfiability without observing the bug shape.
    pub fn reached_only(
        chain_id: impl Into<String>,
        harness_id: impl Into<String>,
        sink_pc: impl Into<String>,
        observed_argument_values: BTreeMap<String, serde_json::Value>,
        reproducer_id: impl Into<String>,
    ) -> Self {
        let status = DynamicStatus::ReachedOnly;
        Self {
            chain_id: chain_id.into(),
            harness_id: harness_id.into(),
            sink_pc: sink_pc.into(),
            status,
            evidence_source: String::new(),
            observed_argument_values,
            reproducer_id: reproducer_id.into(),
            confidence_delta: status.confidence_delta(),
        }
    }

    /// Construct a `NotObserved` record. Use this when a
    /// confirmation backend ran (harness executed, trace was
    /// captured) but the sink wasn't reached.
    pub fn not_observed(
        chain_id: impl Into<String>,
        harness_id: impl Into<String>,
        sink_pc: impl Into<String>,
    ) -> Self {
        let status = DynamicStatus::NotObserved;
        Self {
            chain_id: chain_id.into(),
            harness_id: harness_id.into(),
            sink_pc: sink_pc.into(),
            status,
            evidence_source: String::new(),
            observed_argument_values: BTreeMap::new(),
            reproducer_id: String::new(),
            confidence_delta: status.confidence_delta(),
        }
    }

    /// Construct an `Unavailable` record. Use this when no
    /// confirmation backend is available for this chain (no harness
    /// synthesized, no trace captured, no concolic enabled).
    pub fn unavailable(chain_id: impl Into<String>, sink_pc: impl Into<String>) -> Self {
        let status = DynamicStatus::Unavailable;
        Self {
            chain_id: chain_id.into(),
            harness_id: String::new(),
            sink_pc: sink_pc.into(),
            status,
            evidence_source: String::new(),
            observed_argument_values: BTreeMap::new(),
            reproducer_id: String::new(),
            confidence_delta: status.confidence_delta(),
        }
    }

    /// Defensive check that this evidence's `sink_pc` actually
    /// matches the chain's expected `sink_site_va`. Called by the
    /// scoring formula in `confirmation.rs` before applying any
    /// dynamic factor — mismatched evidence contributes ZERO score
    /// regardless of `status`.
    ///
    /// Accepts both `0x`-prefixed and unprefixed hex strings, but
    /// returns `false` for any string that doesn't parse as hex.
    pub fn sink_pc_matches(&self, expected_sink_va: u64) -> bool {
        let normalized = self
            .sink_pc
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        u64::from_str_radix(normalized, 16)
            .map(|va| va == expected_sink_va)
            .unwrap_or(false)
    }

    /// Format a `u64` VA as the canonical hex-string used in
    /// `sink_pc`: `0x`-prefixed, lowercase, zero-padded to 16 hex
    /// chars. Producers should use this to construct `sink_pc` so
    /// the serialized form is uniform across evidence sources.
    pub fn format_sink_pc(va: u64) -> String {
        format!("0x{va:016x}")
    }

    pub fn with_evidence_source(mut self, source: impl Into<String>) -> Self {
        self.evidence_source = source.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- DynamicStatus -----

    #[test]
    fn status_scoring_weight_orders_confirmed_trigger_highest() {
        assert!(
            DynamicStatus::ConfirmedTrigger.scoring_weight()
                > DynamicStatus::ReachedOnly.scoring_weight()
        );
        assert!(
            DynamicStatus::ReachedOnly.scoring_weight()
                > DynamicStatus::NotObserved.scoring_weight()
        );
        assert_eq!(DynamicStatus::ConfirmedTrigger.scoring_weight(), 1.0);
        assert_eq!(DynamicStatus::ReachedOnly.scoring_weight(), 0.5);
        assert_eq!(DynamicStatus::NotObserved.scoring_weight(), 0.0);
        assert_eq!(DynamicStatus::Unavailable.scoring_weight(), 0.0);
    }

    #[test]
    fn only_confirmed_trigger_carries_confidence_delta() {
        assert_eq!(DynamicStatus::ConfirmedTrigger.confidence_delta(), 0.10);
        assert_eq!(DynamicStatus::ReachedOnly.confidence_delta(), 0.0);
        assert_eq!(DynamicStatus::NotObserved.confidence_delta(), 0.0);
        assert_eq!(DynamicStatus::Unavailable.confidence_delta(), 0.0);
    }

    #[test]
    fn only_confirmed_and_reached_contribute_to_score() {
        // Codex finding 1 enforcement: aggregate-style signals end up
        // as Unavailable (no per-chain attribution) and contribute
        // zero. Only the per-chain-attributed statuses count.
        assert!(DynamicStatus::ConfirmedTrigger.contributes_to_score());
        assert!(DynamicStatus::ReachedOnly.contributes_to_score());
        assert!(!DynamicStatus::NotObserved.contributes_to_score());
        assert!(!DynamicStatus::Unavailable.contributes_to_score());
    }

    #[test]
    fn status_round_trips_through_json_with_snake_case() {
        for status in [
            DynamicStatus::ConfirmedTrigger,
            DynamicStatus::ReachedOnly,
            DynamicStatus::NotObserved,
            DynamicStatus::Unavailable,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: DynamicStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn status_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&DynamicStatus::ConfirmedTrigger).unwrap(),
            "\"confirmed_trigger\""
        );
        assert_eq!(
            serde_json::to_string(&DynamicStatus::ReachedOnly).unwrap(),
            "\"reached_only\""
        );
        assert_eq!(
            serde_json::to_string(&DynamicStatus::NotObserved).unwrap(),
            "\"not_observed\""
        );
        assert_eq!(
            serde_json::to_string(&DynamicStatus::Unavailable).unwrap(),
            "\"unavailable\""
        );
    }

    // ----- DynamicEvidence constructors -----

    #[test]
    fn confirmed_trigger_constructor_sets_status_and_delta() {
        let mut observed = BTreeMap::new();
        observed.insert("n".into(), serde_json::json!(4096));
        let ev = DynamicEvidence::confirmed_trigger("F-1", "H-1", "0x401234", observed, "corpus-1");
        assert_eq!(ev.status, DynamicStatus::ConfirmedTrigger);
        assert_eq!(ev.confidence_delta, 0.10);
        assert_eq!(ev.observed_argument_values.len(), 1);
        assert_eq!(ev.reproducer_id, "corpus-1");
    }

    #[test]
    fn reached_only_constructor_sets_status_and_zero_delta() {
        let ev = DynamicEvidence::reached_only("F-1", "H-1", "0x401234", BTreeMap::new(), "ev-7");
        assert_eq!(ev.status, DynamicStatus::ReachedOnly);
        assert_eq!(ev.confidence_delta, 0.0);
    }

    #[test]
    fn not_observed_constructor_has_zero_delta_and_empty_observations() {
        let ev = DynamicEvidence::not_observed("F-1", "H-1", "0x401234");
        assert_eq!(ev.status, DynamicStatus::NotObserved);
        assert_eq!(ev.confidence_delta, 0.0);
        assert!(ev.observed_argument_values.is_empty());
        assert!(ev.reproducer_id.is_empty());
    }

    #[test]
    fn unavailable_constructor_has_zero_delta_and_no_harness() {
        let ev = DynamicEvidence::unavailable("F-1", "0x401234");
        assert_eq!(ev.status, DynamicStatus::Unavailable);
        assert_eq!(ev.confidence_delta, 0.0);
        assert!(ev.harness_id.is_empty());
        assert!(ev.observed_argument_values.is_empty());
        assert!(ev.reproducer_id.is_empty());
    }

    // ----- sink_pc match (Codex finding 1 defensive check) -----

    #[test]
    fn sink_pc_matches_compares_hex_string_to_u64() {
        let ev =
            DynamicEvidence::confirmed_trigger("F-1", "H-1", "0x4022a4", BTreeMap::new(), "c-1");
        assert!(ev.sink_pc_matches(0x4022a4));
        assert!(!ev.sink_pc_matches(0x4022a5));
    }

    #[test]
    fn sink_pc_matches_accepts_unprefixed_hex() {
        let ev = DynamicEvidence::confirmed_trigger("F-1", "H-1", "4022a4", BTreeMap::new(), "c-1");
        assert!(ev.sink_pc_matches(0x4022a4));
    }

    #[test]
    fn sink_pc_matches_accepts_uppercase_0x_prefix() {
        let ev =
            DynamicEvidence::confirmed_trigger("F-1", "H-1", "0X4022A4", BTreeMap::new(), "c-1");
        assert!(ev.sink_pc_matches(0x4022a4));
    }

    #[test]
    fn sink_pc_matches_returns_false_for_garbage_pc() {
        let ev =
            DynamicEvidence::confirmed_trigger("F-1", "H-1", "not-a-hex", BTreeMap::new(), "c-1");
        // Codex finding 1 invariant: garbage pc => mismatch =>
        // scoring formula MUST contribute zero even though
        // status=ConfirmedTrigger.
        assert!(!ev.sink_pc_matches(0x4022a4));
    }

    #[test]
    fn format_sink_pc_produces_canonical_form() {
        assert_eq!(
            DynamicEvidence::format_sink_pc(0x4022a4),
            "0x00000000004022a4"
        );
        assert_eq!(
            DynamicEvidence::format_sink_pc(0xffffffffffffffff),
            "0xffffffffffffffff"
        );
        assert_eq!(DynamicEvidence::format_sink_pc(0), "0x0000000000000000");
    }

    #[test]
    fn format_sink_pc_round_trips_through_sink_pc_matches() {
        for va in [0u64, 1, 0x1000, 0x140001234, 0xffffffffffffffff] {
            let ev = DynamicEvidence::confirmed_trigger(
                "F-1",
                "H-1",
                DynamicEvidence::format_sink_pc(va),
                BTreeMap::new(),
                "c-1",
            );
            assert!(ev.sink_pc_matches(va), "VA 0x{va:x} should round-trip");
        }
    }

    // ----- Full wire-shape round-trip -----

    #[test]
    fn round_trips_through_json_with_full_payload() {
        let mut observed = BTreeMap::new();
        observed.insert("n".into(), serde_json::json!(4096));
        observed.insert("dst_capacity_inferred".into(), serde_json::json!(1024));
        observed.insert("dst".into(), serde_json::json!("0x140001234"));
        let ev = DynamicEvidence::confirmed_trigger(
            "F-2026-000173",
            "H-F-2026-000173-runnable",
            DynamicEvidence::format_sink_pc(0x4022a4),
            observed,
            "corpus_entry_18432",
        );
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"status\":\"confirmed_trigger\""));
        assert!(json.contains("\"chain_id\":\"F-2026-000173\""));
        assert!(json.contains("\"sink_pc\":\"0x00000000004022a4\""));
        assert!(json.contains("\"reproducer_id\":\"corpus_entry_18432\""));
        let back: DynamicEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn jsonl_round_trip_preserves_all_four_status_variants() {
        let cases = vec![
            DynamicEvidence::confirmed_trigger(
                "F-1",
                "H-1",
                DynamicEvidence::format_sink_pc(0x401000),
                BTreeMap::new(),
                "r-1",
            ),
            DynamicEvidence::reached_only(
                "F-2",
                "H-2",
                DynamicEvidence::format_sink_pc(0x402000),
                BTreeMap::new(),
                "r-2",
            ),
            DynamicEvidence::not_observed("F-3", "H-3", DynamicEvidence::format_sink_pc(0x403000)),
            DynamicEvidence::unavailable("F-4", DynamicEvidence::format_sink_pc(0x404000)),
        ];
        let lines: Vec<String> = cases
            .iter()
            .map(|ev| serde_json::to_string(ev).unwrap())
            .collect();
        for (ev, line) in cases.iter().zip(lines.iter()) {
            let back: DynamicEvidence = serde_json::from_str(line).unwrap();
            assert_eq!(back, *ev);
        }
    }
}
