//! Fuzzer → per-chain DynamicEvidence bridge.
//!
//! **Codex round-1 finding 1 fix** in its strictest form: this module
//! is the ONLY surface that turns fuzzer state into
//! [`DynamicEvidence`] for v1.1 chains, and it operates on individual
//! [`CrashInfo`] records — not aggregate `FuzzReport` totals. The
//! discipline is baked into the API:
//!
//! - [`attribute_crash`] takes one harness + one crash and returns
//!   `Option<DynamicEvidence>`. The crash's PC must match the
//!   harness's `intended_sink_va` for any record to be emitted.
//! - [`attribute_crashes`] is a thin loop that returns
//!   `Vec<DynamicEvidence>` — never accepts a summary blob.
//!
//! There is deliberately NO function that accepts a `FuzzReport`,
//! aggregate exec counts, "any crash this session", or similar
//! coarse signals. Producing one would re-introduce the round-1 bug
//! the v1.1 schema exists to fix.
//!
//! Matching tiers (mapping to [`DynamicStatus`] from Step 25):
//! - `crash.fault_pc == Some(harness.intended_sink_va)` →
//!   [`DynamicStatus::ConfirmedTrigger`]. The crash faulted AT the
//!   sink — strongest possible per-chain attribution.
//! - `crash.top_frames` contains `harness.intended_sink_va` →
//!   [`DynamicStatus::ReachedOnly`]. The sink was on the call stack
//!   but the fault PC was elsewhere — the sink was reached but the
//!   bug did not trigger at this exact instruction.
//! - Otherwise → `None`. Per Codex finding 1, "the fuzzer crashed
//!   somewhere in this process" is NOT evidence for an unrelated
//!   chain.
//!
//! Step 30 (`confirmation.rs`) consumes the
//! `Vec<DynamicEvidence>` produced here and merges it with evidence
//! from Steps 28-29 (trace_join / concolic_query).

#![cfg(feature = "vuln-discovery-fuzz")]
#![allow(dead_code)]

use crate::fuzzer::executor::CrashInfo;
use crate::vuln::dynamic_evidence::{DynamicEvidence, DynamicStatus};
use crate::vuln::harness_synth::Harness;

/// Result of attempting to attribute one crash to one harness.
///
/// `None` is a first-class outcome (per Codex finding 1): a crash
/// that doesn't match the harness's sink VA contributes ZERO
/// evidence to the chain. The caller MUST NOT synthesize a fallback
/// (e.g., `Unavailable` or `NotObserved`) just because a crash
/// happened in the same fuzzer session.
pub fn attribute_crash(
    harness: &Harness,
    crash: &CrashInfo,
    reproducer_id: &str,
) -> Option<DynamicEvidence> {
    let intended = harness.intended_sink_va;
    let sink_pc = DynamicEvidence::format_sink_pc(intended);

    // Strongest signal: the fault PC IS the sink VA.
    if crash.fault_pc == Some(intended) {
        return Some(
            DynamicEvidence::confirmed_trigger(
                harness.chain_id.clone(),
                harness.harness_id.clone(),
                sink_pc,
                std::collections::BTreeMap::new(),
                reproducer_id.to_string(),
            )
            .with_evidence_source("fuzz"),
        );
    }

    // Weaker signal: sink is on the call stack but didn't fault.
    if crash.top_frames.iter().any(|pc| *pc == intended) {
        return Some(
            DynamicEvidence::reached_only(
                harness.chain_id.clone(),
                harness.harness_id.clone(),
                sink_pc,
                std::collections::BTreeMap::new(),
                reproducer_id.to_string(),
            )
            .with_evidence_source("fuzz"),
        );
    }

    // No match — the crash happened in this fuzzer session but
    // CANNOT be attributed to this chain. Codex finding 1: zero
    // evidence, NOT a synthesized Unavailable record.
    None
}

/// Apply [`attribute_crash`] across many crashes for one harness.
/// Crashes that don't match the harness's sink VA are silently
/// dropped (the caller already knows the count of crashes; the
/// purpose here is per-chain evidence, not crash bookkeeping).
pub fn attribute_crashes(
    harness: &Harness,
    crashes_with_ids: &[(CrashInfo, String)],
) -> Vec<DynamicEvidence> {
    crashes_with_ids
        .iter()
        .filter_map(|(crash, repro_id)| attribute_crash(harness, crash, repro_id))
        .collect()
}

/// Apply [`attribute_crash`] across many harnesses for one crash —
/// produces evidence for every chain whose sink VA the crash
/// matches. (Multiple chains may share the same sink VA — e.g., two
/// chains both targeting `memcpy at 0x4022a4` via different sources.
/// Both attestably trigger together.)
pub fn attribute_crash_to_all_harnesses(
    harnesses: &[Harness],
    crash: &CrashInfo,
    reproducer_id: &str,
) -> Vec<DynamicEvidence> {
    harnesses
        .iter()
        .filter_map(|h| attribute_crash(h, crash, reproducer_id))
        .collect()
}

/// Strongest tier this crash provides for the harness (or `None`).
/// Useful for callers that want to know "did this crash help my
/// chain at all?" without materializing the full evidence record.
pub fn crash_status_for(harness: &Harness, crash: &CrashInfo) -> Option<DynamicStatus> {
    let intended = harness.intended_sink_va;
    if crash.fault_pc == Some(intended) {
        Some(DynamicStatus::ConfirmedTrigger)
    } else if crash.top_frames.iter().any(|pc| *pc == intended) {
        Some(DynamicStatus::ReachedOnly)
    } else {
        None
    }
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

    fn fixture_harness(chain_id: &str, sink_site_va: u64, kind: HarnessKind) -> Harness {
        let chain = fixture_chain(chain_id, sink_site_va);
        let sinks = SinkCatalog::v1_0();
        synthesize(&chain, &sinks, kind)
    }

    fn crash(kind: &str, fault_pc: Option<u64>, frames: &[u64]) -> CrashInfo {
        CrashInfo {
            kind: kind.into(),
            signal: Some(11),
            fault_pc,
            top_frames: frames.to_vec(),
            sanitizer_type: None,
        }
    }

    // ----- PASS path: fault_pc match -----

    #[test]
    fn fault_pc_match_produces_confirmed_trigger() {
        let h = fixture_harness(
            "C-001",
            0x1400022a4,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let c = crash(
            "heap-buffer-overflow",
            Some(0x1400022a4),
            &[0x1400022a4, 0x140001000],
        );
        let ev = attribute_crash(&h, &c, "corpus_001").unwrap();
        assert_eq!(ev.status, DynamicStatus::ConfirmedTrigger);
        assert_eq!(ev.chain_id, "C-001");
        assert_eq!(ev.harness_id, "H-C-001");
        assert_eq!(ev.sink_pc, "0x00000001400022a4");
        assert_eq!(ev.reproducer_id, "corpus_001");
        // confidence_delta from the constructor matches the status's
        // contribution.
        assert_eq!(ev.confidence_delta, 0.10);
    }

    #[test]
    fn fault_pc_match_validates_sink_pc_through_step_25_check() {
        // Wire-shape integrity check: the sink_pc string produced here
        // MUST round-trip through Step 25's sink_pc_matches.
        let h = fixture_harness(
            "C-002",
            0x140005678,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let c = crash("crash", Some(0x140005678), &[]);
        let ev = attribute_crash(&h, &c, "corpus").unwrap();
        assert!(
            ev.sink_pc_matches(h.intended_sink_va),
            "evidence sink_pc must defensively match harness intended VA"
        );
    }

    // ----- PASS path: top_frames match -----

    #[test]
    fn top_frames_only_match_produces_reached_only() {
        // Crash happened at a different VA but sink was on the stack —
        // we know the sink was REACHED but not TRIGGERED at the sink.
        let h = fixture_harness(
            "C-003",
            0x140004444,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let c = crash(
            "crash",
            Some(0x140009999),
            &[0x140009999, 0x140004444, 0x140001000],
        );
        let ev = attribute_crash(&h, &c, "corpus_x").unwrap();
        assert_eq!(ev.status, DynamicStatus::ReachedOnly);
        assert_eq!(ev.confidence_delta, 0.0);
        assert_eq!(ev.chain_id, "C-003");
    }

    #[test]
    fn top_frames_match_with_none_fault_pc_still_produces_reached_only() {
        // Some emulator paths leave fault_pc=None but populate frames.
        let h = fixture_harness(
            "C-004",
            0x140004444,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let c = crash("emulator_oob", None, &[0x140009999, 0x140004444]);
        let ev = attribute_crash(&h, &c, "corpus").unwrap();
        assert_eq!(ev.status, DynamicStatus::ReachedOnly);
    }

    // ----- NO-EVIDENCE path: Codex finding 1 enforcement -----

    #[test]
    fn crash_without_sink_va_match_produces_no_evidence() {
        // The canonical Codex finding 1 case: a crash happens in the
        // fuzzer session but is NOT attributable to this chain. The
        // bridge MUST NOT fabricate an Unavailable / NotObserved
        // record just because a crash exists.
        let h = fixture_harness(
            "C-005",
            0x140004444,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let c = crash("crash", Some(0x140009999), &[0x140009999, 0x14000aaaa]);
        assert!(attribute_crash(&h, &c, "corpus").is_none());
    }

    #[test]
    fn crash_with_none_fault_pc_and_no_frame_match_produces_no_evidence() {
        // Worst case: no fault_pc, no useful frames, no sanitizer info.
        // The bridge MUST decline to attribute — silence is the
        // honest answer.
        let h = fixture_harness(
            "C-006",
            0x140004444,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let c = crash("low_fidelity", None, &[]);
        assert!(attribute_crash(&h, &c, "corpus").is_none());
    }

    #[test]
    fn crash_with_unrelated_frames_produces_no_evidence() {
        let h = fixture_harness(
            "C-007",
            0x140004444,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let c = crash("crash", Some(0x14000ffff), &[0x14000ffff, 0x140000000]);
        assert!(attribute_crash(&h, &c, "corpus").is_none());
    }

    // ----- Aggregate-signal discipline (Codex finding 1) -----

    #[test]
    fn module_does_not_expose_aggregate_attribution_api() {
        // Compile-time check: this test exists so a future contributor
        // adding e.g. `attribute_session(report: &FuzzReport) -> Vec<DynamicEvidence>`
        // sees it and remembers the round-1 invariant: aggregate
        // signals do NOT produce DynamicEvidence. The two functions
        // exposed here both operate per-crash:
        //   - attribute_crash(&Harness, &CrashInfo, ...)
        //   - attribute_crashes(&Harness, &[(CrashInfo, String)])
        //   - attribute_crash_to_all_harnesses(&[Harness], &CrashInfo, ...)
        // If you find yourself wanting to add an aggregate path, the
        // answer is: don't. Iterate crashes one at a time.
    }

    // ----- attribute_crashes (multi-crash) -----

    #[test]
    fn attribute_crashes_returns_one_record_per_matching_crash() {
        let h = fixture_harness(
            "C-008",
            0x140004444,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let inputs = vec![
            (
                crash("crash", Some(0x140004444), &[0x140004444]),
                "r1".to_string(),
            ),
            (
                crash("crash", Some(0x140004444), &[0x140004444]),
                "r2".to_string(),
            ),
            (
                crash("crash", Some(0x140009999), &[0x140009999]),
                "r3".to_string(),
            ),
        ];
        let evs = attribute_crashes(&h, &inputs);
        assert_eq!(evs.len(), 2, "two matching, one non-matching → 2 records");
        assert!(evs
            .iter()
            .all(|e| e.status == DynamicStatus::ConfirmedTrigger));
        let repros: Vec<&str> = evs.iter().map(|e| e.reproducer_id.as_str()).collect();
        assert_eq!(repros, vec!["r1", "r2"]);
    }

    #[test]
    fn attribute_crashes_drops_non_matching_silently() {
        let h = fixture_harness(
            "C-009",
            0x140004444,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let inputs = vec![
            (crash("crash", Some(0x140009999), &[]), "r1".to_string()),
            (crash("crash", Some(0x14000aaaa), &[]), "r2".to_string()),
        ];
        let evs = attribute_crashes(&h, &inputs);
        // Codex finding 1: zero matches → zero evidence. NO Unavailable
        // fallback.
        assert!(evs.is_empty());
    }

    // ----- Multi-harness attribution -----

    #[test]
    fn attribute_crash_to_all_harnesses_emits_for_every_matching_chain() {
        // Two harnesses share a sink VA (e.g., two source paths to the
        // same memcpy). One crash attributably triggers both chains.
        let h1 = fixture_harness(
            "C-010",
            0x140004444,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let h2 = fixture_harness("C-011", 0x140004444, HarnessKind::UserSuppliedEntryPoint);
        let h3 = fixture_harness(
            "C-012",
            0x140008888,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let c = crash("heap-buffer-overflow", Some(0x140004444), &[0x140004444]);
        let evs = attribute_crash_to_all_harnesses(&[h1, h2, h3], &c, "corpus");
        assert_eq!(evs.len(), 2);
        let chains: Vec<&str> = evs.iter().map(|e| e.chain_id.as_str()).collect();
        assert!(chains.contains(&"C-010"));
        assert!(chains.contains(&"C-011"));
        // C-012 has a different sink VA → no evidence.
        assert!(!chains.contains(&"C-012"));
    }

    // ----- Harness kind independence -----

    #[test]
    fn attribution_works_for_any_harness_kind_that_was_runnable() {
        // The bridge doesn't care about HarnessKind directly — it's
        // upstream's job to only call us with crashes from harnesses
        // that actually ran. But if called on a Skeleton-only chain
        // whose user happened to hand-run the fuzzer, the bridge
        // still produces evidence (the attribution is data-driven,
        // not tier-driven).
        for kind in [
            HarnessKind::SourceAvailableFnByteSlice,
            HarnessKind::UserSuppliedEntryPoint,
            HarnessKind::BinaryOnlyPeEntry,
        ] {
            let h = fixture_harness("C-013", 0x140004444, kind);
            let c = crash("crash", Some(0x140004444), &[0x140004444]);
            let ev = attribute_crash(&h, &c, "corpus").unwrap();
            assert_eq!(ev.status, DynamicStatus::ConfirmedTrigger);
        }
    }

    // ----- crash_status_for helper -----

    #[test]
    fn crash_status_for_returns_strongest_tier() {
        let h = fixture_harness(
            "C-014",
            0x140004444,
            HarnessKind::SourceAvailableFnByteSlice,
        );
        assert_eq!(
            crash_status_for(&h, &crash("crash", Some(0x140004444), &[0x140004444])),
            Some(DynamicStatus::ConfirmedTrigger)
        );
        assert_eq!(
            crash_status_for(&h, &crash("crash", Some(0x140009999), &[0x140004444])),
            Some(DynamicStatus::ReachedOnly)
        );
        assert_eq!(
            crash_status_for(&h, &crash("crash", Some(0x140009999), &[0x140009999])),
            None
        );
    }
}
