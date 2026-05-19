//! ETW trace → per-chain DynamicEvidence join.
//!
//! **Codex round-1 finding 1 fix** for the dynamic-trace path. The
//! round-1 review flagged "a trace event in this process" as
//! insufficient attribution: many chains share a process; a
//! `network.connect` event in `cmd.exe` does NOT prove anything
//! about a `recv → memcpy` chain in `cmd.exe`. The fix: this module
//! requires BOTH a process-level match (`event.process_hash`
//! matches the chain's image hash) AND a per-function match (an
//! event `static_ref` references the chain's `sink_function_va`).
//! Process-only matches produce zero evidence.
//!
//! Why `ReachedOnly` (never `ConfirmedTrigger`):
//!
//! Trace events don't have crash semantics — they say "this API was
//! invoked in this process at this time", not "the sink triggered
//! with the bug shape". Without v1.1's deferred stack-walking, the
//! per-function attribution comes from
//! [`crate::dynamic_trace::event::TraceEvent::static_refs`]
//! decoration during ingest, which is function-resolution not
//! instruction-resolution. So every trace_join match is
//! [`crate::vuln::dynamic_evidence::DynamicStatus::ReachedOnly`]
//! (half weight in v1.1 scoring) — the status enum from Step 25
//! encodes exactly this resolution gap.
//!
//! `observed_argument_values` is populated from the event's `args`
//! map verbatim — those are the runtime values the dynamic
//! collector captured at the call site, which is exactly the
//! information the LLM consumer needs to reason about the bug.

#![cfg(feature = "vuln-discovery-trace")]
#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::dynamic_trace::event::TraceEvent;
use crate::facts::evidence::EvidenceRef;
use crate::vuln::dynamic_evidence::DynamicEvidence;
use crate::vuln::harness_synth::Harness;

/// Try to attribute one trace event to one harness's chain.
///
/// `expected_image_hash` is the BLAKE3 hash of the analyzed PE — the
/// caller (Step 36 session orchestrator) computes this once per run.
/// An empty string means "no image-hash check" but the plan
/// explicitly forbids that path; we still validate it programmatically
/// for diagnostic clarity.
///
/// Returns `None` when ANY of the following hold:
/// - `expected_image_hash` is empty (no process-level filter possible).
/// - `event.process_hash` is `None` or doesn't equal
///   `expected_image_hash`.
/// - None of `event.static_refs` reference the chain's
///   `sink_function_va`.
///
/// Per Codex finding 1, returning `None` is the correct outcome —
/// the caller MUST NOT fabricate an `Unavailable` or `NotObserved`
/// record from this absence.
pub fn attribute_event(
    harness: &Harness,
    expected_image_hash: &str,
    event: &TraceEvent,
) -> Option<DynamicEvidence> {
    // Process-level gate — empty hash means "I have no way to
    // discriminate processes", which is exactly the Codex-finding-1
    // bad shape. Reject explicitly.
    if expected_image_hash.is_empty() {
        return None;
    }
    if event.process_hash.as_deref() != Some(expected_image_hash) {
        return None;
    }

    // Per-function gate — at least one static_ref must reference
    // the sink function.
    if !any_ref_targets_function(&event.static_refs, harness.sink_function_va) {
        return None;
    }

    // Mirror the event's args into observed_argument_values. The
    // map is consumed by the LLM analyst (Step 33) to suggest tests
    // / patches keyed off the observed runtime values.
    let observed_argument_values: BTreeMap<String, serde_json::Value> = event.args.clone();

    let sink_pc = DynamicEvidence::format_sink_pc(harness.intended_sink_va);
    Some(
        DynamicEvidence::reached_only(
            harness.chain_id.clone(),
            harness.harness_id.clone(),
            sink_pc,
            observed_argument_values,
            event.event_id.clone(),
        )
        .with_evidence_source("trace"),
    )
}

/// Apply [`attribute_event`] across many events for one harness.
/// Events that don't match are silently dropped.
pub fn attribute_events(
    harness: &Harness,
    expected_image_hash: &str,
    events: &[TraceEvent],
) -> Vec<DynamicEvidence> {
    events
        .iter()
        .filter_map(|e| attribute_event(harness, expected_image_hash, e))
        .collect()
}

/// Apply [`attribute_event`] across many harnesses for one event —
/// produces evidence for every chain whose sink function the event
/// references. (Multiple chains may share a sink function — e.g.,
/// two chains targeting different calls inside the same wrapper.)
pub fn attribute_event_to_all_harnesses(
    harnesses: &[Harness],
    expected_image_hash: &str,
    event: &TraceEvent,
) -> Vec<DynamicEvidence> {
    harnesses
        .iter()
        .filter_map(|h| attribute_event(h, expected_image_hash, event))
        .collect()
}

/// Does any `static_ref` in `refs` reference an address inside the
/// function whose entry VA is `function_va`?
///
/// Matching rules:
/// - `Instruction { va }` / `RawAddr { va }` / `Section { va, .. }`:
///   exact match on `function_va`.
/// - `Range { start_va, end_va }`: half-open `[start_va, end_va)`
///   contains `function_va`.
/// - `Artifact { entity_kind: "function", id }`: id contains the
///   16-char lowercase hex of `function_va`.
/// - `DebugRecord`, `TraceEvent`: never match (no VA).
///
/// The exact-VA match for `Instruction`/`RawAddr` is intentional:
/// without a complete function-range table here, conflating "any VA
/// in the binary" with "this function" would over-credit. Step 9 of
/// the dynamic_trace pipeline (symbolicate decoration) emits
/// `Range` for stack-walked frames and `Instruction` for direct
/// call attribution — both shapes match cleanly above.
pub fn any_ref_targets_function(refs: &[EvidenceRef], function_va: u64) -> bool {
    let function_hex = format!("{function_va:016x}");
    refs.iter().any(|r| match r {
        EvidenceRef::Instruction { va }
        | EvidenceRef::RawAddr { va }
        | EvidenceRef::Section { va, .. } => *va == function_va,
        EvidenceRef::Range { start_va, end_va } => {
            *start_va <= function_va && function_va < *end_va
        }
        EvidenceRef::Artifact { entity_kind, id } => {
            (entity_kind == "function" || entity_kind == "function_symbol")
                && id.to_lowercase().contains(&function_hex)
        }
        EvidenceRef::DebugRecord { .. } | EvidenceRef::TraceEvent { .. } => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic_trace::event::{EntityRef, EventSource, EventType, HostOs, TraceEvent};
    use crate::vuln::dynamic_evidence::DynamicStatus;
    use crate::vuln::harness_synth::{synthesize, HarnessKind};
    use crate::vuln::query::CandidateChain;
    use crate::vuln::sinks::SinkCatalog;
    use crate::vuln::taint::PropagationMode;

    fn fixture_chain(sink_function_va: u64) -> CandidateChain {
        CandidateChain {
            chain_id: "C-T-001".into(),
            template_id: "unchecked_copy_length".into(),
            source_kind: "network_recv".into(),
            source_function_va: 0x140001000,
            source_site_va: 0x140001100,
            sink_api: "memcpy".into(),
            sink_function_va,
            sink_site_va: sink_function_va + 0x100,
            propagation_mode: PropagationMode::Summary,
            hop_count: 2,
            dominating_guard_count: 1,
            matched_integer_pattern: false,
        }
    }

    fn fixture_harness(sink_function_va: u64) -> Harness {
        synthesize(
            &fixture_chain(sink_function_va),
            &SinkCatalog::v1_0(),
            HarnessKind::SourceAvailableFnByteSlice,
        )
    }

    fn fixture_event(process_hash: Option<&str>, refs: Vec<EvidenceRef>) -> TraceEvent {
        let mut ev = TraceEvent::new(
            "evt_0000000042",
            "blake3:run",
            1_000_000,
            HostOs::Windows,
            EventSource::Etw,
            4210,
            4214,
            EventType::NetworkRecv,
            "recv",
            EntityRef::process(4210, "2026-05-17T00:00:00Z", Some("target.exe")),
        );
        ev.process_image = Some("C:\\target.exe".into());
        ev.process_hash = process_hash.map(|s| s.to_string());
        ev.static_refs = refs;
        ev.args.insert("byte_count".into(), serde_json::json!(1024));
        ev.args
            .insert("buffer".into(), serde_json::json!("0x140001000"));
        ev
    }

    // ----- PASS path -----

    #[test]
    fn full_match_produces_reached_only_with_event_args_mirrored() {
        let h = fixture_harness(0x140002000);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::Instruction { va: 0x140002000 }],
        );
        let result = attribute_event(&h, "blake3:target", &ev).unwrap();
        assert_eq!(result.status, DynamicStatus::ReachedOnly);
        // Trace evidence never carries ConfirmedTrigger weight — that's
        // structural per Codex finding 1.
        assert_eq!(result.confidence_delta, 0.0);
        // event.args are mirrored verbatim so the LLM analyst can use
        // the observed runtime values.
        assert_eq!(
            result.observed_argument_values.get("byte_count").unwrap(),
            &serde_json::json!(1024)
        );
        assert_eq!(
            result.observed_argument_values.get("buffer").unwrap(),
            &serde_json::json!("0x140001000")
        );
        assert_eq!(result.reproducer_id, "evt_0000000042");
    }

    #[test]
    fn function_match_via_raw_addr_static_ref() {
        let h = fixture_harness(0x140002000);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::RawAddr { va: 0x140002000 }],
        );
        assert!(attribute_event(&h, "blake3:target", &ev).is_some());
    }

    #[test]
    fn function_match_via_range_static_ref() {
        let h = fixture_harness(0x140002500);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::Range {
                start_va: 0x140002000,
                end_va: 0x140002800,
            }],
        );
        assert!(attribute_event(&h, "blake3:target", &ev).is_some());
    }

    #[test]
    fn function_match_via_artifact_static_ref_with_hex_id() {
        let h = fixture_harness(0x140012a40);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::Artifact {
                entity_kind: "function".into(),
                id: "func:0000000140012a40".into(),
            }],
        );
        assert!(attribute_event(&h, "blake3:target", &ev).is_some());
    }

    #[test]
    fn function_match_via_function_symbol_artifact() {
        let h = fixture_harness(0x140012a40);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::Artifact {
                entity_kind: "function_symbol".into(),
                id: "sym:foo@0000000140012a40".into(),
            }],
        );
        assert!(attribute_event(&h, "blake3:target", &ev).is_some());
    }

    // ----- Codex finding 1 enforcement: process-only or function-only
    // ----- matches MUST produce no evidence.

    #[test]
    fn process_only_match_without_function_ref_produces_no_evidence() {
        // The canonical Codex finding 1 anti-pattern: a trace event in
        // the target process, but no reference to the chain's sink
        // function. MUST produce nothing.
        let h = fixture_harness(0x140002000);
        let ev = fixture_event(Some("blake3:target"), vec![]);
        assert!(attribute_event(&h, "blake3:target", &ev).is_none());
    }

    #[test]
    fn function_only_match_in_wrong_process_produces_no_evidence() {
        // Wrong process: process_hash mismatch → reject even if the
        // event somehow references the right function VA.
        let h = fixture_harness(0x140002000);
        let ev = fixture_event(
            Some("blake3:OTHER"),
            vec![EvidenceRef::Instruction { va: 0x140002000 }],
        );
        assert!(attribute_event(&h, "blake3:target", &ev).is_none());
    }

    #[test]
    fn no_process_hash_on_event_produces_no_evidence() {
        let h = fixture_harness(0x140002000);
        let ev = fixture_event(None, vec![EvidenceRef::Instruction { va: 0x140002000 }]);
        assert!(attribute_event(&h, "blake3:target", &ev).is_none());
    }

    #[test]
    fn empty_expected_image_hash_produces_no_evidence() {
        // Defensive: an empty image_hash would degenerate into
        // "match any process" which is exactly the Codex finding 1 bad
        // shape. Reject programmatically rather than trust the
        // caller.
        let h = fixture_harness(0x140002000);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::Instruction { va: 0x140002000 }],
        );
        assert!(attribute_event(&h, "", &ev).is_none());
    }

    #[test]
    fn ref_to_different_function_produces_no_evidence() {
        let h = fixture_harness(0x140002000);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::Instruction { va: 0x140009999 }],
        );
        assert!(attribute_event(&h, "blake3:target", &ev).is_none());
    }

    #[test]
    fn range_not_covering_function_va_produces_no_evidence() {
        let h = fixture_harness(0x140005000);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::Range {
                start_va: 0x140002000,
                end_va: 0x140003000,
            }],
        );
        assert!(attribute_event(&h, "blake3:target", &ev).is_none());
    }

    #[test]
    fn artifact_with_wrong_entity_kind_produces_no_evidence() {
        // Even if the id contains the hex VA, the entity_kind must be
        // function-ish — "type_def" referencing the same VA is not a
        // function reach.
        let h = fixture_harness(0x140002000);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::Artifact {
                entity_kind: "type_def".into(),
                id: "type:0000000140002000".into(),
            }],
        );
        assert!(attribute_event(&h, "blake3:target", &ev).is_none());
    }

    #[test]
    fn debug_record_and_trace_event_refs_never_match() {
        let h = fixture_harness(0x140002000);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![
                EvidenceRef::DebugRecord {
                    provider: "pdb".into(),
                    key: "sym/12".into(),
                },
                EvidenceRef::TraceEvent {
                    event_id: "evt_other".into(),
                },
            ],
        );
        assert!(attribute_event(&h, "blake3:target", &ev).is_none());
    }

    // ----- Multi-event / multi-harness -----

    #[test]
    fn attribute_events_returns_one_record_per_match() {
        let h = fixture_harness(0x140002000);
        let events = vec![
            fixture_event(
                Some("blake3:target"),
                vec![EvidenceRef::Instruction { va: 0x140002000 }],
            ),
            fixture_event(
                Some("blake3:target"),
                vec![EvidenceRef::Instruction { va: 0x140009999 }],
            ),
            fixture_event(
                Some("blake3:target"),
                vec![EvidenceRef::RawAddr { va: 0x140002000 }],
            ),
        ];
        let evs = attribute_events(&h, "blake3:target", &events);
        assert_eq!(evs.len(), 2);
    }

    #[test]
    fn attribute_event_to_all_harnesses_emits_for_every_matching_chain() {
        let h1 = synthesize(
            &CandidateChain {
                chain_id: "C-T-A".into(),
                template_id: "unchecked_copy_length".into(),
                source_kind: "network_recv".into(),
                source_function_va: 0x140001000,
                source_site_va: 0x140001100,
                sink_api: "memcpy".into(),
                sink_function_va: 0x140002000,
                sink_site_va: 0x140002200,
                propagation_mode: PropagationMode::Summary,
                hop_count: 2,
                dominating_guard_count: 1,
                matched_integer_pattern: false,
            },
            &SinkCatalog::v1_0(),
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let h2 = synthesize(
            &CandidateChain {
                chain_id: "C-T-B".into(),
                template_id: "missing_caller_validation".into(),
                source_kind: "network_recv".into(),
                source_function_va: 0x140003000,
                source_site_va: 0x140003100,
                sink_api: "memcpy".into(),
                // Same sink function as h1 — a wrapper called from
                // two source paths.
                sink_function_va: 0x140002000,
                sink_site_va: 0x140002300,
                propagation_mode: PropagationMode::Exact,
                hop_count: 0,
                dominating_guard_count: 0,
                matched_integer_pattern: false,
            },
            &SinkCatalog::v1_0(),
            HarnessKind::SourceAvailableFnByteSlice,
        );
        let h3 = fixture_harness(0x140008000);
        let ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::Instruction { va: 0x140002000 }],
        );
        let evs = attribute_event_to_all_harnesses(&[h1, h2, h3], "blake3:target", &ev);
        assert_eq!(evs.len(), 2);
        let chains: Vec<&str> = evs.iter().map(|e| e.chain_id.as_str()).collect();
        assert!(chains.contains(&"C-T-A"));
        assert!(chains.contains(&"C-T-B"));
        // C-T-C in h3 has a different sink function → no evidence.
    }

    // ----- any_ref_targets_function helper -----

    #[test]
    fn any_ref_targets_function_exact_va_match() {
        assert!(any_ref_targets_function(
            &[EvidenceRef::Instruction { va: 0x1000 }],
            0x1000
        ));
        assert!(!any_ref_targets_function(
            &[EvidenceRef::Instruction { va: 0x1001 }],
            0x1000
        ));
    }

    #[test]
    fn any_ref_targets_function_range_inclusive_start_exclusive_end() {
        let r = vec![EvidenceRef::Range {
            start_va: 0x1000,
            end_va: 0x2000,
        }];
        assert!(any_ref_targets_function(&r, 0x1000));
        assert!(any_ref_targets_function(&r, 0x1500));
        assert!(any_ref_targets_function(&r, 0x1fff));
        assert!(!any_ref_targets_function(&r, 0x2000));
        assert!(!any_ref_targets_function(&r, 0x0fff));
    }

    #[test]
    fn any_ref_targets_function_empty_refs_returns_false() {
        assert!(!any_ref_targets_function(&[], 0x1000));
    }

    // ----- Reproducer id traceability -----

    #[test]
    fn reproducer_id_is_the_event_id_so_consumer_can_dereference() {
        let h = fixture_harness(0x140002000);
        let mut ev = fixture_event(
            Some("blake3:target"),
            vec![EvidenceRef::Instruction { va: 0x140002000 }],
        );
        ev.event_id = "evt_0000019999".into();
        let result = attribute_event(&h, "blake3:target", &ev).unwrap();
        // The LLM consumer / human reviewer can grep events.ndjson
        // by this id to find the exact event that produced the
        // evidence record.
        assert_eq!(result.reproducer_id, "evt_0000019999");
    }
}
