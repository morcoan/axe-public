//! End-to-end harness verification — **Codex round-1 finding 2 fix**.
//!
//! This module enforces the one-way promotion rule:
//! [`HarnessTier::Skeleton`] → [`HarnessTier::Runnable`] requires
//! [`HarnessVerification::Passed`] with an `observed_sink_va` that
//! equals the harness's `intended_sink_va` (which is the chain's
//! `sink_site_va` by construction in
//! [`crate::vuln::harness_synth::synthesize`]).
//!
//! The verification API takes a runner closure rather than spinning
//! up the fuzzer directly so this module can be unit-tested without
//! requiring the `vuln-discovery-fuzz` feature, and so Steps 27-29
//! (fuzz_bridge / trace_join / concolic_query) can all share the
//! same promotion machinery — each plugs in its own runner.
//!
//! Codex finding 2 is enforced at two layers:
//! 1. **Structural** (in [`crate::vuln::harness_synth`]):
//!    [`HarnessKind::BinaryOnlyPeEntry`] CANNOT produce
//!    `runnable_rust`. There is nothing to verify.
//! 2. **Runtime** (here): even for runnable-eligible kinds, the
//!    runner is invoked, but tier flips ONLY when the observed VA
//!    matches the intended one. A runner that crashes at an
//!    unrelated sink does NOT trigger promotion.

#![allow(dead_code)]

use crate::vuln::harness_synth::{Harness, HarnessKind, HarnessTier, HarnessVerification};

/// What the runner observed for one input.
///
/// `observed_sink_va` is `None` when the runner cannot report a PC
/// (e.g. trace was lost). A `Some(va)` that does not match the
/// harness's `intended_sink_va` is treated as a non-PASS observation
/// — the runner reached *a* sink but not *this* chain's sink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationOutcome {
    /// `true` iff the runner reached a sink at all (any sink). Use
    /// in combination with `observed_sink_va` to determine whether
    /// the reach was the right one.
    pub sink_reached: bool,
    /// The PC at which the runner observed the sink, if known.
    pub observed_sink_va: Option<u64>,
}

impl VerificationOutcome {
    /// Convenience: no sink reached.
    pub fn nothing() -> Self {
        Self {
            sink_reached: false,
            observed_sink_va: None,
        }
    }
    /// Convenience: sink reached at a known VA.
    pub fn reached(va: u64) -> Self {
        Self {
            sink_reached: true,
            observed_sink_va: Some(va),
        }
    }
}

/// Run a harness against the supplied inputs and produce a
/// verification result.
///
/// **Codex finding 2 invariant**: for
/// [`HarnessKind::BinaryOnlyPeEntry`] harnesses, the runner is NEVER
/// invoked — the function returns
/// [`HarnessVerification::SkippedBinaryOnly`] immediately. This is
/// the structural guard that complements the runtime VA-match check.
///
/// For runnable-eligible harnesses, the runner is invoked once per
/// input until either:
/// - The runner returns `sink_reached = true` with
///   `observed_sink_va == Some(harness.intended_sink_va)` →
///   [`HarnessVerification::Passed`] with `inputs_tried` set to the
///   1-based index of the input that triggered the match.
/// - All inputs are exhausted without a match →
///   [`HarnessVerification::Failed`] with `inputs_tried` set to the
///   total input count and `reason` indicating why.
pub fn verify_runnable<F>(
    harness: &Harness,
    inputs: &[Vec<u8>],
    mut runner: F,
) -> HarnessVerification
where
    F: FnMut(&[u8]) -> VerificationOutcome,
{
    // Structural guard — never run the runner for binary-only.
    if matches!(harness.kind, HarnessKind::BinaryOnlyPeEntry) {
        return HarnessVerification::SkippedBinaryOnly;
    }

    if inputs.is_empty() {
        return HarnessVerification::Failed {
            reason: "no_inputs_provided".to_string(),
            inputs_tried: 0,
        };
    }

    let mut tried = 0usize;
    for input in inputs {
        tried += 1;
        let outcome = runner(input);
        if !outcome.sink_reached {
            continue;
        }
        match outcome.observed_sink_va {
            Some(va) if va == harness.intended_sink_va => {
                return HarnessVerification::Passed {
                    observed_sink_va: va,
                    inputs_tried: tried,
                };
            }
            // Sink reached but at the wrong VA — keep trying. This is
            // the Codex-finding-2 attribution discipline: a runner
            // that hits a DIFFERENT sink does not authorize promotion
            // for THIS chain.
            _ => continue,
        }
    }

    HarnessVerification::Failed {
        reason: "sink_va_not_reached".to_string(),
        inputs_tried: tried,
    }
}

/// Verify a harness and, on PASS, flip its tier to
/// [`HarnessTier::Runnable`]. Returns `true` iff the tier was
/// promoted. The verification record is attached to
/// `harness.verification` regardless of outcome.
///
/// This is the only sanctioned way to flip a harness from
/// `Skeleton` to `Runnable` — there is no public setter on `tier`.
pub fn try_promote_to_runnable<F>(harness: &mut Harness, inputs: &[Vec<u8>], runner: F) -> bool
where
    F: FnMut(&[u8]) -> VerificationOutcome,
{
    let result = verify_runnable(harness, inputs, runner);
    let pass = result.is_pass();
    harness.verification = result;
    if pass {
        harness.tier = HarnessTier::Runnable;
    }
    pass
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::harness_synth::synthesize;
    use crate::vuln::query::CandidateChain;
    use crate::vuln::sinks::SinkCatalog;
    use crate::vuln::taint::PropagationMode;

    fn fixture_chain() -> CandidateChain {
        CandidateChain {
            chain_id: "C-V-001".into(),
            template_id: "unchecked_copy_length".into(),
            source_kind: "network_recv".into(),
            source_function_va: 0x140001000,
            source_site_va: 0x140001100,
            sink_api: "memcpy".into(),
            sink_function_va: 0x140002000,
            sink_site_va: 0x1400022a4,
            propagation_mode: PropagationMode::Summary,
            hop_count: 2,
            dominating_guard_count: 1,
            matched_integer_pattern: false,
        }
    }

    fn make_harness(kind: HarnessKind) -> Harness {
        let sinks = SinkCatalog::v1_0();
        synthesize(&fixture_chain(), &sinks, kind)
    }

    // ----- Structural: binary-only short-circuits -----

    #[test]
    fn binary_only_kind_never_invokes_runner() {
        let h = make_harness(HarnessKind::BinaryOnlyPeEntry);
        let inputs = vec![vec![0u8; 16]];
        let mut runner_called = false;
        let result = verify_runnable(&h, &inputs, |_| {
            runner_called = true;
            VerificationOutcome::reached(h.intended_sink_va)
        });
        // Codex finding 2 structural guard — runner must NOT be called.
        assert!(
            !runner_called,
            "runner must not be invoked for binary-only harness"
        );
        assert_eq!(result, HarnessVerification::SkippedBinaryOnly);
    }

    #[test]
    fn binary_only_promotion_attempt_returns_false_without_flipping_tier() {
        let mut h = make_harness(HarnessKind::BinaryOnlyPeEntry);
        let inputs = vec![vec![0u8; 16]];
        let intended = h.intended_sink_va;
        let promoted = try_promote_to_runnable(&mut h, &inputs, |_| {
            // Even if a runner were called and reported PASS, the
            // structural guard should prevent promotion.
            VerificationOutcome::reached(intended)
        });
        assert!(!promoted);
        assert_eq!(h.tier, HarnessTier::Skeleton);
        assert_eq!(h.verification, HarnessVerification::SkippedBinaryOnly);
    }

    // ----- Runtime: PASS path -----

    #[test]
    fn source_available_passes_when_runner_observes_intended_sink_va() {
        let h = make_harness(HarnessKind::SourceAvailableFnByteSlice);
        let inputs = vec![vec![0xAAu8; 64]];
        let result = verify_runnable(&h, &inputs, |_| {
            VerificationOutcome::reached(h.intended_sink_va)
        });
        match result {
            HarnessVerification::Passed {
                observed_sink_va,
                inputs_tried,
            } => {
                assert_eq!(observed_sink_va, h.intended_sink_va);
                assert_eq!(inputs_tried, 1);
            }
            other => panic!("expected Passed, got {other:?}"),
        }
    }

    #[test]
    fn user_supplied_passes_with_same_discipline_as_source_available() {
        let h = make_harness(HarnessKind::UserSuppliedEntryPoint);
        let inputs = vec![vec![0xBBu8; 64]];
        let result = verify_runnable(&h, &inputs, |_| {
            VerificationOutcome::reached(h.intended_sink_va)
        });
        assert!(matches!(result, HarnessVerification::Passed { .. }));
    }

    #[test]
    fn promotion_succeeds_when_runner_observes_intended_sink_va() {
        let mut h = make_harness(HarnessKind::SourceAvailableFnByteSlice);
        let inputs = vec![vec![0u8; 16]];
        let intended = h.intended_sink_va;
        let promoted =
            try_promote_to_runnable(&mut h, &inputs, |_| VerificationOutcome::reached(intended));
        assert!(promoted);
        assert_eq!(h.tier, HarnessTier::Runnable);
        assert!(matches!(h.verification, HarnessVerification::Passed { .. }));
    }

    #[test]
    fn passed_inputs_tried_reflects_index_of_triggering_input() {
        let h = make_harness(HarnessKind::SourceAvailableFnByteSlice);
        // 5 inputs, only the 3rd triggers.
        let inputs: Vec<Vec<u8>> = (0..5).map(|_| vec![0u8; 16]).collect();
        let mut call_count = 0;
        let result = verify_runnable(&h, &inputs, |_| {
            call_count += 1;
            if call_count == 3 {
                VerificationOutcome::reached(h.intended_sink_va)
            } else {
                VerificationOutcome::nothing()
            }
        });
        match result {
            HarnessVerification::Passed { inputs_tried, .. } => {
                assert_eq!(inputs_tried, 3, "should stop after triggering input");
            }
            other => panic!("expected Passed, got {other:?}"),
        }
        // Critical: verifier short-circuits after PASS — inputs 4 and
        // 5 are NOT tried, which matters because real runners may be
        // expensive.
        assert_eq!(call_count, 3);
    }

    // ----- Runtime: FAIL paths -----

    #[test]
    fn fail_when_runner_observes_wrong_sink_va() {
        // Codex finding 2 attribution discipline: runner reaches *a*
        // sink, but at the WRONG VA. Promotion must NOT occur.
        let mut h = make_harness(HarnessKind::SourceAvailableFnByteSlice);
        let inputs = vec![vec![0u8; 16]];
        let wrong_va = h.intended_sink_va.wrapping_add(0x100);
        let promoted =
            try_promote_to_runnable(&mut h, &inputs, |_| VerificationOutcome::reached(wrong_va));
        assert!(!promoted);
        assert_eq!(h.tier, HarnessTier::Skeleton);
        match &h.verification {
            HarnessVerification::Failed {
                reason,
                inputs_tried,
            } => {
                assert_eq!(reason, "sink_va_not_reached");
                assert_eq!(*inputs_tried, 1);
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn fail_when_runner_reaches_no_sink() {
        let mut h = make_harness(HarnessKind::SourceAvailableFnByteSlice);
        let inputs = vec![vec![0u8; 16], vec![1u8; 16]];
        let promoted = try_promote_to_runnable(&mut h, &inputs, |_| VerificationOutcome::nothing());
        assert!(!promoted);
        match &h.verification {
            HarnessVerification::Failed {
                reason,
                inputs_tried,
            } => {
                assert_eq!(reason, "sink_va_not_reached");
                assert_eq!(*inputs_tried, 2);
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn fail_when_observed_sink_va_is_none_even_if_sink_reached_is_true() {
        // The runner reports "sink reached" but cannot identify the VA
        // (trace lost, sampling missed it, etc.). Per Codex finding 2
        // attribution discipline this is NOT a pass — we cannot
        // attribute the reach to THIS chain.
        let h = make_harness(HarnessKind::SourceAvailableFnByteSlice);
        let inputs = vec![vec![0u8; 16]];
        let result = verify_runnable(&h, &inputs, |_| VerificationOutcome {
            sink_reached: true,
            observed_sink_va: None,
        });
        assert!(matches!(result, HarnessVerification::Failed { .. }));
    }

    #[test]
    fn fail_when_no_inputs_provided() {
        let mut h = make_harness(HarnessKind::SourceAvailableFnByteSlice);
        let inputs: Vec<Vec<u8>> = vec![];
        let promoted = try_promote_to_runnable(&mut h, &inputs, |_| {
            panic!("runner must not be invoked when input set is empty")
        });
        assert!(!promoted);
        match &h.verification {
            HarnessVerification::Failed {
                reason,
                inputs_tried,
            } => {
                assert_eq!(reason, "no_inputs_provided");
                assert_eq!(*inputs_tried, 0);
            }
            other => panic!("expected Failed (no_inputs_provided), got {other:?}"),
        }
    }

    // ----- Tier discipline -----

    #[test]
    fn failed_verification_leaves_tier_at_skeleton() {
        let mut h = make_harness(HarnessKind::SourceAvailableFnByteSlice);
        assert_eq!(h.tier, HarnessTier::Skeleton);
        let inputs = vec![vec![0u8; 16]];
        try_promote_to_runnable(&mut h, &inputs, |_| VerificationOutcome::nothing());
        assert_eq!(h.tier, HarnessTier::Skeleton);
    }

    #[test]
    fn verification_record_is_always_attached_after_attempt() {
        for kind in [
            HarnessKind::BinaryOnlyPeEntry,
            HarnessKind::SourceAvailableFnByteSlice,
            HarnessKind::UserSuppliedEntryPoint,
        ] {
            let mut h = make_harness(kind);
            assert_eq!(h.verification, HarnessVerification::NotAttempted);
            let inputs = vec![vec![0u8; 16]];
            try_promote_to_runnable(&mut h, &inputs, |_| VerificationOutcome::nothing());
            // Verification field must no longer be NotAttempted after
            // try_promote_to_runnable runs.
            assert_ne!(h.verification, HarnessVerification::NotAttempted);
        }
    }

    // ----- VerificationOutcome helpers -----

    #[test]
    fn outcome_nothing_helper_is_not_reached() {
        let o = VerificationOutcome::nothing();
        assert!(!o.sink_reached);
        assert!(o.observed_sink_va.is_none());
    }

    #[test]
    fn outcome_reached_helper_carries_va() {
        let o = VerificationOutcome::reached(0x1000);
        assert!(o.sink_reached);
        assert_eq!(o.observed_sink_va, Some(0x1000));
    }
}
