//! Themida 3.x partial-recovery path (Phase B5).
//!
//! When `packer_dispatch::check_themida_3x_markers` returns
//! `Themida3xPartial` (≥3 of 4 detection markers) AND the user passed
//! `--devirt-allow-best-effort-3x`, this module runs the same emulator-
//! backed handler walk that `themida.rs` (B3) uses for 2.x — but with a
//! **hard 0.40 confidence-score cap** applied before
//! `snapshot::tier_for_score` is called, forcing the footer tier to
//! `best_effort` regardless of how many step records were captured.
//!
//! Defense in depth: the cap is enforced in TWO places:
//!   1. This module clamps `raw_score` to `≤ 0.40` before writing the
//!      footer.
//!   2. `devirt::trace::TraceWriter::finalize` REJECTS writing a footer
//!      where header.cap_reason == "themida_3x_partial" but tier !=
//!      "best_effort". That validator is hit even if a future bug
//!      replaces (1).
//!
//! The 3.x stepper uses a tighter step budget (256 instructions vs the
//! 16k cap used for 2.x). Modern Themida's dispatchers are obfuscated and
//! divergent enough that long traces add noise without signal.

use crate::unpack::devirt::trace::TraceFooter;
use crate::unpack::UnpackError;

/// Hard cap applied to any 3.x partial-recovery confidence score before
/// `tier_for_score()` maps it to a tier label. 0.40 sits below the
/// `medium` threshold (0.50) and `high` threshold (0.75), so the
/// resulting tier is always `best_effort`.
pub const THEMIDA_3X_SCORE_CAP: f64 = 0.40;

/// Per-run step budget for the 3.x stepper. Smaller than the 2.x budget
/// because mutated dispatchers diverge faster.
pub const THEMIDA_3X_STEP_BUDGET: u32 = 256;

/// Clamp a raw confidence score to the 3.x cap. Used by the 3.x stepper
/// before constructing the footer; also exported for tests.
pub fn cap_score(raw_score: f64) -> f64 {
    raw_score.min(THEMIDA_3X_SCORE_CAP).max(0.0)
}

/// Construct a properly-capped `TraceFooter` for a 3.x run. Always emits
/// `confidence_tier="best_effort"` regardless of how many handlers
/// stepped, matching the defense-in-depth check in
/// `devirt::trace::TraceWriter::finalize`.
pub fn make_capped_footer(steps_total: u32, outcome: &str, raw_score: f64) -> TraceFooter {
    let capped = cap_score(raw_score);
    TraceFooter {
        kind: "footer".to_string(),
        steps_total,
        outcome: outcome.to_string(),
        truncated: outcome == "truncated",
        confidence_score: capped,
        confidence_tier: "best_effort".to_string(),
    }
}

/// Run the 3.x partial-recovery walk. Returns the snapshot-relative path
/// of `devirt_trace.jsonl` on success.
///
/// Stub at session-1 land — the real handler walk needs Unicorn
/// (feature-gated behind `unpack-emulation`, which itself requires
/// `libclang.dll` on PATH for bindgen). When the build environment is
/// configured, this function should:
///   1. Construct an `Emulator` from the snapshot's mapped regions.
///   2. Seed registers to match the target's pre-VM state.
///   3. `emu.step_n(start_va, THEMIDA_3X_STEP_BUDGET)`.
///   4. Per step: render the StepRecord, append via `TraceWriter`.
///   5. On termination (Halted/Faulted/budget-exhausted), compute a raw
///      score from signal count, clamp with `cap_score`, finalize the
///      writer with `make_capped_footer`.
pub fn run_partial_recovery() -> Result<String, UnpackError> {
    #[cfg(not(feature = "unpack-emulation"))]
    {
        return Err(UnpackError::EmulationFeatureMissing);
    }
    #[cfg(feature = "unpack-emulation")]
    {
        // The actual stepper requires a configured Emulator, which in
        // turn requires Unicorn from the unpack-emulation feature build.
        // Wiring the full path is straightforward once the build env has
        // libclang — see the doc comment above. The cap + footer helpers
        // are already exercised by the unit tests below.
        Err(UnpackError::Pipeline(
            "themida3x::run_partial_recovery — implementation pending; \
             requires unicorn-backed Emulator (see B1)"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_score_clamps_above_threshold() {
        assert_eq!(cap_score(0.99), THEMIDA_3X_SCORE_CAP);
        assert_eq!(cap_score(0.50), THEMIDA_3X_SCORE_CAP);
        assert_eq!(cap_score(0.41), THEMIDA_3X_SCORE_CAP);
    }

    #[test]
    fn cap_score_preserves_below_threshold() {
        assert_eq!(cap_score(0.40), THEMIDA_3X_SCORE_CAP);
        assert_eq!(cap_score(0.25), 0.25);
        assert_eq!(cap_score(0.0), 0.0);
    }

    #[test]
    fn cap_score_clamps_negative_to_zero() {
        assert_eq!(cap_score(-0.5), 0.0);
    }

    #[test]
    fn make_capped_footer_always_best_effort() {
        // Negative test: pretend the stepper produced a confidence-of-1.0
        // signal. The footer must still emit best_effort tier — that's
        // the architectural promise of Phase B5.
        let footer = make_capped_footer(1024, "halted", 0.99);
        assert_eq!(footer.confidence_tier, "best_effort");
        assert_eq!(footer.confidence_score, THEMIDA_3X_SCORE_CAP);
        assert!(!footer.truncated);
    }

    #[test]
    fn make_capped_footer_marks_truncated_outcome() {
        let footer = make_capped_footer(10, "truncated", 0.10);
        assert!(footer.truncated);
        assert_eq!(footer.outcome, "truncated");
    }

    #[test]
    #[cfg(not(feature = "unpack-emulation"))]
    fn run_without_feature_returns_emulation_missing() {
        match run_partial_recovery() {
            Err(UnpackError::EmulationFeatureMissing) => {}
            other => panic!("expected EmulationFeatureMissing, got {:?}", other),
        }
    }
}
