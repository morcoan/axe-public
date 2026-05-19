//! Virtualization-layer defeat (opt-in feature
//! `unpack-emulation`). Best-effort tier output for legacy
//! VMProtect (≤2.x) and legacy Themida (≤2.x).
//!
//! Modern VMProtect 3.x, modern Themida 3.x, and Denuvo are
//! explicit non-goals — they're designed to defeat exactly the
//! techniques implemented here.

pub mod themida;
pub mod themida3x;
pub mod trace;
pub mod unicorn_wrap;
pub mod vmprotect;

use crate::unpack::UnpackError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevirtProtector {
    LegacyVmProtect,
    LegacyThemida,
    /// Themida 3.x. Marked **partial** because the modern variant defeats
    /// the generic dispatcher-walking technique — devirt produces a trace
    /// capped at `best_effort` confidence (Phase B5's 0.40 cap rule). The
    /// detection markers fire ≥3 of 4 — see
    /// `packer_dispatch::check_themida_3x_markers`.
    Themida3xPartial,
}

pub fn protector_supported(name: &str) -> Option<DevirtProtector> {
    let lower = name.to_ascii_lowercase();
    if lower.contains("vmprotect") {
        Some(DevirtProtector::LegacyVmProtect)
    } else if lower.contains("themida") {
        Some(DevirtProtector::LegacyThemida)
    } else {
        None
    }
}

/// Attempt to step through the protector's handler dispatcher
/// + emit the decoded opcode stream. Returns the path to the
/// `devirt_trace.jsonl` artifact (relative to the snapshot
/// directory) on success.
pub fn step_handlers(protector: DevirtProtector) -> Result<String, UnpackError> {
    #[cfg(not(feature = "unpack-emulation"))]
    {
        let _ = protector;
        return Err(UnpackError::EmulationFeatureMissing);
    }
    #[cfg(feature = "unpack-emulation")]
    match protector {
        DevirtProtector::LegacyVmProtect | DevirtProtector::LegacyThemida => {
            Err(UnpackError::Pipeline(
                "step_handlers (legacy) — implementation pending; \
                 stepper needs unicorn-engine (B1) + dispatcher walker (B3)"
                    .into(),
            ))
        }
        DevirtProtector::Themida3xPartial => themida3x::run_partial_recovery(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmprotect_classifies_to_legacy_vmprotect() {
        assert_eq!(
            protector_supported("VMProtect"),
            Some(DevirtProtector::LegacyVmProtect)
        );
        assert_eq!(
            protector_supported("vmprotect"),
            Some(DevirtProtector::LegacyVmProtect)
        );
    }

    #[test]
    fn themida_classifies_to_legacy_themida() {
        assert_eq!(
            protector_supported("Themida"),
            Some(DevirtProtector::LegacyThemida)
        );
    }

    #[test]
    fn unknown_protector_returns_none() {
        assert_eq!(protector_supported("UPX"), None);
        assert_eq!(protector_supported(""), None);
    }
}
