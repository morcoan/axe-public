//! Windows Hypervisor Platform stealth tracer (opt-in feature
//! `unpack-whp`).
//!
//! When enabled, Aurora can run the target inside a WHP partition
//! and intercept CPUID / RDTSC / EPT-violation exits invisibly to
//! the guest. Mutually exclusive with VMware/VBox (requires
//! Hyper-V enabled on the host).
//!
//! # Status
//!
//! Skeletons land at Step 34 (this file). The concrete WHP
//! binding selection (whp crate vs. direct `windows-sys::Hypervisor`)
//! lands when the deep wire-up runs.

pub mod cpuid_spoof;
pub mod partition;
pub mod rdtsc_normalize;
pub mod vmexit;

use crate::unpack::UnpackError;

/// Probe whether WHP is available on the host: returns
/// `Ok(true)` when Hyper-V is enabled and WHP-API is callable,
/// `Ok(false)` when WHP is absent (typical bare-metal Windows
/// without Hyper-V role).
#[cfg(feature = "unpack-whp")]
pub fn whp_available() -> Result<bool, UnpackError> {
    // Real probe lands during follow-up; skeleton returns false
    // so `--unpack-tracer auto` falls through to debug mode.
    Ok(false)
}

#[cfg(not(feature = "unpack-whp"))]
pub fn whp_available() -> Result<bool, UnpackError> {
    Err(UnpackError::WhpFeatureMissing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(feature = "unpack-whp"))]
    fn whp_available_without_feature_errors_with_whp_feature_missing() {
        match whp_available() {
            Err(UnpackError::WhpFeatureMissing) => {}
            other => panic!("expected WhpFeatureMissing, got {:?}", other),
        }
    }

    #[test]
    #[cfg(feature = "unpack-whp")]
    fn whp_available_returns_a_boolean() {
        assert!(whp_available().is_ok());
    }
}
