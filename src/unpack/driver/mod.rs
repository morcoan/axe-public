//! Kernel-driver mode (opt-in feature `unpack-driver`).
//!
//! Aurora's `aurora_drv.sys` runs at kernel level to hide VM
//! artifacts from the syscall layer — process enumeration,
//! registry reads, device opens.
//!
//! # Hard prerequisites
//!
//! - Windows test-signing mode enabled (`bcdedit /set testsigning on`
//!   + reboot + visible watermark) OR a user-supplied EV-signed
//!   build of `aurora_drv.sys`.
//! - Aurora-side process running elevated (driver load via SCM).
//!
//! # NEVER
//!
//! No BYOVD ("exploiting a vulnerable signed driver"). Capability
//! probe fails fast if neither prerequisite is met.

pub mod ioctl;
pub mod test_signing;
pub mod user_side;

use crate::unpack::UnpackError;

#[derive(Clone, Debug)]
pub struct DriverCapability {
    pub test_signing_enabled: bool,
    pub elevated: bool,
    pub driver_path_resolved: Option<std::path::PathBuf>,
}

/// Run the full capability probe. Returns a clear, actionable
/// error when prerequisites aren't met.
pub fn probe() -> Result<DriverCapability, UnpackError> {
    #[cfg(not(feature = "unpack-driver"))]
    return Err(UnpackError::DriverFeatureMissing);
    #[cfg(feature = "unpack-driver")]
    {
        let signing = test_signing::is_enabled()?;
        let elevated = test_signing::current_process_elevated();
        let path = user_side::resolve_driver_artifact();
        Ok(DriverCapability {
            test_signing_enabled: signing,
            elevated,
            driver_path_resolved: path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(feature = "unpack-driver"))]
    fn probe_without_feature_errors() {
        match probe() {
            Err(UnpackError::DriverFeatureMissing) => {}
            other => panic!("expected DriverFeatureMissing, got {:?}", other),
        }
    }
}
