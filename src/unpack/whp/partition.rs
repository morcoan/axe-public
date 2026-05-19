//! WHP partition creation + setup (Step 34-35 real impl).
//!
//! Calls `WHvCreatePartition` / `WHvSetupPartition` / (drop)
//! `WHvDeletePartition` through the `windows` crate's
//! `Win32::System::Hypervisor` bindings — no extra crate
//! needed once the `Win32_System_Hypervisor` windows feature is
//! enabled (already added in Cargo.toml).
//!
//! # Resource ownership
//!
//! `WhpPartition` owns a `WHV_PARTITION_HANDLE` that gets
//! deleted on `Drop`. Use `destroy()` for an explicit teardown
//! that surfaces errors.

use crate::unpack::UnpackError;

pub struct WhpPartition {
    #[cfg(all(windows, feature = "unpack-whp"))]
    handle: windows::Win32::System::Hypervisor::WHV_PARTITION_HANDLE,
    #[cfg(not(all(windows, feature = "unpack-whp")))]
    _placeholder: (),
}

impl WhpPartition {
    /// Create + setup a WHP partition with 1 vCPU.
    pub fn create() -> Result<Self, UnpackError> {
        #[cfg(not(all(windows, feature = "unpack-whp")))]
        {
            return Err(UnpackError::WhpFeatureMissing);
        }
        #[cfg(all(windows, feature = "unpack-whp"))]
        {
            use windows::Win32::System::Hypervisor::{
                WHvCreatePartition, WHvDeletePartition, WHvPartitionPropertyCodeProcessorCount,
                WHvSetPartitionProperty, WHvSetupPartition, WHV_PARTITION_PROPERTY,
            };

            unsafe {
                let handle = WHvCreatePartition().map_err(|e| {
                    UnpackError::Pipeline(format!(
                        "WHvCreatePartition failed (Hyper-V enabled?): {}",
                        e
                    ))
                })?;

                let mut processor_count: WHV_PARTITION_PROPERTY = std::mem::zeroed();
                processor_count.ProcessorCount = 1;
                if let Err(e) = WHvSetPartitionProperty(
                    handle,
                    WHvPartitionPropertyCodeProcessorCount,
                    &processor_count as *const _ as *const _,
                    std::mem::size_of::<WHV_PARTITION_PROPERTY>() as u32,
                ) {
                    let _ = WHvDeletePartition(handle);
                    return Err(UnpackError::Pipeline(format!(
                        "WHvSetPartitionProperty(ProcessorCount=1) failed: {}",
                        e
                    )));
                }

                if let Err(e) = WHvSetupPartition(handle) {
                    let _ = WHvDeletePartition(handle);
                    return Err(UnpackError::Pipeline(format!(
                        "WHvSetupPartition failed: {}",
                        e
                    )));
                }

                Ok(Self { handle })
            }
        }
    }

    /// Explicit teardown. Drop will also clean up, but this
    /// surfaces errors the silent drop swallows.
    pub fn destroy(self) -> Result<(), UnpackError> {
        #[cfg(all(windows, feature = "unpack-whp"))]
        {
            use windows::Win32::System::Hypervisor::WHvDeletePartition;
            let h = self.handle;
            std::mem::forget(self); // suppress Drop
            unsafe {
                WHvDeletePartition(h).map_err(|e| {
                    UnpackError::Pipeline(format!("WHvDeletePartition failed: {}", e))
                })?;
            }
        }
        Ok(())
    }
}

#[cfg(all(windows, feature = "unpack-whp"))]
impl Drop for WhpPartition {
    fn drop(&mut self) {
        use windows::Win32::System::Hypervisor::WHvDeletePartition;
        unsafe {
            let _ = WHvDeletePartition(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_without_feature_returns_missing() {
        let err = WhpPartition::create().err().expect("must error");
        match err {
            UnpackError::WhpFeatureMissing | UnpackError::Pipeline(_) => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[cfg(all(windows, feature = "unpack-whp"))]
    #[test]
    fn create_on_whp_enabled_host_succeeds_or_returns_hyperv_required() {
        // On a host with Hyper-V enabled this should succeed +
        // destroy cleanly. On a host WITHOUT Hyper-V, the error
        // message includes "Hyper-V enabled" so the analyst
        // knows what to fix.
        match WhpPartition::create() {
            Ok(p) => p.destroy().expect("destroy"),
            Err(UnpackError::Pipeline(msg)) => {
                assert!(
                    msg.contains("Hyper-V") || msg.contains("WHvCreatePartition"),
                    "error must explain WHP failure: {}",
                    msg
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
