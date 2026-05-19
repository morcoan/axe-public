//! Capability probe: is test-signing mode enabled? Is Aurora
//! running elevated?

use crate::unpack::UnpackError;

/// Returns `Ok(true)` when `bcdedit /enum {current}` shows
/// `testsigning Yes`. `Ok(false)` when it shows `No`. `Err`
/// when bcdedit can't be invoked.
#[cfg(all(windows, feature = "unpack-driver"))]
pub fn is_enabled() -> Result<bool, UnpackError> {
    let output = std::process::Command::new("bcdedit")
        .args(["/enum", "{current}"])
        .output()
        .map_err(|e| UnpackError::Pipeline(format!("bcdedit invocation: {}", e)))?;
    if !output.status.success() {
        return Err(UnpackError::Pipeline(format!(
            "bcdedit returned non-zero status: {}",
            output.status
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("testsigning") {
            let value = rest.trim();
            return Ok(value.eq_ignore_ascii_case("yes"));
        }
    }
    // Not listed = test-signing OFF (default).
    Ok(false)
}

#[cfg(any(not(windows), not(feature = "unpack-driver")))]
pub fn is_enabled() -> Result<bool, UnpackError> {
    Err(UnpackError::DriverFeatureMissing)
}

/// Probe: is the current process elevated (admin)? Driver
/// load requires this.
#[cfg(windows)]
pub fn current_process_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = windows::Win32::Foundation::HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn current_process_elevated() -> bool {
    false
}

/// Compose the actionable remediation message the CLI surfaces
/// when prerequisites aren't met. Pure function — usable in
/// tests without touching the host.
pub fn remediation_message(test_signing: bool, elevated: bool) -> String {
    let mut steps = Vec::new();
    if !test_signing {
        steps.push(
            "  1. Enable Windows test-signing mode (REQUIRES REBOOT):\n     bcdedit /set testsigning on\n     Then reboot. A 'Test Mode' watermark appears on the desktop."
                .to_string(),
        );
    }
    if !elevated {
        steps.push("  2. Run Aurora elevated (right-click → 'Run as administrator').".to_string());
    }
    if steps.is_empty() {
        "Driver-mode prerequisites OK.".to_string()
    } else {
        format!(
            "Driver-mode prerequisites not met. Required steps:\n{}\n\
             NEVER bypass these via BYOVD or by loading an unsigned third-party driver.",
            steps.join("\n")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remediation_lists_test_signing_step_when_disabled() {
        let msg = remediation_message(false, true);
        assert!(msg.contains("testsigning on"));
    }

    #[test]
    fn remediation_lists_elevation_step_when_not_elevated() {
        let msg = remediation_message(true, false);
        assert!(msg.contains("administrator"));
    }

    #[test]
    fn remediation_ok_when_both_satisfied() {
        let msg = remediation_message(true, true);
        assert_eq!(msg, "Driver-mode prerequisites OK.");
    }

    #[test]
    fn remediation_lists_both_when_neither() {
        let msg = remediation_message(false, false);
        assert!(msg.contains("testsigning on"));
        assert!(msg.contains("administrator"));
    }

    #[test]
    fn remediation_never_suggests_byovd() {
        let msg = remediation_message(false, false);
        assert!(msg.contains("NEVER"));
        assert!(!msg.to_lowercase().contains("vulnerable"));
    }
}
