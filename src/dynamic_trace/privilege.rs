//! Capability probe — Codex finding 4 fix.
//!
//! Previous draft only checked token elevation. Elevated ≠
//! "`SeSystemProfilePrivilege` is enabled" ≠ "an ETW SystemTraceProvider
//! private session will actually start under this group policy /
//! MSIX / AppContainer setup."
//!
//! v1 contract: [`capability_probe`] runs THREE checks, returns the
//! exact failure reason verbatim:
//! 1. `is_elevated()` — token has the Administrator integrity level.
//! 2. `enable_privilege("SeSystemProfilePrivilege")` — adjust the
//!    token to actually expose the privilege the kernel logger
//!    requires.
//! 3. Start + stop a throwaway 1-second private ETW session with the
//!    exact requested provider bundle. (The ETW session probe lands
//!    in Step 8 alongside `FerrisEtwCollector`; until then this step
//!    returns `Ok` with `probe_session: "deferred_to_step_8"` when
//!    elevation + privilege succeed.)
//!
//! Non-Windows builds expose stubs that always return
//! [`CapabilityError::UnsupportedOs`]; non-`dynamic-trace-etw`
//! Windows builds still get the elevation + privilege checks but
//! skip the ETW probe.

#![allow(dead_code)]

use crate::dynamic_trace::ProviderKind;

#[derive(Debug, thiserror::Error)]
pub enum CapabilityError {
    #[error("dynamic-trace ETW collector is unsupported on this OS")]
    UnsupportedOs,
    #[error("process is not elevated; ETW kernel providers require Administrator")]
    NotElevated,
    #[error("failed to enable privilege {0}: {1}")]
    EnablePrivilege(String, String),
    #[error("ETW probe session failed: {0}")]
    EtwProbe(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityProbeReport {
    pub elevated: bool,
    pub se_system_profile: PrivilegeStatus,
    pub probe_session: ProbeSessionResult,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivilegeStatus {
    Enabled,
    NotPresent,
    Disabled,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeSessionResult {
    /// Session started + stopped cleanly. Real ETW probe ran in step 8.
    Ok { elapsed_ms: u64 },
    /// Skipped — `dynamic-trace-etw` feature is off (build-time skip).
    SkippedNoEtwFeature,
    /// Skipped — feature is on but probe deferred to step 8 (interim).
    DeferredToStep8,
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    #[cfg(feature = "dynamic-trace-etw")]
    {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut returned: u32 = 0;
            let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                size,
                &mut returned,
            )
            .is_ok();
            let _ = windows::Win32::Foundation::CloseHandle(token);
            ok && elevation.TokenIsElevated != 0
        }
    }
    #[cfg(not(feature = "dynamic-trace-etw"))]
    {
        // No `windows` crate available; conservatively report
        // "not elevated" so capability_probe surfaces a clear error.
        false
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
pub fn enable_privilege(name: &str) -> Result<PrivilegeStatus, CapabilityError> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{HANDLE, LUID};
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        )
        .map_err(|e| CapabilityError::EnablePrivilege(name.to_string(), format!("{e}")))?;

        let mut luid = LUID::default();
        if let Err(e) = LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide.as_ptr()), &mut luid) {
            let _ = windows::Win32::Foundation::CloseHandle(token);
            return Err(CapabilityError::EnablePrivilege(
                name.to_string(),
                format!("lookup_privilege_value: {e}"),
            ));
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let adjust = AdjustTokenPrivileges(
            token,
            false,
            Some(&mut tp as *mut _),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        );
        let last_err = windows::Win32::Foundation::GetLastError();
        let _ = windows::Win32::Foundation::CloseHandle(token);
        if adjust.is_err() {
            return Err(CapabilityError::EnablePrivilege(
                name.to_string(),
                format!("adjust_token_privileges_failed: {last_err:?}"),
            ));
        }
        // ERROR_NOT_ALL_ASSIGNED (1300) means the privilege wasn't on the
        // token at all — distinct from a real failure.
        if last_err.0 == 1300 {
            return Ok(PrivilegeStatus::NotPresent);
        }
        Ok(PrivilegeStatus::Enabled)
    }
}

#[cfg(not(all(windows, feature = "dynamic-trace-etw")))]
pub fn enable_privilege(_name: &str) -> Result<PrivilegeStatus, CapabilityError> {
    Err(CapabilityError::UnsupportedOs)
}

/// Run the full capability probe. Step 8 enhances this to actually
/// start a throwaway ETW session with the requested provider bundle
/// (Codex finding 4 full fix). v1 ships with elevation + privilege
/// enablement only.
pub fn capability_probe(
    _providers: &[ProviderKind],
) -> Result<CapabilityProbeReport, CapabilityError> {
    #[cfg(not(windows))]
    {
        return Err(CapabilityError::UnsupportedOs);
    }
    #[cfg(windows)]
    {
        if !is_elevated() {
            return Err(CapabilityError::NotElevated);
        }
        let se_system_profile = match enable_privilege("SeSystemProfilePrivilege") {
            Ok(s) => s,
            Err(CapabilityError::UnsupportedOs) => PrivilegeStatus::Unknown,
            Err(other) => return Err(other),
        };
        // Probe session lands in step 8 alongside FerrisEtwCollector.
        // Until then, return Ok with explicit deferral marker so the
        // session orchestrator can still call this function.
        let probe_session = if cfg!(feature = "dynamic-trace-etw") {
            ProbeSessionResult::DeferredToStep8
        } else {
            ProbeSessionResult::SkippedNoEtwFeature
        };
        Ok(CapabilityProbeReport {
            elevated: true,
            se_system_profile,
            probe_session,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_windows_capability_probe_returns_unsupported() {
        #[cfg(not(windows))]
        {
            let result = capability_probe(&ProviderKind::v1_default_bundle());
            assert!(matches!(result, Err(CapabilityError::UnsupportedOs)));
        }
        #[cfg(windows)]
        {
            // On Windows this test is informational: it documents that
            // capability_probe at least returns a structured result. We
            // don't assert success because that depends on test runner
            // elevation, which CI cannot guarantee.
            let _ = capability_probe(&ProviderKind::v1_default_bundle());
        }
    }

    #[test]
    fn is_elevated_returns_bool_without_panicking() {
        let _ = is_elevated();
    }

    #[test]
    fn probe_session_marker_distinguishes_no_feature_vs_deferred() {
        // Just verify the enum is constructible; orchestrator code
        // pattern-matches on these.
        let a = ProbeSessionResult::DeferredToStep8;
        let b = ProbeSessionResult::SkippedNoEtwFeature;
        let c = ProbeSessionResult::Ok { elapsed_ms: 42 };
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn capability_error_messages_include_failure_kind() {
        let e = CapabilityError::EnablePrivilege(
            "SeSystemProfilePrivilege".into(),
            "test failure".into(),
        );
        let msg = format!("{e}");
        assert!(msg.contains("SeSystemProfilePrivilege"));
        assert!(msg.contains("test failure"));
    }
}
