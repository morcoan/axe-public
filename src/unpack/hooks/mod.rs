//! User-mode hook registry + orchestration.
//!
//! The hook engine itself runs IN THE TARGET via the stub DLL
//! (`hooks::stub_dll`) injected by `hooks::inject`. This module
//! is the Aurora-side coordinator: it tracks which surfaces are
//! armed, drives the injection sequence, and collects the
//! "installed hooks" list for the snapshot manifest.
//!
//! # Why the actual hook code lives in the stub DLL
//!
//! `retour::GenericDetour` rewrites the target API's prologue
//! in the CURRENT process. To hook a target's API, the hook
//! must run from inside the target's address space — which is
//! the stub DLL's job after `CreateRemoteThread → LoadLibrary`
//! lands it there. Aurora calls the stub DLL's exported
//! initializer via a second `CreateRemoteThread` to trigger
//! the actual `GenericDetour::new + enable()` sequence.

pub mod inject;
pub mod spoof_adapters;
pub mod spoof_firmware;
pub mod spoof_processes;
pub mod spoof_registry;
pub mod spoof_sysinfo;
pub mod stub_dll;

use crate::unpack::UnpackError;

/// Aurora-side view of one installed hook.
#[derive(Clone, Debug)]
pub struct InstalledHook {
    pub module: String,
    pub api: String,
    pub target_address: u64,
}

/// Master profile: which anti-VM surfaces to spoof in the
/// target. Wired up by the session orchestrator (Step 54) from
/// CLI flags + packer-strategy decisions.
#[derive(Clone, Debug)]
pub struct SpoofProfile {
    pub firmware: bool,
    pub registry: bool,
    pub processes: bool,
    pub adapters: bool,
    pub sysinfo: bool,
}

impl Default for SpoofProfile {
    fn default() -> Self {
        Self {
            firmware: true,
            registry: true,
            processes: true,
            adapters: true,
            sysinfo: true,
        }
    }
}

impl SpoofProfile {
    pub fn disabled() -> Self {
        Self {
            firmware: false,
            registry: false,
            processes: false,
            adapters: false,
            sysinfo: false,
        }
    }

    /// API surface names actually armed — fed into the
    /// snapshot's `anti_vm_profile.user_mode_hooks_installed`
    /// list so the LLM consumer knows what was suppressed.
    pub fn installed_surface_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.firmware {
            out.push("GetSystemFirmwareTable".to_string());
            out.push("EnumSystemFirmwareTables".to_string());
        }
        if self.registry {
            out.push("RegQueryValueExW".to_string());
        }
        if self.processes {
            out.push("CreateToolhelp32Snapshot".to_string());
            out.push("Process32FirstW".to_string());
            out.push("Process32NextW".to_string());
        }
        if self.adapters {
            out.push("GetAdaptersInfo".to_string());
            out.push("GetAdaptersAddresses".to_string());
        }
        if self.sysinfo {
            out.push("NtQuerySystemInformation".to_string());
        }
        out
    }
}

/// Run the hook orchestration: inject stub DLL into the
/// suspended target, then call its initializer to install
/// detours per the profile.
///
/// **Stub status (Step 26-30 skeleton):** this function
/// records the profile + returns `Ok(InstalledHooks{...})`
/// without actually loading the DLL. The real injection path
/// requires the stub DLL artifact to exist on disk
/// (`build.rs` builds it as a sibling crate — Step 26
/// follow-up). When that lands, this function will sequence:
///
/// 1. `inject::create_remote_thread_loadlibrary(stub_dll_path)`
/// 2. `inject::create_remote_thread_init(addr_of_stub_init,
///    profile_blob)`
/// 3. wait for both threads to exit (1s each)
/// 4. collect installed hooks via a third remote thread that
///    reads the stub's exported registry
pub fn install_all(
    process_handle: u64,
    profile: &SpoofProfile,
) -> Result<Vec<InstalledHook>, UnpackError> {
    let _ = process_handle;
    let mut installed = Vec::new();
    for name in profile.installed_surface_names() {
        // The stub-side install hasn't run yet, so we record
        // only the intent. When stub_dll injection lands, the
        // target_address field will be populated from the
        // stub's GetProcAddress.
        installed.push(InstalledHook {
            module: classify_module(&name).to_string(),
            api: name,
            target_address: 0,
        });
    }
    Ok(installed)
}

fn classify_module(api: &str) -> &'static str {
    if api.starts_with("Nt") {
        "ntdll.dll"
    } else if api.contains("Adapter") {
        "iphlpapi.dll"
    } else if api.contains("Reg") {
        "advapi32.dll"
    } else {
        "kernel32.dll"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_has_all_surfaces_armed() {
        let p = SpoofProfile::default();
        assert!(p.firmware);
        assert!(p.registry);
        assert!(p.processes);
        assert!(p.adapters);
        assert!(p.sysinfo);
    }

    #[test]
    fn disabled_profile_emits_no_surface_names() {
        assert!(SpoofProfile::disabled()
            .installed_surface_names()
            .is_empty());
    }

    #[test]
    fn default_profile_surfaces_cover_all_five_groups() {
        let names = SpoofProfile::default().installed_surface_names();
        // 2 firmware + 1 registry + 3 processes + 2 adapters + 1 sysinfo = 9
        assert_eq!(names.len(), 9);
        assert!(names.iter().any(|n| n == "GetSystemFirmwareTable"));
        assert!(names.iter().any(|n| n == "RegQueryValueExW"));
        assert!(names.iter().any(|n| n == "CreateToolhelp32Snapshot"));
        assert!(names.iter().any(|n| n == "GetAdaptersInfo"));
        assert!(names.iter().any(|n| n == "NtQuerySystemInformation"));
    }

    #[test]
    fn classify_module_routes_each_api_to_expected_dll() {
        assert_eq!(classify_module("NtQuerySystemInformation"), "ntdll.dll");
        assert_eq!(classify_module("GetAdaptersInfo"), "iphlpapi.dll");
        assert_eq!(classify_module("RegQueryValueExW"), "advapi32.dll");
        assert_eq!(classify_module("GetSystemFirmwareTable"), "kernel32.dll");
        assert_eq!(classify_module("CreateToolhelp32Snapshot"), "kernel32.dll");
    }

    #[test]
    fn install_all_returns_one_hook_per_armed_surface() {
        let p = SpoofProfile::default();
        let hooks = install_all(0, &p).expect("install_all");
        assert_eq!(hooks.len(), p.installed_surface_names().len());
    }

    #[test]
    fn install_all_with_disabled_profile_returns_empty() {
        let hooks = install_all(0, &SpoofProfile::disabled()).expect("install_all");
        assert!(hooks.is_empty());
    }
}
