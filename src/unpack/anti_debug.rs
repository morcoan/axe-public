//! Anti-debug suppression: PEB patch + hooks for the surfaces
//! malware uses to detect a debugger.
//!
//! # Surfaces covered (Step 31 + Step 32)
//!
//! - `PEB.BeingDebugged` — patched directly via
//!   `WriteProcessMemory` after attach (not via API hook so we
//!   don't depend on the stub DLL being loaded yet).
//! - `PEB.NtGlobalFlag` — cleared from `0x70` (heap debug
//!   flags) back to `0x00`.
//! - `IsDebuggerPresent` (kernel32) — returns FALSE
//! - `CheckRemoteDebuggerPresent` (kernel32) — sets *pbDebuggerPresent to FALSE
//! - `NtQueryInformationProcess(ProcessDebugPort)` — returns 0
//! - `NtQueryInformationProcess(ProcessDebugFlags)` — returns 1 (not debugged)
//! - `NtQueryInformationProcess(ProcessDebugObjectHandle)` — returns NULL
//! - `NtSetInformationThread(ThreadHideFromDebugger)` — pretends success
//!
//! # Out of scope (explicit, per `docs/unpack-capabilities.md`)
//!
//! - Integrity-check defeat (byte-pattern compare of
//!   `kernel32.dll` against on-disk image). Malware that
//!   hash-checks the in-memory DLL detects our hooks.
//! - Hardware-breakpoint scanning (`GetThreadContext` to read
//!   Dr0..Dr3). Aurora's HW BPs are visible to a target that
//!   reads its own debug registers.

use crate::unpack::UnpackError;

/// Which anti-debug surfaces are armed for this session.
/// Toggled by `--unpack-hooks-disable` CLI flag (Step 58).
#[derive(Clone, Debug)]
pub struct AntiDebugProfile {
    pub patch_peb_being_debugged: bool,
    pub patch_peb_nt_global_flag: bool,
    pub hook_is_debugger_present: bool,
    pub hook_check_remote_debugger_present: bool,
    pub hook_nt_query_info_process: bool,
    pub hook_nt_set_info_thread: bool,
}

impl Default for AntiDebugProfile {
    fn default() -> Self {
        Self {
            patch_peb_being_debugged: true,
            patch_peb_nt_global_flag: true,
            hook_is_debugger_present: true,
            hook_check_remote_debugger_present: true,
            hook_nt_query_info_process: true,
            hook_nt_set_info_thread: true,
        }
    }
}

impl AntiDebugProfile {
    pub fn disabled() -> Self {
        Self {
            patch_peb_being_debugged: false,
            patch_peb_nt_global_flag: false,
            hook_is_debugger_present: false,
            hook_check_remote_debugger_present: false,
            hook_nt_query_info_process: false,
            hook_nt_set_info_thread: false,
        }
    }

    /// Surface names actually installed — used by
    /// `SnapshotManifest::anti_vm_profile.anti_debug_hooks_installed`
    /// to give the LLM consumer an honest list of what was
    /// suppressed.
    pub fn installed_surface_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.patch_peb_being_debugged {
            out.push("PEB.BeingDebugged (patched)".to_string());
        }
        if self.patch_peb_nt_global_flag {
            out.push("PEB.NtGlobalFlag (cleared)".to_string());
        }
        if self.hook_is_debugger_present {
            out.push("IsDebuggerPresent".to_string());
        }
        if self.hook_check_remote_debugger_present {
            out.push("CheckRemoteDebuggerPresent".to_string());
        }
        if self.hook_nt_query_info_process {
            out.push("NtQueryInformationProcess(ProcessDebugPort/Flags/Handle)".to_string());
        }
        if self.hook_nt_set_info_thread {
            out.push("NtSetInformationThread(ThreadHideFromDebugger)".to_string());
        }
        out
    }
}

/// Find the target's PEB base address.
///
/// On x86-64 Windows the PEB is reachable via the TEB at
/// `gs:[0x60]` — but Aurora is a DIFFERENT process from the
/// target so it can't read its own GS. The supported way is:
/// `NtQueryInformationProcess(ProcessBasicInformation)` returns
/// the target's PEB address. We resolve the function dynamically
/// to avoid needing the windows-rs `Wdk` feature flag.
#[cfg(windows)]
pub fn query_target_peb(process: windows::Win32::Foundation::HANDLE) -> Result<u64, UnpackError> {
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    #[repr(C)]
    struct ProcessBasicInformationData {
        exit_status: i32,
        peb_base: usize,
        affinity_mask: usize,
        base_priority: i32,
        unique_pid: usize,
        inherited_from_unique_pid: usize,
    }
    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        process: windows::Win32::Foundation::HANDLE,
        info_class: u32,
        info: *mut std::ffi::c_void,
        info_len: u32,
        return_length: *mut u32,
    ) -> i32;
    const PROCESS_BASIC_INFORMATION: u32 = 0;
    let ntdll_name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
    let ntdll = unsafe { GetModuleHandleW(windows::core::PCWSTR(ntdll_name.as_ptr())) }
        .map_err(|e| UnpackError::Pipeline(format!("GetModuleHandleW ntdll: {}", e)))?;
    let proc_addr =
        unsafe { GetProcAddress(ntdll, PCSTR(b"NtQueryInformationProcess\0".as_ptr())) }
            .ok_or_else(|| {
                UnpackError::Pipeline("GetProcAddress NtQueryInformationProcess".into())
            })?;
    let nt_query: NtQueryInformationProcessFn = unsafe { std::mem::transmute(proc_addr) };

    let mut info: ProcessBasicInformationData = unsafe { std::mem::zeroed() };
    let mut return_length: u32 = 0;
    let status = unsafe {
        nt_query(
            process,
            PROCESS_BASIC_INFORMATION,
            &mut info as *mut _ as *mut _,
            std::mem::size_of::<ProcessBasicInformationData>() as u32,
            &mut return_length,
        )
    };
    if status != 0 {
        return Err(UnpackError::Pipeline(format!(
            "NtQueryInformationProcess returned status 0x{:08x}",
            status
        )));
    }
    Ok(info.peb_base as u64)
}

#[cfg(not(windows))]
pub fn query_target_peb(_process: ()) -> Result<u64, UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

/// Patch `PEB.BeingDebugged` to 0. The byte sits at PEB+0x02 on
/// x86-64 Windows.
#[cfg(windows)]
pub fn patch_peb_being_debugged(
    process: windows::Win32::Foundation::HANDLE,
    peb_base: u64,
) -> Result<(), UnpackError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    let zero: [u8; 1] = [0];
    let mut written = 0;
    unsafe {
        WriteProcessMemory(
            process,
            (peb_base + 0x02) as *const _,
            zero.as_ptr() as *const _,
            1,
            Some(&mut written),
        )
        .map_err(|e| {
            UnpackError::Pipeline(format!("WriteProcessMemory PEB.BeingDebugged: {}", e))
        })?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn patch_peb_being_debugged(_process: (), _peb_base: u64) -> Result<(), UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

/// Clear `PEB.NtGlobalFlag` (offset 0xBC on x86-64). Heap debug
/// flags `0x70` set here are an anti-debug signal — clearing
/// to `0` masks the analyst-attached state.
#[cfg(windows)]
pub fn clear_peb_nt_global_flag(
    process: windows::Win32::Foundation::HANDLE,
    peb_base: u64,
) -> Result<(), UnpackError> {
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    let zero: [u8; 4] = [0; 4];
    let mut written = 0;
    unsafe {
        WriteProcessMemory(
            process,
            (peb_base + 0xBC) as *const _,
            zero.as_ptr() as *const _,
            4,
            Some(&mut written),
        )
        .map_err(|e| {
            UnpackError::Pipeline(format!("WriteProcessMemory PEB.NtGlobalFlag: {}", e))
        })?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn clear_peb_nt_global_flag(_process: (), _peb_base: u64) -> Result<(), UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

/// Apply the PEB-resident parts of the profile (the parts that
/// don't require the stub DLL to be loaded). The API-hook parts
/// of the profile (`hook_is_debugger_present` etc.) take effect
/// only after `hooks::inject` lands the stub DLL — those are
/// no-ops here.
#[cfg(windows)]
pub fn apply_peb_patches(
    process: windows::Win32::Foundation::HANDLE,
    profile: &AntiDebugProfile,
) -> Result<(), UnpackError> {
    let peb = query_target_peb(process)?;
    if profile.patch_peb_being_debugged {
        patch_peb_being_debugged(process, peb)?;
    }
    if profile.patch_peb_nt_global_flag {
        clear_peb_nt_global_flag(process, peb)?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn apply_peb_patches(_process: (), _profile: &AntiDebugProfile) -> Result<(), UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_profile_has_all_surfaces_armed() {
        let p = AntiDebugProfile::default();
        assert!(p.patch_peb_being_debugged);
        assert!(p.patch_peb_nt_global_flag);
        assert!(p.hook_is_debugger_present);
        assert!(p.hook_check_remote_debugger_present);
        assert!(p.hook_nt_query_info_process);
        assert!(p.hook_nt_set_info_thread);
    }

    #[test]
    fn disabled_profile_has_no_surfaces_armed() {
        let p = AntiDebugProfile::disabled();
        assert!(!p.patch_peb_being_debugged);
        assert!(!p.hook_is_debugger_present);
        assert!(p.installed_surface_names().is_empty());
    }

    #[test]
    fn surface_name_count_matches_armed_bits() {
        let p = AntiDebugProfile::default();
        assert_eq!(p.installed_surface_names().len(), 6);
        let mut p = p;
        p.hook_nt_query_info_process = false;
        assert_eq!(p.installed_surface_names().len(), 5);
    }

    #[test]
    fn surface_names_mention_peb_and_apis() {
        let p = AntiDebugProfile::default();
        let names = p.installed_surface_names();
        assert!(names.iter().any(|n| n.contains("BeingDebugged")));
        assert!(names.iter().any(|n| n.contains("IsDebuggerPresent")));
        assert!(names
            .iter()
            .any(|n| n.contains("NtQueryInformationProcess")));
    }

    #[cfg(not(windows))]
    #[test]
    fn peb_patches_on_non_windows_return_unsupported() {
        match patch_peb_being_debugged((), 0) {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!("expected UnsupportedPlatform, got {:?}", other),
        }
    }

    #[cfg(windows)]
    #[test]
    fn query_target_peb_on_current_process_returns_nonzero_address() {
        use windows::Win32::System::Threading::GetCurrentProcess;
        let peb = query_target_peb(unsafe { GetCurrentProcess() }).expect("query");
        assert!(peb > 0x1000, "PEB should sit in user-mode VA space");
    }
}
