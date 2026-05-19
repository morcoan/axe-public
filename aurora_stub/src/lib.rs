//! Aurora's in-target stub DLL.
//!
//! Loaded into the analysis target via
//! `axe_core::unpack::hooks::inject::inject_dll` (which calls
//! `CreateRemoteThread → LoadLibraryW` from Aurora). Once
//! loaded, Aurora drives a second `CreateRemoteThread` against
//! the exported `aurora_stub_install_hooks` symbol to install
//! the anti-anti-VM + anti-debug detours.
//!
//! # Why retour HERE and not from Aurora's process
//!
//! `retour::GenericDetour` rewrites the prologue of an API in
//! the CURRENT process. The target's APIs live in the target's
//! address space, so the detour install must run from inside
//! the target — which is exactly what this DLL provides after
//! injection.
//!
//! # Default hook set
//!
//! - `IsDebuggerPresent` → returns FALSE
//! - `CheckRemoteDebuggerPresent` → sets `*pbDebuggerPresent = FALSE`,
//!   returns TRUE
//! - `GetSystemFirmwareTable(RSMB, ...)` → returns 0 (no SMBIOS
//!   data)

#![cfg(windows)]

use std::sync::OnceLock;

use retour::GenericDetour;
use windows::core::PCSTR;
use windows::Win32::Foundation::{BOOL, HMODULE};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

type IsDebuggerPresentFn = unsafe extern "system" fn() -> BOOL;
type CheckRemoteDebuggerPresentFn =
    unsafe extern "system" fn(process: isize, debugger_present: *mut BOOL) -> BOOL;
type GetSystemFirmwareTableFn = unsafe extern "system" fn(
    firmware_table_provider_signature: u32,
    firmware_table_id: u32,
    pfirmware_table_buffer: *mut std::ffi::c_void,
    buffer_size: u32,
) -> u32;

static IS_DEBUGGER_PRESENT_DETOUR: OnceLock<GenericDetour<IsDebuggerPresentFn>> = OnceLock::new();
static CHECK_REMOTE_DEBUGGER_DETOUR: OnceLock<GenericDetour<CheckRemoteDebuggerPresentFn>> =
    OnceLock::new();
static FIRMWARE_DETOUR: OnceLock<GenericDetour<GetSystemFirmwareTableFn>> = OnceLock::new();

unsafe extern "system" fn fake_is_debugger_present() -> BOOL {
    BOOL(0)
}

unsafe extern "system" fn fake_check_remote_debugger_present(
    _process: isize,
    debugger_present: *mut BOOL,
) -> BOOL {
    if !debugger_present.is_null() {
        *debugger_present = BOOL(0);
    }
    BOOL(1)
}

/// Unconditional 0-return for the RSMB SMBIOS provider; other
/// firmware-table providers are also zeroed because Aurora's
/// analyst-grade use case doesn't need legitimate firmware
/// data inside the unpacking target. This is slightly more
/// aggressive than the user-side `spoof_firmware::spoofed_return_value`
/// dispatch but simpler — retour 0.3 doesn't expose the
/// trampoline for fallthrough.
unsafe extern "system" fn fake_get_system_firmware_table(
    _firmware_table_provider_signature: u32,
    _firmware_table_id: u32,
    _pfirmware_table_buffer: *mut std::ffi::c_void,
    _buffer_size: u32,
) -> u32 {
    0
}

fn resolve(module: &str, api: &[u8]) -> Option<*const ()> {
    let module_z = format!("{}\0", module);
    unsafe {
        let h: HMODULE = GetModuleHandleA(PCSTR(module_z.as_ptr())).ok()?;
        let addr = GetProcAddress(h, PCSTR(api.as_ptr()))?;
        Some(addr as *const ())
    }
}

/// Aurora calls this via `CreateRemoteThread` after `LoadLibrary`
/// returns. The signature matches `LPTHREAD_START_ROUTINE`:
/// returns a u32 status code (0 = all detours installed,
/// non-zero = number that failed).
///
/// Idempotent: calling twice in the same process leaves the
/// first install in place and counts subsequent attempts as
/// already-installed (no-op success).
#[no_mangle]
pub unsafe extern "system" fn aurora_stub_install_hooks(_arg: *mut std::ffi::c_void) -> u32 {
    let mut failures = 0u32;

    if IS_DEBUGGER_PRESENT_DETOUR.get().is_none() {
        if let Some(addr) = resolve("kernel32.dll", b"IsDebuggerPresent\0") {
            let original: IsDebuggerPresentFn = std::mem::transmute(addr);
            match GenericDetour::<IsDebuggerPresentFn>::new(original, fake_is_debugger_present) {
                Ok(d) => {
                    if d.enable().is_ok() {
                        let _ = IS_DEBUGGER_PRESENT_DETOUR.set(d);
                    } else {
                        failures += 1;
                    }
                }
                Err(_) => failures += 1,
            }
        } else {
            failures += 1;
        }
    }

    if CHECK_REMOTE_DEBUGGER_DETOUR.get().is_none() {
        if let Some(addr) = resolve("kernel32.dll", b"CheckRemoteDebuggerPresent\0") {
            let original: CheckRemoteDebuggerPresentFn = std::mem::transmute(addr);
            match GenericDetour::<CheckRemoteDebuggerPresentFn>::new(
                original,
                fake_check_remote_debugger_present,
            ) {
                Ok(d) => {
                    if d.enable().is_ok() {
                        let _ = CHECK_REMOTE_DEBUGGER_DETOUR.set(d);
                    } else {
                        failures += 1;
                    }
                }
                Err(_) => failures += 1,
            }
        } else {
            failures += 1;
        }
    }

    if FIRMWARE_DETOUR.get().is_none() {
        if let Some(addr) = resolve("kernel32.dll", b"GetSystemFirmwareTable\0") {
            let original: GetSystemFirmwareTableFn = std::mem::transmute(addr);
            match GenericDetour::<GetSystemFirmwareTableFn>::new(
                original,
                fake_get_system_firmware_table,
            ) {
                Ok(d) => {
                    if d.enable().is_ok() {
                        let _ = FIRMWARE_DETOUR.set(d);
                    } else {
                        failures += 1;
                    }
                }
                Err(_) => failures += 1,
            }
        } else {
            failures += 1;
        }
    }

    failures
}

/// Standard DllMain — no-op. All install work happens in
/// `aurora_stub_install_hooks` so Aurora can sequence injection
/// (LoadLibrary) before install (a separate CreateRemoteThread).
#[no_mangle]
pub extern "system" fn DllMain(
    _hinstance: isize,
    _reason: u32,
    _reserved: *mut std::ffi::c_void,
) -> BOOL {
    BOOL(1)
}
