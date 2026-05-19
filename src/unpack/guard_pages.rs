//! PAGE_GUARD install + `STATUS_GUARD_PAGE_VIOLATION` decode.
//!
//! # How PAGE_GUARD works
//!
//! `VirtualProtectEx` with the `PAGE_GUARD` flag added to the
//! base protection (e.g. `PAGE_READWRITE | PAGE_GUARD`) marks
//! the page as "trap on next access". The first access by the
//! target raises `STATUS_GUARD_PAGE_VIOLATION` (0x80000001) AND
//! atomically clears `PAGE_GUARD` from the page (so the page is
//! immediately usable for the access in flight after Aurora
//! continues the exception).
//!
//! Aurora uses guard pages as a low-overhead write tracer:
//! install on every non-executable region, capture the faulting
//! address from each violation event, optionally re-arm the
//! guard if it wants to keep tracing the same page.
//!
//! # `STATUS_GUARD_PAGE_VIOLATION` exception record shape
//!
//! Windows reports this via `EXCEPTION_DEBUG_INFO.ExceptionRecord`
//! with:
//! - `ExceptionCode = STATUS_GUARD_PAGE_VIOLATION`
//! - `ExceptionInformation[0]` = access type (`0` read, `1`
//!   write, `8` execute)
//! - `ExceptionInformation[1]` = the faulting address
//!
//! `guard_pages::decode_guard_violation` extracts the typed
//! `GuardViolation` shape from a raw `EXCEPTION_RECORD`.

use crate::unpack::UnpackError;

/// `STATUS_GUARD_PAGE_VIOLATION` numeric code. Same on all
/// Windows versions.
pub const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardAccessKind {
    Read,
    Write,
    Execute,
    /// Unknown / unrecognized access code from the kernel.
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardViolation {
    /// VA of the byte the target tried to access.
    pub faulting_address: u64,
    pub access: GuardAccessKind,
}

/// Install `PAGE_GUARD` on a range of `size` bytes starting at
/// `address`. The new protection is `original_protect | PAGE_GUARD`.
/// `original_protect` MUST be the current page protection — pass
/// `0` to let the function compute it via `VirtualQueryEx` (small
/// extra cost; usable when the caller doesn't already know).
#[cfg(windows)]
pub fn install_guard(
    process: windows::Win32::Foundation::HANDLE,
    address: u64,
    size: usize,
    original_protect: u32,
) -> Result<u32, UnpackError> {
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_GUARD, PAGE_PROTECTION_FLAGS};
    let base_protect = if original_protect != 0 {
        original_protect
    } else {
        query_protect(process, address)?
    };
    let new_protect = PAGE_PROTECTION_FLAGS(base_protect | PAGE_GUARD.0);
    let mut old: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(process, address as *const _, size, new_protect, &mut old).map_err(
            |e| {
                UnpackError::Pipeline(format!(
                    "VirtualProtectEx +PAGE_GUARD @ {:#x}..{:#x}: {}",
                    address,
                    address + size as u64,
                    e
                ))
            },
        )?;
    }
    Ok(old.0)
}

/// Restore a range to the given `protect` value (the original
/// returned by `install_guard`). Use after handling a violation
/// when the caller does NOT want to keep tracing this page.
#[cfg(windows)]
pub fn restore_protect(
    process: windows::Win32::Foundation::HANDLE,
    address: u64,
    size: usize,
    protect: u32,
) -> Result<(), UnpackError> {
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS};
    let mut old: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            process,
            address as *const _,
            size,
            PAGE_PROTECTION_FLAGS(protect),
            &mut old,
        )
        .map_err(|e| {
            UnpackError::Pipeline(format!(
                "VirtualProtectEx restore @ {:#x}..{:#x}: {}",
                address,
                address + size as u64,
                e
            ))
        })?;
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn install_guard(
    _process: (),
    _address: u64,
    _size: usize,
    _original_protect: u32,
) -> Result<u32, UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

#[cfg(not(windows))]
pub fn restore_protect(
    _process: (),
    _address: u64,
    _size: usize,
    _protect: u32,
) -> Result<(), UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

#[cfg(windows)]
fn query_protect(
    process: windows::Win32::Foundation::HANDLE,
    address: u64,
) -> Result<u32, UnpackError> {
    use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
    let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let written = unsafe {
        VirtualQueryEx(
            process,
            Some(address as *const _),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if written == 0 {
        return Err(UnpackError::Pipeline(format!(
            "VirtualQueryEx @ {:#x} failed",
            address
        )));
    }
    Ok(mbi.Protect.0)
}

/// Decode a raw `EXCEPTION_RECORD` into a typed `GuardViolation`.
/// Returns `None` when the exception code is not
/// `STATUS_GUARD_PAGE_VIOLATION`. Pure function — no FFI; usable
/// in cross-platform tests against a hand-crafted record.
pub fn decode_guard_violation(
    code: u32,
    exception_information: &[usize],
) -> Option<GuardViolation> {
    if code != STATUS_GUARD_PAGE_VIOLATION {
        return None;
    }
    if exception_information.len() < 2 {
        return None;
    }
    let access = match exception_information[0] {
        0 => GuardAccessKind::Read,
        1 => GuardAccessKind::Write,
        8 => GuardAccessKind::Execute,
        _ => GuardAccessKind::Other,
    };
    let faulting_address = exception_information[1] as u64;
    Some(GuardViolation {
        faulting_address,
        access,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_returns_none_for_wrong_code() {
        assert!(decode_guard_violation(0xC0000005, &[0, 0]).is_none());
    }

    #[test]
    fn decode_returns_none_when_info_too_short() {
        assert!(decode_guard_violation(STATUS_GUARD_PAGE_VIOLATION, &[]).is_none());
        assert!(decode_guard_violation(STATUS_GUARD_PAGE_VIOLATION, &[0]).is_none());
    }

    #[test]
    fn decode_read_access() {
        let v = decode_guard_violation(STATUS_GUARD_PAGE_VIOLATION, &[0, 0x140001234]).unwrap();
        assert_eq!(v.access, GuardAccessKind::Read);
        assert_eq!(v.faulting_address, 0x140001234);
    }

    #[test]
    fn decode_write_access() {
        let v = decode_guard_violation(STATUS_GUARD_PAGE_VIOLATION, &[1, 0x140005678]).unwrap();
        assert_eq!(v.access, GuardAccessKind::Write);
        assert_eq!(v.faulting_address, 0x140005678);
    }

    #[test]
    fn decode_execute_access() {
        let v = decode_guard_violation(STATUS_GUARD_PAGE_VIOLATION, &[8, 0x140009abc]).unwrap();
        assert_eq!(v.access, GuardAccessKind::Execute);
        assert_eq!(v.faulting_address, 0x140009abc);
    }

    #[test]
    fn decode_other_access_for_unknown_code() {
        let v = decode_guard_violation(STATUS_GUARD_PAGE_VIOLATION, &[42, 0x0]).unwrap();
        assert_eq!(v.access, GuardAccessKind::Other);
    }

    #[cfg(not(windows))]
    #[test]
    fn install_guard_on_non_windows_returns_unsupported() {
        match install_guard((), 0, 4096, 0) {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!("expected UnsupportedPlatform, got {:?}", other),
        }
    }

    #[cfg(windows)]
    #[test]
    fn install_guard_on_own_heap_page_round_trips_protect() {
        // Allocate a private RW page in our own process, install
        // PAGE_GUARD, restore. Verifies the FFI path against a
        // real allocation without spawning a child process.
        use windows::Win32::System::Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
        };
        use windows::Win32::System::Threading::GetCurrentProcess;
        let process = unsafe { GetCurrentProcess() };
        let page = unsafe { VirtualAlloc(None, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        assert!(!page.is_null(), "VirtualAlloc must succeed");
        let addr = page as u64;
        let original = install_guard(process, addr, 4096, PAGE_READWRITE.0).expect("install_guard");
        // original should reflect the pre-guard protection (RW)
        assert_eq!(original & 0xFF, PAGE_READWRITE.0);
        // Restore back to RW so VirtualFree sees a sane page.
        restore_protect(process, addr, 4096, PAGE_READWRITE.0).expect("restore_protect");
        unsafe {
            let _ = VirtualFree(page, 0, MEM_RELEASE);
        }
    }
}
