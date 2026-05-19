//! Enumerate the target's memory layout via `VirtualQueryEx`.
//!
//! Walks from address 0 upward, calling `VirtualQueryEx` on
//! each successive base and stepping to `base + region_size`
//! until the kernel reports no more regions or the address
//! overflows 64-bit user space (typically `0x7FFFFFFFFFFF` on
//! Windows x64).
//!
//! Used by:
//! - `guard_pages.rs` (Step 14) to pick the non-executable
//!   regions where PAGE_GUARD should be installed.
//! - `snapshot_capture.rs` (Step 17) to know which regions to
//!   ReadProcessMemory.
//! - `api_intercept.rs` (Step 16) to find the loaded
//!   `kernel32.dll` / `ntdll.dll` images for `GetProcAddress`.

use crate::unpack::UnpackError;

/// One row from `VirtualQueryEx`. Mirrors the Windows
/// `MEMORY_BASIC_INFORMATION` shape with portable types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionInfo {
    pub base: u64,
    pub size: u64,
    /// Allocation base — the original VA returned by the
    /// underlying allocator (`VirtualAlloc`, image load, etc.).
    /// Multiple committed regions can share an allocation_base
    /// when the original allocation was later split via
    /// `VirtualProtect`.
    pub allocation_base: u64,
    pub state: RegionState,
    /// "RWX" / "RW-" / "R-X" / "R--" / "---". For
    /// `RegionState::Free` this is always `"---"`.
    pub protect: String,
    pub kind: RegionKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionState {
    /// `MEM_COMMIT` — backed by physical or pagefile memory.
    Committed,
    /// `MEM_RESERVE` — VA space reserved but not backed.
    Reserved,
    /// `MEM_FREE` — VA space available for `VirtualAlloc`.
    Free,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionKind {
    /// `MEM_IMAGE` — loaded EXE or DLL.
    Image,
    /// `MEM_MAPPED` — file or section view.
    Mapped,
    /// `MEM_PRIVATE` — heap / stack / `VirtualAlloc`.
    Private,
    /// `MEM_FREE` regions and unknown.
    None,
}

/// Walk the entire target address space. Returns all regions
/// reported by `VirtualQueryEx`, including `Free` ones (callers
/// that care about committed memory only should filter).
#[cfg(windows)]
pub fn enumerate(
    process: windows::Win32::Foundation::HANDLE,
) -> Result<Vec<RegionInfo>, UnpackError> {
    use windows::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_MAPPED,
        MEM_PRIVATE, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    };

    let mut out = Vec::new();
    let mut addr: u64 = 0;
    // Practical x64 user-space ceiling. Going beyond is harmless
    // (VirtualQueryEx returns 0) but the explicit cap protects
    // against pathological infinite loops if the kernel ever
    // returns a zero-size region without advancing the base.
    let ceiling: u64 = 0x0000_7FFF_FFFE_FFFF;

    while addr < ceiling {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let written = unsafe {
            VirtualQueryEx(
                process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            break;
        }
        let region_size = mbi.RegionSize as u64;
        if region_size == 0 {
            break; // defensive: should never happen, would loop forever
        }
        let state = if mbi.State == MEM_COMMIT {
            RegionState::Committed
        } else if mbi.State == MEM_RESERVE {
            RegionState::Reserved
        } else if mbi.State == MEM_FREE {
            RegionState::Free
        } else {
            // Unknown state — record as Reserved so callers
            // don't try to read it.
            RegionState::Reserved
        };
        let kind = if mbi.Type == MEM_IMAGE {
            RegionKind::Image
        } else if mbi.Type == MEM_MAPPED {
            RegionKind::Mapped
        } else if mbi.Type == MEM_PRIVATE {
            RegionKind::Private
        } else {
            RegionKind::None
        };
        let protect = if state == RegionState::Free {
            "---".to_string()
        } else {
            decode_protect_amd64(
                mbi.Protect,
                PAGE_NOACCESS,
                PAGE_READONLY,
                PAGE_READWRITE,
                PAGE_WRITECOPY,
                PAGE_EXECUTE,
                PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE,
                PAGE_EXECUTE_WRITECOPY,
            )
        };
        out.push(RegionInfo {
            base: mbi.BaseAddress as u64,
            size: region_size,
            allocation_base: mbi.AllocationBase as u64,
            state,
            protect,
            kind,
        });
        // Advance to the next region. saturating_add covers the
        // ceiling case.
        addr = (mbi.BaseAddress as u64).saturating_add(region_size);
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn enumerate(_process: ()) -> Result<Vec<RegionInfo>, UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

/// Convenience filter: only `Committed` regions, useful for
/// guard-page install and snapshot capture.
pub fn committed_only(regions: &[RegionInfo]) -> Vec<RegionInfo> {
    regions
        .iter()
        .filter(|r| r.state == RegionState::Committed)
        .cloned()
        .collect()
}

/// Convenience filter: only `Image` regions (mapped EXE/DLL).
/// Used by `api_intercept.rs` to walk loaded modules.
pub fn image_only(regions: &[RegionInfo]) -> Vec<RegionInfo> {
    regions
        .iter()
        .filter(|r| r.kind == RegionKind::Image)
        .cloned()
        .collect()
}

/// Helper that decodes Win32 `PAGE_*` flags into a compact
/// "RWX"/"R-X"/"RW-"/"R--"/"---" string. Keeps the decode logic
/// portable to platforms that don't expose `PAGE_*` constants.
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn decode_protect_amd64(
    protect: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
    noaccess: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
    readonly: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
    readwrite: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
    writecopy: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
    execute: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
    execute_read: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
    execute_readwrite: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
    execute_writecopy: windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
) -> String {
    // Mask off PAGE_GUARD (0x100), PAGE_NOCACHE (0x200),
    // PAGE_WRITECOMBINE (0x400) so the dispatch below matches
    // the base protect value.
    let masked_raw = protect.0 & 0xFF;
    let m = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(masked_raw);
    if m == noaccess {
        "---".to_string()
    } else if m == readonly {
        "R--".to_string()
    } else if m == readwrite || m == writecopy {
        "RW-".to_string()
    } else if m == execute {
        "--X".to_string()
    } else if m == execute_read {
        "R-X".to_string()
    } else if m == execute_readwrite || m == execute_writecopy {
        "RWX".to_string()
    } else {
        // Unknown combination — emit raw hex so callers can
        // diagnose without crashing.
        format!("0x{:02x}", masked_raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(
        base: u64,
        size: u64,
        state: RegionState,
        kind: RegionKind,
        protect: &str,
    ) -> RegionInfo {
        RegionInfo {
            base,
            size,
            allocation_base: base,
            state,
            protect: protect.into(),
            kind,
        }
    }

    #[test]
    fn committed_only_filters_state() {
        let regions = vec![
            fake(0, 0x1000, RegionState::Committed, RegionKind::Image, "R-X"),
            fake(
                0x1000,
                0x1000,
                RegionState::Reserved,
                RegionKind::None,
                "---",
            ),
            fake(0x2000, 0x1000, RegionState::Free, RegionKind::None, "---"),
            fake(
                0x3000,
                0x1000,
                RegionState::Committed,
                RegionKind::Private,
                "RW-",
            ),
        ];
        let out = committed_only(&regions);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].base, 0);
        assert_eq!(out[1].base, 0x3000);
    }

    #[test]
    fn image_only_filters_kind() {
        let regions = vec![
            fake(0, 0x1000, RegionState::Committed, RegionKind::Image, "R-X"),
            fake(
                0x1000,
                0x1000,
                RegionState::Committed,
                RegionKind::Private,
                "RW-",
            ),
            fake(
                0x2000,
                0x1000,
                RegionState::Committed,
                RegionKind::Mapped,
                "R--",
            ),
        ];
        let out = image_only(&regions);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].base, 0);
    }

    #[cfg(not(windows))]
    #[test]
    fn enumerate_on_non_windows_returns_unsupported() {
        match enumerate(()) {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!("expected UnsupportedPlatform, got {:?}", other),
        }
    }

    #[cfg(windows)]
    #[test]
    fn enumerate_current_process_returns_image_and_stack_regions() {
        use windows::Win32::System::Threading::GetCurrentProcess;
        let process = unsafe { GetCurrentProcess() };
        let regions = enumerate(process).expect("enumerate");
        assert!(regions.len() > 10, "current process must have many regions");
        // At least one Image region (the test binary itself).
        let image_count = regions
            .iter()
            .filter(|r| r.kind == RegionKind::Image)
            .count();
        assert!(
            image_count >= 1,
            "expected ≥1 Image region, got {}",
            image_count
        );
        // At least one Committed Private region (thread stack +
        // heap).
        let private_committed = regions
            .iter()
            .filter(|r| r.kind == RegionKind::Private && r.state == RegionState::Committed)
            .count();
        assert!(
            private_committed >= 1,
            "expected ≥1 Committed Private region, got {}",
            private_committed
        );
    }

    #[cfg(windows)]
    #[test]
    fn enumerated_regions_are_address_ordered_with_no_gaps_in_user_space() {
        use windows::Win32::System::Threading::GetCurrentProcess;
        let regions = enumerate(unsafe { GetCurrentProcess() }).expect("enumerate");
        for w in regions.windows(2) {
            let prev_end = w[0].base.saturating_add(w[0].size);
            assert_eq!(
                prev_end, w[1].base,
                "regions must tile user-space contiguously: prev ends at {:#x}, next starts at {:#x}",
                prev_end, w[1].base
            );
        }
    }
}
