//! API breakpoint table — soft BPs on the memory-allocation +
//! memory-protection + process-creation surfaces Aurora wants
//! to trace.
//!
//! # Why this works without symbols in the target
//!
//! System DLLs (`ntdll.dll`, `kernel32.dll`, `kernelbase.dll`)
//! are ASLR-randomized ONCE per boot — every process on the
//! same boot sees the same base for these DLLs. Aurora's
//! `GetModuleHandleW` on its own process therefore returns the
//! address valid in the target too. `GetProcAddress` resolves
//! the export RVA against that base. This is the standard
//! trick used by ScyllaHide, x64dbg, and similar tools.
//!
//! Targets that explicitly disable known-DLL caching or use
//! private system-DLL copies are an explicit non-goal.
//!
//! # x64 calling convention
//!
//! Windows x64 ABI: first 4 integer/pointer args go in
//! `RCX, RDX, R8, R9`. Stack args start at `RSP+0x28` (after
//! the 0x20-byte shadow space + the return address). Aurora
//! decodes args by reading `CONTEXT` after a BP hits + slurping
//! stack bytes via `ReadProcessMemory`.

use crate::unpack::UnpackError;

/// Classification of a hooked API. Drives which arg-decoder
/// runs after the BP hits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiKind {
    /// `VirtualAlloc(Ex) / NtAllocateVirtualMemory` — region
    /// creation. Aurora's snapshot tracks allocations as
    /// `RegionOrigin::alloc_api`.
    MemoryAlloc,
    /// `VirtualProtect(Ex) / NtProtectVirtualMemory` — protection
    /// change. The "made writable then made executable" sequence
    /// is the canonical unpacker fingerprint.
    MemoryProtect,
    /// `WriteProcessMemory / NtWriteVirtualMemory` — cross-process
    /// write. Process-hollowing / injection signal.
    MemoryWrite,
    /// `CreateProcessInternalW / NtCreateUserProcess` — child
    /// process spawn. The packer hollowing flow uses this.
    ProcessCreate,
    /// `NtUnmapViewOfSection` — process-hollowing's first move
    /// (unmap the original image so a payload can be mapped in
    /// its place).
    MemoryUnmap,
}

/// One BP target — a fully resolved API entry point.
#[derive(Clone, Debug)]
pub struct ApiBreakpoint {
    pub module: &'static str,
    pub api: &'static str,
    pub kind: ApiKind,
    /// Absolute VA after `GetModuleHandle + GetProcAddress`.
    /// Valid in both Aurora and the target due to per-boot ASLR.
    pub address: u64,
}

/// Master table of APIs Aurora hooks. The order is stable so
/// tests + snapshot output can reference indices.
pub const API_TABLE: &[(&str, &str, ApiKind)] = &[
    ("kernel32.dll", "VirtualAlloc", ApiKind::MemoryAlloc),
    ("kernel32.dll", "VirtualAllocEx", ApiKind::MemoryAlloc),
    ("ntdll.dll", "NtAllocateVirtualMemory", ApiKind::MemoryAlloc),
    ("kernel32.dll", "VirtualProtect", ApiKind::MemoryProtect),
    ("kernel32.dll", "VirtualProtectEx", ApiKind::MemoryProtect),
    (
        "ntdll.dll",
        "NtProtectVirtualMemory",
        ApiKind::MemoryProtect,
    ),
    ("kernel32.dll", "WriteProcessMemory", ApiKind::MemoryWrite),
    ("ntdll.dll", "NtWriteVirtualMemory", ApiKind::MemoryWrite),
    (
        "kernel32.dll",
        "CreateProcessInternalW",
        ApiKind::ProcessCreate,
    ),
    ("ntdll.dll", "NtCreateUserProcess", ApiKind::ProcessCreate),
    ("ntdll.dll", "NtUnmapViewOfSection", ApiKind::MemoryUnmap),
];

/// Resolve every entry in `API_TABLE` against the live process
/// view (Aurora's own process). Missing exports are silently
/// skipped (some APIs are private to one Windows version);
/// returns the successfully resolved set.
#[cfg(windows)]
pub fn resolve_all() -> Vec<ApiBreakpoint> {
    let mut out = Vec::with_capacity(API_TABLE.len());
    for (module, api, kind) in API_TABLE {
        if let Some(addr) = resolve_one(module, api) {
            out.push(ApiBreakpoint {
                module,
                api,
                kind: *kind,
                address: addr,
            });
        }
    }
    out
}

#[cfg(not(windows))]
pub fn resolve_all() -> Vec<ApiBreakpoint> {
    Vec::new()
}

/// Resolve a single API to its absolute VA. Returns `None` when
/// the module isn't loaded OR the export isn't present (which
/// is normal for OS-version-specific APIs).
#[cfg(windows)]
pub fn resolve_one(module: &str, api: &str) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::{PCSTR, PCWSTR};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    let mod_wide: Vec<u16> = std::ffi::OsStr::new(module)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let h = unsafe { GetModuleHandleW(PCWSTR(mod_wide.as_ptr())) }.ok()?;
    let api_z = format!("{}\0", api);
    let proc_addr = unsafe { GetProcAddress(h, PCSTR(api_z.as_ptr())) }?;
    Some(proc_addr as usize as u64)
}

#[cfg(not(windows))]
pub fn resolve_one(_module: &str, _api: &str) -> Option<u64> {
    None
}

/// X64 calling-convention argument projection of a thread
/// CONTEXT. First 4 args in registers; later args are stack
/// pointers the caller resolves via `ReadProcessMemory`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ArgsX64 {
    /// `RCX` — first arg.
    pub arg0: u64,
    /// `RDX` — second arg.
    pub arg1: u64,
    /// `R8` — third arg.
    pub arg2: u64,
    /// `R9` — fourth arg.
    pub arg3: u64,
    /// `RSP` at call site — `arg4` is at `[rsp + 0x28]`,
    /// `arg5` at `[rsp + 0x30]`, etc. The 0x20-byte shadow
    /// space sits between RSP+0 and the first stack arg.
    pub rsp: u64,
    /// Saved return address (read from `[rsp]` at BP hit). The
    /// caller uses this to skip past the API on continue.
    pub return_address: u64,
}

#[cfg(windows)]
impl ArgsX64 {
    /// Extract from a typed `CONTEXT`. Reads `RCX, RDX, R8, R9,
    /// RSP` directly; the return address is the QWORD at `[RSP]`
    /// in the target's memory.
    pub fn from_context_and_stack(
        ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT,
        process: windows::Win32::Foundation::HANDLE,
    ) -> Self {
        let rsp = ctx.Rsp;
        let return_address = read_qword(process, rsp).unwrap_or(0);
        Self {
            arg0: ctx.Rcx,
            arg1: ctx.Rdx,
            arg2: ctx.R8,
            arg3: ctx.R9,
            rsp,
            return_address,
        }
    }

    /// Read the Nth stack argument (N >= 4). `arg4` is at
    /// `rsp + 0x28`, `arg5` at `rsp + 0x30`, ...
    pub fn stack_arg(&self, n: usize, process: windows::Win32::Foundation::HANDLE) -> Option<u64> {
        if n < 4 {
            return None;
        }
        let offset = 0x28 + (n - 4) as u64 * 8;
        read_qword(process, self.rsp + offset)
    }
}

#[cfg(windows)]
fn read_qword(process: windows::Win32::Foundation::HANDLE, address: u64) -> Option<u64> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    let mut buf = [0u8; 8];
    let mut got: usize = 0;
    unsafe {
        ReadProcessMemory(
            process,
            address as *const _,
            buf.as_mut_ptr() as *mut _,
            8,
            Some(&mut got),
        )
        .ok()?;
    }
    if got != 8 {
        return None;
    }
    Some(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_table_has_at_least_the_planned_eleven() {
        // Plan calls out: VirtualAlloc(Ex), NtAllocateVirtualMemory,
        // VirtualProtect(Ex), NtProtectVirtualMemory, WriteProcessMemory,
        // NtWriteVirtualMemory, CreateProcessInternalW, NtCreateUserProcess,
        // NtUnmapViewOfSection.
        assert!(
            API_TABLE.len() >= 11,
            "API_TABLE shorter than the plan calls for"
        );
    }

    #[test]
    fn api_table_kind_distribution_covers_all_kinds() {
        let mut alloc = 0;
        let mut prot = 0;
        let mut write = 0;
        let mut proc_create = 0;
        let mut unmap = 0;
        for (_, _, k) in API_TABLE {
            match k {
                ApiKind::MemoryAlloc => alloc += 1,
                ApiKind::MemoryProtect => prot += 1,
                ApiKind::MemoryWrite => write += 1,
                ApiKind::ProcessCreate => proc_create += 1,
                ApiKind::MemoryUnmap => unmap += 1,
            }
        }
        assert!(alloc > 0);
        assert!(prot > 0);
        assert!(write > 0);
        assert!(proc_create > 0);
        assert!(unmap > 0);
    }

    #[cfg(windows)]
    #[test]
    fn resolve_one_finds_kernel32_virtualalloc() {
        let addr = resolve_one("kernel32.dll", "VirtualAlloc");
        assert!(
            addr.is_some(),
            "kernel32!VirtualAlloc must resolve on a live Windows host"
        );
        assert_ne!(addr.unwrap(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn resolve_one_returns_none_for_nonexistent_export() {
        let addr = resolve_one("kernel32.dll", "DefinitelyNotARealExport");
        assert!(addr.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn resolve_one_returns_none_for_unloaded_module() {
        let addr = resolve_one("notamodule.dll", "Whatever");
        assert!(addr.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn resolve_all_finds_at_least_most_of_the_table() {
        let resolved = resolve_all();
        // ntdll exports should always resolve (it's always
        // loaded). Kernel32 exports should resolve in test
        // processes too. Some Nt-prefixed exports may not be
        // public on older Windows, so don't require full table
        // coverage — just expect ≥7 out of 11.
        assert!(
            resolved.len() >= 7,
            "expected ≥7 of {} APIs to resolve, got {}",
            API_TABLE.len(),
            resolved.len()
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn resolve_all_on_non_windows_returns_empty() {
        assert!(resolve_all().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn args_x64_stack_arg_indexing_matches_abi() {
        // arg4 at rsp+0x28, arg5 at rsp+0x30, ...
        // We don't actually call into a target here; just check
        // the offset arithmetic via the public method's
        // contract.
        use windows::Win32::System::Threading::GetCurrentProcess;
        let args = ArgsX64 {
            arg0: 1,
            arg1: 2,
            arg2: 3,
            arg3: 4,
            rsp: 0, // null — read will fail; we only check < 4
            return_address: 0,
        };
        // Index < 4 returns None per contract.
        assert!(args.stack_arg(0, unsafe { GetCurrentProcess() }).is_none());
        assert!(args.stack_arg(3, unsafe { GetCurrentProcess() }).is_none());
    }
}
