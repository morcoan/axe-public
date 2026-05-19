//! `CreateRemoteThread → LoadLibrary` DLL injection sequence.
//!
//! Standard analyst injection: write the stub DLL path into the
//! target's address space via `VirtualAllocEx +
//! WriteProcessMemory`, then `CreateRemoteThread(target,
//! &kernel32!LoadLibraryW, &remote_path_buffer)`. The remote
//! thread runs `LoadLibraryW(stub_dll_path)` in the target's
//! context, calling the stub DLL's `DllMain` which installs
//! the actual API detours.
//!
//! # Why this is safe pre-resume
//!
//! Aurora runs this sequence after `spawn_suspended` but
//! BEFORE `resume_main_thread`. The remote thread runs while
//! the main thread is still suspended — there's no race with
//! the target's first instruction.
//!
//! # Stub status
//!
//! The high-level functions in this file (`inject_dll`,
//! `wait_for_remote_thread`) are wired through to real
//! Windows APIs. The end-to-end sequence is exercised by
//! `tests/unpack_anti_anti_vm.rs` once the stub DLL build
//! artifact lands at `build.rs` time (Step 26 follow-up).

use std::path::Path;

use crate::unpack::UnpackError;

/// Inject the stub DLL at `dll_path` into the target. Returns
/// the load address the stub DLL was loaded at (or 0 if
/// LoadLibrary failed).
#[cfg(windows)]
pub fn inject_dll(
    process: windows::Win32::Foundation::HANDLE,
    dll_path: &Path,
) -> Result<u64, UnpackError> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualFreeEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, GetExitCodeThread, WaitForSingleObject, INFINITE,
    };

    let path_wide: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let path_bytes = path_wide.len() * std::mem::size_of::<u16>();

    // 1. Allocate remote memory for the path string.
    let remote = unsafe {
        VirtualAllocEx(
            process,
            None,
            path_bytes,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if remote.is_null() {
        return Err(UnpackError::Pipeline(
            "VirtualAllocEx for DLL path failed".into(),
        ));
    }

    // 2. Write the path string.
    let mut written = 0;
    let write_res = unsafe {
        WriteProcessMemory(
            process,
            remote,
            path_wide.as_ptr() as *const _,
            path_bytes,
            Some(&mut written),
        )
    };
    if let Err(e) = write_res {
        unsafe {
            let _ = VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        }
        return Err(UnpackError::Pipeline(format!(
            "WriteProcessMemory for DLL path: {}",
            e
        )));
    }

    // 3. Resolve LoadLibraryW in our own process (works in
    // target due to per-boot ASLR).
    let kernel32 = {
        let name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
        unsafe { GetModuleHandleW(PCWSTR(name.as_ptr())) }
            .map_err(|e| UnpackError::Pipeline(format!("GetModuleHandleW kernel32: {}", e)))?
    };
    let loadlib_addr =
        unsafe { GetProcAddress(kernel32, windows::core::PCSTR(b"LoadLibraryW\0".as_ptr())) }
            .ok_or_else(|| UnpackError::Pipeline("GetProcAddress LoadLibraryW".into()))?;
    // Coerce to the lpStartAddress signature.
    let start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
        unsafe { std::mem::transmute(loadlib_addr) };

    // 4. CreateRemoteThread(LoadLibraryW, remote_path).
    let thread =
        unsafe { CreateRemoteThread(process, None, 0, Some(start), Some(remote), 0, None) }
            .map_err(|e| {
                UnpackError::Pipeline(format!("CreateRemoteThread LoadLibraryW: {}", e))
            })?;

    // 5. Wait for the remote thread to finish loading the DLL.
    unsafe {
        WaitForSingleObject(thread, INFINITE);
    }
    let mut exit_code: u32 = 0;
    let _ = unsafe { GetExitCodeThread(thread, &mut exit_code) };
    unsafe {
        let _ = CloseHandle(thread);
        let _ = VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    }
    Ok(exit_code as u64)
}

#[cfg(not(windows))]
pub fn inject_dll(_process: (), _dll_path: &Path) -> Result<u64, UnpackError> {
    Err(UnpackError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn inject_on_non_windows_returns_unsupported() {
        match inject_dll((), Path::new("anything.dll")) {
            Err(UnpackError::UnsupportedPlatform) => {}
            other => panic!("expected UnsupportedPlatform, got {:?}", other),
        }
    }

    // The Windows happy-path test requires a built stub DLL
    // artifact (Step 26 follow-up). Once `build.rs` produces
    // `aurora_stub.dll` in the OUT_DIR, this gets fleshed out
    // with a real injection into a `cmd.exe` suspended target.
}
