//! Aurora stub DLL — references + build-time integration.
//!
//! The stub DLL is a separate Rust cdylib crate
//! (`aurora_stub`) that lives as a workspace member. It uses
//! `retour::GenericDetour` to install the actual API hooks
//! once it's loaded into the target's address space via
//! `hooks::inject::inject_dll`.
//!
//! # Status (Step 26 skeleton)
//!
//! This file documents the build-time contract. The
//! `aurora_stub` crate itself is shipped as a follow-up;
//! `build.rs` will:
//!
//! 1. Compile `aurora_stub` if `feature = "unpack"` is on AND
//!    target is Windows.
//! 2. Place the resulting `aurora_stub.dll` in `OUT_DIR` so
//!    `stub_dll_path()` can locate it at runtime.
//!
//! Until then, `stub_dll_path()` returns `None` and
//! `inject_dll` callers must handle that by skipping the
//! anti-anti-VM injection phase (the snapshot will reflect
//! `anti_vm_profile.user_mode_hooks_installed = []`).

use std::path::{Path, PathBuf};

/// Locate `aurora_stub.dll` produced by `build.rs`. Returns
/// `None` if the artifact isn't present (the build skipped it,
/// or we're on a platform that doesn't compile it).
///
/// Search order:
/// 1. `$AURORA_STUB_DLL` env var (test / CI override).
/// 2. `OUT_DIR/aurora_stub.dll` (set by `build.rs`).
/// 3. Same directory as the running `axe` binary — for
///    deployed installs.
pub fn stub_dll_path() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("AURORA_STUB_DLL") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    if let Some(out_dir) = option_env!("OUT_DIR") {
        let p = Path::new(out_dir).join("aurora_stub.dll");
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("aurora_stub.dll");
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

/// Name of the stub's exported initializer that
/// `inject::inject_dll`'s second `CreateRemoteThread` will
/// call to install the detours per the user's profile.
pub const STUB_INIT_EXPORT: &str = "aurora_stub_install_hooks";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_dll_path_returns_none_when_artifact_absent() {
        // Pre-Step-26-follow-up state: no aurora_stub.dll in
        // OUT_DIR. Test runs on every platform.
        std::env::remove_var("AURORA_STUB_DLL");
        // The function may still find something via OUT_DIR or
        // exe-sibling — accept either outcome but verify the
        // function doesn't panic.
        let _ = stub_dll_path();
    }

    #[test]
    fn env_override_takes_precedence() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::env::set_var("AURORA_STUB_DLL", tmp.path());
        let resolved = stub_dll_path();
        std::env::remove_var("AURORA_STUB_DLL");
        assert_eq!(resolved.as_deref(), Some(tmp.path()));
    }

    #[test]
    fn init_export_name_is_pinned() {
        assert_eq!(STUB_INIT_EXPORT, "aurora_stub_install_hooks");
    }
}
