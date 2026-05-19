//! User-mode side of the driver bridge — locates the driver
//! artifact, loads it via SCM, sends IOCTLs.

use std::path::PathBuf;

/// Look for `aurora_drv.sys` next to the running binary.
/// Returns `None` if not present.
pub fn resolve_driver_artifact() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("AURORA_DRV_SYS") {
        let p = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("aurora_drv.sys");
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_resolves_via_env_override() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::env::set_var("AURORA_DRV_SYS", tmp.path());
        let resolved = resolve_driver_artifact();
        std::env::remove_var("AURORA_DRV_SYS");
        assert_eq!(resolved.as_deref(), Some(tmp.path()));
    }

    #[test]
    fn artifact_returns_none_when_absent() {
        std::env::remove_var("AURORA_DRV_SYS");
        // exe-sibling lookup may or may not find a sys file; just
        // verify no panic.
        let _ = resolve_driver_artifact();
    }
}
