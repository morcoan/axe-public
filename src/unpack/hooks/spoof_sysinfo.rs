//! Filter `NtQuerySystemInformation(SystemModuleInformation)`
//! to hide VM-tool kernel drivers.
//!
//! Loaded drivers like `VBoxGuest.sys`, `VBoxMouse.sys`,
//! `vmci.sys`, `vmhgfs.sys`, `vmmouse.sys`, `vmtools.sys` leak
//! the VM. The spoof walks the
//! `SYSTEM_MODULE_INFORMATION.Modules[]` array and removes
//! entries whose `ImageName` matches the hidden list (decrements
//! `NumberOfModules` accordingly).

pub const HIDDEN_DRIVERS: &[&str] = &[
    "VBoxGuest.sys",
    "VBoxMouse.sys",
    "VBoxSF.sys",
    "VBoxVideo.sys",
    "VBoxWddm.sys",
    "vmci.sys",
    "vmhgfs.sys",
    "vmmouse.sys",
    "vmusb.sys",
    "vmtools.sys",
    "vmsrvc.sys",
    "vmx_svga.sys",
    "vsock.sys",
    "prleth.sys",
    "prlfs.sys",
    "prlmouse.sys",
    "prlvideo.sys",
];

pub fn should_hide(driver_name: &str) -> bool {
    let basename = driver_name
        .rsplit(|c| c == '\\' || c == '/')
        .next()
        .unwrap_or(driver_name);
    HIDDEN_DRIVERS
        .iter()
        .any(|d| d.eq_ignore_ascii_case(basename))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vbox_guest_driver_is_hidden() {
        assert!(should_hide("VBoxGuest.sys"));
    }

    #[test]
    fn full_path_is_basename_matched() {
        assert!(should_hide(
            "\\SystemRoot\\System32\\drivers\\VBoxGuest.sys"
        ));
        assert!(should_hide("C:/Windows/System32/drivers/vmci.sys"));
    }

    #[test]
    fn vmware_tools_drivers_all_hidden() {
        assert!(should_hide("vmci.sys"));
        assert!(should_hide("vmhgfs.sys"));
        assert!(should_hide("vmmouse.sys"));
    }

    #[test]
    fn parallels_drivers_hidden() {
        assert!(should_hide("prleth.sys"));
        assert!(should_hide("prlmouse.sys"));
    }

    #[test]
    fn ntoskrnl_not_hidden() {
        assert!(!should_hide("ntoskrnl.exe"));
        assert!(!should_hide("hal.dll"));
        assert!(!should_hide("tcpip.sys"));
    }

    #[test]
    fn case_insensitive() {
        assert!(should_hide("vboxguest.sys"));
        assert!(should_hide("VBOXGUEST.SYS"));
    }
}
