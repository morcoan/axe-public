//! Hide VM-tooling processes from
//! `CreateToolhelp32Snapshot` + `Process32FirstW/NextW`.
//!
//! Targets enumerate running processes looking for VM-tool
//! signatures (`vmtoolsd.exe`, `vmwaretray.exe`, `VBoxService.exe`,
//! `VBoxTray.exe`, `prl_tools.exe`, `vmsrvc.exe`). The spoof
//! removes matching entries from the snapshot's process list.

/// Process names hidden from snapshot enumeration. Case-
/// insensitive comparison.
pub const HIDDEN_PROCESSES: &[&str] = &[
    "vmtoolsd.exe",
    "vmwaretray.exe",
    "vmwareuser.exe",
    "VBoxService.exe",
    "VBoxTray.exe",
    "vboxservice.exe",
    "vboxtray.exe",
    "prl_tools.exe",
    "prl_cc.exe",
    "vmsrvc.exe",
    "vmusrvc.exe",
    "qemu-ga.exe",
    "xenservice.exe",
];

pub fn should_hide(process_name: &str) -> bool {
    HIDDEN_PROCESSES
        .iter()
        .any(|p| p.eq_ignore_ascii_case(process_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmtoolsd_is_hidden() {
        assert!(should_hide("vmtoolsd.exe"));
    }

    #[test]
    fn vbox_service_is_hidden_case_insensitive() {
        assert!(should_hide("VBoxService.exe"));
        assert!(should_hide("vboxservice.exe"));
        assert!(should_hide("VBOXSERVICE.EXE"));
    }

    #[test]
    fn random_process_not_hidden() {
        assert!(!should_hide("notepad.exe"));
        assert!(!should_hide("explorer.exe"));
        assert!(!should_hide(""));
    }

    #[test]
    fn vmware_qemu_parallels_xen_all_covered() {
        assert!(should_hide("vmwaretray.exe"));
        assert!(should_hide("qemu-ga.exe"));
        assert!(should_hide("prl_tools.exe"));
        assert!(should_hide("xenservice.exe"));
    }
}
