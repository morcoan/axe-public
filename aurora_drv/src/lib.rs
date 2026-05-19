//! Aurora kernel driver — VM-artifact hiding at the syscall
//! layer.
//!
//! This is a **documentation-grade** Rust skeleton. A real
//! production `.sys` binary cannot be produced by stock `cargo
//! build` — kernel drivers need:
//!
//! - The EWDK (Enterprise Windows Driver Kit), OR
//! - `windows-drivers-rs` (Microsoft experimental, nightly
//!   toolchain, custom `x86_64-pc-windows-msvc-kernel` target
//!   spec)
//!
//! AND a test-signed or EV-signed key for loading on a normal
//! Windows host. See `README.md` for the supported build paths.
//!
//! # IOCTL contract
//!
//! The IOCTL function codes match `src/unpack/driver/ioctl.rs`
//! on the user-mode side (DeviceType `0x8001`, functions
//! `0x800..0x80F`). The IOCTL handler dispatch lives in
//! `dispatch_device_io_control()`.
//!
//! # NEVER
//!
//! - **No BYOVD.** Aurora's user-side never auto-loads a
//!   third-party signed driver. This driver is intended to be
//!   built + signed by the analyst (or distributed via a
//!   signed Aurora release).

#![no_std]

/// Aurora device-type identifier. Matches
/// `axe_core::unpack::driver::ioctl::AURORA_DEVICE_TYPE`.
pub const AURORA_DEVICE_TYPE: u32 = 0x8001;

/// IOCTL function codes (low 12 bits of CTL_CODE).
pub const IOCTL_FN_PING: u32 = 0x800;
pub const IOCTL_FN_REGISTER_TARGET_PID: u32 = 0x801;
pub const IOCTL_FN_UNREGISTER_TARGET_PID: u32 = 0x802;
pub const IOCTL_FN_ENABLE_HIDE_PROCESS: u32 = 0x803;
pub const IOCTL_FN_ENABLE_HIDE_REGISTRY: u32 = 0x804;
pub const IOCTL_FN_ENABLE_HIDE_DEVICES: u32 = 0x805;

/// Pack a Windows IOCTL the same way `CTL_CODE` does.
pub const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
    (device << 16) | (access << 14) | (function << 2) | method
}

/// Decision: should this process name be hidden from
/// `NtQuerySystemInformation(SystemProcessInformation)`?
///
/// The driver-mode dispatcher walks the SYSTEM_PROCESS_INFORMATION
/// linked list and unlinks entries where `image_name`
/// matches. This logic is the pure-function half of that;
/// platform-free so it can be reused from the user-side tests
/// in `src/unpack/hooks/spoof_processes.rs` (which already has
/// its own static table — keep them in sync if you extend
/// either side).
pub fn should_hide_process(image_name: &str) -> bool {
    let hidden: &[&str] = &[
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "vboxservice.exe",
        "vboxtray.exe",
        "prl_tools.exe",
        "prl_cc.exe",
        "vmsrvc.exe",
        "vmusrvc.exe",
        "qemu-ga.exe",
        "xenservice.exe",
    ];
    let lower = lower_basename(image_name);
    hidden.iter().any(|h| h.eq_ignore_ascii_case(lower.as_ref()))
}

/// Lowercased basename without allocation when no slash present.
/// In a real driver no-std environment we can't use String, so
/// we just return a `&str` slice into the input.
fn lower_basename(s: &str) -> &str {
    if let Some(pos) = s.rfind(|c| c == '\\' || c == '/') {
        &s[pos + 1..]
    } else {
        s
    }
}

/// Decision: is this `(subkey, value_name)` pair one of the
/// VM-indicator registry reads the driver should answer with
/// STATUS_OBJECT_NAME_NOT_FOUND?
pub fn should_hide_registry(subkey: &str, value_name: &str) -> bool {
    let table: &[(&str, &str)] = &[
        ("SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", "0"),
        ("HARDWARE\\DESCRIPTION\\System", "SystemBiosVersion"),
        ("HARDWARE\\DESCRIPTION\\System", "SystemManufacturer"),
        ("HARDWARE\\DESCRIPTION\\System", "VideoBiosVersion"),
        ("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName"),
        ("SOFTWARE\\Oracle\\VirtualBox Guest Additions", ""),
        ("SOFTWARE\\VMware, Inc.\\VMware Tools", ""),
    ];
    table.iter().any(|(k, v)| {
        subkey.eq_ignore_ascii_case(k) && (v.is_empty() || value_name.eq_ignore_ascii_case(v))
    })
}

/// Decision: is this device name one of the VM-only devices
/// the driver should hide from `IoCreateFile`?
pub fn should_hide_device(device_name: &str) -> bool {
    let hidden: &[&str] = &[
        "\\\\.\\VBoxGuest",
        "\\\\.\\vmci",
        "\\\\.\\HGFS",
        "\\Device\\VBoxGuest",
        "\\Device\\vmci",
    ];
    hidden.iter().any(|d| device_name.eq_ignore_ascii_case(d))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmtoolsd_basename_hidden() {
        assert!(should_hide_process("vmtoolsd.exe"));
        assert!(should_hide_process(
            "\\Device\\HarddiskVolume1\\Program Files\\VMware\\Tools\\vmtoolsd.exe"
        ));
    }

    #[test]
    fn random_process_not_hidden() {
        assert!(!should_hide_process("notepad.exe"));
        assert!(!should_hide_process("explorer.exe"));
    }

    #[test]
    fn vbox_disk_enum_hidden() {
        assert!(should_hide_registry(
            "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
            "0"
        ));
    }

    #[test]
    fn vbox_guest_device_hidden() {
        assert!(should_hide_device("\\\\.\\VBoxGuest"));
        assert!(should_hide_device("\\Device\\VBoxGuest"));
    }

    #[test]
    fn random_device_not_hidden() {
        assert!(!should_hide_device("\\\\.\\PhysicalDrive0"));
    }

    #[test]
    fn ctl_code_packs_correctly() {
        // Should match axe_core::unpack::driver::ioctl::IOCTL_PING
        let expected: u32 = (0x8001u32 << 16) | (0x800u32 << 2);
        assert_eq!(ctl_code(AURORA_DEVICE_TYPE, IOCTL_FN_PING, 0, 0), expected);
    }
}
