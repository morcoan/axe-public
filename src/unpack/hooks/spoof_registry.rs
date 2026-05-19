//! `RegQueryValueExW` spoof for VM-indicator keys.
//!
//! The classic set of registry keys that scream "VM":
//!
//! - `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` — disk
//!   IDs include strings like `VBOX_HARDDISK`, `VMware_Virtual`.
//! - `HKLM\HARDWARE\DESCRIPTION\System\SystemBiosVersion` — BIOS
//!   version mentions "VBOX" or "VMware".
//! - `HKLM\HARDWARE\DESCRIPTION\System\SystemManufacturer` —
//!   reports "VMware Inc." / "innotek GmbH" / "Microsoft
//!   Corporation".
//! - `HKLM\HARDWARE\DESCRIPTION\System\VideoBiosVersion` — same
//!   issue for the video BIOS.
//!
//! The spoof returns `ERROR_FILE_NOT_FOUND` (2) for any read
//! of these values, mimicking a key that genuinely doesn't
//! exist on the host. This is more honest than returning
//! sanitized strings — a real bare-metal Windows install does
//! have these keys but with bare-metal-vendor values.

/// Full path-key pairs that are spoofed. Aurora's stub DLL
/// builds an HRESULT-set from this list and matches incoming
/// `RegQueryValueExW` calls.
pub const SPOOFED_KEYS: &[(&str, &str)] = &[
    ("SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", "0"),
    ("HARDWARE\\DESCRIPTION\\System", "SystemBiosVersion"),
    ("HARDWARE\\DESCRIPTION\\System", "SystemManufacturer"),
    ("HARDWARE\\DESCRIPTION\\System", "VideoBiosVersion"),
    ("HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName"),
    ("SOFTWARE\\Oracle\\VirtualBox Guest Additions", ""),
    ("SOFTWARE\\VMware, Inc.\\VMware Tools", ""),
];

/// Should this `(subkey, value_name)` pair be spoofed?
pub fn should_spoof(subkey: &str, value_name: &str) -> bool {
    for (k, v) in SPOOFED_KEYS {
        if subkey.eq_ignore_ascii_case(k) && (v.is_empty() || value_name.eq_ignore_ascii_case(v)) {
            return true;
        }
    }
    false
}

/// `ERROR_FILE_NOT_FOUND` — what the spoofed call returns.
pub const ERROR_FILE_NOT_FOUND: u32 = 2;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_enum_zero_value_is_spoofed() {
        assert!(should_spoof(
            "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
            "0"
        ));
    }

    #[test]
    fn case_insensitive_subkey_match() {
        assert!(should_spoof(
            "system\\currentcontrolset\\services\\disk\\enum",
            "0"
        ));
    }

    #[test]
    fn vbox_guest_additions_key_is_spoofed() {
        assert!(should_spoof(
            "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            "AnyValue"
        ));
    }

    #[test]
    fn vmware_tools_key_is_spoofed() {
        assert!(should_spoof(
            "SOFTWARE\\VMware, Inc.\\VMware Tools",
            "Version"
        ));
    }

    #[test]
    fn unrelated_keys_are_not_spoofed() {
        assert!(!should_spoof(
            "SOFTWARE\\Microsoft\\Windows",
            "ProgramFiles"
        ));
        assert!(!should_spoof("HARDWARE\\Random\\Path", "Anything"));
    }

    #[test]
    fn spoof_table_covers_all_planned_surfaces() {
        // SystemBiosVersion, SystemManufacturer, VideoBiosVersion,
        // SystemProductName, Disk Enum, VBox Guest Additions,
        // VMware Tools = ≥7 entries.
        assert!(SPOOFED_KEYS.len() >= 7);
    }
}
