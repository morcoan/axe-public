//! Rewrite VM MAC OUI prefixes in `GetAdaptersInfo` /
//! `GetAdaptersAddresses` responses.
//!
//! VMware: `00:50:56`, `00:0C:29`, `00:05:69`, `00:1C:14`.
//! VirtualBox: `08:00:27`.
//! Hyper-V: `00:15:5D`.
//! Parallels: `00:1C:42`.
//! Xen: `00:16:3E`.
//!
//! The spoof rewrites the first 3 bytes of any matching MAC to
//! a generic OEM OUI (Intel: `00:1B:21`).

pub const SPOOF_REPLACEMENT_OUI: [u8; 3] = [0x00, 0x1B, 0x21]; // Intel

pub const VM_OUI_PREFIXES: &[[u8; 3]] = &[
    [0x00, 0x50, 0x56], // VMware
    [0x00, 0x0C, 0x29], // VMware
    [0x00, 0x05, 0x69], // VMware
    [0x00, 0x1C, 0x14], // VMware
    [0x08, 0x00, 0x27], // VirtualBox
    [0x00, 0x15, 0x5D], // Hyper-V
    [0x00, 0x1C, 0x42], // Parallels
    [0x00, 0x16, 0x3E], // Xen
];

pub fn is_vm_oui(prefix: &[u8; 3]) -> bool {
    VM_OUI_PREFIXES.contains(prefix)
}

/// Rewrite the OUI in-place when it matches a VM prefix. Returns
/// `true` if a rewrite happened.
pub fn rewrite_oui(mac: &mut [u8; 6]) -> bool {
    let prefix: [u8; 3] = [mac[0], mac[1], mac[2]];
    if is_vm_oui(&prefix) {
        mac[0] = SPOOF_REPLACEMENT_OUI[0];
        mac[1] = SPOOF_REPLACEMENT_OUI[1];
        mac[2] = SPOOF_REPLACEMENT_OUI[2];
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmware_oui_is_detected() {
        assert!(is_vm_oui(&[0x00, 0x50, 0x56]));
        assert!(is_vm_oui(&[0x00, 0x0C, 0x29]));
    }

    #[test]
    fn virtualbox_oui_is_detected() {
        assert!(is_vm_oui(&[0x08, 0x00, 0x27]));
    }

    #[test]
    fn hyper_v_oui_is_detected() {
        assert!(is_vm_oui(&[0x00, 0x15, 0x5D]));
    }

    #[test]
    fn random_oui_not_detected() {
        assert!(!is_vm_oui(&[0xAA, 0xBB, 0xCC]));
        assert!(!is_vm_oui(&[0x00, 0x00, 0x00]));
    }

    #[test]
    fn rewrite_replaces_oui_keeps_nic_id() {
        let mut mac = [0x00, 0x50, 0x56, 0x12, 0x34, 0x56];
        let rewrote = rewrite_oui(&mut mac);
        assert!(rewrote);
        assert_eq!(&mac[0..3], &SPOOF_REPLACEMENT_OUI[..]);
        assert_eq!(&mac[3..6], &[0x12, 0x34, 0x56]);
    }

    #[test]
    fn rewrite_skips_non_vm_oui() {
        let mut mac = [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03];
        assert!(!rewrite_oui(&mut mac));
        assert_eq!(mac, [0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]);
    }
}
