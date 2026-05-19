//! `GetSystemFirmwareTable` + `EnumSystemFirmwareTables` spoof.
//!
//! VMware/VirtualBox/Hyper-V leak themselves through the SMBIOS
//! (`RSMB` firmware table 0x52534D42). Targets enumerate the
//! table looking for known vendor strings ("VMware", "VBOX",
//! "VirtualBox", "Microsoft Corporation virt"). The spoof
//! returns 0 from `GetSystemFirmwareTable` for the RSMB id,
//! making the target believe SMBIOS data is unavailable —
//! which a real bare-metal Windows host would never return,
//! but is enough to defeat the vendor-string compare path that
//! most crimeware uses.
//!
//! # Stub status
//!
//! The detour body itself lives in `aurora_stub` (loaded into
//! the target via injection). This file documents the
//! Aurora-side contract: the function signature the stub
//! exports + the spoof rules.

/// SMBIOS firmware-table provider signature.
pub const FIRMWARE_PROVIDER_RSMB: u32 = 0x52534D42; // 'RSMB'

/// Decision: does the target's `GetSystemFirmwareTable` call
/// for `firmware_table_provider_signature` get spoofed?
pub fn should_spoof(firmware_table_provider_signature: u32) -> bool {
    firmware_table_provider_signature == FIRMWARE_PROVIDER_RSMB
}

/// What to return from the spoofed call. Always `0` for RSMB
/// (kernel returns 0 == "table not available").
pub fn spoofed_return_value(firmware_table_provider_signature: u32) -> u32 {
    if should_spoof(firmware_table_provider_signature) {
        0
    } else {
        // Caller must invoke the original (non-spoofed) API.
        u32::MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsmb_signature_is_spoofed() {
        assert!(should_spoof(FIRMWARE_PROVIDER_RSMB));
    }

    #[test]
    fn other_signatures_are_not_spoofed() {
        assert!(!should_spoof(0x41435049)); // 'ACPI'
        assert!(!should_spoof(0x46495257)); // 'FIRM'
    }

    #[test]
    fn spoofed_return_value_for_rsmb_is_zero() {
        assert_eq!(spoofed_return_value(FIRMWARE_PROVIDER_RSMB), 0);
    }

    #[test]
    fn spoofed_return_value_for_other_signals_passthrough() {
        assert_eq!(spoofed_return_value(0x41435049), u32::MAX);
    }
}
