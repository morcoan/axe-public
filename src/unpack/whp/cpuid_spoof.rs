//! CPUID spoof (Step 37). On VMEXIT for CPUID, rewrite the
//! result registers so the guest doesn't see virt indicators.
//!
//! Key rewrites:
//! - Leaf 1: clear ECX bit 31 (hypervisor present).
//! - Leaves 0x40000000..0x4000FFFF: return zero (the
//!   hypervisor info leaves).
//! - Leaf 0: rewrite EBX/EDX/ECX to spell `GenuineIntel`.

/// CPUID leaf-1 ECX layout: bit 31 = hypervisor present.
pub const CPUID_LEAF1_ECX_HYPERVISOR_BIT: u32 = 1 << 31;

pub fn rewrite_leaf1_ecx(original_ecx: u32) -> u32 {
    original_ecx & !CPUID_LEAF1_ECX_HYPERVISOR_BIT
}

pub fn is_hypervisor_leaf(leaf: u32) -> bool {
    (0x4000_0000..=0x4000_00FF).contains(&leaf)
}

/// `GenuineIntel` packed into (EBX, EDX, ECX) registers for
/// CPUID leaf 0.
pub fn genuine_intel_vendor() -> (u32, u32, u32) {
    // 'Genu' / 'ineI' / 'ntel' in little-endian quad bytes.
    let ebx = u32::from_le_bytes(*b"Genu");
    let edx = u32::from_le_bytes(*b"ineI");
    let ecx = u32::from_le_bytes(*b"ntel");
    (ebx, edx, ecx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hypervisor_bit_is_cleared() {
        let original = 0xFFFF_FFFFu32;
        let rewritten = rewrite_leaf1_ecx(original);
        assert_eq!(rewritten & CPUID_LEAF1_ECX_HYPERVISOR_BIT, 0);
        // Other bits unchanged.
        assert_eq!(rewritten | CPUID_LEAF1_ECX_HYPERVISOR_BIT, 0xFFFF_FFFF);
    }

    #[test]
    fn hypervisor_bit_unset_stays_unset() {
        assert_eq!(rewrite_leaf1_ecx(0), 0);
    }

    #[test]
    fn hypervisor_leaves_detected() {
        assert!(is_hypervisor_leaf(0x4000_0000));
        assert!(is_hypervisor_leaf(0x4000_0001));
        assert!(is_hypervisor_leaf(0x4000_00FF));
        assert!(!is_hypervisor_leaf(0x3FFF_FFFF));
        assert!(!is_hypervisor_leaf(0x4000_0100));
    }

    #[test]
    fn genuine_intel_vendor_decodes_correctly() {
        let (ebx, edx, ecx) = genuine_intel_vendor();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ebx.to_le_bytes());
        bytes.extend_from_slice(&edx.to_le_bytes());
        bytes.extend_from_slice(&ecx.to_le_bytes());
        assert_eq!(&bytes[..], b"GenuineIntel");
    }
}
