//! VMEXIT dispatch (Step 36 skeleton). Routes EPT violations,
//! CPUID, RDTSC, and MSR accesses to the appropriate handler.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmExitReason {
    EptViolation,
    Cpuid,
    Rdtsc,
    MsrAccess,
    Halt,
    Unknown(u32),
}

pub fn classify(reason_code: u32) -> VmExitReason {
    match reason_code {
        0x01 => VmExitReason::Halt,
        0x0A => VmExitReason::Cpuid,
        0x10 => VmExitReason::Rdtsc,
        0x1C | 0x1D => VmExitReason::MsrAccess,
        0x30 => VmExitReason::EptViolation,
        other => VmExitReason::Unknown(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_exits() {
        assert_eq!(classify(0x01), VmExitReason::Halt);
        assert_eq!(classify(0x0A), VmExitReason::Cpuid);
        assert_eq!(classify(0x10), VmExitReason::Rdtsc);
        assert_eq!(classify(0x30), VmExitReason::EptViolation);
    }

    #[test]
    fn classify_unknown_carries_raw_code() {
        assert_eq!(classify(0xFF), VmExitReason::Unknown(0xFF));
    }
}
