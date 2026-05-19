//! RDTSC normalization (Step 38). On VMEXIT for RDTSC, return
//! a rolling counter with a plausible cadence so the guest's
//! timing-based VM-detection (compare RDTSC delta against
//! expected cycle counts) doesn't see hypervisor overhead.
//!
//! Honest doc: this defeats *opportunistic* timing checks. A
//! determined target with a dedicated cycle-budget oracle can
//! still detect virt via TLB / cache timing. See
//! `docs/unpack-capabilities.md`.

use std::sync::atomic::{AtomicU64, Ordering};

/// Tracks the rolling counter Aurora returns from RDTSC.
pub struct TscNormalizer {
    counter: AtomicU64,
    /// Cycles to advance per RDTSC call. Roughly matches modern
    /// CPU cycle-per-RDTSC cost (≈30 cycles).
    cycles_per_call: u64,
}

impl TscNormalizer {
    pub fn new(initial: u64) -> Self {
        Self {
            counter: AtomicU64::new(initial),
            cycles_per_call: 30,
        }
    }

    pub fn with_cadence(initial: u64, cycles_per_call: u64) -> Self {
        Self {
            counter: AtomicU64::new(initial),
            cycles_per_call,
        }
    }

    pub fn next_tsc(&self) -> u64 {
        // fetch_add returns the PREVIOUS value, so add first +
        // return that.
        self.counter
            .fetch_add(self.cycles_per_call, Ordering::Relaxed)
            + self.cycles_per_call
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdtsc_returns_monotonically_increasing_values() {
        let n = TscNormalizer::new(1000);
        let a = n.next_tsc();
        let b = n.next_tsc();
        let c = n.next_tsc();
        assert!(b > a);
        assert!(c > b);
    }

    #[test]
    fn cadence_30_cycles_per_call() {
        let n = TscNormalizer::new(0);
        let a = n.next_tsc();
        let b = n.next_tsc();
        assert_eq!(b - a, 30);
    }

    #[test]
    fn custom_cadence_honored() {
        let n = TscNormalizer::with_cadence(0, 100);
        let a = n.next_tsc();
        let b = n.next_tsc();
        assert_eq!(b - a, 100);
    }
}
