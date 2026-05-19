//! Interval analysis — wraps `src/vsa.rs::VsaValueRecord` to give
//! templates a uniform `Range` type to reason about taint variables.
//!
//! v1.0 doesn't perform its own value-set analysis — it reads the
//! ranges axe's VSA pass already computed and surfaces them in a
//! shape templates can pattern-match.

#![allow(dead_code)]

use serde::Serialize;

use crate::pe::VsaValueRecord;

/// A closed interval `[lo, hi]` over a (signed or unsigned) integer.
/// `Unknown` means VSA couldn't bound the value — templates treat
/// it as the maximum range for the relevant width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Range {
    Bounded { lo: i128, hi: i128, signed: bool },
    Unknown,
}

impl Range {
    pub fn unknown() -> Self {
        Self::Unknown
    }

    pub fn singleton(value: i128, signed: bool) -> Self {
        Self::Bounded {
            lo: value,
            hi: value,
            signed,
        }
    }

    /// `true` iff the range provably excludes values strictly greater
    /// than `bound`. Returns `false` when the range is `Unknown` —
    /// the conservative "we don't know, assume the worst" answer.
    pub fn is_bounded_above_by(&self, bound: i128) -> bool {
        match self {
            Self::Bounded { hi, .. } => *hi <= bound,
            Self::Unknown => false,
        }
    }

    /// `true` iff the range provably excludes values strictly less
    /// than `bound`.
    pub fn is_bounded_below_by(&self, bound: i128) -> bool {
        match self {
            Self::Bounded { lo, .. } => *lo >= bound,
            Self::Unknown => true,
        }
    }

    /// Width of the range in bits (smallest power-of-two width that
    /// contains both `lo` and `hi`). Returns `None` for `Unknown`.
    pub fn approximate_width(&self) -> Option<u32> {
        match self {
            Self::Bounded { lo, hi, signed } => {
                let max = (*lo).abs().max((*hi).abs()) as u128;
                Some(if *signed {
                    if max <= 0x7F {
                        8
                    } else if max <= 0x7FFF {
                        16
                    } else if max <= 0x7FFF_FFFF {
                        32
                    } else {
                        64
                    }
                } else {
                    if max <= 0xFF {
                        8
                    } else if max <= 0xFFFF {
                        16
                    } else if max <= 0xFFFF_FFFF {
                        32
                    } else {
                        64
                    }
                })
            }
            Self::Unknown => None,
        }
    }
}

/// Convert a VSA record's `lo`/`hi` to a `Range`. Returns `Unknown`
/// when VSA didn't bound the value (both `lo` and `hi` are `None`).
pub fn infer_range(record: &VsaValueRecord) -> Range {
    match (record.lo, record.hi) {
        (Some(lo), Some(hi)) => Range::Bounded {
            lo: lo as i128,
            hi: hi as i128,
            // VSA stores u64; templates that need signedness derive it
            // from the type-cast node, not from VSA.
            signed: false,
        },
        _ => Range::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vsa(lo: Option<u64>, hi: Option<u64>) -> VsaValueRecord {
        VsaValueRecord {
            value_id: "v".into(),
            function: 0x1000,
            site_va: 0x1010,
            location: "rax".into(),
            kind: "scalar".into(),
            lo,
            hi,
            stride: 0,
            value: None,
            target_va: None,
            evidence: vec![],
            confidence: "medium".into(),
            region: "stack".into(),
            expression: None,
            base: None,
            index: None,
            scale: 1,
            displacement: 0,
            possible_values: vec![],
            work_budget_exhausted: false,
        }
    }

    #[test]
    fn bounded_range_round_trips_through_infer() {
        let r = infer_range(&vsa(Some(0), Some(1024)));
        assert_eq!(
            r,
            Range::Bounded {
                lo: 0,
                hi: 1024,
                signed: false
            }
        );
    }

    #[test]
    fn no_vsa_bound_returns_unknown() {
        let r = infer_range(&vsa(None, None));
        assert_eq!(r, Range::Unknown);
    }

    #[test]
    fn half_bound_returns_unknown() {
        // VSA gave us only one side — that's not enough to bound.
        let r = infer_range(&vsa(Some(0), None));
        assert_eq!(r, Range::Unknown);
    }

    #[test]
    fn is_bounded_above_holds_for_in_range_bound() {
        let r = Range::Bounded {
            lo: 0,
            hi: 1024,
            signed: false,
        };
        assert!(r.is_bounded_above_by(1024));
        assert!(r.is_bounded_above_by(2048));
        assert!(!r.is_bounded_above_by(1023));
    }

    #[test]
    fn unknown_is_never_bounded_above() {
        assert!(!Range::Unknown.is_bounded_above_by(i128::MAX));
    }

    #[test]
    fn is_bounded_below_holds_for_in_range_bound() {
        let r = Range::Bounded {
            lo: 10,
            hi: 100,
            signed: false,
        };
        assert!(r.is_bounded_below_by(10));
        assert!(r.is_bounded_below_by(0));
        assert!(!r.is_bounded_below_by(11));
    }

    #[test]
    fn unknown_is_always_bounded_below_for_safety() {
        // Counterintuitive but correct: "no proof of value above X"
        // is the conservative default; templates that rely on lower
        // bounds should query is_bounded_above instead.
        assert!(Range::Unknown.is_bounded_below_by(0));
    }

    #[test]
    fn approximate_width_picks_smallest_power_of_two() {
        assert_eq!(
            Range::Bounded {
                lo: 0,
                hi: 100,
                signed: false
            }
            .approximate_width(),
            Some(8)
        );
        assert_eq!(
            Range::Bounded {
                lo: 0,
                hi: 1024,
                signed: false
            }
            .approximate_width(),
            Some(16)
        );
        assert_eq!(
            Range::Bounded {
                lo: 0,
                hi: 0x10_0000,
                signed: false
            }
            .approximate_width(),
            Some(32)
        );
        assert_eq!(
            Range::Bounded {
                lo: 0,
                hi: 1_000_000_000_000,
                signed: false
            }
            .approximate_width(),
            Some(64)
        );
        assert_eq!(Range::Unknown.approximate_width(), None);
    }

    #[test]
    fn singleton_is_bounded_at_value() {
        let r = Range::singleton(42, false);
        assert!(r.is_bounded_above_by(42));
        assert!(r.is_bounded_below_by(42));
        assert!(!r.is_bounded_above_by(41));
    }
}
