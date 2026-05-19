//! 6 memory-corruption templates.
//!
//! All `GroundTruth` tier. Each fixes on a specific shape of misuse
//! of one of the SinkCatalog entries.

use crate::vuln::bug_class::{
    BugClass, EvidenceTier, GuardRequirement, IntegerPatternRequirement, SinkArgRequirement,
};
use crate::vuln::sinks::ArgRole;

pub fn register() -> Vec<BugClass> {
    vec![
        BugClass {
            id: "unchecked_copy_length",
            name: "Unchecked copy length",
            category: "memory_corruption",
            source_kinds: &[],
            sink_apis: &["memcpy", "memmove", "strncpy", "RtlCopyMemory"],
            sink_requirement: SinkArgRequirement::DestSizeKnownByteCountUnbounded,
            guard_requirement: GuardRequirement::NoDominatingGuard,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::GroundTruth,
            confidence_cap: None,
            description: "Tainted byte count reaches a copy sink with a known destination size; no dominating guard proves count ≤ destination size.",
        },
        BugClass {
            id: "tainted_allocation_size",
            name: "Tainted allocation size",
            category: "memory_corruption",
            source_kinds: &[],
            sink_apis: &["malloc", "calloc", "realloc", "VirtualAlloc", "VirtualAllocEx"],
            sink_requirement: SinkArgRequirement::TaintedArgRole(ArgRole::Size),
            guard_requirement: GuardRequirement::NoDominatingGuard,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::GroundTruth,
            confidence_cap: None,
            description: "Allocator size argument is attacker-controlled with no dominating range check.",
        },
        BugClass {
            id: "integer_overflow_before_alloc",
            name: "Integer overflow before allocation",
            category: "memory_corruption",
            source_kinds: &[],
            sink_apis: &["malloc", "calloc", "realloc"],
            sink_requirement: SinkArgRequirement::TaintedArgRole(ArgRole::Size),
            guard_requirement: GuardRequirement::DontCare,
            integer_pattern: IntegerPatternRequirement::OverflowPossible,
            evidence_tier: EvidenceTier::GroundTruth,
            confidence_cap: None,
            description: "Allocator size is a multiplication of tainted operands whose product can overflow.",
        },
        BugClass {
            id: "signed_unsigned_length_confusion",
            name: "Signed/unsigned length confusion",
            category: "memory_corruption",
            source_kinds: &[],
            sink_apis: &["memcpy", "memmove", "strncpy", "RtlCopyMemory"],
            sink_requirement: SinkArgRequirement::TaintedArgRole(ArgRole::ByteCount),
            guard_requirement: GuardRequirement::DontCare,
            integer_pattern: IntegerPatternRequirement::SignedUnsignedCast,
            evidence_tier: EvidenceTier::GroundTruth,
            confidence_cap: None,
            description: "Copy length passes through a signed↔unsigned cast; signed-negative interpretations bypass naive 'len > max' checks.",
        },
        BugClass {
            id: "missing_bounds_check_var_mismatch",
            name: "Bounds check on wrong variable",
            category: "memory_corruption",
            source_kinds: &[],
            sink_apis: &["memcpy", "memmove", "strncpy", "RtlCopyMemory"],
            sink_requirement: SinkArgRequirement::TaintedArgRole(ArgRole::ByteCount),
            // Guard is present but doesn't protect the sink — chain
            // query distinguishes by checking that the guard's
            // `protects_var` differs from the sink's byte-count var.
            guard_requirement: GuardRequirement::DominatingGuardPresent,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::GroundTruth,
            // The chain query now requires API argument facts for the
            // byte-count operand and a dominating BoundsCheck on a
            // different variable before this template scores.
            confidence_cap: None,
            description: "Code path has a dominating bound check, but the checked variable is NOT the one used as the copy size.",
        },
        BugClass {
            id: "dangerous_memory_perm_transition",
            name: "Dangerous memory permission transition",
            category: "memory_corruption",
            source_kinds: &[],
            sink_apis: &["VirtualProtect"],
            sink_requirement: SinkArgRequirement::PrecedingTaintedWrite,
            guard_requirement: GuardRequirement::DontCare,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::GroundTruth,
            confidence_cap: None,
            description: "VirtualProtect flips an attacker-influenced region to executable; canonical W→X transition red flag.",
        },
    ]
}
