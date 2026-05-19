//! 4 data-handling templates: deserialization, format string, path
//! traversal, TOCTOU.

use crate::vuln::bug_class::{
    BugClass, EvidenceTier, GuardRequirement, IntegerPatternRequirement, SinkArgRequirement,
};
use crate::vuln::sinks::ArgRole;

pub fn register() -> Vec<BugClass> {
    vec![
        BugClass {
            id: "deserialization_to_dangerous_type",
            name: "Deserialization to dangerous type",
            category: "deserialization",
            source_kinds: &[],
            sink_apis: &["BinaryFormatter::Deserialize", "pickle.loads"],
            sink_requirement: SinkArgRequirement::TaintedArgRole(ArgRole::Source),
            guard_requirement: GuardRequirement::DontCare,
            integer_pattern: IntegerPatternRequirement::DontCare,
            // Best-effort: depends on type-inference depth.
            evidence_tier: EvidenceTier::BestEffort,
            confidence_cap: None,
            description: "Tainted bytes flow into a deserializer known for gadget-chain attacks.",
        },
        BugClass {
            id: "format_string_controlled",
            name: "Attacker-controlled format string",
            category: "memory_corruption",
            source_kinds: &[],
            sink_apis: &[
                "sprintf",
                "snprintf",
                "printf",
                "fprintf",
                "vfprintf",
                "vsprintf",
                "__stdio_common_vfprintf",
            ],
            sink_requirement: SinkArgRequirement::TaintedArgRole(ArgRole::FormatString),
            guard_requirement: GuardRequirement::DontCare,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::GroundTruth,
            confidence_cap: None,
            description: "Tainted bytes reach the format-string argument of a printf-family function.",
        },
        BugClass {
            id: "path_traversal_to_file_op",
            name: "Path traversal to file operation",
            category: "path_injection",
            source_kinds: &[],
            sink_apis: &["CreateFile", "fopen", "open", "unlink", "DeleteFile"],
            sink_requirement: SinkArgRequirement::TaintedArgRole(ArgRole::Path),
            guard_requirement: GuardRequirement::NoDominatingGuard,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::GroundTruth,
            confidence_cap: None,
            description: "Attacker-controlled string reaches a file-path argument with no dominating sanitization.",
        },
        BugClass {
            id: "toctou_file_access",
            name: "TOCTOU file access",
            category: "race_condition",
            source_kinds: &[],
            sink_apis: &["CreateFile", "fopen", "open", "rename", "unlink"],
            sink_requirement: SinkArgRequirement::AnyCall,
            // Chain query special-cases this template to look for two
            // sink calls with the same path argument and no dominating
            // lock; the guard-requirement field is reused.
            guard_requirement: GuardRequirement::DominatingGuardPresent,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::GroundTruth,
            // The chain query requires same-path API argument facts
            // across two file ops and rejects paths protected by a
            // dominating lock acquisition.
            confidence_cap: None,
            description: "Two file operations on the same path with no dominating lock — TOCTOU candidate.",
        },
    ]
}
