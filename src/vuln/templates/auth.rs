//! 2 auth/permission templates.

use crate::vuln::bug_class::{
    BugClass, EvidenceTier, GuardRequirement, IntegerPatternRequirement, SinkArgRequirement,
};

pub fn register() -> Vec<BugClass> {
    vec![
        BugClass {
            id: "auth_check_after_action",
            name: "Authorization check after privileged action",
            category: "auth_bypass",
            source_kinds: &[],
            sink_apis: &["AccessCheck"],
            sink_requirement: SinkArgRequirement::AnyCall,
            // We use "DominatingGuardPresent" here as a stand-in:
            // the chain query special-cases this template to check
            // call-order rather than guard-order, but the schema
            // field is recycled to keep the BugClass shape uniform.
            guard_requirement: GuardRequirement::DominatingGuardPresent,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::GroundTruth,
            // The chain query requires a privileged action that
            // dominates/precedes this AccessCheck before scoring.
            confidence_cap: None,
            description: "An AccessCheck happens AFTER the protected action — useless gate.",
        },
        BugClass {
            id: "missing_caller_validation",
            name: "Missing caller validation on exported function",
            category: "auth_bypass",
            source_kinds: &["network_recv", "ipc_pipe", "com_server_ingress", "rpc_inbound", "ioctl_input_buffer"],
            sink_apis: &[
                "WriteProcessMemory",
                "VirtualAllocEx",
                "CreateRemoteThread",
                "DeleteFile",
                "unlink",
            ],
            sink_requirement: SinkArgRequirement::AnyCall,
            guard_requirement: GuardRequirement::NoDominatingGuard,
            integer_pattern: IntegerPatternRequirement::DontCare,
            evidence_tier: EvidenceTier::GroundTruth,
            confidence_cap: None,
            description: "Exported function performs a privileged action with no caller-identity check on the request.",
        },
    ]
}
