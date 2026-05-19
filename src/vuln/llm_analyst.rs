//! Pure-Rust template-based analyst — `suggest_patches`,
//! `suggest_tests`, `triage_priority`.
//!
//! v1.1 ships ZERO live-LLM calls in this module. Every output is
//! deterministic, derived from the finding's `bug_class` via a
//! lookup table. The wire shape carries `source: "template"` so the
//! consumer can distinguish these from any future live-LLM
//! suggestions (which would carry e.g. `source: "claude-opus-4.7"`).
//!
//! Why pure-Rust templates and not a live LLM call:
//! - **Deterministic CI**: every run produces the same suggestion
//!   bytes given the same input.
//! - **Offline-able**: no network dependency, no rate limit, no
//!   API-key plumbing in the v1.1 binary.
//! - **Audit trail**: the user can read these templates and verify
//!   they don't recommend dangerous fixes (e.g. blanket `try/except`
//!   swallowing the symptom).
//!
//! The 14 bug-class branches below cover the 12 v1.0 templates plus
//! the 2 v1.1 lifetime templates. An unknown `bug_class` falls
//! through to a safe-default branch that emits a "review manually"
//! note rather than a wrong-looking suggestion.

#![cfg(feature = "vuln-discovery")]
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use crate::vuln::finding::FindingRecord;

pub const ANALYST_SOURCE: &str = "template";

/// Per-finding triage priority. Maps from `risk_score` bands, but
/// stays a coarse enum to encourage human triage rather than
/// hair-splitting between 7.2 and 7.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriagePriority {
    /// Risk ≥ 8.0 — investigate before merging the next release.
    Critical,
    /// Risk ≥ 6.0 — investigate before the next planned release.
    High,
    /// Risk ≥ 3.0 — schedule a review within the next milestone.
    Medium,
    /// Risk < 3.0 — note for future review.
    Low,
}

impl TriagePriority {
    /// Map from numeric risk band to ordinal priority.
    pub fn from_risk(risk: f32) -> Self {
        if risk >= 8.0 {
            Self::Critical
        } else if risk >= 6.0 {
            Self::High
        } else if risk >= 3.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

/// One template-based patch suggestion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PatchSuggestion {
    /// Always [`ANALYST_SOURCE`] for v1.1 — distinguishes template
    /// output from any future live-LLM output.
    pub source: String,
    /// `bug_class` of the finding this suggestion applies to.
    pub bug_class: String,
    /// One-sentence summary of the fix shape.
    pub summary: String,
    /// Multi-line rationale — what to add, what to remove, why it
    /// addresses the chain.
    pub description: String,
    /// Reference URLs (CWE entries, language-specific docs) so the
    /// consumer can verify the recommendation.
    pub references: Vec<String>,
}

/// One template-based test suggestion.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TestSuggestion {
    pub source: String,
    pub bug_class: String,
    pub summary: String,
    /// Multi-line description of the test shape (inputs to construct,
    /// invariants to assert).
    pub description: String,
}

/// Patch suggestions for one finding. Dispatched on `finding.bug_class`.
pub fn suggest_patches(finding: &FindingRecord) -> Vec<PatchSuggestion> {
    let bc = finding.bug_class.as_str();
    let (summary, description, references) = patch_template_for(bc);
    vec![PatchSuggestion {
        source: ANALYST_SOURCE.to_string(),
        bug_class: bc.to_string(),
        summary: summary.to_string(),
        description: description.to_string(),
        references: references.iter().map(|s| s.to_string()).collect(),
    }]
}

/// Test suggestions for one finding. Dispatched on `finding.bug_class`.
pub fn suggest_tests(finding: &FindingRecord) -> Vec<TestSuggestion> {
    let bc = finding.bug_class.as_str();
    let (summary, description) = test_template_for(bc);
    vec![TestSuggestion {
        source: ANALYST_SOURCE.to_string(),
        bug_class: bc.to_string(),
        summary: summary.to_string(),
        description: description.to_string(),
    }]
}

/// Triage priority for one finding — coarse band derived from
/// `risk_score`.
pub fn triage_priority(finding: &FindingRecord) -> TriagePriority {
    TriagePriority::from_risk(finding.risk_score)
}

fn patch_template_for(bug_class: &str) -> (&'static str, &'static str, &'static [&'static str]) {
    match bug_class {
        "unchecked_copy_length" => (
            "Bound the byte-count against the destination size before the copy.",
            "Insert an explicit `if (byte_count > sizeof(dst)) return ERROR;` immediately before the memcpy/strcpy call. Prefer the bounded variant (memcpy_s, strncpy_s, RtlCopyMemoryEx) when the platform exposes it. Do NOT cast the byte_count to size_t hoping the comparison will catch overflow — verify the source value's range against the destination's compile-time-known capacity.",
            &[
                "https://cwe.mitre.org/data/definitions/121.html",
                "https://cwe.mitre.org/data/definitions/787.html",
            ],
        ),
        "tainted_allocation_size" => (
            "Range-check the allocation size before calling the allocator.",
            "Reject allocation sizes greater than a documented upper bound (e.g. MAX_PROTOCOL_FRAME or the per-channel ceiling). Treat zero as a separate error case — many bugs are 'malloc(0) returned NULL was treated as failure'. Avoid relying on the allocator returning NULL: defensively check the size FIRST.",
            &["https://cwe.mitre.org/data/definitions/789.html"],
        ),
        "integer_overflow_before_alloc" => (
            "Use a checked multiplication helper before passing to the allocator.",
            "Replace `malloc(n * sizeof(T))` with a checked helper (e.g. __builtin_mul_overflow, calloc(n, sizeof(T)) for cases where calloc-style semantics are acceptable). For multi-operand calculations, validate each operand against the upper bound that prevents overflow given the product, not just the post-product value.",
            &[
                "https://cwe.mitre.org/data/definitions/190.html",
                "https://cwe.mitre.org/data/definitions/680.html",
            ],
        ),
        "signed_unsigned_length_confusion" => (
            "Pin every length-comparison operand to the same signed-ness.",
            "Audit every comparison along the chain from the source value to the sink's length argument. If the source is unsigned but a sub-expression compares signed, the negative branch will pass an unsigned-overflowed value to the sink. Use a single typedef (e.g. size_t) along the entire data path; static-cast at the boundary, not at the compare.",
            &["https://cwe.mitre.org/data/definitions/195.html"],
        ),
        "missing_bounds_check_var_mismatch" => (
            "Bind the bound-checked variable to the variable actually passed.",
            "Common bug: the function bounds-checks `requested_len` but passes `record_len` to memcpy. Re-read the source between the bound check and the sink to confirm the SAME variable name flows through. If a wrapper renamed it, audit the wrapper.",
            &["https://cwe.mitre.org/data/definitions/787.html"],
        ),
        "dangerous_memory_perm_transition" => (
            "Reject W→X permission transitions on attacker-influenced regions.",
            "If the region's base or size derives from network input, refuse the call. Legitimate W→X is rare outside JIT engines — gate this code path behind a feature flag and audit every entry. Use VirtualProtect2 with the CFG-compatible flags where the platform supports it.",
            &["https://cwe.mitre.org/data/definitions/787.html"],
        ),
        "auth_check_after_action" => (
            "Move the AccessCheck (or equivalent) BEFORE the protected action.",
            "Hoist the access check to the function entry; if the check fails, return the error before any state mutation. If the check needs context produced by the action, split the function: check on the metadata before, perform action only after success. NEVER use the result of the action to influence whether the check happens.",
            &["https://cwe.mitre.org/data/definitions/863.html"],
        ),
        "missing_caller_validation" => (
            "Validate the caller's identity/token at the function entry.",
            "Add an explicit `IsCallerAuthorized()` call (or equivalent for the platform) at the top of the function. Prefer Windows' impersonation-aware variants (ImpersonateNamedPipeClient + RevertToSelf in a guard pattern) so the validation cannot be skipped by a thread-local impersonation hijack.",
            &["https://cwe.mitre.org/data/definitions/862.html"],
        ),
        "deserialization_to_dangerous_type" => (
            "Replace the dangerous deserializer with a strict schema-based parser.",
            "BinaryFormatter, pickle.loads, ObjectInputStream — these are gadget-chain enabled by design. Switch to a typed JSON/MessagePack/protobuf parser that requires the type schema up-front. If migration is multi-phase, gate the dangerous deserializer behind a flag and a per-call type allowlist.",
            &["https://cwe.mitre.org/data/definitions/502.html"],
        ),
        "format_string_controlled" => (
            "Use a literal format string; pass the user data as an argument.",
            "Replace `printf(user)` with `printf(\"%s\", user)`. For `sprintf` family, prefer `snprintf` with a literal format. Audit every wrapper that takes a `const char *fmt` parameter — that parameter MUST be a literal at every callsite. A grep for `vfprintf(.*,.*[^\"])` finds most live cases.",
            &["https://cwe.mitre.org/data/definitions/134.html"],
        ),
        "path_traversal_to_file_op" => (
            "Resolve to absolute path + reject any traversal segment.",
            "Convert the user-supplied path to an absolute path (PathCchCanonicalize / realpath), then verify it starts with the expected base directory after normalization. Reject any literal `..` segment present BEFORE normalization too — some attackers exploit canonicalization differences between OS calls.",
            &["https://cwe.mitre.org/data/definitions/22.html"],
        ),
        "toctou_file_access" => (
            "Open the file ONCE and operate via handle.",
            "Replace `stat(path); fopen(path)` with `fopen(path); fstat(handle)`. Use platform-specific atomic operations (CreateFile with FILE_SHARE_NONE + locking, openat with O_NOFOLLOW) so the path-to-handle resolution cannot be redirected between calls.",
            &["https://cwe.mitre.org/data/definitions/367.html"],
        ),
        "uaf_candidate" => (
            "Null the pointer immediately after free; use ownership types.",
            "C/C++ code: set `ptr = NULL` immediately after `free(ptr)`. The compiler will not stop you from passing NULL to a subsequent dereference, but a NULL deref is a much easier crash to triage than UAF. Better: migrate the allocation to RAII (unique_ptr / Box / smart pointer) where the ownership lifecycle is enforced by the type system.",
            &["https://cwe.mitre.org/data/definitions/416.html"],
        ),
        "double_free_candidate" => (
            "Null after free; track ownership explicitly in error paths.",
            "Most double-frees come from error-path cleanup: the success path frees, the error path also frees. Use a single cleanup landing pad (goto cleanup in C; ? operator + Drop in Rust) and null the pointer after the first free. For C++, prefer unique_ptr to make double-ownership a compile error.",
            &["https://cwe.mitre.org/data/definitions/415.html"],
        ),
        _ => (
            "Manual review required — bug_class not in v1.1 analyst template registry.",
            "This finding's bug_class is not yet covered by the template-based analyst. Treat as a candidate requiring human review: inspect the source-to-sink chain, the dominating guards, and the propagation mode. File an issue if the bug_class is recurrent so the registry can grow.",
            &[],
        ),
    }
}

fn test_template_for(bug_class: &str) -> (&'static str, &'static str) {
    match bug_class {
        "unchecked_copy_length" => (
            "Boundary-test the byte-count against the destination's size.",
            "Construct a fixture where the source value is at the destination size + 1, at 2 × destination size, and at the maximum representable value for the byte-count type. The current code MUST reject (or saturate) each; the test FAILS if any of these reaches the sink with the oversized value.",
        ),
        "tainted_allocation_size" => (
            "Boundary-test the allocation size at 0, MAX_PROTOCOL_FRAME + 1, and SIZE_MAX.",
            "Drive the allocation with sizes 0, the documented per-channel ceiling + 1, and SIZE_MAX. The current code MUST reject (or clamp) each; the test FAILS if any reaches the allocator with an over-large value or causes the function to dereference the resulting (possibly NULL) pointer without checking.",
        ),
        "integer_overflow_before_alloc" => (
            "Compute the post-multiplication value just below and above the overflow boundary.",
            "For `n * sizeof(T)`, supply n equal to floor(MAX/sizeof(T)), ceil(MAX/sizeof(T)), and MAX. The current code MUST detect overflow at the second and third inputs; the test FAILS if the allocator is called with a wrapped (small) size.",
        ),
        "signed_unsigned_length_confusion" => (
            "Drive the source value with -1, INT_MIN, UINT_MAX, and 0.",
            "Each must either be rejected at the boundary or produce a deterministic, sized result. The test FAILS if the negative inputs reach the sink as their unsigned-cast representation.",
        ),
        "missing_bounds_check_var_mismatch" => (
            "Drive `requested_len` and `record_len` with different values and assert the sink receives the bounded value.",
            "Construct an input where `requested_len = 1024` (bound check would pass) but `record_len = 65536` (the variable actually passed). The current code MUST reject; the test FAILS if the sink sees the unbounded value.",
        ),
        "dangerous_memory_perm_transition" => (
            "Assert no W→X transition is attempted on regions whose base derives from network input.",
            "Mock the VirtualProtect/mprotect call to record the (base, size, new_perm) tuples. The test FAILS if any tuple has new_perm containing PAGE_EXECUTE AND the base is reachable from any source-trust > trusted.",
        ),
        "auth_check_after_action" => (
            "Run the function with a forged-unprivileged subject; assert the action's side-effects didn't happen.",
            "Construct a caller whose token would fail AccessCheck. The test FAILS if any of the function's side-effects (file written, registry modified, process spawned) occurred before the check rejected the caller.",
        ),
        "missing_caller_validation" => (
            "Invoke from a caller without the required token claim; assert the function refused.",
            "Provide a caller token missing the required SID/claim. The test FAILS if the function executes its main code path. Negative-fixture: provide a properly authorized caller and assert the function DOES execute (proves the check didn't over-fire).",
        ),
        "deserialization_to_dangerous_type" => (
            "Feed a known gadget-chain payload to the deserializer.",
            "Use published gadget payloads (e.g. ysoserial.net for BinaryFormatter). The test FAILS if any gadget chain instantiates an unintended type. Sanitize the test: run the deserializer with the network disconnected and assert no spawned processes / file writes.",
        ),
        "format_string_controlled" => (
            "Feed `%s%s%s%s%s%s%s%s` and `%n` to the format-string parameter.",
            "The current code MUST treat the input as data, not as a format string. The test FAILS if the program crashes (reading stack via %s) or modifies memory (via %n). Audit: also run with `%.2147483647d` to catch DoS-via-formatter.",
        ),
        "path_traversal_to_file_op" => (
            "Drive the path argument with `../`, `..\\`, `%2e%2e/`, and a long sequence.",
            "The current code MUST reject paths escaping the base directory. The test FAILS if any of the traversal-bearing paths reaches the file op with the unresolved relative-path form.",
        ),
        "toctou_file_access" => (
            "Run two concurrent threads: one symlinks the path between stat and open.",
            "The current code MUST use handle-based operations so the redirect cannot occur. The test FAILS if the open succeeds on a different file than the stat described.",
        ),
        "uaf_candidate" => (
            "After free, dereference the pointer through every alias path.",
            "Construct a fixture where `ptr` is freed, then every aliased copy (via field store, pointer copy, wrapper return) is dereferenced. The current code SHOULD crash (under sanitizer) or refuse (with null-checks). The test FAILS if a dereference reads any value other than the post-free poison value.",
        ),
        "double_free_candidate" => (
            "Run the function through every error path and assert free is called at most once per allocation.",
            "Instrument the allocator to record (alloc_id, free_count). Drive the function through each documented failure mode. The test FAILS if any alloc_id's free_count exceeds 1.",
        ),
        _ => (
            "Manual test design required — bug_class not in v1.1 analyst template registry.",
            "Bug classes not in the template registry require human test design. Start by enumerating the chain's preconditions and asserting each is reachable independently; then construct inputs that satisfy all preconditions simultaneously to verify the chain.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::confidence::Confidence;
    use crate::vuln::bug_class::EvidenceTier;
    use crate::vuln::finding::{
        FindingRecord, FindingSink, FindingSource, ScoringFactors, FINDING_SCHEMA,
    };
    use crate::vuln::taint::PropagationMode;

    fn make_finding(bug_class: &str, risk: f32) -> FindingRecord {
        FindingRecord {
            schema: FINDING_SCHEMA.into(),
            finding_id: "F-T-001".into(),
            run_id: "run-1".into(),
            bug_class: bug_class.into(),
            evidence_tier: EvidenceTier::GroundTruth,
            phase: "v1.1_dynamic".into(),
            chain_id: None,
            harness: None,
            dynamic_evidence: None,
            severity_guess: "medium".into(),
            risk_score: risk,
            confidence: Confidence::from_score(0.75),
            trust_boundary: "remote_authenticated".into(),
            source_to_sink_summary: "test".into(),
            source: FindingSource {
                kind: "network_recv".into(),
                function_va: "0x0000000000401000".into(),
                site_va: "0x0000000000401100".into(),
            },
            sink: FindingSink {
                api: "memcpy".into(),
                function_va: "0x0000000000402000".into(),
                site_va: "0x0000000000402200".into(),
            },
            propagation_mode: PropagationMode::Exact,
            dominating_guard_count: 0,
            matched_integer_pattern: false,
            scoring: ScoringFactors {
                source_trust: 1.0,
                sink_danger: 1.0,
                taint_confidence: 1.0,
                missing_mitigation: 1.0,
                reachability: 1.0,
                exploitability_prior: 1.0,
                false_positive_penalty: 0.0,
                weights_calibration: "test".into(),
            },
            uncertainties: vec![],
            provenance: Vec::new(),
        }
    }

    const ALL_14_BUG_CLASSES: &[&str] = &[
        "unchecked_copy_length",
        "tainted_allocation_size",
        "integer_overflow_before_alloc",
        "signed_unsigned_length_confusion",
        "missing_bounds_check_var_mismatch",
        "dangerous_memory_perm_transition",
        "auth_check_after_action",
        "missing_caller_validation",
        "deserialization_to_dangerous_type",
        "format_string_controlled",
        "path_traversal_to_file_op",
        "toctou_file_access",
        "uaf_candidate",
        "double_free_candidate",
    ];

    // ----- TriagePriority -----

    #[test]
    fn triage_priority_bands_match_plan_thresholds() {
        assert_eq!(TriagePriority::from_risk(9.5), TriagePriority::Critical);
        assert_eq!(TriagePriority::from_risk(8.0), TriagePriority::Critical);
        assert_eq!(TriagePriority::from_risk(7.99), TriagePriority::High);
        assert_eq!(TriagePriority::from_risk(6.0), TriagePriority::High);
        assert_eq!(TriagePriority::from_risk(5.99), TriagePriority::Medium);
        assert_eq!(TriagePriority::from_risk(3.0), TriagePriority::Medium);
        assert_eq!(TriagePriority::from_risk(2.99), TriagePriority::Low);
        assert_eq!(TriagePriority::from_risk(0.0), TriagePriority::Low);
    }

    #[test]
    fn triage_priority_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&TriagePriority::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn triage_priority_derives_from_finding_risk() {
        let f = make_finding("unchecked_copy_length", 8.5);
        assert_eq!(triage_priority(&f), TriagePriority::Critical);
    }

    // ----- Plan validation: 14 bug classes produce non-empty
    // suggestions. -----

    #[test]
    fn all_14_bug_classes_produce_non_empty_patch_suggestions() {
        for bc in ALL_14_BUG_CLASSES {
            let f = make_finding(bc, 5.0);
            let suggestions = suggest_patches(&f);
            assert!(
                !suggestions.is_empty(),
                "bug_class {bc} produced no patch suggestions"
            );
            for s in &suggestions {
                assert_eq!(s.source, ANALYST_SOURCE);
                assert_eq!(s.bug_class, *bc);
                assert!(!s.summary.is_empty(), "bug_class {bc} has empty summary");
                assert!(
                    !s.description.is_empty(),
                    "bug_class {bc} has empty description"
                );
            }
        }
    }

    #[test]
    fn all_14_bug_classes_produce_non_empty_test_suggestions() {
        for bc in ALL_14_BUG_CLASSES {
            let f = make_finding(bc, 5.0);
            let suggestions = suggest_tests(&f);
            assert!(
                !suggestions.is_empty(),
                "bug_class {bc} produced no test suggestions"
            );
            for s in &suggestions {
                assert_eq!(s.source, ANALYST_SOURCE);
                assert_eq!(s.bug_class, *bc);
                assert!(!s.summary.is_empty());
                assert!(!s.description.is_empty());
            }
        }
    }

    #[test]
    fn unknown_bug_class_falls_through_to_review_manually_template() {
        let f = make_finding("never_heard_of_this", 5.0);
        let p = suggest_patches(&f);
        assert_eq!(p.len(), 1);
        assert!(
            p[0].description.contains("not yet covered"),
            "unknown bug_class must produce a 'review manually' template, got: {}",
            p[0].description
        );
        let t = suggest_tests(&f);
        assert_eq!(t.len(), 1);
        assert!(t[0].description.contains("require human test design"));
    }

    // ----- Wire-shape discipline -----

    #[test]
    fn every_suggestion_marked_source_template() {
        // Plan requirement: "Pure-Rust template-based; output marked
        // source: \"template\"".
        for bc in ALL_14_BUG_CLASSES {
            let f = make_finding(bc, 5.0);
            for s in suggest_patches(&f) {
                assert_eq!(s.source, "template");
            }
            for s in suggest_tests(&f) {
                assert_eq!(s.source, "template");
            }
        }
    }

    #[test]
    fn patch_suggestion_round_trips_through_json() {
        let f = make_finding("unchecked_copy_length", 5.0);
        let s = suggest_patches(&f).into_iter().next().unwrap();
        let json = serde_json::to_string(&s).unwrap();
        let back: PatchSuggestion = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn test_suggestion_round_trips_through_json() {
        let f = make_finding("tainted_allocation_size", 5.0);
        let s = suggest_tests(&f).into_iter().next().unwrap();
        let json = serde_json::to_string(&s).unwrap();
        let back: TestSuggestion = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    // ----- Quality smell checks -----

    #[test]
    fn patch_suggestions_reference_at_least_one_cwe_for_known_classes() {
        // Sanity check: most known bug classes should reference at
        // least one CWE. (Skip lifetime which are also CWE-referenced
        // and the deserialization which has CWE-502.)
        for bc in ALL_14_BUG_CLASSES {
            let f = make_finding(bc, 5.0);
            let s = suggest_patches(&f).into_iter().next().unwrap();
            assert!(
                !s.references.is_empty() || bc == &"never_heard_of_this",
                "bug_class {bc} has zero references — at least one CWE expected"
            );
        }
    }

    #[test]
    fn patch_summary_and_description_are_distinct() {
        // The summary is a one-liner; the description should expand
        // on it. If they're identical, the template is degenerate.
        for bc in ALL_14_BUG_CLASSES {
            let f = make_finding(bc, 5.0);
            let s = suggest_patches(&f).into_iter().next().unwrap();
            assert_ne!(
                s.summary, s.description,
                "bug_class {bc} has identical summary and description"
            );
            assert!(
                s.description.len() > s.summary.len(),
                "bug_class {bc} description shorter than summary"
            );
        }
    }
}
