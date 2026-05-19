//! Fuzz target derivation from the analyzer's already-shipped facts.
//!
//! Step 9 wires three target sources:
//! - [`VulnCandidateRecord`] (from `portable.rs`) — explicit vuln
//!   leads with `confidence == "high"|"medium"|...`.
//! - [`crate::eh::CatchHandler`] — C++ catch sites; typed catches
//!   indicate hot error paths.
//! - [`crate::cpp_classes::ClassFact`] `destructors` — RAII unwind
//!   paths, historically bug-rich.
//!
//! User-supplied targets (`--fuzz-target <name|va>`) are derived in
//! step 15; the `UserDefined` variant is exposed today so the CLI
//! layer can populate it directly.
//!
//! Priority bands match the plan's table. Ties broken by VA ascending
//! for stability. Same `(kind, function_va)` from multiple sources
//! accumulates `evidence` and takes `max(priority)`.

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::cpp_classes::ClassFact;
use crate::eh::{CatchKind, EhFunctionFact};
use crate::facts::EvidenceRef;
use crate::portable::VulnCandidateRecord;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetKind {
    VulnCandidate,
    CatchHandler,
    Destructor,
    UnsafeBlock,
    UserDefined,
}

impl TargetKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TargetKind::VulnCandidate => "vuln_candidate",
            TargetKind::CatchHandler => "catch_handler",
            TargetKind::Destructor => "destructor",
            TargetKind::UnsafeBlock => "unsafe_block",
            TargetKind::UserDefined => "user_defined",
        }
    }
}

/// A function the fuzzer biases toward via the reachability bonus in
/// [`crate::fuzzer::scheduler`].
#[derive(Clone, Debug)]
pub struct FuzzTarget {
    pub id: String,
    pub kind: TargetKind,
    pub function_va: u64,
    pub function_name: Option<String>,
    pub priority: f32,
    pub evidence: Vec<EvidenceRef>,
    pub notes: String,
}

/// Bundle of fact references handed to [`derive_targets`].
pub struct TargetFacts<'a> {
    pub vuln_candidates: &'a [VulnCandidateRecord],
    pub eh_facts: &'a [EhFunctionFact],
    pub class_facts: &'a [ClassFact],
    /// User-supplied `(function_va, optional_name)` pairs from
    /// `--fuzz-target` (wired in step 15).
    pub user_targets: &'a [(u64, Option<String>)],
}

impl<'a> Default for TargetFacts<'a> {
    fn default() -> Self {
        Self {
            vuln_candidates: &[],
            eh_facts: &[],
            class_facts: &[],
            user_targets: &[],
        }
    }
}

/// Walk every source, build provisional targets, then merge by
/// `(kind, function_va)`.
pub fn derive_targets(facts: &TargetFacts<'_>) -> Vec<FuzzTarget> {
    let mut acc: BTreeMap<(TargetKind, u64), FuzzTarget> = BTreeMap::new();

    for vc in facts.vuln_candidates {
        if let Some(target) = target_from_vuln(vc) {
            merge(&mut acc, target);
        }
    }

    for eh in facts.eh_facts {
        for handler in &eh.catch_handlers {
            let kind_priority = catch_priority(&handler.catch_kind);
            let mut evidence = vec![EvidenceRef::Instruction {
                va: handler.handler_va,
            }];
            if let CatchKind::Typed {
                type_descriptor_va, ..
            } = handler.catch_kind
            {
                evidence.push(EvidenceRef::RawAddr {
                    va: type_descriptor_va,
                });
            }
            let notes = match &handler.catch_kind {
                CatchKind::Typed { type_name, .. } => format!(
                    "C++ catch handler — {} (in function 0x{:016x})",
                    type_name.as_deref().unwrap_or("(unnamed type)"),
                    eh.function_va,
                ),
                CatchKind::Ellipsis => format!(
                    "C++ catch(...) handler (in function 0x{:016x})",
                    eh.function_va
                ),
                CatchKind::Cleanup => format!(
                    "Cleanup landing pad (in function 0x{:016x})",
                    eh.function_va
                ),
                CatchKind::Filter => {
                    format!("SEH filter (in function 0x{:016x})", eh.function_va)
                }
            };
            merge(
                &mut acc,
                FuzzTarget {
                    id: target_id(TargetKind::CatchHandler, handler.handler_va),
                    kind: TargetKind::CatchHandler,
                    function_va: handler.handler_va,
                    function_name: None,
                    priority: kind_priority,
                    evidence,
                    notes,
                },
            );
        }
    }

    for cls in facts.class_facts {
        for &dtor_va in &cls.destructors {
            let name = cls
                .demangled_name
                .as_ref()
                .map(|c| c.value.clone())
                .or_else(|| cls.mangled_name.clone());
            let notes = format!(
                "Destructor for class {} — RAII unwind path",
                name.as_deref().unwrap_or("(unnamed)"),
            );
            merge(
                &mut acc,
                FuzzTarget {
                    id: target_id(TargetKind::Destructor, dtor_va),
                    kind: TargetKind::Destructor,
                    function_va: dtor_va,
                    function_name: name,
                    priority: 0.65,
                    evidence: vec![EvidenceRef::Instruction { va: dtor_va }],
                    notes,
                },
            );
        }
    }

    for (va, name) in facts.user_targets {
        merge(
            &mut acc,
            FuzzTarget {
                id: target_id(TargetKind::UserDefined, *va),
                kind: TargetKind::UserDefined,
                function_va: *va,
                function_name: name.clone(),
                priority: 1.0,
                evidence: vec![EvidenceRef::Instruction { va: *va }],
                notes: "User-supplied via --fuzz-target".into(),
            },
        );
    }

    // Stable VA-ascending iteration order (BTreeMap key sorted).
    acc.into_values().collect()
}

fn target_from_vuln(vc: &VulnCandidateRecord) -> Option<FuzzTarget> {
    let va = vc.function.or(vc.site_va)?;
    let priority = match vc.confidence.to_ascii_lowercase().as_str() {
        "high" => 0.95,
        "medium" | "med" => 0.80,
        _ => 0.60,
    };
    let evidence: Vec<EvidenceRef> = vc
        .evidence
        .iter()
        .map(|&v| EvidenceRef::RawAddr { va: v })
        .collect();
    Some(FuzzTarget {
        id: target_id(TargetKind::VulnCandidate, va),
        kind: TargetKind::VulnCandidate,
        function_va: va,
        function_name: None,
        priority,
        evidence,
        notes: format!(
            "VulnCandidate ({}): {} [conf={}]",
            vc.kind, vc.summary, vc.confidence
        ),
    })
}

fn catch_priority(catch: &CatchKind) -> f32 {
    match catch {
        CatchKind::Typed { type_name, .. } if type_name.is_some() => 0.75,
        CatchKind::Typed { .. } => 0.65,
        CatchKind::Ellipsis => 0.55,
        CatchKind::Cleanup | CatchKind::Filter => 0.50,
    }
}

fn target_id(kind: TargetKind, va: u64) -> String {
    format!("target-{}-{:016x}", kind.as_str(), va)
}

fn merge(acc: &mut BTreeMap<(TargetKind, u64), FuzzTarget>, t: FuzzTarget) {
    let key = (t.kind, t.function_va);
    if let Some(existing) = acc.get_mut(&key) {
        if t.priority > existing.priority {
            existing.priority = t.priority;
        }
        existing.evidence.extend(t.evidence);
        if existing.function_name.is_none() {
            existing.function_name = t.function_name;
        }
    } else {
        acc.insert(key, t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpp_classes::fact::{ClassFact, CppAbi, CLASS_SCHEMA};
    use crate::eh::fact::{CatchHandler, CatchKind, EhAbi, EhFunctionFact, UnwindRange, EH_SCHEMA};
    use crate::facts::{Claim, ClaimSource};

    fn vuln(va: u64, conf: &str) -> VulnCandidateRecord {
        VulnCandidateRecord {
            candidate_id: format!("vc:{va:x}"),
            function: Some(va),
            site_va: Some(va + 0x10),
            kind: "format-string".into(),
            summary: "user-controlled format".into(),
            confidence: conf.into(),
            evidence: vec![va, va + 4],
            fuzz_harness_ref: String::new(),
        }
    }

    fn eh_with_typed_catch(fn_va: u64, handler_va: u64, type_name: &str) -> EhFunctionFact {
        EhFunctionFact {
            schema: EH_SCHEMA,
            function_va: fn_va,
            function_end_va: fn_va + 0x100,
            abi: EhAbi::MsvcFH3,
            personality: None,
            personality_va: None,
            unwind_ranges: vec![UnwindRange {
                begin_va: fn_va,
                end_va: fn_va + 0x100,
            }],
            try_regions: Vec::new(),
            catch_handlers: vec![CatchHandler {
                handler_va,
                catch_kind: CatchKind::Typed {
                    type_name: Some(type_name.into()),
                    type_descriptor_va: 0x140030000,
                },
                adjectives: 0,
                frame_offset: None,
                continuation_va: None,
            }],
            cleanup_actions: Vec::new(),
            claim: Claim::new((), ClaimSource::ExceptionHandling).with_score(0.95),
        }
    }

    fn class_with_destructors(name: &str, dtors: &[u64]) -> ClassFact {
        ClassFact {
            schema: CLASS_SCHEMA,
            class_id: format!("class-{name}"),
            demangled_name: Some(Claim::new(name.into(), ClaimSource::Pdb).with_score(0.99)),
            mangled_name: None,
            size: None,
            abi: CppAbi::Msvc,
            vtables: Vec::new(),
            bases: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            constructors: Vec::new(),
            destructors: dtors.to_vec(),
            claim: Claim::new((), ClaimSource::Pdb).with_score(0.99),
            contributing_sources: vec![ClaimSource::Pdb],
        }
    }

    #[test]
    fn vuln_high_confidence_gets_top_priority() {
        let facts = TargetFacts {
            vuln_candidates: &[vuln(0x1000, "high")],
            ..Default::default()
        };
        let targets = derive_targets(&facts);
        assert_eq!(targets.len(), 1);
        assert!((targets[0].priority - 0.95).abs() < 1e-6);
        assert_eq!(targets[0].kind, TargetKind::VulnCandidate);
    }

    #[test]
    fn vuln_priority_steps_by_confidence_band() {
        let facts = TargetFacts {
            vuln_candidates: &[
                vuln(0x1000, "high"),
                vuln(0x2000, "medium"),
                vuln(0x3000, "low"),
            ],
            ..Default::default()
        };
        let targets = derive_targets(&facts);
        assert_eq!(targets.len(), 3);
        let p_at = |va: u64| {
            targets
                .iter()
                .find(|t| t.function_va == va)
                .unwrap()
                .priority
        };
        assert!(p_at(0x1000) > p_at(0x2000));
        assert!(p_at(0x2000) > p_at(0x3000));
    }

    #[test]
    fn typed_catch_handler_priority_higher_than_ellipsis() {
        let typed = eh_with_typed_catch(0x1000, 0x1100, "std::exception");
        let mut ellipsis = typed.clone();
        ellipsis.catch_handlers[0].catch_kind = CatchKind::Ellipsis;
        ellipsis.catch_handlers[0].handler_va = 0x1200;

        let facts = TargetFacts {
            eh_facts: &[typed, ellipsis],
            ..Default::default()
        };
        let targets = derive_targets(&facts);
        assert_eq!(targets.len(), 2);
        let t_typed = targets.iter().find(|t| t.function_va == 0x1100).unwrap();
        let t_ellipsis = targets.iter().find(|t| t.function_va == 0x1200).unwrap();
        assert!(t_typed.priority > t_ellipsis.priority);
    }

    #[test]
    fn destructors_promote_to_targets() {
        let facts = TargetFacts {
            class_facts: &[class_with_destructors("Foo", &[0xa000, 0xa100])],
            ..Default::default()
        };
        let targets = derive_targets(&facts);
        assert_eq!(targets.len(), 2);
        for t in &targets {
            assert_eq!(t.kind, TargetKind::Destructor);
            assert!((t.priority - 0.65).abs() < 1e-6);
            assert!(t.notes.contains("Foo"));
        }
    }

    #[test]
    fn dedup_by_kind_and_va_takes_max_priority() {
        // Same VA reported as VulnCandidate with "high" AND "low" —
        // the merged record gets the high priority.
        let facts = TargetFacts {
            vuln_candidates: &[vuln(0x1000, "low"), vuln(0x1000, "high")],
            ..Default::default()
        };
        let targets = derive_targets(&facts);
        assert_eq!(targets.len(), 1, "same (kind, va) merges to one");
        assert!((targets[0].priority - 0.95).abs() < 1e-6);
        // Evidence accumulates across both records.
        assert!(targets[0].evidence.len() >= 4);
    }

    #[test]
    fn distinct_kinds_at_same_va_are_separate_targets() {
        let facts = TargetFacts {
            vuln_candidates: &[vuln(0x1000, "high")],
            user_targets: &[(0x1000, Some("user_foo".into()))],
            ..Default::default()
        };
        let targets = derive_targets(&facts);
        assert_eq!(targets.len(), 2, "different kinds don't merge");
    }

    #[test]
    fn user_targets_get_top_priority() {
        let facts = TargetFacts {
            user_targets: &[(0x1000, Some("important".into()))],
            ..Default::default()
        };
        let targets = derive_targets(&facts);
        assert_eq!(targets.len(), 1);
        assert!((targets[0].priority - 1.0).abs() < 1e-6);
        assert_eq!(targets[0].function_name.as_deref(), Some("important"));
    }

    #[test]
    fn empty_facts_produces_no_targets() {
        let facts = TargetFacts::default();
        let targets = derive_targets(&facts);
        assert!(targets.is_empty());
    }
}
