//! Template DSL — declarative bug-class definitions.
//!
//! v1.0 ships 12 templates (all `GroundTruth` or `BestEffort` tier).
//! v1.1 adds 2 lifetime templates at `Candidate` tier with opt-in
//! gating (per Codex finding 3).
//!
//! Each `BugClass` is a *small data record* that the chain query
//! interprets generically — there's no per-template imperative code
//! in v1.0. That keeps the surface small and makes the negative-
//! fixture test discipline (preempt B) one-shot per template.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use crate::vuln::sinks::ArgRole;

/// How much trust we place in a finding emitted by this template.
/// Drives the `confidence_base` in `scoring.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceTier {
    /// Detector + evidence chain are precise enough that the finding
    /// is actionable as-is (modulo calibration).
    GroundTruth,
    /// Detector requires heuristics (e.g. type inference depth) that
    /// can miss or false-positive; finding still useful but lower
    /// confidence baseline.
    BestEffort,
    /// **v1.1 only.** Detector depends on analyses (alias) that axe
    /// doesn't do well in v1; finding is a *candidate*, not ground
    /// truth. Hard-capped confidence. Excluded from default top-N.
    Candidate,
}

impl EvidenceTier {
    /// Scoring `confidence_base`. UAF/double-free hard cap of 0.65
    /// is enforced by `confidence_cap` on the `BugClass` itself.
    pub fn confidence_base(&self) -> f32 {
        match self {
            Self::GroundTruth => 0.85,
            Self::BestEffort => 0.70,
            Self::Candidate => 0.50,
        }
    }
}

/// What a chain must do at its sink to satisfy this template.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkArgRequirement {
    /// The taint must reach the sink argument with this role.
    TaintedArgRole(ArgRole),
    /// The sink's *destination* arg must have a known size AND the
    /// tainted byte-count arg must be unbounded above that size
    /// (templates: `unchecked_copy_length`).
    DestSizeKnownByteCountUnbounded,
    /// The sink call must follow a write of tainted bytes to the
    /// region the sink references (template:
    /// `dangerous_memory_perm_transition`).
    PrecedingTaintedWrite,
    /// No taint requirement — any call to the sink with the matched
    /// shape qualifies (template: `auth_check_after_action`).
    AnyCall,
}

/// What guard pattern (or absence of guard) the template needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardRequirement {
    /// At least one dominating guard exists (template:
    /// `auth_check_after_action` needs an auth check BEFORE the
    /// action — but for this template "after_action" means the
    /// dominator order is *wrong*, so we encode the negation as
    /// `NoDominatingGuard` with category-specific semantics).
    DominatingGuardPresent,
    /// No guard dominates the sink (template:
    /// `unchecked_copy_length`).
    NoDominatingGuard,
    /// Don't care — guard semantics are not part of this template.
    DontCare,
}

/// What integer-shape pattern (if any) the template requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegerPatternRequirement {
    /// Template fires only if there's an integer-op node on the
    /// taint path AND the relevant operand is range-bounded such
    /// that overflow is possible (template:
    /// `integer_overflow_before_alloc`).
    OverflowPossible,
    /// Template fires only if there's a signed↔unsigned type cast
    /// on the taint path (template:
    /// `signed_unsigned_length_confusion`).
    SignedUnsignedCast,
    DontCare,
}

/// A bug class. The 12 v1.0 templates are constructed via the
/// `templates/*.rs` files. Each template is interpreted by the chain
/// query in Step 20.
///
/// `PartialEq` only (not `Eq`) because `confidence_cap: Option<f32>`
/// carries a non-`Eq` float.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct BugClass {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    /// Catalog source-kinds that can start a chain for this template
    /// (empty = any source).
    pub source_kinds: &'static [&'static str],
    /// Catalog sink APIs that can terminate a chain for this template.
    pub sink_apis: &'static [&'static str],
    pub sink_requirement: SinkArgRequirement,
    pub guard_requirement: GuardRequirement,
    pub integer_pattern: IntegerPatternRequirement,
    pub evidence_tier: EvidenceTier,
    /// Hard ceiling on the `confidence.score` for findings emitted
    /// from this template. `None` = no ceiling beyond the overall
    /// scoring clamp.
    pub confidence_cap: Option<f32>,
    pub description: &'static str,
}

/// Read-only template registry.
pub struct TemplateRegistry {
    templates: Vec<BugClass>,
}

impl TemplateRegistry {
    /// Default v1.0 set: the 12 templates from `templates/memory.rs`,
    /// `templates/auth.rs`, `templates/data_handling.rs`. Lifetime
    /// templates are NOT loaded by `load_v1_0`; they're v1.1 + opt-in
    /// via [`Self::load_v1_1_with_lifetime`].
    pub fn load_v1_0() -> Self {
        let mut templates = Vec::new();
        templates.extend(crate::vuln::templates::memory::register());
        templates.extend(crate::vuln::templates::auth::register());
        templates.extend(crate::vuln::templates::data_handling::register());
        Self { templates }
    }

    /// **v1.1 opt-in.** Loads the 12 v1.0 templates PLUS the 2
    /// lifetime templates (`uaf_candidate`, `double_free_candidate`).
    /// Gated by the `vuln-discovery-lifetime` Cargo feature; gated
    /// at runtime by `--vuln-include-lifetime` (Step 35). Codex
    /// finding 3 fix.
    #[cfg(feature = "vuln-discovery-lifetime")]
    pub fn load_v1_1_with_lifetime() -> Self {
        let mut me = Self::load_v1_0();
        me.templates
            .extend(crate::vuln::templates::lifetime::register());
        me
    }

    pub fn iter(&self) -> impl Iterator<Item = &BugClass> {
        self.templates.iter()
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    pub fn by_id(&self, id: &str) -> Option<&BugClass> {
        self.templates.iter().find(|b| b.id == id)
    }

    /// Filter templates whose `id` is in the comma-separated `csv`
    /// (or all of them when `csv == "all"`).
    pub fn filter_csv(&self, csv: &str) -> Vec<&BugClass> {
        if csv == "all" {
            return self.templates.iter().collect();
        }
        let allow: rustc_hash::FxHashSet<&str> = csv.split(',').map(str::trim).collect();
        self.templates
            .iter()
            .filter(|b| allow.contains(b.id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_tier_confidence_base_orders_ground_truth_highest() {
        assert!(
            EvidenceTier::GroundTruth.confidence_base()
                > EvidenceTier::BestEffort.confidence_base()
        );
        assert!(
            EvidenceTier::BestEffort.confidence_base() > EvidenceTier::Candidate.confidence_base()
        );
    }

    #[test]
    fn registry_v1_0_has_exactly_12_templates() {
        let r = TemplateRegistry::load_v1_0();
        assert_eq!(r.len(), 12, "v1.0 must register exactly 12 templates");
    }

    #[test]
    fn registry_template_ids_are_unique() {
        let r = TemplateRegistry::load_v1_0();
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for t in r.iter() {
            assert!(seen.insert(t.id), "duplicate template id: {}", t.id);
        }
    }

    #[test]
    fn registry_filter_csv_all_returns_full_set() {
        let r = TemplateRegistry::load_v1_0();
        assert_eq!(r.filter_csv("all").len(), 12);
    }

    #[test]
    fn registry_filter_csv_selects_named_subset() {
        let r = TemplateRegistry::load_v1_0();
        let subset = r.filter_csv("unchecked_copy_length,format_string_controlled");
        assert_eq!(subset.len(), 2);
    }

    #[test]
    fn registry_filter_csv_drops_unknown_names_silently() {
        let r = TemplateRegistry::load_v1_0();
        let subset = r.filter_csv("not_a_template,unchecked_copy_length");
        assert_eq!(subset.len(), 1);
        assert_eq!(subset[0].id, "unchecked_copy_length");
    }

    #[test]
    fn no_v1_0_template_has_candidate_tier() {
        // Codex finding 3 fix: lifetime/Candidate templates are v1.1
        // only. v1.0 has zero Candidate-tier templates.
        let r = TemplateRegistry::load_v1_0();
        for t in r.iter() {
            assert_ne!(
                t.evidence_tier,
                EvidenceTier::Candidate,
                "v1.0 template {} must not be Candidate-tier",
                t.id
            );
        }
    }
}
