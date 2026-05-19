//! Cross-source [`ClassFact`] merger + field-type enrichment.
//!
//! Multiple sources (PDB, MSVC RTTI, Itanium typeinfo, heuristic
//! ctor analysis) can each emit a [`ClassFact`] for the same class.
//! [`merge`] groups facts by `class_id` and produces one unified
//! fact per class:
//! - Per-slot fields (`demangled_name`, `size`) pick the
//!   highest-confidence claim across all contributors.
//! - Evidence vecs concatenate.
//! - `vtables` / `bases` / `fields` / `methods` / `constructors` /
//!   `destructors` are unioned (deduplicated where the natural key is
//!   obvious — vftable_va, function_va, etc.).
//! - `contributing_sources` aggregates every distinct source.
//!
//! [`enrich_field_types`] is a second pass that walks the existing
//! `TypeHintRecord` table and back-fills `FieldFact.type_guess` when
//! a known type hint exists at the field's offset.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

use crate::cpp_classes::fact::{BaseClassFact, ClassFact, FieldFact, MethodFact, VTableFact};
use crate::facts::{Claim, ClaimSource, Confidence};
use crate::pe::TypeHintRecord;

/// Merge multiple `ClassFact` rows (possibly from different sources)
/// into one fact per `class_id`. The highest-confidence claim wins
/// for each slot; evidence accumulates across all sources.
pub fn merge(facts: Vec<ClassFact>) -> Vec<ClassFact> {
    let mut grouped: BTreeMap<String, Vec<ClassFact>> = BTreeMap::new();
    for fact in facts {
        grouped.entry(fact.class_id.clone()).or_default().push(fact);
    }
    grouped
        .into_iter()
        .map(|(_, group)| merge_group(group))
        .collect()
}

fn merge_group(mut group: Vec<ClassFact>) -> ClassFact {
    // Sort by descending confidence so the "winner" of each per-slot
    // contest is `group[0]` for that slot.
    group.sort_by(|a, b| {
        b.claim
            .confidence
            .as_f32()
            .partial_cmp(&a.claim.confidence.as_f32())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut winner = group[0].clone();

    // Demangled name: highest-conf wins; evidence aggregates.
    winner.demangled_name = pick_highest_named(&group, |f| f.demangled_name.clone());
    // mangled_name: first non-None.
    if winner.mangled_name.is_none() {
        winner.mangled_name = group.iter().find_map(|f| f.mangled_name.clone());
    }
    // Size: highest-conf wins.
    winner.size = pick_highest_named(&group, |f| f.size.clone());
    // ABI: prefer non-Unknown.
    for f in &group {
        if f.abi != crate::cpp_classes::CppAbi::Unknown {
            winner.abi = f.abi;
            break;
        }
    }

    // Vtables: union by vftable_va (first wins for tie-break).
    let mut vt_seen = BTreeSet::new();
    winner.vtables = group
        .iter()
        .flat_map(|f| f.vtables.iter().cloned())
        .filter(|vt: &VTableFact| vt_seen.insert(vt.vftable_va))
        .collect();

    // Bases: union by base_class_id.
    let mut base_seen = BTreeSet::new();
    winner.bases = group
        .iter()
        .flat_map(|f| f.bases.iter().cloned())
        .filter(|b: &BaseClassFact| base_seen.insert(b.base_class_id.clone()))
        .collect();

    // Methods: union by function_va.
    let mut method_seen = BTreeSet::new();
    winner.methods = group
        .iter()
        .flat_map(|f| f.methods.iter().cloned())
        .filter(|m: &MethodFact| method_seen.insert(m.function_va))
        .collect();

    // Fields: merge by offset (highest-conf size wins; access sites
    // concatenate).
    winner.fields = merge_fields(&group);

    // Constructors / destructors: union.
    winner.constructors = group
        .iter()
        .flat_map(|f| f.constructors.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    winner.destructors = group
        .iter()
        .flat_map(|f| f.destructors.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    // Sources: aggregate distinct.
    winner.contributing_sources = group
        .iter()
        .flat_map(|f| f.contributing_sources.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    // Top-level claim: keep the winner's source, but concatenate evidence
    // across all sources and bump confidence to the max observed.
    let mut all_evidence = Vec::new();
    for f in &group {
        all_evidence.extend(f.claim.evidence.iter().cloned());
    }
    let best_score = group
        .iter()
        .map(|f| f.claim.confidence.as_f32())
        .fold(0.0_f32, f32::max);
    winner.claim = Claim {
        value: (),
        source: winner.claim.source,
        confidence: Confidence::from_score(best_score),
        evidence: all_evidence,
    };

    winner
}

fn pick_highest_named<T: Clone>(
    group: &[ClassFact],
    extract: impl Fn(&ClassFact) -> Option<Claim<T>>,
) -> Option<Claim<T>> {
    group.iter().filter_map(|f| extract(f)).max_by(|a, b| {
        a.confidence
            .as_f32()
            .partial_cmp(&b.confidence.as_f32())
            .unwrap_or(std::cmp::Ordering::Equal)
    })
}

fn merge_fields(group: &[ClassFact]) -> Vec<FieldFact> {
    let mut by_offset: BTreeMap<u64, FieldFact> = BTreeMap::new();
    for fact in group {
        for field in &fact.fields {
            by_offset
                .entry(field.offset)
                .and_modify(|existing| {
                    // Prefer higher-confidence size.
                    if field.size.confidence.as_f32() > existing.size.confidence.as_f32() {
                        existing.size = field.size.clone();
                    }
                    // Concatenate access sites (dedup downstream).
                    existing
                        .access_sites
                        .extend(field.access_sites.iter().copied());
                    // Take name and type_guess if not already present.
                    if existing.name.is_none() {
                        existing.name = field.name.clone();
                    }
                    if existing.type_guess.is_none() {
                        existing.type_guess = field.type_guess.clone();
                    }
                })
                .or_insert_with(|| field.clone());
        }
    }
    let mut out: Vec<FieldFact> = by_offset.into_values().collect();
    for f in &mut out {
        f.access_sites.sort_unstable();
        f.access_sites.dedup();
    }
    out
}

/// Back-fill `FieldFact.type_guess` from existing `TypeHintRecord`s.
/// A type hint with a `location` matching `[rcx + offset]` for an
/// observed access site populates the corresponding field.
pub fn enrich_field_types(facts: &mut Vec<ClassFact>, hints: &[TypeHintRecord]) {
    if hints.is_empty() {
        return;
    }
    let hints_by_site: BTreeMap<u64, &TypeHintRecord> =
        hints.iter().map(|h| (h.site_va, h)).collect();
    for fact in facts {
        for field in &mut fact.fields {
            if field.type_guess.is_some() {
                continue;
            }
            for site in &field.access_sites {
                if let Some(hint) = hints_by_site.get(site) {
                    field.type_guess = Some(
                        Claim::new(hint.type_tag.clone(), ClaimSource::FieldAccessInference)
                            .with_score(0.60),
                    );
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpp_classes::fact::{build_class_id, CppAbi, CLASS_SCHEMA};
    use crate::facts::{Claim, ClaimSource};

    fn fact(id: &str, source: ClaimSource, score: f32) -> ClassFact {
        ClassFact {
            schema: CLASS_SCHEMA,
            class_id: id.to_string(),
            demangled_name: Some(Claim::new("Foo".into(), source).with_score(score)),
            mangled_name: Some(".?AVFoo@@".into()),
            size: None,
            abi: CppAbi::Msvc,
            vtables: Vec::new(),
            bases: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            constructors: Vec::new(),
            destructors: Vec::new(),
            claim: Claim::new((), source).with_score(score),
            contributing_sources: vec![source],
        }
    }

    #[test]
    fn merge_groups_by_class_id() {
        let id = build_class_id(Some("Foo"), None);
        let pdb_fact = fact(&id, ClaimSource::Pdb, 0.99);
        let rtti_fact = fact(&id, ClaimSource::Rtti, 0.90);
        let merged = merge(vec![pdb_fact, rtti_fact]);
        assert_eq!(merged.len(), 1, "same class_id -> one fact");
        // PDB wins on confidence.
        assert!(merged[0].claim.confidence.as_f32() >= 0.99);
        // Sources aggregated.
        assert!(merged[0].contributing_sources.contains(&ClaimSource::Pdb));
        assert!(merged[0].contributing_sources.contains(&ClaimSource::Rtti));
    }

    #[test]
    fn merge_preserves_distinct_classes() {
        let f1 = fact(&build_class_id(Some("Foo"), None), ClaimSource::Pdb, 0.99);
        let f2 = fact(&build_class_id(Some("Bar"), None), ClaimSource::Pdb, 0.99);
        let merged = merge(vec![f1, f2]);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merge_fields_picks_highest_conf_size() {
        let id = build_class_id(Some("Foo"), None);
        let mut fact_a = fact(&id, ClaimSource::FieldAccessInference, 0.50);
        fact_a.fields.push(FieldFact {
            offset: 0x10,
            size: Claim::new(4, ClaimSource::FieldAccessInference).with_score(0.55),
            name: None,
            type_guess: None,
            access_sites: vec![0x1000],
        });
        let mut fact_b = fact(&id, ClaimSource::Pdb, 0.99);
        fact_b.fields.push(FieldFact {
            offset: 0x10,
            size: Claim::new(8, ClaimSource::Pdb).with_score(0.99),
            name: None,
            type_guess: None,
            access_sites: vec![0x1004],
        });
        let merged = merge(vec![fact_a, fact_b]);
        assert_eq!(merged.len(), 1);
        let f = &merged[0];
        assert_eq!(f.fields.len(), 1);
        // PDB-claimed size wins.
        assert_eq!(f.fields[0].size.value, 8);
        // Access sites from both sources retained.
        assert_eq!(f.fields[0].access_sites, vec![0x1000, 0x1004]);
    }

    #[test]
    fn enrich_field_types_fills_in_type_hints() {
        let id = build_class_id(Some("Foo"), None);
        let mut fact_a = fact(&id, ClaimSource::FieldAccessInference, 0.55);
        fact_a.fields.push(FieldFact {
            offset: 0x10,
            size: Claim::new(4, ClaimSource::FieldAccessInference).with_score(0.55),
            name: None,
            type_guess: None,
            access_sites: vec![0x1000],
        });
        let mut facts = vec![fact_a];

        let hints = vec![TypeHintRecord {
            type_id: "type:1".into(),
            function: 0x1000,
            site_va: 0x1000,
            location: "[rcx+0x10]".into(),
            type_tag: "i32".into(),
            source: "vsa".into(),
            confidence: "medium".into(),
            evidence: Vec::new(),
        }];

        enrich_field_types(&mut facts, &hints);
        assert!(facts[0].fields[0].type_guess.is_some());
        assert_eq!(facts[0].fields[0].type_guess.as_ref().unwrap().value, "i32");
    }
}
