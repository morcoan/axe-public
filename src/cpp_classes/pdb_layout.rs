//! Promote PDB/DWARF [`DebugTypeRecord`] rows into [`ClassFact`]s.
//!
//! Debug-info-driven layout is the highest-confidence source
//! (`ClaimSource::Pdb` / `ClaimSource::Dwarf`, band 0.98-1.00). When
//! present, it supplies authoritative class name, size, and (in a
//! follow-up) field layout from `LF_FIELDLIST` / DWARF
//! `DW_TAG_member` entries.
//!
//! Step 9 ships the *name + size* path only. The deeper
//! `LF_FIELDLIST` / `DW_TAG_member` walk lands alongside the
//! heuristic solver in step 13/14 since it shares the
//! field-merging plumbing.

#![allow(dead_code)]

use crate::cpp_classes::fact::{build_class_id, ClassFact, CppAbi, CLASS_SCHEMA};
use crate::cpp_classes::names::demangle;
use crate::debug_symbols::DebugTypeRecord;
use crate::facts::{Claim, ClaimSource, Confidence, EvidenceRef};

/// Promote `class`/`struct` debug-type rows into `ClassFact`s.
pub fn collect(debug_types: &[DebugTypeRecord]) -> Vec<ClassFact> {
    debug_types
        .iter()
        .filter(|t| is_class_kind(&t.kind))
        .filter_map(promote_one)
        .collect()
}

fn is_class_kind(kind: &str) -> bool {
    matches!(
        kind.to_ascii_lowercase().as_str(),
        "class" | "struct" | "union"
    )
}

fn promote_one(record: &DebugTypeRecord) -> Option<ClassFact> {
    let raw_name = record.name.as_deref()?;
    let source = match record.provider.to_ascii_lowercase().as_str() {
        "pdb" => ClaimSource::Pdb,
        "dwarf" => ClaimSource::Dwarf,
        _ => ClaimSource::ObjectSymbol,
    };
    let abi = match source {
        ClaimSource::Pdb => CppAbi::Msvc,
        ClaimSource::Dwarf => CppAbi::Itanium,
        _ => CppAbi::Unknown,
    };

    // The "name" in DebugTypeRecord may already be human-readable
    // (DWARF stores demangled type names) or may be mangled (PDB
    // TypeDescriptor strings). Try demangling; keep the raw form
    // as the `mangled_name` fallback.
    let demangled = demangle(raw_name);
    let display_name = demangled.clone().unwrap_or_else(|| raw_name.to_string());
    let mangled_name = if demangled.is_some() {
        Some(raw_name.to_string())
    } else {
        None
    };

    let mut evidence = vec![EvidenceRef::DebugRecord {
        provider: record.provider.clone(),
        key: record.raw_key.clone(),
    }];
    for &va in &record.evidence {
        evidence.push(EvidenceRef::RawAddr { va });
    }

    let confidence_score = Confidence::from_str(&record.confidence).as_f32();

    let size = record.size.map(|sz| {
        Claim::new(sz, source)
            .with_score(confidence_score)
            .with_evidence(vec![EvidenceRef::DebugRecord {
                provider: record.provider.clone(),
                key: record.raw_key.clone(),
            }])
    });

    let class_claim = Claim::new((), source)
        .with_score(confidence_score)
        .with_evidence(evidence.clone());

    Some(ClassFact {
        schema: CLASS_SCHEMA,
        class_id: build_class_id(Some(&display_name), None),
        demangled_name: Some(
            Claim::new(display_name, source)
                .with_score(confidence_score)
                .with_evidence(evidence),
        ),
        mangled_name,
        size,
        abi,
        vtables: Vec::new(),
        bases: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        constructors: Vec::new(),
        destructors: Vec::new(),
        claim: class_claim,
        contributing_sources: vec![source],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug_symbols::DebugTypeRecord;

    fn rec(provider: &str, kind: &str, name: &str, size: Option<u64>) -> DebugTypeRecord {
        DebugTypeRecord {
            type_id: format!("type:{name}"),
            module_id: "mod:1".into(),
            provider: provider.into(),
            namespace: String::new(),
            raw_key: format!("key:{name}"),
            kind: kind.into(),
            name: Some(name.into()),
            size,
            confidence: "high".into(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn promotes_pdb_class_with_size() {
        let inputs = vec![rec("pdb", "class", "Foo", Some(48))];
        let facts = collect(&inputs);
        assert_eq!(facts.len(), 1);
        let f = &facts[0];
        assert_eq!(f.abi, CppAbi::Msvc);
        assert_eq!(f.contributing_sources, vec![ClaimSource::Pdb]);
        assert!(f.size.is_some());
        assert_eq!(f.size.as_ref().unwrap().value, 48);
        assert!(f.demangled_name.is_some());
        assert!(f.class_id.contains("Foo"));
    }

    #[test]
    fn promotes_dwarf_class_as_itanium() {
        let inputs = vec![rec("dwarf", "class", "Bar", Some(16))];
        let facts = collect(&inputs);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].abi, CppAbi::Itanium);
        assert_eq!(facts[0].contributing_sources, vec![ClaimSource::Dwarf]);
    }

    #[test]
    fn skips_non_class_kinds() {
        let inputs = vec![
            rec("pdb", "enum", "MyEnum", Some(4)),
            rec("pdb", "typedef", "MyAlias", None),
        ];
        let facts = collect(&inputs);
        assert!(facts.is_empty(), "non-class kinds must be skipped");
    }

    #[test]
    fn struct_and_union_are_promoted() {
        let inputs = vec![
            rec("pdb", "struct", "S", Some(8)),
            rec("pdb", "union", "U", Some(8)),
        ];
        let facts = collect(&inputs);
        assert_eq!(facts.len(), 2);
    }

    #[test]
    fn demangles_msvc_type_descriptor_names() {
        let inputs = vec![rec("pdb", "class", ".?AVexception@std@@", Some(8))];
        let facts = collect(&inputs);
        assert_eq!(facts.len(), 1);
        let f = &facts[0];
        // Demangled name should differ from the raw mangled form.
        assert!(f.mangled_name.is_some());
        assert_eq!(f.mangled_name.as_deref(), Some(".?AVexception@std@@"));
    }
}
