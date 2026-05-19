//! MSVC RTTI walker: lifts existing [`VTableRecord`] rows (already
//! enriched with class name, COL pointer, base-class list, and method
//! slots by [`crate::cpp::recover_cpp`]) into [`ClassFact`]s.
//!
//! For each vtable with a recognized `probable_class`, emits one
//! ClassFact carrying:
//! - the vtable VA + slot list as a [`VTableFact`]
//! - the constructor-candidate VAs
//! - one [`BaseClassFact`] per recovered base-class name
//! - `ClaimSource::Rtti` with confidence ~0.90
//!
//! Step 10 focuses on single-inheritance classes (one vtable per
//! class). Multi-inheritance (multiple secondary vftables per class
//! + adjustor thunks) is step 11.

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::cpp_classes::fact::{
    build_class_id, BaseClassFact, ClassFact, CppAbi, MethodFact, VTableFact, CLASS_SCHEMA,
};
use crate::cpp_classes::names::demangle;
use crate::cpp_classes::thunks::AdjustorInfo;
use crate::facts::{Claim, ClaimSource, EvidenceRef};
use crate::pe::{RttiRecord, VTableRecord};

const RTTI_SCORE: f32 = 0.90;

pub fn collect(
    vtables: &[VTableRecord],
    rtti: &[RttiRecord],
    thunks: &BTreeMap<u64, AdjustorInfo>,
) -> Vec<ClassFact> {
    // Index RTTI by mangled name for quick "is this name known RTTI?" checks.
    let rtti_by_name: BTreeMap<&str, &RttiRecord> =
        rtti.iter().map(|r| (r.text.as_str(), r)).collect();

    // Group vtables by class name. Multiple vtables sharing a name
    // (multi-inheritance secondary vftables) get merged into one fact
    // — step 11 distinguishes primary vs secondary.
    let mut by_class: BTreeMap<String, Vec<&VTableRecord>> = BTreeMap::new();
    for vt in vtables {
        let Some(name) = &vt.probable_class else {
            continue;
        };
        by_class.entry(name.clone()).or_default().push(vt);
    }

    by_class
        .into_iter()
        .map(|(class_name, vts)| build_one(&class_name, &vts, &rtti_by_name, thunks))
        .collect()
}

fn build_one(
    class_name: &str,
    vtables: &[&VTableRecord],
    rtti_by_name: &BTreeMap<&str, &RttiRecord>,
    thunks: &BTreeMap<u64, AdjustorInfo>,
) -> ClassFact {
    let demangled = demangle(class_name);
    let display = demangled.clone().unwrap_or_else(|| class_name.to_string());

    let mut evidence = Vec::new();
    for vt in vtables {
        evidence.push(EvidenceRef::RawAddr { va: vt.va });
        if let Some(col_va) = vt.col_va {
            evidence.push(EvidenceRef::RawAddr { va: col_va });
        }
    }
    if let Some(rtti) = rtti_by_name.get(class_name) {
        evidence.push(EvidenceRef::Section {
            name: rtti.section.clone().unwrap_or_default(),
            va: rtti.va,
        });
    }

    // VTables: the first vtable is the primary subobject (offset 0);
    // subsequent vtables are secondary base subobjects. Step 11
    // assigns sequential placeholder offsets (8, 16, …) and tags
    // each secondary with the corresponding base name from the
    // base_classes list. Step 14 (solver) replaces the placeholders
    // with real offsets recovered from constructor-write analysis.
    let unique_bases: Vec<String> = vtables
        .iter()
        .flat_map(|vt| vt.base_classes.iter().cloned())
        .filter(|n| n != class_name)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let vtable_facts: Vec<VTableFact> = vtables
        .iter()
        .enumerate()
        .map(|(idx, vt)| {
            let (subobject_offset, for_base) = if idx == 0 {
                (0, None)
            } else {
                let placeholder_offset = (idx as i64) * 8;
                let base_name = unique_bases.get(idx - 1).cloned();
                (placeholder_offset, base_name)
            };
            VTableFact {
                vftable_va: vt.va,
                subobject_offset,
                slots: vt.methods.clone(),
                for_base,
                source: ClaimSource::Rtti,
            }
        })
        .collect();

    // Bases: one BaseClassFact per recovered base name. Offset 0 is
    // a placeholder until step 11 walks the BCD pmd triples for real
    // offsets.
    let bases: Vec<BaseClassFact> = vtables
        .iter()
        .flat_map(|vt| vt.base_classes.iter())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter(|n| n != class_name)
        .map(|base_name| {
            let base_demangled = demangle(&base_name);
            let base_display = base_demangled.clone().unwrap_or_else(|| base_name.clone());
            BaseClassFact {
                base_class_id: build_class_id(Some(&base_display), None),
                base_name: Claim::new(base_display, ClaimSource::Rtti).with_score(RTTI_SCORE),
                offset: Claim::new(0, ClaimSource::Rtti).with_score(0.50),
                virtual_base: false,
                vbtable_offset: None,
            }
        })
        .collect();

    // Methods: each vtable slot becomes a MethodFact pointing at the
    // function VA. Names are unknown at this layer (no PDB).
    let methods: Vec<MethodFact> = vtables
        .iter()
        .flat_map(|vt| {
            vt.methods.iter().enumerate().map(|(slot, &fn_va)| {
                let thunk_info = thunks.get(&fn_va);
                MethodFact {
                    function_va: fn_va,
                    name: None,
                    vtable_va: Some(vt.va),
                    vtable_slot: Some(slot),
                    is_virtual: true,
                    is_thunk: thunk_info.is_some(),
                    adjustor_offset: thunk_info.map(|t| t.offset),
                }
            })
        })
        .collect();

    let constructors: Vec<u64> = vtables
        .iter()
        .flat_map(|vt| vt.constructor_candidates.iter().copied())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let primary_vftable_va = vtables.first().map(|vt| vt.va);
    let class_id = build_class_id(Some(&display), primary_vftable_va);

    ClassFact {
        schema: CLASS_SCHEMA,
        class_id,
        demangled_name: Some(
            Claim::new(display, ClaimSource::Rtti)
                .with_score(RTTI_SCORE)
                .with_evidence(evidence.clone()),
        ),
        mangled_name: Some(class_name.to_string()),
        size: None,
        abi: CppAbi::Msvc,
        vtables: vtable_facts,
        bases,
        fields: Vec::new(),
        methods,
        constructors,
        destructors: Vec::new(),
        claim: Claim::new((), ClaimSource::Rtti)
            .with_score(RTTI_SCORE)
            .with_evidence(evidence),
        contributing_sources: vec![ClaimSource::Rtti],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{RttiRecord, VTableRecord};

    fn no_thunks() -> BTreeMap<u64, AdjustorInfo> {
        BTreeMap::new()
    }

    fn vtable(
        va: u64,
        class: Option<&str>,
        bases: &[&str],
        methods: &[u64],
        ctors: &[u64],
    ) -> VTableRecord {
        VTableRecord {
            va,
            rva: va,
            section: ".rdata".into(),
            method_count: methods.len(),
            methods: methods.to_vec(),
            probable_class: class.map(String::from),
            col_va: Some(va.wrapping_sub(8)),
            class_descriptor_va: Some(va.wrapping_sub(16)),
            base_classes: bases.iter().map(|s| s.to_string()).collect(),
            constructor_candidates: ctors.to_vec(),
            ownership_confidence: "medium".into(),
        }
    }

    #[test]
    fn collect_emits_one_class_per_vtable_with_known_name() {
        let vts = vec![vtable(
            0x140020000,
            Some(".?AVFoo@@"),
            &[],
            &[0x1100, 0x1200],
            &[0x1500],
        )];
        let facts = collect(&vts, &[], &no_thunks());
        assert_eq!(facts.len(), 1);
        let f = &facts[0];
        assert_eq!(f.abi, CppAbi::Msvc);
        assert_eq!(f.mangled_name.as_deref(), Some(".?AVFoo@@"));
        assert_eq!(f.vtables.len(), 1);
        assert_eq!(f.vtables[0].slots, vec![0x1100, 0x1200]);
        assert_eq!(f.methods.len(), 2);
        assert_eq!(f.constructors, vec![0x1500]);
        assert_eq!(f.contributing_sources, vec![ClaimSource::Rtti]);
    }

    #[test]
    fn collect_skips_vtables_without_class_name() {
        let vts = vec![vtable(0x140020000, None, &[], &[0x1100], &[])];
        let facts = collect(&vts, &[], &no_thunks());
        assert!(facts.is_empty());
    }

    #[test]
    fn collect_merges_multiple_vtables_for_same_class() {
        let vts = vec![
            vtable(0x140020000, Some(".?AVFoo@@"), &[], &[0x1100], &[0x1500]),
            vtable(0x140020100, Some(".?AVFoo@@"), &[], &[0x1200], &[0x1600]),
        ];
        let facts = collect(&vts, &[], &no_thunks());
        assert_eq!(facts.len(), 1, "same class -> one ClassFact");
        let f = &facts[0];
        assert_eq!(f.vtables.len(), 2, "both vtables retained");
        // Two ctors merged across the two vtables.
        assert_eq!(f.constructors.len(), 2);
    }

    #[test]
    fn collect_populates_bases() {
        let vts = vec![vtable(
            0x140020000,
            Some(".?AVDerived@@"),
            &[".?AVBase@@"],
            &[0x1100],
            &[],
        )];
        let facts = collect(&vts, &[], &no_thunks());
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].bases.len(), 1);
        assert!(facts[0].bases[0].base_class_id.contains("Base"));
    }

    #[test]
    fn collect_cross_references_rtti_section() {
        let vts = vec![vtable(0x140020000, Some(".?AVFoo@@"), &[], &[0x1100], &[])];
        let rtti = vec![RttiRecord {
            va: 0x140030000,
            rva: 0x30000,
            text: ".?AVFoo@@".into(),
            section: Some(".rdata".into()),
        }];
        let facts = collect(&vts, &rtti, &no_thunks());
        assert_eq!(facts.len(), 1);
        // Evidence vec should now include a Section ref for the RTTI record.
        assert!(facts[0]
            .claim
            .evidence
            .iter()
            .any(|e| matches!(e, EvidenceRef::Section { name, .. } if name == ".rdata")));
    }
}
