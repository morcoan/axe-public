//! Itanium C++ ABI class walker for ELF / Mach-O binaries.
//!
//! Detects classes by scanning extracted strings for Itanium typeinfo
//! *name* records (`_ZTS<encoded>`). Per the Itanium C++ ABI, every
//! class type with a vtable has a typeinfo object whose `name()` C-string
//! is `_ZTS<encoded>` — these strings are stable, locatable from the
//! string table, and don't require walking the vtable groups directly.
//!
//! Step 12 emits one [`ClassFact`] per discovered `_ZTS` string, with
//! the encoded portion preserved as `mangled_name`. The follow-up
//! (step 13/14) walks the typeinfo OBJECTS in `.data.rel.ro` to
//! recover base-class lists and vtable VAs.

#![allow(dead_code)]

use std::collections::BTreeSet;

use crate::cpp_classes::fact::{build_class_id, ClassFact, CppAbi, CLASS_SCHEMA};
use crate::cpp_classes::names::demangle;
use crate::facts::{Claim, ClaimSource, EvidenceRef};
use crate::image::Format;
use crate::pe::StringRecord;

const ITANIUM_RTTI_SCORE: f32 = 0.85;

pub fn collect(strings: &[StringRecord], image_format: Format) -> Vec<ClassFact> {
    if matches!(image_format, Format::Pe) {
        return Vec::new();
    }
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut facts = Vec::new();
    for s in strings {
        let Some(encoded) = s.text.strip_prefix("_ZTS") else {
            continue;
        };
        if encoded.is_empty() || !is_plausible_itanium_encoding(encoded) {
            continue;
        }
        if !seen.insert(s.text.clone()) {
            continue;
        }
        facts.push(build_fact(&s.text, encoded, s));
    }
    facts
}

/// Heuristic filter: real Itanium type encodings start with either a
/// digit (length-prefixed name like `3Foo`), `N` (nested), `St`
/// (std namespace shorthand), or a single-letter builtin like `c`/`i`.
/// Reject strings that look accidental (very long or full of non-ASCII).
fn is_plausible_itanium_encoding(encoded: &str) -> bool {
    if encoded.len() > 256 {
        return false;
    }
    if !encoded.is_ascii() {
        return false;
    }
    let first = encoded.as_bytes()[0];
    first.is_ascii_digit() || first == b'N' || first == b'S' || (first as char).is_ascii_lowercase()
}

fn build_fact(full: &str, encoded: &str, source: &StringRecord) -> ClassFact {
    // Attempt to demangle by reconstructing as a typeinfo symbol
    // (`_ZTI<encoded>` is the typeinfo OBJECT mangling; some
    // demanglers accept it). Falls back to the raw encoded part if
    // demangling fails.
    let synthetic_typeinfo = format!("_ZTI{encoded}");
    let demangled = demangle(&synthetic_typeinfo);
    let display = demangled.clone().unwrap_or_else(|| encoded.to_string());

    let evidence = vec![
        EvidenceRef::Section {
            name: source.section.clone().unwrap_or_default(),
            va: source.va,
        },
        EvidenceRef::RawAddr { va: source.va },
    ];

    let class_id = build_class_id(Some(&display), Some(source.va));
    ClassFact {
        schema: CLASS_SCHEMA,
        class_id,
        demangled_name: Some(
            Claim::new(display, ClaimSource::Rtti)
                .with_score(ITANIUM_RTTI_SCORE)
                .with_evidence(evidence.clone()),
        ),
        mangled_name: Some(full.to_string()),
        size: None,
        abi: CppAbi::Itanium,
        vtables: Vec::new(),
        bases: Vec::new(),
        fields: Vec::new(),
        methods: Vec::new(),
        constructors: Vec::new(),
        destructors: Vec::new(),
        claim: Claim::new((), ClaimSource::Rtti)
            .with_score(ITANIUM_RTTI_SCORE)
            .with_evidence(evidence),
        contributing_sources: vec![ClaimSource::Rtti],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::Format;

    fn string(text: &str) -> StringRecord {
        StringRecord {
            va: 0x140030000,
            rva: 0x30000,
            file_offset: 0x3000,
            encoding: "utf8".into(),
            size: text.len(),
            text: text.to_string(),
            classifiers: Vec::new(),
            section: Some(".rodata".into()),
        }
    }

    #[test]
    fn detects_itanium_typeinfo_name_strings() {
        let strings = vec![
            string("_ZTS3Foo"),
            string("_ZTSSt9exception"),
            string("hello world"), // unrelated
        ];
        let facts = collect(&strings, Format::Elf);
        assert_eq!(facts.len(), 2);
        assert!(facts.iter().all(|f| f.abi == CppAbi::Itanium));
    }

    #[test]
    fn skips_when_pe_format() {
        let strings = vec![string("_ZTS3Foo")];
        let facts = collect(&strings, Format::Pe);
        assert!(facts.is_empty(), "PE binaries don't use Itanium typeinfo");
    }

    #[test]
    fn skips_short_or_implausible_encodings() {
        let strings = vec![
            string("_ZTS"),    // empty encoded part
            string("_ZTSZZZ"), // doesn't start with digit/N/S/lowercase
        ];
        let facts = collect(&strings, Format::Elf);
        assert!(facts.is_empty(), "implausible encodings must be rejected");
    }

    #[test]
    fn deduplicates_repeated_strings() {
        let strings = vec![string("_ZTS3Foo"), string("_ZTS3Foo")];
        let facts = collect(&strings, Format::Elf);
        assert_eq!(facts.len(), 1, "same _ZTS string only produces one fact");
    }

    #[test]
    fn preserves_mangled_name() {
        let strings = vec![string("_ZTSSt9exception")];
        let facts = collect(&strings, Format::Elf);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].mangled_name.as_deref(), Some("_ZTSSt9exception"));
        assert_eq!(facts[0].contributing_sources, vec![ClaimSource::Rtti]);
    }
}
