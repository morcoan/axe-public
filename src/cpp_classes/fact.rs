//! Normalized C++ class fact types.
//!
//! Per-field `Claim<T>` so cross-source merge (step 14) can pick the
//! highest-confidence winner per slot while accumulating evidence
//! across all contributing sources (PDB + RTTI + Heuristic).

#![allow(dead_code)]

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::facts::{Claim, ClaimSource};

pub const CLASS_SCHEMA: &str = "class_fact/1";

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CppAbi {
    Msvc,
    Itanium,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClassFact {
    pub schema: &'static str,
    /// Stable cross-run identifier. Content-derived from the
    /// demangled or mangled name; falls back to vftable VA when no
    /// name source exists. See [`build_class_id`].
    pub class_id: String,
    pub demangled_name: Option<Claim<String>>,
    pub mangled_name: Option<String>,
    pub size: Option<Claim<u64>>,
    pub abi: CppAbi,
    pub vtables: Vec<VTableFact>,
    pub bases: Vec<BaseClassFact>,
    pub fields: Vec<FieldFact>,
    pub methods: Vec<MethodFact>,
    pub constructors: Vec<u64>,
    pub destructors: Vec<u64>,
    pub claim: Claim<()>,
    pub contributing_sources: Vec<ClaimSource>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VTableFact {
    #[serde(serialize_with = "hex_va")]
    pub vftable_va: u64,
    pub subobject_offset: i64,
    #[serde(serialize_with = "hex_va_vec")]
    pub slots: Vec<u64>,
    pub for_base: Option<String>,
    pub source: ClaimSource,
}

#[derive(Clone, Debug, Serialize)]
pub struct BaseClassFact {
    pub base_class_id: String,
    pub base_name: Claim<String>,
    pub offset: Claim<i64>,
    pub virtual_base: bool,
    pub vbtable_offset: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FieldFact {
    pub offset: u64,
    pub size: Claim<u32>,
    pub name: Option<Claim<String>>,
    pub type_guess: Option<Claim<String>>,
    #[serde(serialize_with = "hex_va_vec")]
    pub access_sites: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MethodFact {
    #[serde(serialize_with = "hex_va")]
    pub function_va: u64,
    pub name: Option<Claim<String>>,
    #[serde(serialize_with = "opt_hex_va")]
    pub vtable_va: Option<u64>,
    pub vtable_slot: Option<usize>,
    pub is_virtual: bool,
    pub is_thunk: bool,
    pub adjustor_offset: Option<i64>,
}

/// Build a stable cross-run class identifier from the best available
/// name. Format:
/// - `class:<sha256_hex_8>:<safe_name>` when a name is known
/// - `class:vftable:<va_hex>` as last-resort fallback
///
/// The SHA256 prefix ensures stability across renames while keeping
/// the suffix human-readable for diff inspection.
pub fn build_class_id(name: Option<&str>, vftable_va: Option<u64>) -> String {
    if let Some(name) = name {
        let mut hasher = Sha256::new();
        hasher.update(name.as_bytes());
        let digest = hasher.finalize();
        let prefix = &digest[..4];
        let safe: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .take(32)
            .collect();
        format!(
            "class:{:02x}{:02x}{:02x}{:02x}:{}",
            prefix[0], prefix[1], prefix[2], prefix[3], safe
        )
    } else if let Some(va) = vftable_va {
        format!("class:vftable:{va:016x}")
    } else {
        "class:unknown".to_string()
    }
}

fn hex_va<S: serde::Serializer>(va: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("0x{va:016x}"))
}

fn opt_hex_va<S: serde::Serializer>(va: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
    match va {
        Some(v) => s.serialize_str(&format!("0x{v:016x}")),
        None => s.serialize_none(),
    }
}

fn hex_va_vec<S: serde::Serializer>(vs: &[u64], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(vs.len()))?;
    for v in vs {
        seq.serialize_element(&format!("0x{v:016x}"))?;
    }
    seq.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_id_is_stable_for_same_name() {
        let a = build_class_id(Some("std::exception"), None);
        let b = build_class_id(Some("std::exception"), None);
        assert_eq!(a, b);
    }

    #[test]
    fn class_id_differs_for_different_names() {
        let a = build_class_id(Some("std::exception"), None);
        let b = build_class_id(Some("std::bad_alloc"), None);
        assert_ne!(a, b);
    }

    #[test]
    fn class_id_falls_back_to_vftable_va() {
        let id = build_class_id(None, Some(0x140020000));
        assert_eq!(id, "class:vftable:0000000140020000");
    }

    #[test]
    fn class_id_sanitizes_non_alphanumerics() {
        let id = build_class_id(Some("Foo::Bar<int>"), None);
        // ':' and '<' '>' get sanitized to '_'.
        assert!(id.ends_with(":Foo__Bar_int_"), "got: {id}");
    }

    #[test]
    fn class_fact_serializes_with_schema_and_abi() {
        let fact = ClassFact {
            schema: CLASS_SCHEMA,
            class_id: build_class_id(Some("Foo"), None),
            demangled_name: Some(Claim::new("Foo".into(), ClaimSource::Pdb).with_score(0.99)),
            mangled_name: Some(".?AVFoo@@".into()),
            size: Some(Claim::new(48, ClaimSource::Pdb).with_score(0.99)),
            abi: CppAbi::Msvc,
            vtables: Vec::new(),
            bases: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            constructors: Vec::new(),
            destructors: Vec::new(),
            claim: Claim::new((), ClaimSource::Pdb).with_score(0.99),
            contributing_sources: vec![ClaimSource::Pdb],
        };
        let json = serde_json::to_string(&fact).unwrap();
        assert!(json.contains(r#""schema":"class_fact/1""#));
        assert!(json.contains(r#""abi":"msvc""#));
        assert!(json.contains(r#""source":"pdb""#));
    }
}
