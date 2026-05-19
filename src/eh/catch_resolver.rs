//! Cross-references FH3/FH4 catch type-descriptor RVAs with the existing
//! [`RttiRecord`] index to recover human-readable catch type names.
//!
//! MSVC's `HandlerType.dispType` is an image-relative pointer to a
//! `TypeDescriptor` (RTTI structure). The existing
//! [`crate::pe`] RTTI pass already discovers these structures and
//! stores their mangled name in `RttiRecord.text`. This module just
//! indexes by VA and offers an O(1) lookup.

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::pe::RttiRecord;

pub struct CatchResolver<'a> {
    by_va: BTreeMap<u64, &'a RttiRecord>,
}

impl<'a> CatchResolver<'a> {
    pub fn from_rtti(rtti: &'a [RttiRecord]) -> Self {
        Self {
            by_va: rtti.iter().map(|r| (r.va, r)).collect(),
        }
    }

    /// Returns the mangled type-descriptor name (e.g.
    /// `.?AVexception@std@@`) when a `TypeDescriptor` is known at `va`.
    pub fn lookup(&self, va: u64) -> Option<String> {
        self.by_va.get(&va).map(|r| r.text.clone())
    }

    pub fn is_empty(&self) -> bool {
        self.by_va.is_empty()
    }

    pub fn len(&self) -> usize {
        self.by_va.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(va: u64, text: &str) -> RttiRecord {
        RttiRecord {
            va,
            rva: va,
            text: text.to_string(),
            section: Some(".rdata".into()),
        }
    }

    #[test]
    fn resolver_finds_known_descriptors() {
        let records = vec![
            rec(0x140003000, ".?AVexception@std@@"),
            rec(0x140003020, ".?AVbad_alloc@std@@"),
        ];
        let r = CatchResolver::from_rtti(&records);
        assert_eq!(
            r.lookup(0x140003000).as_deref(),
            Some(".?AVexception@std@@")
        );
        assert_eq!(
            r.lookup(0x140003020).as_deref(),
            Some(".?AVbad_alloc@std@@")
        );
    }

    #[test]
    fn resolver_returns_none_for_unknown_va() {
        let r = CatchResolver::from_rtti(&[]);
        assert!(r.lookup(0x140003000).is_none());
        assert!(r.is_empty());
    }
}
