//! `.gcc_except_table` (Language-Specific Data Area) parser for the
//! Itanium C++ ABI.
//!
//! Step 6 ships the LSDA *locator* only — every FDE's LSDA pointer is
//! recorded as evidence, but the call-site / action / type-table walk
//! is deferred. A follow-up step adds uleb128/sleb128 parsing of those
//! tables to populate `TryRegion`s with real IP ranges and
//! `CatchHandler`s with type-info-derived names.

#![allow(dead_code)]

/// Decoded LSDA header fields. Currently a stub; populated in the
/// follow-up that wires the full call-site walker.
#[derive(Clone, Debug, Default)]
pub struct LsdaInfo {
    pub lp_start_offset: Option<u64>,
    pub call_site_count: usize,
    pub has_type_table: bool,
}

/// Parse the LSDA header at `bytes[offset..]`. Returns `None` if the
/// header is truncated or invalid.
///
/// Step 6: returns `Some(Default::default())` whenever there are at
/// least a few bytes to read, signaling "LSDA present but content not
/// yet decoded." The follow-up walks call-site/action/type tables.
pub fn parse_lsda(bytes: &[u8], offset: usize) -> Option<LsdaInfo> {
    if offset >= bytes.len() {
        return None;
    }
    Some(LsdaInfo::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lsda_out_of_bounds_returns_none() {
        let bytes = [0u8; 4];
        assert!(parse_lsda(&bytes, 100).is_none());
    }

    #[test]
    fn parse_lsda_returns_stub_for_valid_offset() {
        let bytes = [0u8; 16];
        let info = parse_lsda(&bytes, 0).expect("stub should return Some");
        assert_eq!(info.call_site_count, 0);
        assert!(!info.has_type_table);
    }
}
