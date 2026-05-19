//! Microsoft SEH parsers: `__C_specific_handler` and
//! `__GSHandlerCheck_EH`/`__GSHandlerCheck_SEH`.
//!
//! SEH's language-specific data is a flat `ScopeTable`:
//! `count: u32` followed by `count` 16-byte `ScopeTableEntry` records.
//! Each entry encodes one `__try { ... } __except (filter) { body }` or
//! `__try { ... } __finally { body }` region by its IP range plus the
//! filter and body RVAs.
//!
//! `__GSHandlerCheck_*` variants prepend a 4-byte stack-cookie offset
//! before the scope table — handled by the `has_gs_cookie` flag rather
//! than a duplicate parser.

#![allow(dead_code)]

use crate::eh::fact::{
    CatchHandler, CatchKind, CleanupAction, EhAbi, EhFunctionFact, TryRegion, UnwindRange,
    EH_SCHEMA,
};
use crate::eh::pe_unwind::{Personality, UnwindInfo};
use crate::facts::{Claim, ClaimSource, EvidenceRef};
use crate::pe::{ExceptionRecord, PEImage};

/// `handler_rva == 1` is MSVC's sentinel marking a `__finally` region
/// (the slot is reused because no real RVA can be 1).
const FINALLY_SENTINEL: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeTableEntry {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub handler_rva: u32,
    pub jump_target_rva: u32,
}

impl ScopeTableEntry {
    pub fn is_finally(&self) -> bool {
        self.handler_rva == FINALLY_SENTINEL
    }
}

pub fn parse_seh(
    pe: &PEImage,
    exc: &ExceptionRecord,
    unwind: &UnwindInfo,
    personality: &Personality,
    has_gs_cookie: bool,
) -> Option<EhFunctionFact> {
    let lang_offset = unwind.language_specific_data_offset?;
    let bytes = pe.bytes();
    // GS variants prepend a 4-byte cookie offset before the scope table.
    let scope_offset = if has_gs_cookie {
        lang_offset.checked_add(4)?
    } else {
        lang_offset
    };
    if scope_offset + 4 > bytes.len() {
        return None;
    }
    let count = read_u32(bytes, scope_offset)? as usize;
    // Sanity cap: realistic functions have at most ~few hundred scopes;
    // anything larger is almost always a misread.
    if count > 4096 {
        return None;
    }
    let table_start = scope_offset + 4;
    let table_bytes = count.saturating_mul(16);
    if table_start + table_bytes > bytes.len() {
        return None;
    }

    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let base = table_start + i * 16;
        entries.push(ScopeTableEntry {
            begin_rva: read_u32(bytes, base)?,
            end_rva: read_u32(bytes, base + 4)?,
            handler_rva: read_u32(bytes, base + 8)?,
            jump_target_rva: read_u32(bytes, base + 12)?,
        });
    }

    let image_base = pe_base(pe);
    let mut try_regions = Vec::new();
    let mut catch_handlers = Vec::new();
    let mut cleanup_actions = Vec::new();

    for entry in &entries {
        let region_begin = image_base.wrapping_add(entry.begin_rva as u64);
        let region_end = image_base.wrapping_add(entry.end_rva as u64);

        if entry.is_finally() {
            cleanup_actions.push(CleanupAction {
                region_begin_va: region_begin,
                region_end_va: region_end,
                landing_pad_va: Some(image_base.wrapping_add(entry.jump_target_rva as u64)),
                unwind_handler_va: None,
                state_from: None,
                state_to: None,
            });
        } else {
            let handler_idx = catch_handlers.len() as u32;
            try_regions.push(TryRegion {
                try_begin_va: region_begin,
                try_end_va: region_end,
                try_state_low: None,
                try_state_high: None,
                call_site_index: None,
                catch_handler_indices: vec![handler_idx],
            });
            catch_handlers.push(CatchHandler {
                handler_va: image_base.wrapping_add(entry.handler_rva as u64),
                catch_kind: CatchKind::Filter,
                adjectives: 0,
                frame_offset: None,
                continuation_va: Some(image_base.wrapping_add(entry.jump_target_rva as u64)),
            });
        }
    }

    let abi = if has_gs_cookie {
        EhAbi::MsGSHandlerEH
    } else {
        EhAbi::MsSEH
    };

    let evidence = vec![
        EvidenceRef::Section {
            name: ".pdata".into(),
            va: exc.begin,
        },
        EvidenceRef::RawAddr {
            va: image_base.wrapping_add(scope_offset as u64),
        },
    ];

    Some(EhFunctionFact {
        schema: EH_SCHEMA,
        function_va: exc.begin,
        function_end_va: exc.end,
        abi,
        personality: personality.name.clone(),
        personality_va: personality.va,
        unwind_ranges: vec![UnwindRange {
            begin_va: exc.begin,
            end_va: exc.end,
        }],
        try_regions,
        catch_handlers,
        cleanup_actions,
        claim: Claim::new((), ClaimSource::ExceptionHandling)
            .with_score(0.85)
            .with_evidence(evidence),
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

fn pe_base(pe: &PEImage) -> u64 {
    use crate::image::BinaryImage;
    pe.base()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finally_sentinel_recognized() {
        let finally_entry = ScopeTableEntry {
            begin_rva: 0x1000,
            end_rva: 0x1100,
            handler_rva: FINALLY_SENTINEL,
            jump_target_rva: 0x2000,
        };
        assert!(finally_entry.is_finally());

        let except_entry = ScopeTableEntry {
            begin_rva: 0x1000,
            end_rva: 0x1100,
            handler_rva: 0x1500,
            jump_target_rva: 0x2000,
        };
        assert!(!except_entry.is_finally());
    }

    #[test]
    fn read_u32_le() {
        let bytes = [0x10, 0x00, 0x00, 0x00];
        assert_eq!(read_u32(&bytes, 0), Some(0x10));
    }
}
