//! `__CxxFrameHandler3` (MSVC FH3) parser.
//!
//! Reads the `FuncInfo` block referenced by the personality routine's
//! language-specific data, walks the `TryBlockMap` array, and emits
//! one [`EhFunctionFact`] per function with the recovered try regions
//! and catch handlers (with type names resolved via
//! [`crate::eh::catch_resolver`]).
//!
//! Layout reference: Microsoft's `<ehdata.h>` (publicly documented in
//! parts of the MSVC RTL source) — magics:
//! - `0x19930520` → base layout (28-byte header)
//! - `0x19930521` → adds `UnwindHelp`
//! - `0x19930522` → adds `ESTypeList` + `EHFlags`
//!
//! Step 4 implementation: handles the base 0x19930520 layout fully,
//! and reads the same prefix for 0x19930521/22 (extra fields ignored,
//! graceful degradation).

#![allow(dead_code)]

use crate::eh::catch_resolver::CatchResolver;
use crate::eh::fact::{
    CatchHandler, CatchKind, EhAbi, EhFunctionFact, TryRegion, UnwindRange, EH_SCHEMA,
};
use crate::eh::pe_unwind::{Personality, UnwindInfo};
use crate::facts::{Claim, ClaimSource, EvidenceRef};
use crate::pe::{ExceptionRecord, PEImage};

pub const FH3_MAGIC_BASE: u32 = 0x19930520;
pub const FH3_MAGIC_UNWIND_HELP: u32 = 0x19930521;
pub const FH3_MAGIC_ES_TYPES: u32 = 0x19930522;

/// FH3 `FuncInfo` header (the first 28 bytes; later magics add fields
/// past this prefix that this parser tolerates but does not consume).
#[derive(Clone, Debug)]
pub struct FuncInfo {
    pub magic: u32,
    pub max_state: i32,
    pub unwind_map_rva: u32,
    pub try_blocks_count: u32,
    pub try_block_map_rva: u32,
    pub ip_map_count: u32,
    pub ip_to_state_map_rva: u32,
}

/// FH3 `TryBlockMap` entry (20 bytes on x64).
#[derive(Clone, Debug)]
pub struct TryBlockMapEntry {
    pub try_low: i32,
    pub try_high: i32,
    pub catch_high: i32,
    pub handlers_count: u32,
    pub handler_array_rva: u32,
}

/// FH3 `HandlerType` entry on x64 (20 bytes).
#[derive(Clone, Debug)]
pub struct HandlerTypeEntry {
    pub adjectives: u32,
    pub type_descriptor_rva: u32,
    pub catch_object_offset: i32,
    pub handler_rva: u32,
    pub frame_offset: i32,
}

pub fn parse_fh3(
    pe: &PEImage,
    exc: &ExceptionRecord,
    unwind: &UnwindInfo,
    personality: &Personality,
    resolver: &CatchResolver<'_>,
) -> Option<EhFunctionFact> {
    let lang_offset = unwind.language_specific_data_offset?;
    let bytes = pe.bytes();
    if lang_offset + 4 > bytes.len() {
        return None;
    }
    // language-specific data for FH3 is a single u32 RVA pointing to FuncInfo.
    let func_info_rva = read_u32(bytes, lang_offset)?;
    let func_info = parse_func_info(pe, func_info_rva)?;

    if !matches!(
        func_info.magic,
        FH3_MAGIC_BASE | FH3_MAGIC_UNWIND_HELP | FH3_MAGIC_ES_TYPES
    ) {
        return None;
    }

    let try_blocks = parse_try_block_map(pe, &func_info).unwrap_or_default();
    let mut try_regions = Vec::with_capacity(try_blocks.len());
    let mut catch_handlers = Vec::new();

    for tb in &try_blocks {
        // Step 4 does not yet walk the IP-to-state map; we use the
        // function's full range as a placeholder for try IP-bounds.
        // Step 5+ replaces this with the real IPtoStateMap walk.
        let handler_indices: Vec<u32> = (0..tb.handlers_count).collect();
        try_regions.push(TryRegion {
            try_begin_va: exc.begin,
            try_end_va: exc.end,
            try_state_low: Some(tb.try_low),
            try_state_high: Some(tb.try_high),
            call_site_index: None,
            catch_handler_indices: handler_indices,
        });

        let handlers = parse_handler_array(pe, tb).unwrap_or_default();
        for handler in handlers {
            let type_descriptor_va = pe_base(pe).wrapping_add(handler.type_descriptor_rva as u64);
            let catch_kind = if handler.type_descriptor_rva == 0 {
                CatchKind::Ellipsis
            } else {
                CatchKind::Typed {
                    type_name: resolver.lookup(type_descriptor_va),
                    type_descriptor_va,
                }
            };
            catch_handlers.push(CatchHandler {
                handler_va: pe_base(pe).wrapping_add(handler.handler_rva as u64),
                catch_kind,
                adjectives: handler.adjectives,
                frame_offset: Some(handler.frame_offset),
                continuation_va: None,
            });
        }
    }

    let mut evidence = Vec::with_capacity(2 + try_blocks.len());
    evidence.push(EvidenceRef::Section {
        name: ".pdata".into(),
        va: exc.begin,
    });
    evidence.push(EvidenceRef::RawAddr {
        va: pe_base(pe).wrapping_add(func_info_rva as u64),
    });
    for h in &catch_handlers {
        evidence.push(EvidenceRef::Instruction { va: h.handler_va });
    }

    Some(EhFunctionFact {
        schema: EH_SCHEMA,
        function_va: exc.begin,
        function_end_va: exc.end,
        abi: EhAbi::MsvcFH3,
        personality: personality.name.clone(),
        personality_va: personality.va,
        unwind_ranges: vec![UnwindRange {
            begin_va: exc.begin,
            end_va: exc.end,
        }],
        try_regions,
        catch_handlers,
        cleanup_actions: Vec::new(),
        claim: Claim::new((), ClaimSource::ExceptionHandling)
            .with_score(0.95)
            .with_evidence(evidence),
    })
}

fn parse_func_info(pe: &PEImage, rva: u32) -> Option<FuncInfo> {
    let off = pe.rva_to_file_offset(rva)?;
    let bytes = pe.bytes();
    if off + 28 > bytes.len() {
        return None;
    }
    Some(FuncInfo {
        magic: read_u32(bytes, off)?,
        max_state: read_u32(bytes, off + 4)? as i32,
        unwind_map_rva: read_u32(bytes, off + 8)?,
        try_blocks_count: read_u32(bytes, off + 12)?,
        try_block_map_rva: read_u32(bytes, off + 16)?,
        ip_map_count: read_u32(bytes, off + 20)?,
        ip_to_state_map_rva: read_u32(bytes, off + 24)?,
    })
}

fn parse_try_block_map(pe: &PEImage, info: &FuncInfo) -> Option<Vec<TryBlockMapEntry>> {
    if info.try_blocks_count == 0 || info.try_block_map_rva == 0 {
        return Some(Vec::new());
    }
    let off = pe.rva_to_file_offset(info.try_block_map_rva)?;
    let bytes = pe.bytes();
    let total = (info.try_blocks_count as usize).saturating_mul(20);
    if off + total > bytes.len() {
        return None;
    }
    let mut entries = Vec::with_capacity(info.try_blocks_count as usize);
    for i in 0..info.try_blocks_count as usize {
        let base = off + i * 20;
        entries.push(TryBlockMapEntry {
            try_low: read_u32(bytes, base)? as i32,
            try_high: read_u32(bytes, base + 4)? as i32,
            catch_high: read_u32(bytes, base + 8)? as i32,
            handlers_count: read_u32(bytes, base + 12)?,
            handler_array_rva: read_u32(bytes, base + 16)?,
        });
    }
    Some(entries)
}

fn parse_handler_array(pe: &PEImage, tb: &TryBlockMapEntry) -> Option<Vec<HandlerTypeEntry>> {
    if tb.handlers_count == 0 || tb.handler_array_rva == 0 {
        return Some(Vec::new());
    }
    let off = pe.rva_to_file_offset(tb.handler_array_rva)?;
    let bytes = pe.bytes();
    let total = (tb.handlers_count as usize).saturating_mul(20);
    if off + total > bytes.len() {
        return None;
    }
    let mut entries = Vec::with_capacity(tb.handlers_count as usize);
    for i in 0..tb.handlers_count as usize {
        let base = off + i * 20;
        entries.push(HandlerTypeEntry {
            adjectives: read_u32(bytes, base)?,
            type_descriptor_rva: read_u32(bytes, base + 4)?,
            catch_object_offset: read_u32(bytes, base + 8)? as i32,
            handler_rva: read_u32(bytes, base + 12)?,
            frame_offset: read_u32(bytes, base + 16)? as i32,
        });
    }
    Some(entries)
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
    fn read_u32_le() {
        let bytes = [0x20, 0x05, 0x93, 0x19];
        assert_eq!(read_u32(&bytes, 0), Some(0x19930520));
    }

    #[test]
    fn read_u32_out_of_bounds() {
        let bytes = [0x00, 0x01, 0x02];
        assert_eq!(read_u32(&bytes, 0), None);
    }

    #[test]
    fn fh3_magic_constants_match_msvc() {
        assert_eq!(FH3_MAGIC_BASE, 0x19930520);
        assert_eq!(FH3_MAGIC_UNWIND_HELP, 0x19930521);
        assert_eq!(FH3_MAGIC_ES_TYPES, 0x19930522);
    }
}
