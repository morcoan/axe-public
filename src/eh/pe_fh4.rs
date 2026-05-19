//! `__CxxFrameHandler4` (MSVC FH4) parser.
//!
//! FH4 replaces FH3's fixed-size table records with packed varint /
//! image-relative encodings, shrinking C++ EH metadata substantially
//! on x64. Microsoft's blog "Making C++ exception handling smaller
//! on x64" (Visual Studio 2019) is the primary public reference;
//! Wine's `dlls/msvcrt/cppexcept_x64.c` and LLVM's
//! `MicrosoftCXXABI.cpp` are the cross-validation sources for the
//! exact packed-table layout.
//!
//! **Step 7 scope (header-parsing fact):** the `FuncInfo4` header
//! byte is parsed and validated; if it looks plausible we emit an
//! `EhAbi::MsvcFH4` fact with the function's unwind range and
//! confidence 0.70. The packed try-block / unwind / IP-to-state
//! tables are NOT walked in this slice — that work needs careful
//! cross-validation against Wine/LLVM and lands as a follow-up. An
//! unrecognized header pattern degrades to a low-confidence
//! `EhAbi::Unknown` fact (per the plan's risk-mitigation strategy).

#![allow(dead_code)]

use crate::eh::fact::{EhAbi, EhFunctionFact, UnwindRange, EH_SCHEMA};
use crate::eh::pe_unwind::{Personality, UnwindInfo};
use crate::facts::{Claim, ClaimSource, EvidenceRef};
use crate::pe::{ExceptionRecord, PEImage};

/// Decoded FH4 `FuncInfo4` header byte. Bits per Microsoft's blog post.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FuncInfo4Header {
    pub is_catch_funclet: bool,
    pub has_unwind_map: bool,
    pub has_try_block_map: bool,
    pub has_es_types: bool,
    pub bbt_flags: u8,
}

impl FuncInfo4Header {
    pub fn parse(byte: u8) -> Self {
        Self {
            is_catch_funclet: (byte & 0x01) != 0,
            has_unwind_map: (byte & 0x02) != 0,
            has_try_block_map: (byte & 0x04) != 0,
            has_es_types: (byte & 0x08) != 0,
            bbt_flags: (byte >> 4) & 0x03,
        }
    }

    /// Returns true when at least one of the body-bearing tables is
    /// present. A pure catch funclet with no tables is unusual and
    /// suggests we may be reading the wrong byte.
    pub fn is_plausible(self) -> bool {
        self.has_unwind_map || self.has_try_block_map || self.is_catch_funclet
    }
}

pub fn parse_fh4(
    pe: &PEImage,
    exc: &ExceptionRecord,
    unwind: &UnwindInfo,
    personality: &Personality,
) -> Option<EhFunctionFact> {
    let lang_offset = unwind.language_specific_data_offset?;
    let bytes = pe.bytes();
    if lang_offset >= bytes.len() {
        return None;
    }
    // FH4 language-specific data is an image-relative pointer to FuncInfo4.
    if lang_offset + 4 > bytes.len() {
        return None;
    }
    let func_info_rva = u32::from_le_bytes(bytes[lang_offset..lang_offset + 4].try_into().ok()?);
    let func_info_off = pe.rva_to_file_offset(func_info_rva)?;
    if func_info_off >= bytes.len() {
        return None;
    }
    let header = FuncInfo4Header::parse(bytes[func_info_off]);

    // Reserved bits (6 and 7) should be zero in current toolchains.
    // If set, the byte is probably not actually FH4 FuncInfo (could be
    // an alignment artifact or a misread). Degrade to Unknown.
    if (bytes[func_info_off] & 0xC0) != 0 || !header.is_plausible() {
        return Some(degraded_fact(exc, personality));
    }

    let evidence = vec![
        EvidenceRef::Section {
            name: ".pdata".into(),
            va: exc.begin,
        },
        EvidenceRef::RawAddr {
            va: pe_base(pe).wrapping_add(func_info_rva as u64),
        },
    ];

    Some(EhFunctionFact {
        schema: EH_SCHEMA,
        function_va: exc.begin,
        function_end_va: exc.end,
        abi: EhAbi::MsvcFH4,
        personality: personality.name.clone(),
        personality_va: personality.va,
        unwind_ranges: vec![UnwindRange {
            begin_va: exc.begin,
            end_va: exc.end,
        }],
        try_regions: Vec::new(),
        catch_handlers: Vec::new(),
        cleanup_actions: Vec::new(),
        claim: Claim::new((), ClaimSource::ExceptionHandling)
            .with_score(0.70)
            .with_evidence(evidence),
    })
}

fn degraded_fact(exc: &ExceptionRecord, personality: &Personality) -> EhFunctionFact {
    EhFunctionFact {
        schema: EH_SCHEMA,
        function_va: exc.begin,
        function_end_va: exc.end,
        abi: EhAbi::Unknown,
        personality: personality.name.clone(),
        personality_va: personality.va,
        unwind_ranges: vec![UnwindRange {
            begin_va: exc.begin,
            end_va: exc.end,
        }],
        try_regions: Vec::new(),
        catch_handlers: Vec::new(),
        cleanup_actions: Vec::new(),
        claim: Claim::new((), ClaimSource::ExceptionHandling)
            .with_score(0.40)
            .with_evidence(vec![EvidenceRef::Section {
                name: ".pdata".into(),
                va: exc.begin,
            }]),
    }
}

fn pe_base(pe: &PEImage) -> u64 {
    use crate::image::BinaryImage;
    pe.base()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_decodes_all_bits() {
        let h = FuncInfo4Header::parse(0b0011_1111);
        assert!(h.is_catch_funclet);
        assert!(h.has_unwind_map);
        assert!(h.has_try_block_map);
        assert!(h.has_es_types);
        assert_eq!(h.bbt_flags, 0b11);
    }

    #[test]
    fn header_empty_is_implausible() {
        let h = FuncInfo4Header::parse(0);
        assert!(!h.is_plausible());
    }

    #[test]
    fn header_with_try_map_only_is_plausible() {
        let h = FuncInfo4Header::parse(0b0000_0100);
        assert!(h.is_plausible());
        assert!(h.has_try_block_map);
        assert!(!h.has_unwind_map);
    }
}
