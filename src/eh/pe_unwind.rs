//! Shared UNWIND_INFO decoder used by FH3 / FH4 / SEH parsers.
//!
//! Reads the per-function `UNWIND_INFO` block referenced by an
//! `ExceptionRecord`, extracts the handler RVA (when `UNW_FLAG_EHANDLER`
//! or `UNW_FLAG_UHANDLER` is set), and returns the file offset of the
//! language-specific data block (which the handler-specific parser then
//! consumes as a `FuncInfo`, `FuncInfo4`, or `ScopeTable`).
//!
//! Microsoft's x64 unwind format reference:
//! <https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64>.

#![allow(dead_code)]

use crate::pe::{ExceptionRecord, ImportRecord, PEImage};

pub const UNW_FLAG_NHANDLER: u8 = 0x0;
pub const UNW_FLAG_EHANDLER: u8 = 0x1;
pub const UNW_FLAG_UHANDLER: u8 = 0x2;
pub const UNW_FLAG_CHAININFO: u8 = 0x4;

/// Decoded `UNWIND_INFO` header. `handler_rva` and
/// `language_specific_data_offset` are populated only when the
/// `EHANDLER` or `UHANDLER` flag is set.
#[derive(Clone, Debug)]
pub struct UnwindInfo {
    pub version: u8,
    pub flags: u8,
    pub prolog_size: u8,
    pub code_count: u8,
    pub frame_register: u8,
    /// Total bytes consumed by the unwind-code array
    /// (= `code_count * 2` rounded up to a 4-byte alignment).
    pub unwind_codes_bytes: usize,
    /// RVA of the personality routine when EHANDLER/UHANDLER is set.
    pub handler_rva: Option<u32>,
    /// File-offset of the language-specific data block (immediately
    /// after `handler_rva`). Consumed by FH3/FH4/SEH parsers.
    pub language_specific_data_offset: Option<usize>,
}

impl UnwindInfo {
    pub fn has_exception_handler(&self) -> bool {
        (self.flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) != 0
    }

    pub fn is_chained(&self) -> bool {
        (self.flags & UNW_FLAG_CHAININFO) != 0
    }
}

pub fn parse_unwind_info(pe: &PEImage, exc: &ExceptionRecord) -> Option<UnwindInfo> {
    let file_offset = pe.rva_to_file_offset(exc.unwind_rva)?;
    let bytes = pe.bytes();
    if file_offset + 4 > bytes.len() {
        return None;
    }
    let b = &bytes[file_offset..];
    let version_flags = b[0];
    let version = version_flags & 0x07;
    let flags = (version_flags >> 3) & 0x1F;
    let prolog_size = b[1];
    let code_count = b[2];
    let frame_register = b[3];

    // Unwind codes are `code_count` u16 slots, padded to 4-byte alignment.
    let codes_bytes = (((code_count as usize) * 2) + 3) & !3;
    let after_codes = 4 + codes_bytes;

    let mut handler_rva = None;
    let mut lang_specific = None;
    if (flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER)) != 0 {
        if file_offset + after_codes + 4 > bytes.len() {
            return None;
        }
        let rva = u32::from_le_bytes(
            bytes[file_offset + after_codes..file_offset + after_codes + 4]
                .try_into()
                .ok()?,
        );
        handler_rva = Some(rva);
        lang_specific = Some(file_offset + after_codes + 4);
    }

    Some(UnwindInfo {
        version,
        flags,
        prolog_size,
        code_count,
        frame_register,
        unwind_codes_bytes: codes_bytes,
        handler_rva,
        language_specific_data_offset: lang_specific,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersonalityKind {
    CxxFrameHandler3,
    CxxFrameHandler4,
    CSpecificHandler,
    GSHandlerCheckEH,
    GxxPersonalityV0,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Personality {
    pub kind: PersonalityKind,
    pub name: Option<String>,
    pub va: Option<u64>,
}

/// Resolve the personality routine by matching the handler RVA against
/// the import table (PE handler is loaded from IAT). Falls back to
/// `Unknown` when the RVA points to a non-imported symbol.
pub fn resolve_personality(unwind: &UnwindInfo, imports: &[ImportRecord]) -> Personality {
    let Some(rva) = unwind.handler_rva else {
        return Personality {
            kind: PersonalityKind::Unknown,
            name: None,
            va: None,
        };
    };
    let imp = imports.iter().find(|i| i.rva == rva as u64);
    let name = imp.map(|i| i.name.clone());
    let kind = match name.as_deref() {
        Some("__CxxFrameHandler3") => PersonalityKind::CxxFrameHandler3,
        Some("__CxxFrameHandler4") => PersonalityKind::CxxFrameHandler4,
        Some("__C_specific_handler") => PersonalityKind::CSpecificHandler,
        Some("__GSHandlerCheck_EH") | Some("__GSHandlerCheck_SEH") => {
            PersonalityKind::GSHandlerCheckEH
        }
        Some("__gxx_personality_v0") | Some("__gxx_personality_v15") => {
            PersonalityKind::GxxPersonalityV0
        }
        _ => PersonalityKind::Unknown,
    };
    Personality {
        kind,
        name,
        va: Some(rva as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_helpers_match_msvc_constants() {
        let info = UnwindInfo {
            version: 1,
            flags: UNW_FLAG_EHANDLER,
            prolog_size: 0,
            code_count: 0,
            frame_register: 0,
            unwind_codes_bytes: 0,
            handler_rva: Some(0x1000),
            language_specific_data_offset: Some(0x100),
        };
        assert!(info.has_exception_handler());
        assert!(!info.is_chained());

        let chained = UnwindInfo {
            flags: UNW_FLAG_CHAININFO,
            ..info.clone()
        };
        assert!(chained.is_chained());
    }
}
