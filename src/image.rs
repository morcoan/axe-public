use crate::pe::{ExceptionRecord, ExportRecord, ImportRecord, SectionRecord};
use std::error::Error;
use std::fmt;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Pe,
    Elf,
    MachO,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Format::Pe => write!(f, "pe"),
            Format::Elf => write!(f, "elf"),
            Format::MachO => write!(f, "macho"),
        }
    }
}

pub trait BinaryImage {
    fn format(&self) -> Format;
    fn bytes(&self) -> &[u8];
    fn base(&self) -> u64;
    fn entry_va(&self) -> u64;
    fn machine(&self) -> u16;
    fn sections(&self) -> &[SectionRecord];
    fn imports(&self) -> &[ImportRecord];
    fn exports(&self) -> &[ExportRecord];
    fn exceptions(&self) -> &[ExceptionRecord] {
        &[]
    }
    fn section_for_va(&self, va: u64) -> Option<&SectionRecord>;
    fn section_by_rva(&self, rva: u32) -> Option<&SectionRecord>;
    fn function_seeds(&self) -> Vec<u64>;
    fn overlay_range(&self) -> Option<std::ops::Range<usize>>;
    fn source_path(&self) -> &str;
    fn rva_to_file_offset(&self, _rva: u32) -> Option<usize> {
        None
    }
    fn as_pe(&self) -> Option<&crate::pe::PEImage> {
        None
    }
}

pub fn detect_format(bytes: &[u8]) -> Option<Format> {
    if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        return Some(Format::Pe);
    }
    if bytes.len() >= 4 && &bytes[..4] == b"\x7fELF" {
        return Some(Format::Elf);
    }
    if bytes.len() >= 4 {
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if matches!(
            magic,
            0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE | 0xBEBAFECA
        ) {
            return Some(Format::MachO);
        }
    }
    None
}

pub fn detect_format_at_path(path: &Path) -> Result<Format, Box<dyn Error>> {
    let mut head = [0u8; 8];
    use std::fs::File;
    use std::io::Read;
    let mut file = File::open(path)?;
    let read = file.read(&mut head)?;
    detect_format(&head[..read]).ok_or_else(|| {
        format!(
            "unsupported_or_unknown_format at {}: first bytes {:02X?}",
            path.display(),
            &head[..read.min(8)]
        )
        .into()
    })
}

pub const X86_MACHINE: u16 = 0x014c;
pub const X64_MACHINE: u16 = 0x8664;

pub fn is_supported_machine(machine: u16) -> bool {
    machine == X86_MACHINE || machine == X64_MACHINE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pe_magic() {
        assert_eq!(Some(Format::Pe), detect_format(b"MZ\x90\x00"));
    }

    #[test]
    fn detects_elf_magic() {
        assert_eq!(Some(Format::Elf), detect_format(b"\x7fELF\x02\x01"));
    }

    #[test]
    fn detects_macho_little_endian_64() {
        assert_eq!(
            Some(Format::MachO),
            detect_format(&[0xCF, 0xFA, 0xED, 0xFE])
        );
    }

    #[test]
    fn detects_macho_big_endian() {
        assert_eq!(
            Some(Format::MachO),
            detect_format(&[0xFE, 0xED, 0xFA, 0xCE])
        );
    }

    #[test]
    fn detects_macho_universal() {
        assert_eq!(
            Some(Format::MachO),
            detect_format(&[0xCA, 0xFE, 0xBA, 0xBE])
        );
    }

    #[test]
    fn rejects_unknown_magic() {
        assert_eq!(None, detect_format(b"\x00\x01\x02\x03"));
        assert_eq!(None, detect_format(b""));
    }
}

pub struct ParsedImage {
    pub format: Format,
    pub bytes: Vec<u8>,
    pub base: u64,
    pub entry_va: u64,
    pub machine: u16,
    pub sections: Vec<SectionRecord>,
    pub imports: Vec<ImportRecord>,
    pub exports: Vec<ExportRecord>,
    pub function_seeds: Vec<u64>,
    pub source_path: String,
}

impl BinaryImage for ParsedImage {
    fn format(&self) -> Format {
        self.format
    }
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn base(&self) -> u64 {
        self.base
    }
    fn entry_va(&self) -> u64 {
        self.entry_va
    }
    fn machine(&self) -> u16 {
        self.machine
    }
    fn sections(&self) -> &[SectionRecord] {
        &self.sections
    }
    fn imports(&self) -> &[ImportRecord] {
        &self.imports
    }
    fn exports(&self) -> &[ExportRecord] {
        &self.exports
    }
    fn section_for_va(&self, va: u64) -> Option<&SectionRecord> {
        self.sections.iter().find(|section| {
            let size = section
                .virtual_size
                .max(section.raw_size)
                .max(section.data_size as u32);
            section.va <= va && va < section.va + size as u64
        })
    }
    fn section_by_rva(&self, rva: u32) -> Option<&SectionRecord> {
        self.sections.iter().find(|section| section.rva == rva)
    }
    fn function_seeds(&self) -> Vec<u64> {
        self.function_seeds.clone()
    }
    fn overlay_range(&self) -> Option<std::ops::Range<usize>> {
        None
    }
    fn source_path(&self) -> &str {
        &self.source_path
    }
}
