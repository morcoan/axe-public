use crate::image::{Format, ParsedImage};
use crate::pe::{ExportRecord, ImportRecord, SectionRecord};
use crate::strings;
use object::{Architecture, Object, ObjectSection, ObjectSymbol};
use std::error::Error;
use std::fs;

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in data {
        counts[*byte as usize] += 1;
    }
    let total = data.len() as f64;
    let entropy = counts
        .iter()
        .filter(|count| **count != 0)
        .map(|count| {
            let p = *count as f64 / total;
            -p * p.log2()
        })
        .sum::<f64>();
    (entropy * 10000.0).round() / 10000.0
}

pub fn parse_macho(path: &str) -> Result<ParsedImage, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let obj = object::read::File::parse(&bytes[..])?;
    if !matches!(
        obj.architecture(),
        Architecture::X86_64 | Architecture::I386
    ) {
        return Err(format!(
            "unsupported_arch: Mach-O architecture {:?} (only x86/x64 supported)",
            obj.architecture()
        )
        .into());
    }
    let machine = match obj.architecture() {
        Architecture::X86_64 => 0x8664,
        Architecture::I386 => 0x014c,
        _ => 0,
    };
    let base = obj
        .sections()
        .map(|s| s.address())
        .filter(|addr| *addr != 0)
        .min()
        .unwrap_or(0);
    let entry_va = obj.entry();

    let sections = collect_sections(&obj, &bytes, base);
    let imports = collect_imports(&obj);
    let exports = collect_exports(&obj);
    let mut function_seeds = vec![entry_va];
    function_seeds.extend(exports.iter().map(|e| e.va));
    function_seeds.sort();
    function_seeds.dedup();

    Ok(ParsedImage {
        format: Format::MachO,
        bytes,
        base,
        entry_va,
        machine,
        sections,
        imports,
        exports,
        function_seeds,
        source_path: path.to_string(),
    })
}

fn collect_sections(obj: &object::read::File<'_>, bytes: &[u8], base: u64) -> Vec<SectionRecord> {
    let mut rows = Vec::new();
    for section in obj.sections() {
        let name = section.name().unwrap_or("").to_string();
        let va = section.address();
        let virtual_size = section.size() as u32;
        let file_range = section.file_range();
        let (raw_start, raw_size) = file_range
            .map(|(off, sz)| (off as u32, sz as u32))
            .unwrap_or((0, 0));
        let data_size = raw_size as usize;
        let data_range = if data_size > 0 {
            let start = raw_start as usize;
            let end = (start + data_size).min(bytes.len());
            start..end
        } else {
            0..0
        };
        let data_slice = bytes.get(data_range.clone()).unwrap_or(&[]);
        let entropy = shannon_entropy(data_slice);
        let kind = section.kind();
        let executable = matches!(kind, object::SectionKind::Text);
        let writable = matches!(
            kind,
            object::SectionKind::Data
                | object::SectionKind::UninitializedData
                | object::SectionKind::Tls
                | object::SectionKind::TlsVariables
        );
        let readable = !matches!(kind, object::SectionKind::Unknown);
        let rva = va.saturating_sub(base) as u32;
        rows.push(SectionRecord {
            name,
            rva,
            va,
            virtual_size,
            raw_start,
            raw_size,
            data_size,
            executable,
            readable,
            writable,
            entropy,
            data_range,
        });
    }
    rows
}

fn collect_imports(obj: &object::read::File<'_>) -> Vec<ImportRecord> {
    let mut rows = Vec::new();
    let imports = match obj.imports() {
        Ok(list) => list,
        Err(_) => return rows,
    };
    for import in imports {
        let dll = String::from_utf8_lossy(import.library()).to_string();
        let name = String::from_utf8_lossy(import.name()).to_string();
        let symbol = if dll.is_empty() {
            name.clone()
        } else {
            format!("{}!{}", dll, name)
        };
        rows.push(ImportRecord {
            dll: dll.clone(),
            name,
            symbol: symbol.clone(),
            va: 0,
            rva: 0,
            hint: None,
            categories: strings::import_categories(&symbol),
        });
    }
    rows
}

fn collect_exports(obj: &object::read::File<'_>) -> Vec<ExportRecord> {
    let mut rows = Vec::new();
    for symbol in obj.exports().unwrap_or_default() {
        let name = String::from_utf8_lossy(symbol.name()).to_string();
        rows.push(ExportRecord {
            name,
            ordinal: 0,
            va: symbol.address(),
            rva: symbol.address() as u32,
        });
    }
    for symbol in obj.symbols() {
        if !symbol.is_definition() {
            continue;
        }
        if !matches!(
            symbol.kind(),
            object::SymbolKind::Text | object::SymbolKind::Data
        ) {
            continue;
        }
        let name = symbol.name().unwrap_or("").to_string();
        if name.is_empty() || rows.iter().any(|r| r.name == name) {
            continue;
        }
        let va = symbol.address();
        rows.push(ExportRecord {
            name,
            ordinal: 0,
            va,
            rva: va as u32,
        });
    }
    rows
}
