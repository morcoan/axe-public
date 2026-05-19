use crate::image::{BinaryImage, Format};
use crate::pe::FunctionRecord;
use crate::portable::safe_file_component;
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use pdb::FallibleIterator;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};

const SCHEMA_VERSION: &str = "debug_symbols/1";
const CODEVIEW_RSDS: &[u8; 4] = b"RSDS";
const ELF_NOTE_GNU_BUILD_ID: u32 = 3;

#[derive(Clone, Debug, Serialize)]
pub struct DebugModuleRecord {
    pub module_id: String,
    pub source_path: String,
    pub format: String,
    pub machine: u16,
    pub image_base: u64,
    pub entry_rva: u64,
    pub address_size: u8,
    pub section_count: usize,
    pub symbol_mode: String,
    pub cache_key: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DebugIdentityRecord {
    pub identity_id: String,
    pub module_id: String,
    pub provider: String,
    pub identity_kind: String,
    pub path_hint: Option<String>,
    pub build_id: Option<String>,
    pub guid: Option<String>,
    pub age: Option<u32>,
    pub debuglink: Option<String>,
    pub uuid: Option<String>,
    pub found_path: Option<String>,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DebugSymbolRecord {
    pub symbol_id: String,
    pub module_id: String,
    pub provider: String,
    pub name: String,
    pub linkage_name: Option<String>,
    pub kind: String,
    pub start_rva: u64,
    pub end_rva: u64,
    pub function: bool,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceFileRecord {
    pub file_id: String,
    pub module_id: String,
    pub provider: String,
    pub path: String,
    pub checksum: Option<String>,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LineEntryRecord {
    pub line_id: String,
    pub module_id: String,
    pub provider: String,
    pub start_rva: u64,
    pub end_rva: u64,
    pub file_id: String,
    pub line: u64,
    pub column: Option<u64>,
    pub flags: Vec<String>,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InlineScopeRecord {
    pub scope_id: String,
    pub module_id: String,
    pub provider: String,
    pub function_ref: Option<String>,
    pub start_rva: u64,
    pub end_rva: u64,
    pub call_file_id: Option<String>,
    pub call_line: Option<u64>,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DebugTypeRecord {
    pub type_id: String,
    pub module_id: String,
    pub provider: String,
    pub namespace: String,
    pub raw_key: String,
    pub kind: String,
    pub name: Option<String>,
    pub size: Option<u64>,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SymbolUncertaintyRecord {
    pub uncertainty_id: String,
    pub module_id: String,
    pub provider: String,
    pub code: String,
    pub message: String,
    pub recommended_action: String,
    pub severity: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct DebugSymbolOutput {
    pub modules: Vec<DebugModuleRecord>,
    pub identities: Vec<DebugIdentityRecord>,
    pub symbols: Vec<DebugSymbolRecord>,
    pub source_files: Vec<SourceFileRecord>,
    pub line_entries: Vec<LineEntryRecord>,
    pub inline_scopes: Vec<InlineScopeRecord>,
    pub debug_types: Vec<DebugTypeRecord>,
    pub uncertainties: Vec<SymbolUncertaintyRecord>,
}

#[derive(Clone, Copy)]
pub struct DebugSymbolInput<'a> {
    pub image: &'a dyn BinaryImage,
    pub functions: &'a [FunctionRecord],
    pub mode: &'a str,
    pub symbol_paths: &'a [String],
    pub symbol_cache: Option<&'a str>,
}

trait DebugSymbolProvider {
    fn name(&self) -> &'static str;
    fn collect(&self, input: DebugSymbolInput<'_>, module_id: &str, output: &mut DebugSymbolOutput);
}

trait PdbDebugSymbolProvider {
    fn name(&self) -> &'static str;
    fn collect_pdb(&self, module_id: &str, path: &Path, output: &mut DebugSymbolOutput);
}

struct ObjectSymbolsProvider {
    provider: &'static str,
}

struct DwarfGimliProvider;

struct PdbBasicProvider;

struct PdbDeepMsProvider;

impl DebugSymbolProvider for ObjectSymbolsProvider {
    fn name(&self) -> &'static str {
        self.provider
    }

    fn collect(
        &self,
        input: DebugSymbolInput<'_>,
        module_id: &str,
        output: &mut DebugSymbolOutput,
    ) {
        collect_object_symbols(input, module_id, self.name(), output);
    }
}

impl DebugSymbolProvider for DwarfGimliProvider {
    fn name(&self) -> &'static str {
        "dwarf"
    }

    fn collect(
        &self,
        input: DebugSymbolInput<'_>,
        module_id: &str,
        output: &mut DebugSymbolOutput,
    ) {
        match collect_dwarf_provider(input.image, module_id, output) {
            Ok((unit_count, _line_count)) if unit_count > 0 => {
                if let Err(message) = collect_addr2line_inline_frames(input.image, module_id, output)
                {
                    output.uncertainties.push(uncertainty(
                        module_id,
                        "addr2line",
                        "PARTIAL_RESULT",
                        &format!("addr2line inline-frame lookup was unavailable: {message}"),
                        "Use direct DWARF line/function records; inline enrichment is best-effort.",
                        "low",
                        Vec::new(),
                    ));
                }
            }
            Ok(_) => output.uncertainties.push(uncertainty(
                module_id,
                self.name(),
                "SYMBOL_NOT_FOUND",
                "No DWARF compilation units were available in the image.",
                "Use a binary built with debug info, or provide a local split debug file when locator support can resolve it.",
                "low",
                Vec::new(),
            )),
            Err(message) => output.uncertainties.push(uncertainty(
                module_id,
                self.name(),
                "PARSE_ERROR",
                &format!("DWARF provider could not parse debug sections: {message}"),
                "Verify the debug sections are not corrupt and rerun with a matching unstripped image.",
                "medium",
                Vec::new(),
            )),
        }
    }
}

impl PdbDebugSymbolProvider for PdbBasicProvider {
    fn name(&self) -> &'static str {
        "pdb"
    }

    fn collect_pdb(&self, module_id: &str, path: &Path, output: &mut DebugSymbolOutput) {
        collect_pdb_provider(module_id, path, output);
    }
}

impl PdbDebugSymbolProvider for PdbDeepMsProvider {
    fn name(&self) -> &'static str {
        "ms-pdb"
    }

    fn collect_pdb(&self, module_id: &str, path: &Path, output: &mut DebugSymbolOutput) {
        collect_ms_pdb_provider(module_id, path, output);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdbIdentity {
    pub guid: String,
    pub age: u32,
    pub path: String,
    pub evidence_offset: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeIndexEntry {
    pub id: String,
    pub start: u64,
    pub end: u64,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct RangeIndex {
    entries: Vec<RangeIndexEntry>,
}

#[allow(dead_code)]
impl RangeIndex {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn insert(&mut self, id: impl Into<String>, start: u64, end: u64) {
        if start >= end {
            return;
        }
        self.entries.push(RangeIndexEntry {
            id: id.into(),
            start,
            end,
        });
        self.entries.sort_by_key(|row| (row.start, row.end));
    }

    pub fn lookup(&self, address: u64) -> Option<&RangeIndexEntry> {
        self.entries
            .iter()
            .filter(|row| row.start <= address && address < row.end)
            .min_by_key(|row| (row.end - row.start, std::cmp::Reverse(row.start)))
    }
}

pub fn build_debug_symbols(input: DebugSymbolInput<'_>) -> DebugSymbolOutput {
    let module_id = "module:main".to_string();
    let mut output = DebugSymbolOutput::default();

    if input.mode == "off" {
        return output;
    }

    output.modules.push(DebugModuleRecord {
        module_id: module_id.clone(),
        source_path: input.image.source_path().to_string(),
        format: input.image.format().to_string(),
        machine: input.image.machine(),
        image_base: input.image.base(),
        entry_rva: va_to_rva(input.image, input.image.entry_va()),
        address_size: address_size(input.image.machine()),
        section_count: input.image.sections().len(),
        symbol_mode: input.mode.to_string(),
        cache_key: cache_key(input),
    });

    match input.image.format() {
        Format::Pe => collect_pe_symbols(input, &module_id, &mut output),
        Format::Elf => collect_elf_symbols(input, &module_id, &mut output),
        Format::MachO => collect_macho_symbols(input, &module_id, &mut output),
    }

    add_function_fallback_symbols(input, &module_id, &mut output);
    dedup_symbols(&mut output.symbols);
    output
}

pub fn parse_rsds_records(bytes: &[u8]) -> Vec<PdbIdentity> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = bytes[cursor..]
        .windows(CODEVIEW_RSDS.len())
        .position(|window| window == CODEVIEW_RSDS)
    {
        let offset = cursor + relative;
        let record_start = offset + CODEVIEW_RSDS.len();
        if record_start + 20 > bytes.len() {
            break;
        }
        let guid_bytes = &bytes[record_start..record_start + 16];
        let age = u32::from_le_bytes([
            bytes[record_start + 16],
            bytes[record_start + 17],
            bytes[record_start + 18],
            bytes[record_start + 19],
        ]);
        let path_start = record_start + 20;
        let path_end = bytes[path_start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|index| path_start + index)
            .unwrap_or(bytes.len());
        let path = String::from_utf8_lossy(&bytes[path_start..path_end])
            .trim_matches(char::from(0))
            .to_string();
        if !path.is_empty() {
            out.push(PdbIdentity {
                guid: format_guid(guid_bytes),
                age,
                path,
                evidence_offset: offset as u64,
            });
        }
        cursor = path_end.saturating_add(1).max(offset + CODEVIEW_RSDS.len());
        if cursor >= bytes.len() {
            break;
        }
    }
    out
}

fn collect_pe_symbols(
    input: DebugSymbolInput<'_>,
    module_id: &str,
    output: &mut DebugSymbolOutput,
) {
    let identities = parse_rsds_records(input.image.bytes());
    if identities.is_empty() {
        output.uncertainties.push(uncertainty(
            module_id,
            "pdb",
            "SYMBOL_NOT_FOUND",
            "No CodeView RSDS PDB identity was found in the PE image.",
            "Build or locate the matching PDB locally and pass its directory with --symbol-path.",
            "medium",
            Vec::new(),
        ));
    }

    for (index, pdb_identity) in identities.into_iter().enumerate() {
        let found_path = locate_debug_file(&pdb_identity.path, input);
        output.identities.push(DebugIdentityRecord {
            identity_id: format!("debug_identity:pdb:{index:04X}"),
            module_id: module_id.to_string(),
            provider: "pdb".to_string(),
            identity_kind: "pdb_rsds".to_string(),
            path_hint: Some(pdb_identity.path.clone()),
            build_id: None,
            guid: Some(pdb_identity.guid.clone()),
            age: Some(pdb_identity.age),
            debuglink: None,
            uuid: None,
            found_path: found_path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string()),
            confidence: "high".to_string(),
            evidence: vec![pdb_identity.evidence_offset],
        });

        match found_path {
            Some(path) => {
                PdbBasicProvider.collect_pdb(module_id, &path, output);
                PdbDeepMsProvider.collect_pdb(module_id, &path, output);
            }
            None => output.uncertainties.push(uncertainty(
                module_id,
                "pdb",
                "SYMBOL_NOT_FOUND",
                &format!(
                    "PDB identity {} age {} was present but no local PDB file was found.",
                    pdb_identity.guid, pdb_identity.age
                ),
                "Add the PDB directory with --symbol-path or place the PDB next to the input binary.",
                "medium",
                vec![pdb_identity.evidence_offset],
            )),
        }
    }

    ObjectSymbolsProvider { provider: "object" }.collect(input, module_id, output);
}

fn collect_elf_symbols(
    input: DebugSymbolInput<'_>,
    module_id: &str,
    output: &mut DebugSymbolOutput,
) {
    collect_elf_identities(input.image, module_id, output);
    ObjectSymbolsProvider { provider: "object" }.collect(input, module_id, output);
    DwarfGimliProvider.collect(input, module_id, output);
}

fn collect_macho_symbols(
    input: DebugSymbolInput<'_>,
    module_id: &str,
    output: &mut DebugSymbolOutput,
) {
    output.identities.push(DebugIdentityRecord {
        identity_id: "debug_identity:macho:locator_metadata".to_string(),
        module_id: module_id.to_string(),
        provider: "dwarf".to_string(),
        identity_kind: "macho_dsym_locator_pending".to_string(),
        path_hint: None,
        build_id: None,
        guid: None,
        age: None,
        debuglink: None,
        uuid: None,
        found_path: None,
        confidence: "low".to_string(),
        evidence: Vec::new(),
    });
    output.uncertainties.push(uncertainty(
        module_id,
        "dwarf",
        "INDEX_NOT_READY",
        "Mach-O UUID/dSYM locator metadata is recorded, but full dSYM lookup is not implemented in this slice.",
        "Place DWARF-bearing Mach-O content directly in the analyzed file until dSYM discovery is expanded.",
        "low",
        Vec::new(),
    ));
    ObjectSymbolsProvider { provider: "object" }.collect(input, module_id, output);
}

fn collect_object_symbols(
    input: DebugSymbolInput<'_>,
    module_id: &str,
    provider: &str,
    output: &mut DebugSymbolOutput,
) {
    let Ok(object) = object::read::File::parse(input.image.bytes()) else {
        output.uncertainties.push(uncertainty(
            module_id,
            provider,
            "UNSUPPORTED_FORMAT",
            "object parser could not expose symbols for this image.",
            "Rely on function recovery records or provide native debug symbols.",
            "low",
            Vec::new(),
        ));
        return;
    };

    for symbol in object.symbols().chain(object.dynamic_symbols()) {
        if !symbol.is_definition() {
            continue;
        }
        let kind = symbol.kind();
        if !matches!(
            kind,
            SymbolKind::Text | SymbolKind::Data | SymbolKind::Unknown
        ) {
            continue;
        }
        let Ok(name) = symbol.name() else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let start_rva = va_to_rva(input.image, symbol.address());
        let size = symbol.size().max(1);
        let end_rva = start_rva.saturating_add(size);
        let symbol_id = format!(
            "symbol:{provider}:{start_rva:016X}:{}",
            safe_file_component(name)
        );
        output.symbols.push(DebugSymbolRecord {
            symbol_id,
            module_id: module_id.to_string(),
            provider: provider.to_string(),
            name: name.to_string(),
            linkage_name: Some(name.to_string()),
            kind: symbol_kind_label(kind).to_string(),
            start_rva,
            end_rva,
            function: matches!(kind, SymbolKind::Text),
            confidence: "medium".to_string(),
            evidence: vec![symbol.address()],
        });
    }
}

fn collect_elf_identities(
    image: &dyn BinaryImage,
    module_id: &str,
    output: &mut DebugSymbolOutput,
) {
    let Ok(object) = object::read::File::parse(image.bytes()) else {
        return;
    };
    let mut identity_index = 0usize;
    for section in object.sections() {
        let name = section.name().unwrap_or("");
        if name == ".note.gnu.build-id" {
            if let Ok(data) = section.data() {
                if let Some(build_id) = parse_gnu_build_id(data, object.is_little_endian()) {
                    output.identities.push(DebugIdentityRecord {
                        identity_id: format!("debug_identity:dwarf:{identity_index:04X}"),
                        module_id: module_id.to_string(),
                        provider: "dwarf".to_string(),
                        identity_kind: "elf_build_id".to_string(),
                        path_hint: None,
                        build_id: Some(build_id),
                        guid: None,
                        age: None,
                        debuglink: None,
                        uuid: None,
                        found_path: None,
                        confidence: "high".to_string(),
                        evidence: vec![section.address()],
                    });
                    identity_index += 1;
                }
            }
        } else if name == ".gnu_debuglink" {
            if let Ok(data) = section.data() {
                if let Some(debuglink) = parse_debuglink(data) {
                    output.identities.push(DebugIdentityRecord {
                        identity_id: format!("debug_identity:dwarf:{identity_index:04X}"),
                        module_id: module_id.to_string(),
                        provider: "dwarf".to_string(),
                        identity_kind: "elf_gnu_debuglink".to_string(),
                        path_hint: Some(debuglink.clone()),
                        build_id: None,
                        guid: None,
                        age: None,
                        debuglink: Some(debuglink),
                        uuid: None,
                        found_path: None,
                        confidence: "high".to_string(),
                        evidence: vec![section.address()],
                    });
                    identity_index += 1;
                }
            }
        } else if name.starts_with(".debug_") {
            let already_has_dwarf = output
                .identities
                .iter()
                .any(|row| row.identity_kind == "embedded_dwarf");
            if !already_has_dwarf {
                output.identities.push(DebugIdentityRecord {
                    identity_id: format!("debug_identity:dwarf:{identity_index:04X}"),
                    module_id: module_id.to_string(),
                    provider: "dwarf".to_string(),
                    identity_kind: "embedded_dwarf".to_string(),
                    path_hint: None,
                    build_id: None,
                    guid: None,
                    age: None,
                    debuglink: None,
                    uuid: None,
                    found_path: Some(image.source_path().to_string()),
                    confidence: "medium".to_string(),
                    evidence: vec![section.address()],
                });
                identity_index += 1;
            }
        }
    }
}

fn collect_pdb_provider(module_id: &str, path: &Path, output: &mut DebugSymbolOutput) {
    let result = (|| -> pdb::Result<(usize, usize)> {
        let file = File::open(path)?;
        let mut pdb = pdb::PDB::open(file)?;
        let address_map = pdb.address_map()?;
        let mut symbol_count = 0usize;
        let mut line_count = 0usize;
        let mut source_files = BTreeMap::<String, String>::new();

        let symbol_table = pdb.global_symbols()?;
        let mut symbols = symbol_table.iter();
        while let Some(symbol) = symbols.next()? {
            if let Ok(pdb::SymbolData::Public(data)) = symbol.parse() {
                let Some(rva) = data.offset.to_rva(&address_map) else {
                    continue;
                };
                let name = data.name.to_string().into_owned();
                let start_rva = rva.0 as u64;
                output.symbols.push(DebugSymbolRecord {
                    symbol_id: format!(
                        "symbol:pdb_public:{start_rva:016X}:{}",
                        safe_file_component(&name)
                    ),
                    module_id: module_id.to_string(),
                    provider: "pdb".to_string(),
                    name: name.clone(),
                    linkage_name: Some(name),
                    kind: if data.function || data.code {
                        "function"
                    } else {
                        "public"
                    }
                    .to_string(),
                    start_rva,
                    end_rva: start_rva.saturating_add(1),
                    function: data.function || data.code,
                    confidence: "high".to_string(),
                    evidence: vec![start_rva],
                });
                symbol_count += 1;
            }
        }

        let string_table = pdb.string_table()?;
        let dbi = pdb.debug_information()?;
        let mut modules = dbi.modules()?;
        while let Some(module) = modules.next()? {
            let Some(info) = pdb.module_info(&module)? else {
                continue;
            };
            let line_program = info.line_program().ok();
            let mut module_symbols = info.symbols()?;
            while let Some(symbol) = module_symbols.next()? {
                let Ok(pdb::SymbolData::Procedure(procedure)) = symbol.parse() else {
                    continue;
                };
                let Some(rva) = procedure.offset.to_rva(&address_map) else {
                    continue;
                };
                let name = procedure.name.to_string().into_owned();
                let start_rva = rva.0 as u64;
                let end_rva = start_rva.saturating_add(procedure.len.max(1) as u64);
                output.symbols.push(DebugSymbolRecord {
                    symbol_id: format!(
                        "symbol:pdb_proc:{start_rva:016X}:{}",
                        safe_file_component(&name)
                    ),
                    module_id: module_id.to_string(),
                    provider: "pdb".to_string(),
                    name: name.clone(),
                    linkage_name: Some(name),
                    kind: "function".to_string(),
                    start_rva,
                    end_rva,
                    function: true,
                    confidence: "high".to_string(),
                    evidence: vec![start_rva],
                });
                symbol_count += 1;

                let Some(program) = &line_program else {
                    continue;
                };
                let mut lines = program.lines_for_symbol(procedure.offset);
                while let Some(line_info) = lines.next()? {
                    let Some(line_rva) = line_info.offset.to_rva(&address_map) else {
                        continue;
                    };
                    let file_info = program.get_file_info(line_info.file_index)?;
                    let file_name = file_info.name.to_string_lossy(&string_table)?;
                    let file_path = file_name.to_string();
                    let file_id = if let Some(existing) = source_files.get(&file_path) {
                        existing.clone()
                    } else {
                        let next_id = format!(
                            "source_file:pdb:{:04X}:{}",
                            source_files.len(),
                            safe_file_component(&file_path)
                        );
                        source_files.insert(file_path.clone(), next_id.clone());
                        output.source_files.push(SourceFileRecord {
                            file_id: next_id.clone(),
                            module_id: module_id.to_string(),
                            provider: "pdb".to_string(),
                            path: file_path.clone(),
                            checksum: None,
                            confidence: "high".to_string(),
                            evidence: vec![line_rva.0 as u64],
                        });
                        next_id
                    };
                    let start_rva = line_rva.0 as u64;
                    output.line_entries.push(LineEntryRecord {
                        line_id: format!("line:pdb:{start_rva:016X}:{line_count:04X}"),
                        module_id: module_id.to_string(),
                        provider: "pdb".to_string(),
                        start_rva,
                        end_rva: start_rva.saturating_add(1),
                        file_id,
                        line: line_info.line_start as u64,
                        column: None,
                        flags: Vec::new(),
                        confidence: "high".to_string(),
                        evidence: vec![start_rva],
                    });
                    line_count += 1;
                }
            }
        }

        Ok((symbol_count, line_count))
    })();

    match result {
        Ok((symbols, lines)) if symbols > 0 || lines > 0 => {}
        Ok(_) => output.uncertainties.push(uncertainty(
            module_id,
            "pdb",
            "PARTIAL_RESULT",
            "The matching PDB opened successfully, but no public/procedure/line records were extracted.",
            "Check whether the PDB contains public symbols or module streams with C13 line records.",
            "low",
            Vec::new(),
        )),
        Err(err) => output.uncertainties.push(uncertainty(
            module_id,
            "pdb",
            "PARSE_ERROR",
            &format!("PDB file was found but could not be opened by the Rust pdb crate: {err}"),
            "Check that the PDB matches the image identity and is not corrupt.",
            "medium",
            Vec::new(),
        )),
    }
}

fn collect_ms_pdb_provider(module_id: &str, path: &Path, output: &mut DebugSymbolOutput) {
    let result = (|| -> anyhow::Result<(usize, usize)> {
        let pdb = ms_pdb::Pdb::open(path)?;
        let mut module_count = 0usize;
        let modules = pdb.modules()?;
        for module in modules.iter().take(4096) {
            let module_name = String::from_utf8_lossy(module.module_name().as_ref()).into_owned();
            let obj_file = String::from_utf8_lossy(module.obj_file().as_ref()).into_owned();
            let label = if module_name.is_empty() {
                obj_file.clone()
            } else {
                module_name.clone()
            };
            if label.is_empty() {
                continue;
            }
            output.source_files.push(SourceFileRecord {
                file_id: format!(
                    "source_file:ms_pdb:{module_count:04X}:{}",
                    safe_file_component(&label)
                ),
                module_id: module_id.to_string(),
                provider: "ms-pdb".to_string(),
                path: label,
                checksum: None,
                confidence: "medium".to_string(),
                evidence: Vec::new(),
            });
            module_count += 1;
        }

        let mut type_count = 0usize;
        if let Ok(header) = pdb.tpi_header() {
            let begin = header.type_index_begin().0;
            let end = header.type_index_end().0;
            if end > begin {
                type_count += (end - begin) as usize;
                output.debug_types.push(DebugTypeRecord {
                    type_id: "type:ms_pdb:tpi_range".to_string(),
                    module_id: module_id.to_string(),
                    provider: "ms-pdb".to_string(),
                    namespace: "pdb_tpi".to_string(),
                    raw_key: format!("0x{begin:08X}..0x{end:08X}"),
                    kind: "type_index_range".to_string(),
                    name: Some("ms-pdb TPI type range".to_string()),
                    size: Some(type_count as u64),
                    confidence: "medium".to_string(),
                    evidence: Vec::new(),
                });
            }
        }
        if let Ok(header) = pdb.ipi_header() {
            let begin = header.type_index_begin().0;
            let end = header.type_index_end().0;
            if end > begin {
                output.debug_types.push(DebugTypeRecord {
                    type_id: "type:ms_pdb:ipi_range".to_string(),
                    module_id: module_id.to_string(),
                    provider: "ms-pdb".to_string(),
                    namespace: "pdb_ipi".to_string(),
                    raw_key: format!("0x{begin:08X}..0x{end:08X}"),
                    kind: "item_index_range".to_string(),
                    name: Some("ms-pdb IPI item range".to_string()),
                    size: Some((end - begin) as u64),
                    confidence: "medium".to_string(),
                    evidence: Vec::new(),
                });
            }
        }

        Ok((module_count, type_count))
    })();

    match result {
        Ok((modules, types)) if modules > 0 || types > 0 => {}
        Ok(_) => output.uncertainties.push(uncertainty(
            module_id,
            PdbDeepMsProvider.name(),
            "INDEX_NOT_READY",
            "ms-pdb opened the PDB but did not expose DBI module or TPI/IPI metadata in this slice.",
            "Keep the pdb fallback records; add a richer ms-pdb CodeView/TPI walk when a fixture is available.",
            "low",
            Vec::new(),
        )),
        Err(err) => output.uncertainties.push(uncertainty(
            module_id,
            PdbDeepMsProvider.name(),
            "PARSE_ERROR",
            &format!("ms-pdb could not open or index the PDB: {err}"),
            "Use the stable pdb fallback records or verify this PDB is a supported MSF/MSFZ file.",
            "low",
            Vec::new(),
        )),
    }
}

#[allow(deprecated)]
fn collect_dwarf_provider(
    image: &dyn BinaryImage,
    module_id: &str,
    output: &mut DebugSymbolOutput,
) -> Result<(usize, usize), String> {
    let object = object::read::File::parse(image.bytes()).map_err(|err| err.to_string())?;
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let dwarf_cow = gimli::Dwarf::load(|section_id| -> Result<Cow<'_, [u8]>, gimli::Error> {
        Ok(object
            .section_by_name(section_id.name())
            .and_then(|section| section.uncompressed_data().ok())
            .unwrap_or(Cow::Borrowed(&[])))
    })
    .map_err(|err| err.to_string())?;
    let dwarf = dwarf_cow.borrow(|section| gimli::EndianSlice::new(section.as_ref(), endian));
    let mut units = dwarf.units();
    let mut count = 0usize;
    let mut line_count = 0usize;
    let mut source_files = BTreeMap::<String, String>::new();
    while let Some(header) = units.next().map_err(|err| err.to_string())? {
        let unit = dwarf.unit(header).map_err(|err| err.to_string())?;
        if let Some(program) = unit.line_program.clone() {
            let (program, sequences) = program.sequences().map_err(|err| err.to_string())?;
            for sequence in sequences {
                let mut rows = program.resume_from(&sequence);
                while let Some((header, row)) = rows.next_row().map_err(|err| err.to_string())? {
                    if row.end_sequence() {
                        continue;
                    }
                    let Some(line) = row.line().map(|line| line.get()) else {
                        continue;
                    };
                    let Some(file) = row.file(header) else {
                        continue;
                    };
                    let file_path = dwarf_file_path(&dwarf, &unit, header, file)
                        .unwrap_or_else(|| "unknown".to_string());
                    let file_id = if let Some(existing) = source_files.get(&file_path) {
                        existing.clone()
                    } else {
                        let next_id = format!(
                            "source_file:dwarf:{:04X}:{}",
                            source_files.len(),
                            safe_file_component(&file_path)
                        );
                        source_files.insert(file_path.clone(), next_id.clone());
                        output.source_files.push(SourceFileRecord {
                            file_id: next_id.clone(),
                            module_id: module_id.to_string(),
                            provider: "dwarf".to_string(),
                            path: file_path.clone(),
                            checksum: header.file_has_md5().then(|| hex(file.md5())),
                            confidence: "high".to_string(),
                            evidence: vec![row.address()],
                        });
                        next_id
                    };
                    let start_rva = va_to_rva(image, row.address());
                    let column = match row.column() {
                        gimli::ColumnType::LeftEdge => None,
                        gimli::ColumnType::Column(column) => Some(column.get()),
                    };
                    let mut flags = Vec::new();
                    if row.is_stmt() {
                        flags.push("is_stmt".to_string());
                    }
                    output.line_entries.push(LineEntryRecord {
                        line_id: format!("line:dwarf:{start_rva:016X}:{line_count:04X}"),
                        module_id: module_id.to_string(),
                        provider: "dwarf".to_string(),
                        start_rva,
                        end_rva: start_rva.saturating_add(1),
                        file_id,
                        line,
                        column,
                        flags,
                        confidence: "high".to_string(),
                        evidence: vec![row.address()],
                    });
                    line_count += 1;
                }
            }
        }
        let mut entries = unit.entries();
        let mut die_index = 0usize;
        while let Some((_depth_delta, entry)) = entries.next_dfs().map_err(|err| err.to_string())? {
            die_index += 1;
            match entry.tag() {
                gimli::DW_TAG_subprogram => {
                    let Some(low_pc) = dwarf_low_pc(entry) else {
                        continue;
                    };
                    let Some(high_pc) = dwarf_high_pc(entry, low_pc) else {
                        continue;
                    };
                    if low_pc >= high_pc {
                        continue;
                    }
                    let start_rva = va_to_rva(image, low_pc);
                    let end_rva = va_to_rva(image, high_pc).max(start_rva.saturating_add(1));
                    let name = dwarf_entry_attr_string(&dwarf, &unit, entry, gimli::DW_AT_name)
                        .or_else(|| {
                            dwarf_entry_attr_string(&dwarf, &unit, entry, gimli::DW_AT_linkage_name)
                        })
                        .or_else(|| {
                            dwarf_entry_attr_string(
                                &dwarf,
                                &unit,
                                entry,
                                gimli::DW_AT_MIPS_linkage_name,
                            )
                        })
                        .unwrap_or_else(|| format!("dwarf_subprogram_{start_rva:016X}"));
                    let linkage_name =
                        dwarf_entry_attr_string(&dwarf, &unit, entry, gimli::DW_AT_linkage_name)
                            .or_else(|| {
                                dwarf_entry_attr_string(
                                    &dwarf,
                                    &unit,
                                    entry,
                                    gimli::DW_AT_MIPS_linkage_name,
                                )
                            });
                    output.symbols.push(DebugSymbolRecord {
                        symbol_id: format!(
                            "symbol:dwarf:{start_rva:016X}:{}",
                            safe_file_component(&name)
                        ),
                        module_id: module_id.to_string(),
                        provider: "dwarf".to_string(),
                        name,
                        linkage_name,
                        kind: "function".to_string(),
                        start_rva,
                        end_rva,
                        function: true,
                        confidence: "high".to_string(),
                        evidence: vec![low_pc],
                    });
                }
                tag if dwarf_type_kind(tag).is_some() => {
                    let kind = dwarf_type_kind(tag).unwrap();
                    let raw_key = format!("{:?}", entry.offset());
                    let name = dwarf_entry_attr_string(&dwarf, &unit, entry, gimli::DW_AT_name);
                    let size = dwarf_entry_udata(entry, gimli::DW_AT_byte_size);
                    output.debug_types.push(DebugTypeRecord {
                        type_id: format!(
                            "type:dwarf:{:04X}:{}",
                            output.debug_types.len(),
                            safe_file_component(name.as_deref().unwrap_or(&raw_key))
                        ),
                        module_id: module_id.to_string(),
                        provider: "dwarf".to_string(),
                        namespace: "dwarf_die".to_string(),
                        raw_key,
                        kind: kind.to_string(),
                        name,
                        size,
                        confidence: "medium".to_string(),
                        evidence: Vec::new(),
                    });
                }
                _ => {}
            }
            if die_index >= 100_000 {
                output.uncertainties.push(uncertainty(
                    module_id,
                    "dwarf",
                    "PARTIAL_RESULT",
                    "DWARF DIE traversal hit the deterministic record budget.",
                    "Rerun with a narrower binary or extend the semantic budget for deeper type/local recovery.",
                    "low",
                    Vec::new(),
                ));
                break;
            }
        }
        count += 1;
        if count >= 4096 {
            break;
        }
    }
    Ok((count, line_count))
}

fn dwarf_file_path<R: gimli::Reader>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R>,
    header: &gimli::LineProgramHeader<R>,
    file: &gimli::FileEntry<R>,
) -> Option<String> {
    let path = dwarf
        .attr_string(unit, file.path_name())
        .ok()?
        .to_string_lossy()
        .ok()?
        .into_owned();
    let Some(directory_attr) = file.directory(header) else {
        return Some(path);
    };
    let directory = dwarf
        .attr_string(unit, directory_attr)
        .ok()?
        .to_string_lossy()
        .ok()?
        .into_owned();
    if directory.is_empty() {
        Some(path)
    } else if path.contains(':') || path.starts_with('/') || path.starts_with('\\') {
        Some(path)
    } else {
        Some(format!("{directory}/{path}"))
    }
}

fn dwarf_entry_attr_string<R, Offset>(
    dwarf: &gimli::Dwarf<R>,
    unit: &gimli::Unit<R, Offset>,
    entry: &gimli::DebuggingInformationEntry<'_, '_, R, Offset>,
    attr_name: gimli::DwAt,
) -> Option<String>
where
    R: gimli::Reader<Offset = Offset>,
    Offset: gimli::ReaderOffset,
{
    let attr = entry.attr(attr_name).ok().flatten()?;
    dwarf
        .attr_string(unit, attr.value())
        .ok()?
        .to_string_lossy()
        .ok()
        .map(|value| value.into_owned())
}

fn dwarf_low_pc<R, Offset>(
    entry: &gimli::DebuggingInformationEntry<'_, '_, R, Offset>,
) -> Option<u64>
where
    R: gimli::Reader<Offset = Offset>,
    Offset: gimli::ReaderOffset,
{
    let attr = entry.attr(gimli::DW_AT_low_pc).ok().flatten()?;
    match attr.value() {
        gimli::AttributeValue::Addr(address) => Some(address),
        _ => None,
    }
}

fn dwarf_high_pc<R, Offset>(
    entry: &gimli::DebuggingInformationEntry<'_, '_, R, Offset>,
    low_pc: u64,
) -> Option<u64>
where
    R: gimli::Reader<Offset = Offset>,
    Offset: gimli::ReaderOffset,
{
    let attr = entry.attr(gimli::DW_AT_high_pc).ok().flatten()?;
    match attr.value() {
        gimli::AttributeValue::Addr(address) => Some(address),
        gimli::AttributeValue::Udata(size) => Some(low_pc.saturating_add(size)),
        gimli::AttributeValue::Data1(size) => Some(low_pc.saturating_add(size as u64)),
        gimli::AttributeValue::Data2(size) => Some(low_pc.saturating_add(size as u64)),
        gimli::AttributeValue::Data4(size) => Some(low_pc.saturating_add(size as u64)),
        gimli::AttributeValue::Data8(size) => Some(low_pc.saturating_add(size)),
        _ => None,
    }
}

fn dwarf_entry_udata<R, Offset>(
    entry: &gimli::DebuggingInformationEntry<'_, '_, R, Offset>,
    attr_name: gimli::DwAt,
) -> Option<u64>
where
    R: gimli::Reader<Offset = Offset>,
    Offset: gimli::ReaderOffset,
{
    let attr = entry.attr(attr_name).ok().flatten()?;
    match attr.value() {
        gimli::AttributeValue::Udata(value) => Some(value),
        gimli::AttributeValue::Data1(value) => Some(value as u64),
        gimli::AttributeValue::Data2(value) => Some(value as u64),
        gimli::AttributeValue::Data4(value) => Some(value as u64),
        gimli::AttributeValue::Data8(value) => Some(value),
        _ => None,
    }
}

fn dwarf_type_kind(tag: gimli::DwTag) -> Option<&'static str> {
    match tag {
        gimli::DW_TAG_base_type => Some("base"),
        gimli::DW_TAG_pointer_type => Some("pointer"),
        gimli::DW_TAG_reference_type => Some("reference"),
        gimli::DW_TAG_const_type => Some("const"),
        gimli::DW_TAG_typedef => Some("typedef"),
        gimli::DW_TAG_structure_type => Some("struct"),
        gimli::DW_TAG_class_type => Some("class"),
        gimli::DW_TAG_union_type => Some("union"),
        gimli::DW_TAG_array_type => Some("array"),
        gimli::DW_TAG_enumeration_type => Some("enum"),
        gimli::DW_TAG_subroutine_type => Some("function"),
        _ => None,
    }
}

fn collect_addr2line_inline_frames(
    image: &dyn BinaryImage,
    module_id: &str,
    output: &mut DebugSymbolOutput,
) -> Result<usize, String> {
    let loader =
        addr2line::Loader::new(Path::new(image.source_path())).map_err(|err| err.to_string())?;
    let mut source_files = output
        .source_files
        .iter()
        .map(|row| (row.path.clone(), row.file_id.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut seen_scopes = BTreeSet::new();
    let symbols = output
        .symbols
        .iter()
        .filter(|row| row.function)
        .take(256)
        .cloned()
        .collect::<Vec<_>>();
    let mut count = 0usize;

    for symbol in symbols {
        let probe = if image.base() != 0 {
            image.base().saturating_add(symbol.start_rva)
        } else {
            symbol.start_rva
        };
        let Ok(mut frames) = loader.find_frames(probe) else {
            continue;
        };
        let mut frame_index = 0usize;
        while let Some(frame) = frames.next().map_err(|err| err.to_string())? {
            let function_ref = frame
                .function
                .as_ref()
                .and_then(|function| function.demangle().ok().map(|name| name.into_owned()));
            let (call_file_id, call_line) = if let Some(location) = frame.location {
                let file_id = location.file.map(|file| {
                    if let Some(existing) = source_files.get(file) {
                        existing.clone()
                    } else {
                        let next_id = format!(
                            "source_file:addr2line:{:04X}:{}",
                            source_files.len(),
                            safe_file_component(file)
                        );
                        source_files.insert(file.to_string(), next_id.clone());
                        output.source_files.push(SourceFileRecord {
                            file_id: next_id.clone(),
                            module_id: module_id.to_string(),
                            provider: "addr2line".to_string(),
                            path: file.to_string(),
                            checksum: None,
                            confidence: "medium".to_string(),
                            evidence: vec![probe],
                        });
                        next_id
                    }
                });
                (file_id, location.line.map(u64::from))
            } else {
                (None, None)
            };
            let scope_id = format!(
                "inline:addr2line:{:016X}:{frame_index:04X}",
                symbol.start_rva
            );
            if seen_scopes.insert(scope_id.clone()) {
                output.inline_scopes.push(InlineScopeRecord {
                    scope_id,
                    module_id: module_id.to_string(),
                    provider: "addr2line".to_string(),
                    function_ref,
                    start_rva: symbol.start_rva,
                    end_rva: symbol.end_rva.max(symbol.start_rva.saturating_add(1)),
                    call_file_id,
                    call_line,
                    confidence: "medium".to_string(),
                    evidence: vec![probe],
                });
                count += 1;
            }
            frame_index += 1;
            if frame_index >= 32 {
                break;
            }
        }
    }
    Ok(count)
}

fn add_function_fallback_symbols(
    input: DebugSymbolInput<'_>,
    module_id: &str,
    output: &mut DebugSymbolOutput,
) {
    let existing = output
        .symbols
        .iter()
        .map(|row| (row.start_rva, row.end_rva))
        .collect::<BTreeSet<_>>();
    for function in input.functions {
        let start_rva = va_to_rva(input.image, function.start);
        let end_rva = va_to_rva(input.image, function.end).max(start_rva.saturating_add(1));
        if existing.contains(&(start_rva, end_rva)) {
            continue;
        }
        output.symbols.push(DebugSymbolRecord {
            symbol_id: format!("symbol:function:{start_rva:016X}"),
            module_id: module_id.to_string(),
            provider: "function_recovery".to_string(),
            name: format!("function_{:016X}", function.start),
            linkage_name: None,
            kind: "function".to_string(),
            start_rva,
            end_rva,
            function: true,
            confidence: "low".to_string(),
            evidence: vec![function.start],
        });
    }
}

fn dedup_symbols(symbols: &mut Vec<DebugSymbolRecord>) {
    let mut seen = BTreeSet::new();
    symbols.retain(|row| {
        seen.insert((
            row.provider.clone(),
            row.name.clone(),
            row.start_rva,
            row.end_rva,
        ))
    });
    symbols.sort_by_key(|row| {
        (
            row.start_rva,
            row.end_rva,
            row.provider.clone(),
            row.name.clone(),
        )
    });
}

fn locate_debug_file(path_hint: &str, input: DebugSymbolInput<'_>) -> Option<PathBuf> {
    let hinted = Path::new(path_hint);
    let mut candidates = Vec::new();
    candidates.push(hinted.to_path_buf());
    let file_name = hinted.file_name().map(|name| name.to_os_string());
    if let Some(name) = &file_name {
        if let Some(parent) = Path::new(input.image.source_path()).parent() {
            candidates.push(parent.join(name));
        }
        for root in input.symbol_paths {
            let root = Path::new(root);
            candidates.push(root.join(name));
            if !hinted.is_absolute() {
                candidates.push(root.join(hinted));
            }
        }
    }
    for candidate in candidates {
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn parse_gnu_build_id(data: &[u8], little_endian: bool) -> Option<String> {
    let mut cursor = 0usize;
    while cursor + 12 <= data.len() {
        let namesz = read_u32(&data[cursor..cursor + 4], little_endian)? as usize;
        let descsz = read_u32(&data[cursor + 4..cursor + 8], little_endian)? as usize;
        let note_type = read_u32(&data[cursor + 8..cursor + 12], little_endian)?;
        cursor += 12;
        let name_end = cursor.checked_add(namesz)?;
        if name_end > data.len() {
            return None;
        }
        let name = &data[cursor..name_end];
        cursor = align4(name_end);
        let desc_end = cursor.checked_add(descsz)?;
        if desc_end > data.len() {
            return None;
        }
        let desc = &data[cursor..desc_end];
        cursor = align4(desc_end);
        if note_type == ELF_NOTE_GNU_BUILD_ID && name.starts_with(b"GNU") && !desc.is_empty() {
            return Some(hex(desc));
        }
    }
    None
}

fn parse_debuglink(data: &[u8]) -> Option<String> {
    let end = data.iter().position(|byte| *byte == 0)?;
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&data[..end]).to_string())
}

fn read_u32(bytes: &[u8], little_endian: bool) -> Option<u32> {
    if bytes.len() != 4 {
        return None;
    }
    let array = [bytes[0], bytes[1], bytes[2], bytes[3]];
    Some(if little_endian {
        u32::from_le_bytes(array)
    } else {
        u32::from_be_bytes(array)
    })
}

fn align4(value: usize) -> usize {
    (value + 3) & !3
}

fn format_guid(bytes: &[u8]) -> String {
    if bytes.len() != 16 {
        return String::new();
    }
    let d1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn symbol_kind_label(kind: SymbolKind) -> &'static str {
    match kind {
        SymbolKind::Text => "function",
        SymbolKind::Data => "data",
        SymbolKind::Section => "section",
        SymbolKind::File => "file",
        SymbolKind::Label => "label",
        SymbolKind::Tls => "tls",
        _ => "unknown",
    }
}

fn address_size(machine: u16) -> u8 {
    match machine {
        0x8664 => 8,
        0x014c => 4,
        _ => 0,
    }
}

fn va_to_rva(image: &dyn BinaryImage, address: u64) -> u64 {
    if image.base() != 0 && address >= image.base() {
        address - image.base()
    } else {
        address
    }
}

fn cache_key(input: DebugSymbolInput<'_>) -> String {
    let digest = Sha256::digest(input.image.bytes());
    let mut digest_hex = String::with_capacity(64);
    for byte in digest {
        digest_hex.push_str(&format!("{byte:02x}"));
    }
    let cache_root = input.symbol_cache.unwrap_or("memory");
    format!(
        "{}:{}:{:04X}:{}:{}:{}",
        SCHEMA_VERSION,
        input.image.format(),
        input.image.machine(),
        input.mode,
        safe_file_component(cache_root),
        digest_hex
    )
}

fn uncertainty(
    module_id: &str,
    provider: &str,
    code: &str,
    message: &str,
    recommended_action: &str,
    severity: &str,
    evidence: Vec<u64>,
) -> SymbolUncertaintyRecord {
    SymbolUncertaintyRecord {
        uncertainty_id: format!(
            "symbol_uncertainty:{provider}:{}:{:04X}",
            safe_file_component(code),
            evidence.first().copied().unwrap_or(0)
        ),
        module_id: module_id.to_string(),
        provider: provider.to_string(),
        code: code.to_string(),
        message: message.to_string(),
        recommended_action: recommended_action.to_string(),
        severity: severity.to_string(),
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsds_parser_extracts_guid_age_and_path() {
        let mut bytes = b"prefixRSDS".to_vec();
        bytes.extend_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ]);
        bytes.extend_from_slice(&7u32.to_le_bytes());
        bytes.extend_from_slice(b"C:\\symbols\\fixture.pdb\0tail");

        let records = parse_rsds_records(&bytes);

        assert_eq!(1, records.len());
        assert_eq!("12345678-9ABC-DEF0-1122-334455667788", records[0].guid);
        assert_eq!(7, records[0].age);
        assert_eq!("C:\\symbols\\fixture.pdb", records[0].path);
        assert_eq!(6, records[0].evidence_offset);
    }

    #[test]
    fn range_index_prefers_most_specific_overlap() {
        let mut index = RangeIndex::new();
        index.insert("outer", 0x1000, 0x1100);
        index.insert("inner", 0x1040, 0x1050);
        index.insert("left", 0x1030, 0x1080);

        let hit = index.lookup(0x1048).expect("range hit");

        assert_eq!("inner", hit.id);
    }

    #[test]
    fn parses_elf_gnu_build_id_note() {
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes());
        note.extend_from_slice(&3u32.to_le_bytes());
        note.extend_from_slice(&ELF_NOTE_GNU_BUILD_ID.to_le_bytes());
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        assert_eq!(Some("aabbcc".to_string()), parse_gnu_build_id(&note, true));
    }
}
