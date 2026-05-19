//! Edge / PC → (function, source file, source line) resolution.
//!
//! Consumes the analyzer's [`DebugSymbolOutput`] (DWARF + PDB +
//! object-symbol layer) and exposes O(log n) lookups for the LLM
//! export layer (step 12) to attach human-readable symbols to NDJSON
//! event records and crash findings.
//!
//! C++ mangled `linkage_name` values are demangled on-the-fly via
//! [`crate::cpp_classes::names::demangle`].

#![allow(dead_code)]

use std::collections::BTreeMap;

use crate::cpp_classes::names::demangle;
use crate::debug_symbols::{DebugSymbolOutput, DebugSymbolRecord, LineEntryRecord};

/// Human-readable resolution of a single PC.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResolvedSymbol {
    pub function_name: Option<String>,
    pub linkage_name: Option<String>,
    pub demangled: Option<String>,
    pub source_file: Option<String>,
    pub line: Option<u64>,
    pub column: Option<u64>,
}

/// Symbol + line-entry indexes built from a fresh `DebugSymbolOutput`.
/// All lookups are by RVA (image-relative VA); callers convert from
/// absolute VA via `va - image_base`.
pub struct SymbolResolver<'a> {
    /// Sorted-by-start-rva index into the input record slice.
    symbol_starts: Vec<u64>,
    symbols_by_start: BTreeMap<u64, &'a DebugSymbolRecord>,
    line_starts: Vec<u64>,
    lines_by_start: BTreeMap<u64, &'a LineEntryRecord>,
    files_by_id: BTreeMap<String, String>,
    image_base: u64,
}

impl<'a> SymbolResolver<'a> {
    pub fn new(output: &'a DebugSymbolOutput, image_base: u64) -> Self {
        let mut symbols_by_start: BTreeMap<u64, &DebugSymbolRecord> = BTreeMap::new();
        for sym in &output.symbols {
            symbols_by_start.entry(sym.start_rva).or_insert(sym);
        }
        let symbol_starts: Vec<u64> = symbols_by_start.keys().copied().collect();

        let mut lines_by_start: BTreeMap<u64, &LineEntryRecord> = BTreeMap::new();
        for line in &output.line_entries {
            lines_by_start.entry(line.start_rva).or_insert(line);
        }
        let line_starts: Vec<u64> = lines_by_start.keys().copied().collect();

        let files_by_id: BTreeMap<String, String> = output
            .source_files
            .iter()
            .map(|sf| (sf.file_id.clone(), sf.path.clone()))
            .collect();

        Self {
            symbol_starts,
            symbols_by_start,
            line_starts,
            lines_by_start,
            files_by_id,
            image_base,
        }
    }

    /// Resolve an absolute virtual address to whatever debug-info
    /// detail we have. Returns `None` when no symbol covers the VA
    /// (the line entry may still be populated separately).
    pub fn resolve(&self, va: u64) -> Option<ResolvedSymbol> {
        let rva = va.checked_sub(self.image_base)?;
        let sym = self.symbol_for_rva(rva);
        let line = self.line_for_rva(rva);
        if sym.is_none() && line.is_none() {
            return None;
        }
        let function_name = sym.map(|s| s.name.clone());
        let linkage_name = sym.and_then(|s| s.linkage_name.clone());
        let demangled = linkage_name.as_deref().and_then(demangle);
        let (source_file, source_line, column) = line
            .map(|l| {
                let path = self.files_by_id.get(&l.file_id).cloned();
                (path, Some(l.line), l.column)
            })
            .unwrap_or((None, None, None));
        Some(ResolvedSymbol {
            function_name,
            linkage_name,
            demangled,
            source_file,
            line: source_line,
            column,
        })
    }

    /// Resolve both endpoints of an edge in one call. Convenience for
    /// the NDJSON event writer.
    pub fn resolve_edge(
        &self,
        from_va: u64,
        to_va: u64,
    ) -> (Option<ResolvedSymbol>, Option<ResolvedSymbol>) {
        (self.resolve(from_va), self.resolve(to_va))
    }

    fn symbol_for_rva(&self, rva: u64) -> Option<&DebugSymbolRecord> {
        let idx = self
            .symbol_starts
            .partition_point(|&start| start <= rva)
            .checked_sub(1)?;
        let start = self.symbol_starts[idx];
        let sym = *self.symbols_by_start.get(&start)?;
        if sym.start_rva <= rva && rva < sym.end_rva {
            Some(sym)
        } else {
            None
        }
    }

    fn line_for_rva(&self, rva: u64) -> Option<&LineEntryRecord> {
        let idx = self
            .line_starts
            .partition_point(|&start| start <= rva)
            .checked_sub(1)?;
        let start = self.line_starts[idx];
        let line = *self.lines_by_start.get(&start)?;
        if line.start_rva <= rva && rva < line.end_rva {
            Some(line)
        } else {
            None
        }
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn symbol_count(&self) -> usize {
        self.symbols_by_start.len()
    }

    pub fn line_count(&self) -> usize {
        self.lines_by_start.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug_symbols::{
        DebugIdentityRecord, DebugModuleRecord, DebugSymbolOutput, DebugSymbolRecord,
        DebugTypeRecord, InlineScopeRecord, LineEntryRecord, SourceFileRecord,
        SymbolUncertaintyRecord,
    };

    fn empty_output() -> DebugSymbolOutput {
        DebugSymbolOutput {
            modules: Vec::<DebugModuleRecord>::new(),
            identities: Vec::<DebugIdentityRecord>::new(),
            symbols: Vec::new(),
            source_files: Vec::new(),
            line_entries: Vec::new(),
            inline_scopes: Vec::<InlineScopeRecord>::new(),
            debug_types: Vec::<DebugTypeRecord>::new(),
            uncertainties: Vec::<SymbolUncertaintyRecord>::new(),
        }
    }

    fn sym(start: u64, end: u64, name: &str, linkage: Option<&str>) -> DebugSymbolRecord {
        DebugSymbolRecord {
            symbol_id: format!("sym:{name}"),
            module_id: "mod:1".into(),
            provider: "test".into(),
            name: name.into(),
            linkage_name: linkage.map(String::from),
            kind: "function".into(),
            start_rva: start,
            end_rva: end,
            function: true,
            confidence: "high".into(),
            evidence: Vec::new(),
        }
    }

    fn line(start: u64, end: u64, file: &str, line: u64) -> LineEntryRecord {
        LineEntryRecord {
            line_id: format!("line:{start:x}"),
            module_id: "mod:1".into(),
            provider: "test".into(),
            start_rva: start,
            end_rva: end,
            file_id: file.into(),
            line,
            column: None,
            flags: Vec::new(),
            confidence: "high".into(),
            evidence: Vec::new(),
        }
    }

    fn file(id: &str, path: &str) -> SourceFileRecord {
        SourceFileRecord {
            file_id: id.into(),
            module_id: "mod:1".into(),
            provider: "test".into(),
            path: path.into(),
            checksum: None,
            confidence: "high".into(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn resolves_function_name_for_va_in_range() {
        let mut out = empty_output();
        out.symbols.push(sym(0x1000, 0x1100, "parser_parse", None));
        let r = SymbolResolver::new(&out, 0x140000000);
        let res = r.resolve(0x140001050).unwrap();
        assert_eq!(res.function_name.as_deref(), Some("parser_parse"));
    }

    #[test]
    fn returns_none_outside_any_symbol() {
        let out = empty_output();
        let r = SymbolResolver::new(&out, 0x140000000);
        assert!(r.resolve(0x140009999).is_none());
    }

    #[test]
    fn resolves_source_line() {
        let mut out = empty_output();
        out.line_entries.push(line(0x1000, 0x1100, "f1", 42));
        out.source_files.push(file("f1", "src/parser.rs"));
        let r = SymbolResolver::new(&out, 0x140000000);
        let res = r.resolve(0x140001050).unwrap();
        assert_eq!(res.line, Some(42));
        assert_eq!(res.source_file.as_deref(), Some("src/parser.rs"));
    }

    #[test]
    fn resolves_both_symbol_and_source_line() {
        let mut out = empty_output();
        out.symbols.push(sym(0x1000, 0x1100, "parse", None));
        out.line_entries.push(line(0x1010, 0x1050, "f1", 99));
        out.source_files.push(file("f1", "src/parser.rs"));
        let r = SymbolResolver::new(&out, 0x140000000);
        let res = r.resolve(0x140001020).unwrap();
        assert_eq!(res.function_name.as_deref(), Some("parse"));
        assert_eq!(res.line, Some(99));
    }

    #[test]
    fn demangles_mangled_linkage_name() {
        let mut out = empty_output();
        out.symbols.push(sym(
            0x1000,
            0x1100,
            "_ZNSt9exception4whatEv",
            Some("_ZNSt9exception4whatEv"),
        ));
        let r = SymbolResolver::new(&out, 0x140000000);
        let res = r.resolve(0x140001050).unwrap();
        assert!(res.demangled.is_some());
        let dem = res.demangled.unwrap();
        assert!(dem.contains("exception"));
        assert!(dem.contains("what"));
    }

    #[test]
    fn end_rva_is_exclusive() {
        let mut out = empty_output();
        out.symbols.push(sym(0x1000, 0x1100, "fn", None));
        let r = SymbolResolver::new(&out, 0x140000000);
        // 0x1100 is end-exclusive.
        assert!(r.resolve(0x140001100).is_none());
        // 0x10FF is the last covered RVA.
        assert!(r.resolve(0x1400010FF).is_some());
    }

    #[test]
    fn resolve_edge_resolves_both_endpoints() {
        let mut out = empty_output();
        out.symbols.push(sym(0x1000, 0x1100, "caller", None));
        out.symbols.push(sym(0x2000, 0x2100, "callee", None));
        let r = SymbolResolver::new(&out, 0x140000000);
        let (a, b) = r.resolve_edge(0x140001050, 0x140002050);
        assert_eq!(a.unwrap().function_name.as_deref(), Some("caller"));
        assert_eq!(b.unwrap().function_name.as_deref(), Some("callee"));
    }
}
