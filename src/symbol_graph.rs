use crate::debug_symbols::{
    DebugSymbolOutput, DebugSymbolRecord, LineEntryRecord, SourceFileRecord,
    SymbolUncertaintyRecord,
};
use crate::portable::safe_file_component;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

const GRAPH_SCHEMA: &str = "symbol_graph/1";
const INDEX_SCHEMA: &str = "symbol_indexes/1";
const PACKET_SCHEMA: &str = "llm_symbol_packet/1";
const PACKET_MANIFEST_SCHEMA: &str = "symbol_packet_manifest/1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArtifactId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompileUnitId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceFileId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct TypeId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code)]
pub struct VariableId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct InlineSiteId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolGraphRecord {
    pub schema: String,
    pub id: String,
    pub kind: String,
    pub label: String,
    pub artifact_id: String,
    pub provider: String,
    pub confidence: String,
    pub rva_start: Option<u64>,
    pub rva_end: Option<u64>,
    pub source_file: Option<String>,
    pub line_start: Option<u64>,
    pub line_end: Option<u64>,
    pub related: Vec<String>,
    pub evidence: Vec<String>,
    pub attributes: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressIndexEntry {
    pub start_rva: u64,
    pub end_rva: u64,
    pub target_id: String,
    pub target_kind: String,
    pub label: String,
    pub confidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolIndexes {
    pub schema: String,
    pub address_range_index: Vec<AddressIndexEntry>,
    pub name_index: BTreeMap<String, Vec<String>>,
    pub source_index: BTreeMap<String, Vec<String>>,
    pub type_index: BTreeMap<String, Vec<String>>,
    pub compile_unit_index: BTreeMap<String, Vec<String>>,
    pub evidence_index: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressRangeFact {
    pub rva_start: u64,
    pub rva_end: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceFact {
    pub file: String,
    pub line_start: u64,
    pub line_end: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolFact {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub provider: String,
    pub confidence: String,
    pub address_ranges: Vec<AddressRangeFact>,
    pub source: Vec<SourceFact>,
    pub evidence: Vec<String>,
    pub attributes: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LlmSymbolPacket {
    pub schema: String,
    pub packet_id: String,
    pub query_kind: String,
    pub query: String,
    pub exact_matches: Vec<SymbolFact>,
    pub nearby_symbols: Vec<SymbolFact>,
    pub source_context: Vec<SymbolFact>,
    pub inline_frames: Vec<SymbolFact>,
    pub type_context: Vec<SymbolFact>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolPacketManifestEntry {
    pub path: String,
    pub packet_id: String,
    pub query_kind: String,
    pub query: String,
    pub exact_match_count: usize,
    pub nearby_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolPacketManifest {
    pub schema: String,
    pub packet_mode: String,
    pub packets: Vec<SymbolPacketManifestEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SymbolGraphSummary {
    pub schema: String,
    pub graph_records: usize,
    pub address_ranges: usize,
    pub name_keys: usize,
    pub packets: usize,
    pub packet_mode: String,
}

#[derive(Clone, Debug)]
pub struct SymbolGraphArtifacts {
    pub rows: Vec<SymbolGraphRecord>,
    pub indexes: SymbolIndexes,
    pub packets: Vec<(String, LlmSymbolPacket)>,
    pub manifest: SymbolPacketManifest,
    pub summary: SymbolGraphSummary,
}

#[derive(Clone, Debug)]
struct GraphContext {
    artifact_id: String,
    source_files: BTreeMap<String, SourceFileRecord>,
}

pub fn build_symbol_graph(debug: &DebugSymbolOutput, packet_mode: &str) -> SymbolGraphArtifacts {
    let artifact_id = debug
        .modules
        .first()
        .map(|row| ArtifactId(format!("artifact:{}", row.module_id)).0)
        .unwrap_or_else(|| ArtifactId("artifact:unknown".to_string()).0);
    let mut rows = Vec::new();
    let ctx = build_context(debug, &artifact_id);

    for module in &debug.modules {
        rows.push(SymbolGraphRecord {
            schema: GRAPH_SCHEMA.to_string(),
            id: format!("debug_module:{}", module.module_id),
            kind: "debug_module".to_string(),
            label: module.source_path.clone(),
            artifact_id: artifact_id.clone(),
            provider: "object".to_string(),
            confidence: "high".to_string(),
            rva_start: Some(module.entry_rva),
            rva_end: Some(module.entry_rva.saturating_add(1)),
            source_file: None,
            line_start: None,
            line_end: None,
            related: Vec::new(),
            evidence: vec![module.cache_key.clone()],
            attributes: json!({
                "format": module.format,
                "machine": module.machine,
                "image_base": module.image_base,
                "address_size": module.address_size,
                "section_count": module.section_count,
                "symbol_mode": module.symbol_mode,
            }),
        });
    }

    for identity in &debug.identities {
        rows.push(SymbolGraphRecord {
            schema: GRAPH_SCHEMA.to_string(),
            id: identity.identity_id.clone(),
            kind: "symbol_evidence".to_string(),
            label: identity.identity_kind.clone(),
            artifact_id: artifact_id.clone(),
            provider: identity.provider.clone(),
            confidence: identity.confidence.clone(),
            rva_start: None,
            rva_end: None,
            source_file: identity.path_hint.clone(),
            line_start: None,
            line_end: None,
            related: vec![format!("debug_module:{}", identity.module_id)],
            evidence: address_evidence(&identity.evidence),
            attributes: json!({
                "category": "debug_identity",
                "path_hint": identity.path_hint,
                "build_id": identity.build_id,
                "guid": identity.guid,
                "age": identity.age,
                "debuglink": identity.debuglink,
                "uuid": identity.uuid,
                "found_path": identity.found_path,
            }),
        });
    }

    for source in &debug.source_files {
        rows.push(source_file_row(source, &artifact_id));
        rows.push(SymbolGraphRecord {
            schema: GRAPH_SCHEMA.to_string(),
            id: CompileUnitId(format!("compile_unit:{}", source.file_id)).0,
            kind: "compile_unit".to_string(),
            label: source.path.clone(),
            artifact_id: artifact_id.clone(),
            provider: source.provider.clone(),
            confidence: source.confidence.clone(),
            rva_start: None,
            rva_end: None,
            source_file: Some(source.path.clone()),
            line_start: None,
            line_end: None,
            related: vec![source.file_id.clone()],
            evidence: address_evidence(&source.evidence),
            attributes: json!({
                "source_file_id": source.file_id,
                "checksum": source.checksum,
            }),
        });
    }

    for symbol in &debug.symbols {
        rows.push(symbol_row(symbol, &artifact_id, debug, &ctx));
    }

    for line in &debug.line_entries {
        rows.push(line_row(line, &artifact_id, &ctx));
    }

    for scope in &debug.inline_scopes {
        let source = scope
            .call_file_id
            .as_ref()
            .and_then(|id| ctx.source_files.get(id))
            .map(|row| row.path.clone());
        rows.push(SymbolGraphRecord {
            schema: GRAPH_SCHEMA.to_string(),
            id: InlineSiteId(scope.scope_id.clone()).0,
            kind: "inline_site".to_string(),
            label: scope
                .function_ref
                .clone()
                .unwrap_or_else(|| "inline_site".to_string()),
            artifact_id: artifact_id.clone(),
            provider: scope.provider.clone(),
            confidence: scope.confidence.clone(),
            rva_start: Some(scope.start_rva),
            rva_end: Some(scope.end_rva.max(scope.start_rva.saturating_add(1))),
            source_file: source,
            line_start: scope.call_line,
            line_end: scope.call_line,
            related: scope
                .function_ref
                .clone()
                .into_iter()
                .chain(scope.call_file_id.clone())
                .collect(),
            evidence: address_evidence(&scope.evidence),
            attributes: json!({
                "function_ref": scope.function_ref,
                "call_file_id": scope.call_file_id,
            }),
        });
    }

    for ty in &debug.debug_types {
        rows.push(SymbolGraphRecord {
            schema: GRAPH_SCHEMA.to_string(),
            id: TypeId(ty.type_id.clone()).0,
            kind: "type_def".to_string(),
            label: ty.name.clone().unwrap_or_else(|| ty.raw_key.clone()),
            artifact_id: artifact_id.clone(),
            provider: ty.provider.clone(),
            confidence: ty.confidence.clone(),
            rva_start: None,
            rva_end: None,
            source_file: None,
            line_start: None,
            line_end: None,
            related: Vec::new(),
            evidence: address_evidence(&ty.evidence),
            attributes: json!({
                "namespace": ty.namespace,
                "raw_key": ty.raw_key,
                "kind": ty.kind,
                "size": ty.size,
            }),
        });
    }

    for uncertainty in &debug.uncertainties {
        rows.push(uncertainty_row(uncertainty, &artifact_id));
    }

    rows.sort_by(|left, right| {
        (
            left.kind.as_str(),
            left.rva_start.unwrap_or(u64::MAX),
            left.id.as_str(),
        )
            .cmp(&(
                right.kind.as_str(),
                right.rva_start.unwrap_or(u64::MAX),
                right.id.as_str(),
            ))
    });

    let indexes = build_indexes(&rows);
    let (packets, manifest) = build_packets(&rows, &indexes, packet_mode);
    let summary = SymbolGraphSummary {
        schema: "symbol_graph_summary/1".to_string(),
        graph_records: rows.len(),
        address_ranges: indexes.address_range_index.len(),
        name_keys: indexes.name_index.len(),
        packets: packets.len(),
        packet_mode: packet_mode.to_string(),
    };

    SymbolGraphArtifacts {
        rows,
        indexes,
        packets,
        manifest,
        summary,
    }
}

pub fn write_symbol_artifacts(
    out_dir: &Path,
    artifacts: &SymbolGraphArtifacts,
) -> Result<(), Box<dyn Error>> {
    write_jsonl(out_dir.join("symbol_graph.jsonl"), &artifacts.rows)?;
    write_json(out_dir.join("symbol_indexes.json"), &artifacts.indexes)?;

    let packet_dir = out_dir.join("symbol_packets");
    fs::create_dir_all(&packet_dir)?;
    for (file_name, packet) in &artifacts.packets {
        write_json(packet_dir.join(file_name), packet)?;
    }
    write_json(packet_dir.join("manifest.json"), &artifacts.manifest)?;
    Ok(())
}

pub fn query_symbol_packet(
    out_dir: &Path,
    query_kind: &str,
    query: &str,
) -> Result<LlmSymbolPacket, Box<dyn Error>> {
    let rows = read_symbol_graph(out_dir)?;
    let indexes = build_indexes(&rows);
    let matches = query_matches(&rows, &indexes, query_kind, query);
    Ok(packet_for_matches(
        &rows, &indexes, query_kind, query, matches,
    ))
}

fn build_context(debug: &DebugSymbolOutput, artifact_id: &str) -> GraphContext {
    let mut source_files = BTreeMap::new();
    for file in &debug.source_files {
        source_files.insert(file.file_id.clone(), file.clone());
    }
    GraphContext {
        artifact_id: artifact_id.to_string(),
        source_files,
    }
}

fn source_file_row(source: &SourceFileRecord, artifact_id: &str) -> SymbolGraphRecord {
    SymbolGraphRecord {
        schema: GRAPH_SCHEMA.to_string(),
        id: SourceFileId(source.file_id.clone()).0,
        kind: "source_file".to_string(),
        label: source.path.clone(),
        artifact_id: artifact_id.to_string(),
        provider: source.provider.clone(),
        confidence: source.confidence.clone(),
        rva_start: None,
        rva_end: None,
        source_file: Some(source.path.clone()),
        line_start: None,
        line_end: None,
        related: Vec::new(),
        evidence: address_evidence(&source.evidence),
        attributes: json!({
            "checksum": source.checksum,
        }),
    }
}

fn symbol_row(
    symbol: &DebugSymbolRecord,
    artifact_id: &str,
    debug: &DebugSymbolOutput,
    ctx: &GraphContext,
) -> SymbolGraphRecord {
    let mut related = vec![format!("debug_module:{}", symbol.module_id)];
    let mut source_file = None;
    let mut line_start = None;
    let mut line_end = None;
    for line in overlapping_lines(symbol, debug).into_iter().take(8) {
        related.push(line.line_id.clone());
        if source_file.is_none() {
            source_file = ctx
                .source_files
                .get(&line.file_id)
                .map(|source| source.path.clone());
            line_start = Some(line.line);
            line_end = Some(line.line);
        } else {
            line_start = line_start.map(|current| current.min(line.line));
            line_end = line_end.map(|current| current.max(line.line));
        }
    }

    SymbolGraphRecord {
        schema: GRAPH_SCHEMA.to_string(),
        id: SymbolId(symbol.symbol_id.clone()).0,
        kind: if symbol.function {
            "function_symbol"
        } else {
            "data_symbol"
        }
        .to_string(),
        label: symbol.name.clone(),
        artifact_id: artifact_id.to_string(),
        provider: symbol.provider.clone(),
        confidence: symbol.confidence.clone(),
        rva_start: Some(symbol.start_rva),
        rva_end: Some(symbol.end_rva.max(symbol.start_rva.saturating_add(1))),
        source_file,
        line_start,
        line_end,
        related,
        evidence: address_evidence(&symbol.evidence),
        attributes: json!({
            "linkage_name": symbol.linkage_name,
            "kind": symbol.kind,
            "function": symbol.function,
        }),
    }
}

fn line_row(line: &LineEntryRecord, artifact_id: &str, ctx: &GraphContext) -> SymbolGraphRecord {
    let source = ctx.source_files.get(&line.file_id);
    SymbolGraphRecord {
        schema: GRAPH_SCHEMA.to_string(),
        id: line.line_id.clone(),
        kind: "line_row".to_string(),
        label: source
            .map(|row| format!("{}:{}", row.path, line.line))
            .unwrap_or_else(|| format!("line:{}", line.line)),
        artifact_id: ctx.artifact_id.clone().if_empty(artifact_id),
        provider: line.provider.clone(),
        confidence: line.confidence.clone(),
        rva_start: Some(line.start_rva),
        rva_end: Some(line.end_rva.max(line.start_rva.saturating_add(1))),
        source_file: source.map(|row| row.path.clone()),
        line_start: Some(line.line),
        line_end: Some(line.line),
        related: vec![line.file_id.clone()],
        evidence: address_evidence(&line.evidence),
        attributes: json!({
            "file_id": line.file_id,
            "column": line.column,
            "flags": line.flags,
        }),
    }
}

fn uncertainty_row(uncertainty: &SymbolUncertaintyRecord, artifact_id: &str) -> SymbolGraphRecord {
    SymbolGraphRecord {
        schema: GRAPH_SCHEMA.to_string(),
        id: EvidenceId(uncertainty.uncertainty_id.clone()).0,
        kind: "symbol_evidence".to_string(),
        label: uncertainty.code.clone(),
        artifact_id: artifact_id.to_string(),
        provider: uncertainty.provider.clone(),
        confidence: uncertainty.severity.clone(),
        rva_start: None,
        rva_end: None,
        source_file: None,
        line_start: None,
        line_end: None,
        related: vec![format!("debug_module:{}", uncertainty.module_id)],
        evidence: address_evidence(&uncertainty.evidence),
        attributes: json!({
            "category": "uncertainty",
            "code": uncertainty.code,
            "message": uncertainty.message,
            "recommended_action": uncertainty.recommended_action,
            "severity": uncertainty.severity,
        }),
    }
}

fn build_indexes(rows: &[SymbolGraphRecord]) -> SymbolIndexes {
    let mut address_range_index = Vec::new();
    let mut name_index = BTreeMap::<String, BTreeSet<String>>::new();
    let mut source_index = BTreeMap::<String, BTreeSet<String>>::new();
    let mut type_index = BTreeMap::<String, BTreeSet<String>>::new();
    let mut compile_unit_index = BTreeMap::<String, BTreeSet<String>>::new();
    let mut evidence_index = BTreeMap::<String, Vec<String>>::new();

    for row in rows {
        if let (Some(start), Some(end)) = (row.rva_start, row.rva_end) {
            if start < end
                && matches!(
                    row.kind.as_str(),
                    "function_symbol" | "data_symbol" | "line_row" | "inline_site"
                )
            {
                address_range_index.push(AddressIndexEntry {
                    start_rva: start,
                    end_rva: end,
                    target_id: row.id.clone(),
                    target_kind: row.kind.clone(),
                    label: row.label.clone(),
                    confidence: row.confidence.clone(),
                });
            }
        }

        for key in name_keys(row) {
            insert_index(&mut name_index, key, &row.id);
        }

        if let Some(source) = &row.source_file {
            insert_index(&mut source_index, source.clone(), &row.id);
            insert_index(&mut source_index, source.to_ascii_lowercase(), &row.id);
            if let Some(short) = Path::new(source).file_name().and_then(|name| name.to_str()) {
                insert_index(&mut source_index, short.to_string(), &row.id);
                insert_index(&mut source_index, short.to_ascii_lowercase(), &row.id);
            }
        }

        if row.kind == "type_def" {
            insert_index(&mut type_index, row.label.clone(), &row.id);
            insert_index(&mut type_index, row.label.to_ascii_lowercase(), &row.id);
            if let Some(raw_key) = row.attributes.get("raw_key").and_then(Value::as_str) {
                insert_index(&mut type_index, raw_key.to_string(), &row.id);
            }
        }

        if row.kind == "compile_unit" {
            insert_index(&mut compile_unit_index, row.label.clone(), &row.id);
            insert_index(
                &mut compile_unit_index,
                row.label.to_ascii_lowercase(),
                &row.id,
            );
        }

        evidence_index.insert(row.id.clone(), row.evidence.clone());
    }

    address_range_index.sort_by(|left, right| {
        (
            left.start_rva,
            left.end_rva,
            left.target_kind.as_str(),
            left.target_id.as_str(),
        )
            .cmp(&(
                right.start_rva,
                right.end_rva,
                right.target_kind.as_str(),
                right.target_id.as_str(),
            ))
    });

    SymbolIndexes {
        schema: INDEX_SCHEMA.to_string(),
        address_range_index,
        name_index: flatten_index(name_index),
        source_index: flatten_index(source_index),
        type_index: flatten_index(type_index),
        compile_unit_index: flatten_index(compile_unit_index),
        evidence_index,
    }
}

fn build_packets(
    rows: &[SymbolGraphRecord],
    indexes: &SymbolIndexes,
    packet_mode: &str,
) -> (Vec<(String, LlmSymbolPacket)>, SymbolPacketManifest) {
    if packet_mode == "off" {
        return (
            Vec::new(),
            SymbolPacketManifest {
                schema: PACKET_MANIFEST_SCHEMA.to_string(),
                packet_mode: packet_mode.to_string(),
                packets: Vec::new(),
            },
        );
    }

    let limit = if packet_mode == "all" { usize::MAX } else { 32 };
    let mut packets = Vec::new();
    let mut manifest_entries = Vec::new();

    for (index, row) in rows
        .iter()
        .filter(|row| row.kind == "function_symbol")
        .take(limit)
        .enumerate()
    {
        let packet = packet_for_matches(rows, indexes, "name", &row.label, vec![row.id.clone()]);
        let file_name = format!(
            "function_{index:04}_{}.json",
            safe_file_component(&row.label)
        );
        manifest_entries.push(SymbolPacketManifestEntry {
            path: format!("symbol_packets/{file_name}"),
            packet_id: packet.packet_id.clone(),
            query_kind: packet.query_kind.clone(),
            query: packet.query.clone(),
            exact_match_count: packet.exact_matches.len(),
            nearby_count: packet.nearby_symbols.len(),
        });
        packets.push((file_name, packet));
    }

    (
        packets,
        SymbolPacketManifest {
            schema: PACKET_MANIFEST_SCHEMA.to_string(),
            packet_mode: packet_mode.to_string(),
            packets: manifest_entries,
        },
    )
}

fn query_matches(
    rows: &[SymbolGraphRecord],
    indexes: &SymbolIndexes,
    query_kind: &str,
    query: &str,
) -> Vec<String> {
    match query_kind {
        "address" => parse_address(query)
            .into_iter()
            .flat_map(|address| most_specific_address_hits(indexes, address))
            .collect(),
        "name" => lookup_index(&indexes.name_index, query),
        "source" => lookup_source(indexes, query),
        "type" => lookup_index(&indexes.type_index, query),
        _ => rows
            .iter()
            .filter(|row| row.label == query)
            .map(|row| row.id.clone())
            .collect(),
    }
}

fn packet_for_matches(
    rows: &[SymbolGraphRecord],
    indexes: &SymbolIndexes,
    query_kind: &str,
    query: &str,
    matches: Vec<String>,
) -> LlmSymbolPacket {
    let row_by_id = rows
        .iter()
        .map(|row| (row.id.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    let exact_rows = matches
        .iter()
        .filter_map(|id| row_by_id.get(id.as_str()).copied())
        .collect::<Vec<_>>();

    let exact_matches = exact_rows
        .iter()
        .map(|row| fact_from_row(row))
        .collect::<Vec<_>>();
    let nearby_symbols = nearby_symbols(rows, &exact_rows)
        .into_iter()
        .map(fact_from_row)
        .collect::<Vec<_>>();
    let source_context = source_context(rows, &exact_rows)
        .into_iter()
        .map(fact_from_row)
        .collect::<Vec<_>>();
    let inline_frames = inline_context(rows, &exact_rows)
        .into_iter()
        .map(fact_from_row)
        .collect::<Vec<_>>();
    let type_context = type_context(rows, &exact_rows, indexes)
        .into_iter()
        .map(fact_from_row)
        .collect::<Vec<_>>();

    LlmSymbolPacket {
        schema: PACKET_SCHEMA.to_string(),
        packet_id: format!(
            "symbol_packet:{}:{}",
            query_kind,
            safe_file_component(query)
        ),
        query_kind: query_kind.to_string(),
        query: query.to_string(),
        exact_matches,
        nearby_symbols,
        source_context,
        inline_frames,
        type_context,
        warnings: uncertainty_warnings(rows),
    }
}

fn fact_from_row(row: &SymbolGraphRecord) -> SymbolFact {
    let address_ranges = match (row.rva_start, row.rva_end) {
        (Some(start), Some(end)) => vec![AddressRangeFact {
            rva_start: start,
            rva_end: end,
        }],
        _ => Vec::new(),
    };
    let source = match (&row.source_file, row.line_start, row.line_end) {
        (Some(file), Some(start), Some(end)) => vec![SourceFact {
            file: file.clone(),
            line_start: start,
            line_end: end,
        }],
        _ => Vec::new(),
    };

    SymbolFact {
        id: row.id.clone(),
        kind: row.kind.clone(),
        label: row.label.clone(),
        provider: row.provider.clone(),
        confidence: row.confidence.clone(),
        address_ranges,
        source,
        evidence: row.evidence.clone(),
        attributes: row.attributes.clone(),
    }
}

fn overlapping_lines<'a>(
    symbol: &DebugSymbolRecord,
    debug: &'a DebugSymbolOutput,
) -> Vec<&'a LineEntryRecord> {
    let mut lines = debug
        .line_entries
        .iter()
        .filter(|line| {
            ranges_overlap(
                symbol.start_rva,
                symbol.end_rva,
                line.start_rva,
                line.end_rva,
            )
        })
        .collect::<Vec<_>>();
    lines.sort_by_key(|line| (line.start_rva, line.line_id.clone()));
    lines
}

fn source_context<'a>(
    rows: &'a [SymbolGraphRecord],
    exact_rows: &[&'a SymbolGraphRecord],
) -> Vec<&'a SymbolGraphRecord> {
    let mut out = Vec::new();
    for exact in exact_rows {
        if let (Some(start), Some(end)) = (exact.rva_start, exact.rva_end) {
            out.extend(rows.iter().filter(|row| {
                row.kind == "line_row"
                    && row
                        .rva_start
                        .zip(row.rva_end)
                        .map(|(line_start, line_end)| {
                            ranges_overlap(start, end, line_start, line_end)
                        })
                        .unwrap_or(false)
            }));
        }
    }
    dedup_row_refs(out, 16)
}

fn inline_context<'a>(
    rows: &'a [SymbolGraphRecord],
    exact_rows: &[&'a SymbolGraphRecord],
) -> Vec<&'a SymbolGraphRecord> {
    let mut out = Vec::new();
    for exact in exact_rows {
        if let (Some(start), Some(end)) = (exact.rva_start, exact.rva_end) {
            out.extend(rows.iter().filter(|row| {
                row.kind == "inline_site"
                    && row
                        .rva_start
                        .zip(row.rva_end)
                        .map(|(inline_start, inline_end)| {
                            ranges_overlap(start, end, inline_start, inline_end)
                        })
                        .unwrap_or(false)
            }));
        }
    }
    dedup_row_refs(out, 16)
}

fn type_context<'a>(
    rows: &'a [SymbolGraphRecord],
    exact_rows: &[&'a SymbolGraphRecord],
    indexes: &SymbolIndexes,
) -> Vec<&'a SymbolGraphRecord> {
    let mut ids = BTreeSet::new();
    for exact in exact_rows {
        for key in name_keys(exact) {
            for id in lookup_index(&indexes.type_index, &key) {
                ids.insert(id);
            }
        }
    }
    let by_id = rows
        .iter()
        .map(|row| (row.id.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    ids.into_iter()
        .filter_map(|id| by_id.get(id.as_str()).copied())
        .take(16)
        .collect()
}

fn nearby_symbols<'a>(
    rows: &'a [SymbolGraphRecord],
    exact_rows: &[&'a SymbolGraphRecord],
) -> Vec<&'a SymbolGraphRecord> {
    let Some(anchor) = exact_rows.iter().find_map(|row| row.rva_start) else {
        return Vec::new();
    };
    let mut candidates = rows
        .iter()
        .filter(|row| row.kind == "function_symbol")
        .filter(|row| !exact_rows.iter().any(|exact| exact.id == row.id))
        .filter_map(|row| row.rva_start.map(|start| (start.abs_diff(anchor), row)))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(distance, row)| (*distance, row.rva_start, row.id.clone()));
    candidates.into_iter().map(|(_, row)| row).take(6).collect()
}

fn uncertainty_warnings(rows: &[SymbolGraphRecord]) -> Vec<String> {
    rows.iter()
        .filter(|row| {
            row.kind == "symbol_evidence"
                && row
                    .attributes
                    .get("category")
                    .and_then(Value::as_str)
                    .is_some_and(|category| category == "uncertainty")
        })
        .filter_map(|row| {
            let message = row.attributes.get("message").and_then(Value::as_str)?;
            Some(format!("{}: {}", row.label, message))
        })
        .take(16)
        .collect()
}

fn most_specific_address_hits(indexes: &SymbolIndexes, address: u64) -> Vec<String> {
    let mut hits = indexes
        .address_range_index
        .iter()
        .filter(|entry| entry.start_rva <= address && address < entry.end_rva)
        .collect::<Vec<_>>();
    hits.sort_by_key(|entry| {
        (
            entry.end_rva.saturating_sub(entry.start_rva),
            std::cmp::Reverse(entry.start_rva),
            entry.target_id.clone(),
        )
    });
    hits.into_iter()
        .take(8)
        .map(|entry| entry.target_id.clone())
        .collect()
}

fn lookup_index(index: &BTreeMap<String, Vec<String>>, query: &str) -> Vec<String> {
    index
        .get(query)
        .or_else(|| index.get(&query.to_ascii_lowercase()))
        .cloned()
        .unwrap_or_default()
}

fn lookup_source(indexes: &SymbolIndexes, query: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for id in lookup_index(&indexes.source_index, query) {
        out.insert(id);
    }
    let needle = query.to_ascii_lowercase();
    for (key, ids) in &indexes.source_index {
        if key.to_ascii_lowercase().contains(&needle) {
            for id in ids {
                out.insert(id.clone());
            }
        }
    }
    out.into_iter().collect()
}

fn name_keys(row: &SymbolGraphRecord) -> Vec<String> {
    if !matches!(
        row.kind.as_str(),
        "function_symbol" | "data_symbol" | "type_def" | "compile_unit" | "source_file"
    ) {
        return Vec::new();
    }
    let mut keys = BTreeSet::new();
    keys.insert(row.label.clone());
    keys.insert(row.label.to_ascii_lowercase());
    for separator in ["::", "!", ".", "$"] {
        if let Some(short) = row.label.rsplit(separator).next() {
            if !short.is_empty() {
                keys.insert(short.to_string());
                keys.insert(short.to_ascii_lowercase());
            }
        }
    }
    if let Some(linkage) = row.attributes.get("linkage_name").and_then(Value::as_str) {
        keys.insert(linkage.to_string());
        keys.insert(linkage.to_ascii_lowercase());
    }
    keys.into_iter().collect()
}

fn insert_index(index: &mut BTreeMap<String, BTreeSet<String>>, key: String, id: &str) {
    if key.is_empty() {
        return;
    }
    index.entry(key).or_default().insert(id.to_string());
}

fn flatten_index(index: BTreeMap<String, BTreeSet<String>>) -> BTreeMap<String, Vec<String>> {
    index
        .into_iter()
        .map(|(key, ids)| (key, ids.into_iter().collect()))
        .collect()
}

fn dedup_row_refs<'a>(
    rows: Vec<&'a SymbolGraphRecord>,
    limit: usize,
) -> Vec<&'a SymbolGraphRecord> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for row in rows {
        if seen.insert(row.id.clone()) {
            out.push(row);
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn read_symbol_graph(out_dir: &Path) -> Result<Vec<SymbolGraphRecord>, Box<dyn Error>> {
    let path = out_dir.join("symbol_graph.jsonl");
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    let mut rows = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        rows.push(serde_json::from_str::<SymbolGraphRecord>(&line)?);
    }
    Ok(rows)
}

fn write_json<T: Serialize>(path: PathBuf, value: &T) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    serde_json::to_writer_pretty(BufWriter::new(file), value)?;
    Ok(())
}

fn write_jsonl<T: Serialize>(path: PathBuf, rows: &[T]) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);
    for row in rows {
        serde_json::to_writer(&mut writer, row)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn address_evidence(addresses: &[u64]) -> Vec<String> {
    addresses
        .iter()
        .map(|address| format!("rva_or_va:{address:016X}"))
        .collect()
}

fn parse_address(query: &str) -> Option<u64> {
    let trimmed = query.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        trimmed
            .parse::<u64>()
            .ok()
            .or_else(|| u64::from_str_radix(trimmed, 16).ok())
    }
}

fn ranges_overlap(left_start: u64, left_end: u64, right_start: u64, right_end: u64) -> bool {
    let left_end = left_end.max(left_start.saturating_add(1));
    let right_end = right_end.max(right_start.saturating_add(1));
    left_start < right_end && right_start < left_end
}

trait IfEmpty {
    fn if_empty(self, fallback: &str) -> String;
}

impl IfEmpty for String {
    fn if_empty(self, fallback: &str) -> String {
        if self.is_empty() {
            fallback.to_string()
        } else {
            self
        }
    }
}
