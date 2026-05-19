use crate::{
    api_hash, behavior, cfg, cpp, dataflow, debug_symbols, decoder, deobfuscation, disasm,
    dossiers, eval, functions, jump_tables, llm_artifacts, portable, pseudo_ir, second_pass,
    semantic_index, ssa, strings, structured, symbol_graph, type_inference, value_graph, vsa,
    winapi, wrappers, xrefs,
};
#[cfg(feature = "unpack")]
use memmap2::MmapMut;
use memmap2::{Mmap, MmapOptions};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLLCHARACTERISTICS_GUARD_CF: u16 = 0x4000;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

// Feature-conditional element type for `AnalysisOptions::vuln_dynamic_evidence`.
// When `vuln-discovery` is enabled, the slot carries real `DynamicEvidence`
// records; otherwise it holds an opaque `()` placeholder so the surrounding
// struct (and its consumers) still compile on default features. The field
// itself stays unconditional so callers can always set `Vec::new()` without
// `cfg!` shims.
#[cfg(feature = "vuln-discovery")]
pub type VulnDynamicEvidenceItem = crate::vuln::dynamic_evidence::DynamicEvidence;
#[cfg(not(feature = "vuln-discovery"))]
pub type VulnDynamicEvidenceItem = ();

#[derive(Clone)]
pub struct AnalysisOptions {
    pub preset: Option<String>,
    pub max_strings: usize,
    pub max_functions: usize,
    pub max_xrefs: usize,
    pub deep: bool,
    pub precomputed_sha256: Option<String>,
    pub native_inner_workers: Option<String>,
    pub profile_analysis: bool,
    pub semantic_level: String,
    pub second_pass: String,
    pub semantic_budget: String,
    pub semantic_focus: String,
    pub wrapper_collapse_depth: usize,
    pub pseudo_ir: String,
    pub capability_profile: String,
    pub portable_tools_dir: String,
    pub emulation_budget: String,
    pub fuzz_mode: String,
    pub fuzz_iterations: usize,
    pub trace_dir: Option<String>,
    // Dynamic-trace pipeline (Codex finding 1 fix: standalone feature
    // not implied by `fuzzer`). Default `off`.
    pub dynamic_trace_mode: String,
    pub dynamic_trace_duration_secs: u64,
    pub dynamic_trace_target: Option<String>,
    pub dynamic_trace_out: Option<String>,
    pub dynamic_trace_providers: String,
    pub dynamic_trace_loss_policy: String,
    // Vuln-discovery pipeline (v1.0 static-only; v1.1 gated by
    // real-binary calibration per docs/vuln-calibration.md).
    pub vuln_discovery_mode: String,
    pub vuln_templates: String,
    pub vuln_confidence_threshold: f32,
    pub vuln_out: Option<String>,
    pub vuln_dynamic_confirmation: String,
    pub vuln_dynamic_evidence: Vec<VulnDynamicEvidenceItem>,
    pub vuln_include_lifetime: bool,
    pub vuln_harness_tier: String,
    // Aurora unpacker. Default `off`; when enabled, the analyzer
    // records unavailable/skipped states honestly and only recurses
    // into a snapshot when Aurora actually emits one.
    pub unpack_mode: String,
    pub unpack_tracer: String,
    pub unpack_timeout_secs: u64,
    pub unpack_instr_budget: u64,
    pub unpack_out: Option<String>,
    pub unpack_hooks_disable: bool,
    pub unpack_include_devirt: bool,
    pub decompile_c: String,
    pub llm_artifacts: String,
    pub review_packs: String,
    pub decompile_source: String,
    pub symbols: String,
    pub symbol_packets: String,
    pub symbol_paths: Vec<String>,
    pub symbol_cache: Option<String>,
    pub progress_path: Option<String>,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            preset: None,
            max_strings: 8192,
            max_functions: 4096,
            max_xrefs: 65536,
            deep: true,
            precomputed_sha256: None,
            native_inner_workers: None,
            profile_analysis: false,
            semantic_level: "basic".to_string(),
            second_pass: "auto".to_string(),
            semantic_budget: "normal".to_string(),
            semantic_focus: "malware".to_string(),
            wrapper_collapse_depth: 4,
            pseudo_ir: "basic".to_string(),
            capability_profile: "native-max".to_string(),
            portable_tools_dir: "tools".to_string(),
            emulation_budget: "normal".to_string(),
            fuzz_mode: "execute".to_string(),
            fuzz_iterations: 16,
            trace_dir: None,
            dynamic_trace_mode: "off".to_string(),
            dynamic_trace_duration_secs: 30,
            dynamic_trace_target: None,
            dynamic_trace_out: None,
            dynamic_trace_providers: "file,registry,network,dns,process,image_load".to_string(),
            dynamic_trace_loss_policy: "partial".to_string(),
            vuln_discovery_mode: "off".to_string(),
            vuln_templates: "all".to_string(),
            vuln_confidence_threshold: 0.45,
            vuln_out: None,
            vuln_dynamic_confirmation: "off".to_string(),
            vuln_dynamic_evidence: Vec::new(),
            vuln_include_lifetime: false,
            vuln_harness_tier: "skeleton".to_string(),
            unpack_mode: "off".to_string(),
            unpack_tracer: "debug".to_string(),
            unpack_timeout_secs: 60,
            unpack_instr_budget: 100_000_000,
            unpack_out: None,
            unpack_hooks_disable: false,
            unpack_include_devirt: false,
            decompile_c: "selected".to_string(),
            llm_artifacts: "all".to_string(),
            review_packs: "ranked".to_string(),
            decompile_source: "selected".to_string(),
            symbols: "basic".to_string(),
            symbol_packets: "ranked".to_string(),
            symbol_paths: Vec::new(),
            symbol_cache: None,
            progress_path: None,
        }
    }
}

impl AnalysisOptions {
    pub fn real_5_preset() -> Self {
        let mut options = Self {
            preset: Some("real-5".to_string()),
            ..Self::default()
        };
        options.apply_real_5_profile();
        options
    }

    pub fn real_8_preset() -> Self {
        let mut options = Self {
            preset: Some("real-8".to_string()),
            ..Self::default()
        };
        options.apply_real_8_profile();
        options
    }

    pub fn real_9_preset() -> Self {
        let mut options = Self {
            preset: Some("real-9".to_string()),
            ..Self::default()
        };
        options.apply_real_9_profile();
        options
    }

    pub fn apply_real_5_profile(&mut self) {
        self.preset = Some("real-5".to_string());
        self.vuln_discovery_mode = "on".to_string();
        self.vuln_dynamic_confirmation = "all".to_string();
        self.vuln_include_lifetime = true;
        self.vuln_harness_tier = "both".to_string();
        self.pseudo_ir = "expanded".to_string();
        self.semantic_budget = "high".to_string();
        self.second_pass = "all".to_string();
        self.llm_artifacts = "all".to_string();
        self.review_packs = "all".to_string();
        self.symbols = "full".to_string();
        self.symbol_packets = "all".to_string();
        self.decompile_c = "selected".to_string();
    }

    pub fn apply_real_8_profile(&mut self) {
        self.apply_real_5_profile();
        self.preset = Some("real-8".to_string());
    }

    pub fn apply_real_9_profile(&mut self) {
        self.apply_real_8_profile();
        self.preset = Some("real-9".to_string());
    }
}

#[derive(Clone, Serialize)]
pub struct SectionRecord {
    pub name: String,
    pub rva: u32,
    pub va: u64,
    pub virtual_size: u32,
    pub raw_start: u32,
    pub raw_size: u32,
    pub data_size: usize,
    pub executable: bool,
    pub readable: bool,
    pub writable: bool,
    pub entropy: f64,
    #[serde(skip)]
    pub data_range: Range<usize>,
}

impl SectionRecord {
    pub fn data<'a>(&self, bytes: &'a [u8]) -> &'a [u8] {
        &bytes[self.data_range.clone()]
    }
}

#[derive(Clone, Serialize)]
pub struct ImportRecord {
    pub dll: String,
    pub name: String,
    pub symbol: String,
    pub va: u64,
    pub rva: u64,
    pub hint: Option<u16>,
    pub categories: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct ExportRecord {
    pub name: String,
    pub ordinal: u32,
    pub va: u64,
    pub rva: u32,
}

#[derive(Clone, Serialize)]
pub struct ExceptionRecord {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_rva: u32,
    pub begin: u64,
    pub end: u64,
    pub unwind: u64,
}

#[derive(Clone, Serialize)]
pub struct StringRecord {
    pub va: u64,
    pub rva: u64,
    pub file_offset: u64,
    pub encoding: String,
    pub size: usize,
    pub text: String,
    pub classifiers: Vec<String>,
    pub section: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct InstructionRecord {
    pub address: u64,
    pub size: u32,
    pub mnemonic: String,
    pub op_str: String,
    pub section: String,
    pub groups: Vec<String>,
    #[serde(skip)]
    pub is_call: bool,
    #[serde(skip)]
    pub is_jump: bool,
    #[serde(skip)]
    pub is_ret: bool,
    #[serde(skip)]
    pub branch_target: Option<u64>,
}

#[derive(Clone, Serialize)]
pub struct XrefRecord {
    pub kind: String,
    pub from: u64,
    pub target: u64,
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct FunctionRecord {
    pub start: u64,
    pub end: u64,
    pub size: u64,
    pub source: String,
    pub calls: Vec<u64>,
    pub calls_imports: Vec<String>,
    pub strings: Vec<String>,
    pub xrefs: usize,
}

#[derive(Clone, Serialize)]
pub struct BasicBlockRecord {
    pub start: u64,
    pub end: u64,
    pub instruction_count: usize,
}

#[derive(Clone, Serialize)]
pub struct EdgeRecord {
    pub from: u64,
    pub to: u64,
    #[serde(rename = "type")]
    pub edge_type: String,
}

#[derive(Clone, Serialize)]
pub struct CfgRecord {
    pub function: u64,
    pub blocks: Vec<BasicBlockRecord>,
    pub edges: Vec<EdgeRecord>,
}

#[derive(Clone, Serialize)]
pub struct VTableRecord {
    pub va: u64,
    pub rva: u64,
    pub section: String,
    pub method_count: usize,
    pub methods: Vec<u64>,
    pub probable_class: Option<String>,
    pub col_va: Option<u64>,
    pub class_descriptor_va: Option<u64>,
    pub base_classes: Vec<String>,
    pub constructor_candidates: Vec<u64>,
    pub ownership_confidence: String,
}

#[derive(Clone, Serialize)]
pub struct RttiRecord {
    pub va: u64,
    pub rva: u64,
    pub text: String,
    pub section: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct ApiFlowRecord {
    pub flow_id: String,
    pub function: u64,
    pub callsite: u64,
    pub api: String,
    pub normalized_api: String,
    pub api_tier: String,
    pub api_family: String,
    pub semantic_relevance: String,
    pub noise_reason: Option<String>,
    pub api_categories: Vec<String>,
    pub value: String,
    pub value_tags: Vec<String>,
    pub argument: String,
    pub argument_register: Option<String>,
    pub argument_index: Option<usize>,
    pub argument_name: Option<String>,
    pub confidence: String,
    pub mode: String,
    pub resolved_api: Option<String>,
    pub wrapper_chain: Vec<u64>,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct CallGraphRecord {
    pub caller: u64,
    pub callee: Option<u64>,
    pub import: Option<String>,
    pub callsite: u64,
    pub call_kind: String,
    pub confidence: String,
    pub resolved_api: Option<String>,
    pub wrapper_chain: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct ResolvedCallRecord {
    pub caller: u64,
    pub callsite: u64,
    pub original_callee: u64,
    pub resolved_api: String,
    pub wrapper_chain: Vec<u64>,
    pub chain_depth: usize,
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vtable_va: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vtable_slot: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidate_targets: Vec<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidate_classes: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct ValueGraphRecord {
    pub value_id: String,
    pub function: u64,
    pub source_instruction: u64,
    pub location: String,
    pub inferred_type: String,
    pub value: Option<String>,
    pub target_va: Option<u64>,
    pub evidence: Vec<u64>,
    pub confidence: String,
}

#[derive(Clone, Serialize)]
pub struct VsaValueRecord {
    pub value_id: String,
    pub function: u64,
    pub site_va: u64,
    pub location: String,
    pub kind: String,
    pub lo: Option<u64>,
    pub hi: Option<u64>,
    pub stride: u64,
    pub value: Option<String>,
    pub target_va: Option<u64>,
    pub evidence: Vec<u64>,
    pub confidence: String,
    pub region: String,
    pub expression: Option<String>,
    pub base: Option<String>,
    pub index: Option<String>,
    pub scale: u32,
    pub displacement: i64,
    pub possible_values: Vec<u64>,
    pub work_budget_exhausted: bool,
}

#[derive(Clone, Serialize)]
pub struct SsaValueRecord {
    pub ssa_id: String,
    pub function: u64,
    pub block: Option<u64>,
    pub site_va: u64,
    pub storage: String,
    pub version: u32,
    pub kind: String,
    pub source: String,
    pub value: Option<String>,
    pub evidence: Vec<u64>,
    pub confidence: String,
}

#[derive(Clone, Serialize)]
pub struct DataflowEdgeRecord {
    pub edge_id: String,
    pub function: u64,
    pub from_value: Option<String>,
    pub to_value: String,
    pub from_va: Option<u64>,
    pub to_va: u64,
    pub from_storage: Option<String>,
    pub to_storage: String,
    pub edge_kind: String,
    pub type_tag: Option<String>,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct JumpTableRecord {
    pub table_id: String,
    pub function: u64,
    pub jump_va: u64,
    pub table_va: Option<u64>,
    pub entry_size: u32,
    pub targets: Vec<u64>,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct TypeHintRecord {
    pub type_id: String,
    pub function: u64,
    pub site_va: u64,
    pub location: String,
    pub type_tag: String,
    pub source: String,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct ApiHashResolutionRecord {
    pub resolution_id: String,
    pub function: u64,
    pub site_va: Option<u64>,
    pub algorithm: String,
    pub hash_value: String,
    pub resolved_api: String,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct FunctionQualityRecord {
    pub boundary_source: String,
    pub has_pdata: bool,
    pub has_return: bool,
    pub overlaps_known_function: bool,
    pub confidence: String,
}

#[derive(Clone, Serialize)]
pub struct RecoveredStringRecord {
    pub recovered_id: String,
    pub function: u64,
    pub kind: String,
    pub text: String,
    pub tags: Vec<String>,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct ObfuscationHintRecord {
    pub hint_id: String,
    pub function: u64,
    pub candidate_kind: String,
    pub description: String,
    pub tags: Vec<String>,
    pub confidence: String,
    pub evidence: Vec<u64>,
    pub uncertainty_reason: String,
}

#[derive(Clone, Serialize)]
pub struct FunctionDossierRecord {
    pub id: String,
    pub sample_sha256: String,
    pub function: u64,
    pub end: u64,
    pub size: u64,
    pub source: String,
    pub score: i64,
    pub confidence: String,
    pub calls: Vec<u64>,
    pub imports: Vec<String>,
    pub strings: Vec<String>,
    pub xrefs: usize,
    pub cfg_blocks: usize,
    pub cfg_edges: usize,
    pub tags: Vec<String>,
    pub semantic_tags: Vec<String>,
    pub behavior_summary: String,
    pub intent_summary: String,
    pub side_effects: Vec<String>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub resolved_api_summaries: Vec<ResolvedApiSummaryRecord>,
    pub pseudo_ir_id: Option<String>,
    pub structured_flow_id: Option<String>,
    pub api_flow_ids: Vec<String>,
    pub api_flow_summaries: Vec<ApiFlowSummaryRecord>,
    pub recovered_string_ids: Vec<String>,
    pub recovered_string_summaries: Vec<RecoveredStringSummaryRecord>,
    pub behavior_refs: Vec<String>,
    pub type_summaries: Vec<TypeSummaryRecord>,
    pub class_refs: Vec<String>,
    pub claim_evidence: Vec<ClaimEvidenceRecord>,
    pub dossier_quality: String,
    pub function_quality: FunctionQualityRecord,
}

#[derive(Clone, Serialize)]
pub struct ResolvedApiSummaryRecord {
    pub callsite: u64,
    pub resolved_api: String,
    pub chain_depth: usize,
    pub confidence: String,
}

#[derive(Clone, Serialize)]
pub struct ApiFlowSummaryRecord {
    pub flow_id: String,
    pub callsite: u64,
    pub api: String,
    pub value: String,
    pub value_tags: Vec<String>,
    pub argument: String,
    pub confidence: String,
    pub mode: String,
}

#[derive(Clone, Serialize)]
pub struct RecoveredStringSummaryRecord {
    pub recovered_id: String,
    pub kind: String,
    pub text: String,
    pub tags: Vec<String>,
    pub confidence: String,
}

#[derive(Clone, Serialize)]
pub struct TypeSummaryRecord {
    pub type_id: String,
    pub location: String,
    pub type_tag: String,
    pub confidence: String,
}

#[derive(Clone, Serialize)]
pub struct ClaimEvidenceRecord {
    pub claim: String,
    pub evidence_vas: Vec<u64>,
    pub confidence: String,
}

#[derive(Clone, Serialize)]
pub struct ClassDossierRecord {
    pub class_id: String,
    pub vtable: u64,
    pub vftable_va: u64,
    pub probable_class: Option<String>,
    pub base_classes: Vec<String>,
    pub method_count: usize,
    pub methods: Vec<u64>,
    pub constructors: Vec<u64>,
    pub col_va: Option<u64>,
    pub ownership_confidence: String,
    pub confidence: String,
}

#[derive(Clone, Serialize)]
pub struct BehaviorFeatureRecord {
    pub feature: String,
    pub name: String,
    pub va: Option<u64>,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct BehaviorDossierRecord {
    pub behavior_id: String,
    pub sample_sha256: String,
    pub function: u64,
    pub capability: String,
    pub title: String,
    pub supporting_features: Vec<BehaviorFeatureRecord>,
    pub api_flow_ids: Vec<String>,
    pub recovered_string_ids: Vec<String>,
    pub type_hint_ids: Vec<String>,
    pub evidence_vas: Vec<u64>,
    pub confidence: f64,
    pub uncertainty: Option<String>,
}

/// Runtime-observed behavior fact produced by the dynamic-trace
/// pipeline. Parallel to [`BehaviorDossierRecord`] (the static side)
/// — does NOT extend it. Codex finding 2 fix: keeping the records
/// separate avoids forcing schema changes through ~15 static-side
/// consumers (`attack.rs`, `dossiers.rs`, `summary.rs`, …).
///
/// The two record kinds are unioned at output time in
/// `dynamic_trace::llm_pack::emit_behavior_fact_union` (Step 12) so
/// the LLM consumer sees one fact stream.
///
/// `confidence` uses the structured `Confidence` shape (`band` +
/// `score`) instead of a bare f64 because the dynamic side often
/// emits low-confidence facts (e.g. a single small file write scored
/// 0.48) and the band makes LLM filtering easier.
#[cfg(feature = "dynamic-trace")]
#[derive(Clone, Debug, Serialize, serde::Deserialize)]
pub struct DynamicBehaviorFactRecord {
    pub schema: String,
    pub fact_id: String,
    pub run_id: String,
    pub category: String,
    pub claim: String,
    pub confidence: crate::facts::confidence::Confidence,
    pub evidence: Vec<crate::facts::evidence::EvidenceRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncertainty: Option<String>,
}

#[derive(Clone, Serialize)]
pub struct StructuredFlowRecord {
    pub structured_flow_id: String,
    pub function: u64,
    pub block_order: Vec<u64>,
    pub branch_edges: Vec<EdgeRecord>,
    pub fallthrough_edges: Vec<EdgeRecord>,
    pub return_blocks: Vec<u64>,
    pub backedges: Vec<EdgeRecord>,
    pub switch_candidates: Vec<u64>,
    pub has_loop_like_backedge: bool,
    pub switch_cases: Vec<u64>,
    pub goto_edges: Vec<EdgeRecord>,
    pub regions: Vec<String>,
    pub natural_loops: Vec<EdgeRecord>,
    pub shared_return_blocks: Vec<u64>,
    pub structuring_notes: Vec<String>,
    pub refined: bool,
    pub confidence: String,
}

#[derive(Clone, Serialize)]
pub struct PseudoIrRecord {
    pub pseudo_ir_id: String,
    pub function: u64,
    pub lines: Vec<String>,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct SecondPassTargetRecord {
    pub target_id: String,
    pub function: u64,
    pub reason: String,
    pub priority_score: i64,
    pub pass1_uncertainty: String,
    pub result_status: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct UncertaintyRecord {
    pub uncertainty_id: String,
    pub function: u64,
    pub site_va: Option<u64>,
    pub reason: String,
    pub details: String,
    pub tried: Vec<String>,
    pub recommended_action: String,
    pub severity_hint: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct SecondPassSummaryRecord {
    pub status: String,
    pub eligible_functions: usize,
    pub analyzed_functions: usize,
    pub skipped_by_budget: usize,
    pub reason_counts: BTreeMap<String, usize>,
    pub elapsed_seconds: f64,
    pub caps_hit: bool,
    pub vsa_values: usize,
    pub resolved_jump_tables: usize,
    pub resolved_hashes: usize,
    pub decoded_strings: usize,
    pub type_hints: usize,
    pub structured_refinements: usize,
    pub rtti_ownership_refinements: usize,
    pub resolved_virtual_calls: usize,
    pub ssa_values: usize,
    pub dataflow_edges: usize,
    pub behavior_dossiers: usize,
}

pub struct DisasmRange {
    pub section_rva: u32,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone)]
struct DataDirectory {
    rva: u32,
    size: u32,
}

pub struct PEImage {
    path: PathBuf,
    map: Mmap,
    pub base: u64,
    pub entry_va: u64,
    pub machine: u16,
    dll_characteristics: u16,
    data_directories: Vec<DataDirectory>,
    pub sections: Vec<SectionRecord>,
    pub imports: Vec<ImportRecord>,
    pub exports: Vec<ExportRecord>,
    pub exceptions: Vec<ExceptionRecord>,
    pub function_seeds_cache: Vec<u64>,
    pub overlay_offset_cache: Option<usize>,
}

impl PEImage {
    pub fn bytes(&self) -> &[u8] {
        &self.map
    }

    pub fn section_for_rva(&self, rva: u32) -> Option<&SectionRecord> {
        self.sections.iter().find(|section| {
            let size = section
                .virtual_size
                .max(section.raw_size)
                .max(section.data_size as u32);
            section.rva <= rva && rva < section.rva.saturating_add(size)
        })
    }

    pub fn section_for_va(&self, va: u64) -> Option<&SectionRecord> {
        if va < self.base {
            return None;
        }
        self.section_for_rva((va - self.base) as u32)
    }

    pub fn section_by_rva(&self, rva: u32) -> Option<&SectionRecord> {
        self.sections.iter().find(|section| section.rva == rva)
    }

    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        let section = self.section_for_rva(rva)?;
        let offset = rva.checked_sub(section.rva)? as usize;
        if offset >= section.raw_size.max(section.data_size as u32) as usize {
            return None;
        }
        Some(section.raw_start as usize + offset)
    }

    fn read_c_string_rva(&self, rva: u32) -> Option<String> {
        let start = self.rva_to_file_offset(rva)?;
        let bytes = self.bytes();
        let mut end = start;
        while end < bytes.len() && bytes[end] != 0 {
            end += 1;
        }
        Some(String::from_utf8_lossy(&bytes[start..end]).to_string())
    }

    fn directory(&self, index: usize) -> Option<&DataDirectory> {
        self.data_directories
            .get(index)
            .filter(|dir| dir.rva != 0 && dir.size != 0)
    }
}

impl crate::image::BinaryImage for PEImage {
    fn format(&self) -> crate::image::Format {
        crate::image::Format::Pe
    }
    fn bytes(&self) -> &[u8] {
        self.bytes()
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
    fn exceptions(&self) -> &[ExceptionRecord] {
        &self.exceptions
    }
    fn section_for_va(&self, va: u64) -> Option<&SectionRecord> {
        self.section_for_va(va)
    }
    fn section_by_rva(&self, rva: u32) -> Option<&SectionRecord> {
        self.section_by_rva(rva)
    }
    fn function_seeds(&self) -> Vec<u64> {
        self.function_seeds_cache.clone()
    }
    fn overlay_range(&self) -> Option<std::ops::Range<usize>> {
        self.overlay_offset_cache.map(|off| off..self.bytes().len())
    }
    fn source_path(&self) -> &str {
        self.path.to_str().unwrap_or("")
    }
    fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        PEImage::rva_to_file_offset(self, rva)
    }
    fn as_pe(&self) -> Option<&PEImage> {
        Some(self)
    }
}

pub fn run_analysis(
    image: &dyn crate::image::BinaryImage,
    out_dir: &str,
    options: AnalysisOptions,
) -> Result<String, Box<dyn Error>> {
    let total_started = Instant::now();
    let out_dir = Path::new(out_dir);
    fs::create_dir_all(out_dir)?;
    let mut profile = BTreeMap::new();
    let pe_path = image.source_path();
    let unpack_summary = maybe_run_unpack(pe_path, out_dir, &options)?;

    let hash_started = Instant::now();
    write_progress(&options, pe_path, "hash", &hash_started, &total_started);
    let sha256 = options
        .precomputed_sha256
        .clone()
        .unwrap_or_else(|| sha256_hex(image.bytes()));
    profile.insert("hash", hash_started.elapsed().as_secs_f64());

    let import_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "pe_tables",
        &import_started,
        &total_started,
    );
    let imports: Vec<ImportRecord> = image.imports().to_vec();
    let exports: Vec<ExportRecord> = image.exports().to_vec();
    let exceptions: Vec<ExceptionRecord> = image.exceptions().to_vec();
    profile.insert("pe_tables", import_started.elapsed().as_secs_f64());

    let string_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "strings",
        &string_started,
        &total_started,
    );
    let string_rows = strings::extract_strings(image, options.max_strings);
    profile.insert("strings", string_started.elapsed().as_secs_f64());

    let mut instructions = Vec::new();
    let mut ir_rows = Vec::new();
    let mut xref_rows = Vec::new();
    let mut function_rows = Vec::new();
    let mut cfg_rows = Vec::new();
    let mut disasm_capped = false;
    let max_instructions = instruction_budget(&options);
    if options.deep && image.machine() == IMAGE_FILE_MACHINE_AMD64 {
        let disasm_started = Instant::now();
        write_progress(&options, pe_path, "disasm", &disasm_started, &total_started);
        let import_symbols: BTreeMap<u64, String> = imports
            .iter()
            .map(|row| (row.va, row.symbol.clone()))
            .collect();
        let string_texts: BTreeMap<u64, String> = string_rows
            .iter()
            .map(|row| (row.va, row.text.clone()))
            .collect();
        let ranges = disassembly_ranges(image, &exceptions);
        let disasm_output = disasm::disassemble(
            image,
            &ranges,
            &import_symbols,
            &string_texts,
            options.max_xrefs,
            max_instructions,
        );
        disasm_capped = disasm_output.capped;
        instructions = disasm_output.instructions;
        ir_rows = disasm_output.ir;
        xref_rows = disasm_output.xrefs;
        profile.insert("disasm", disasm_started.elapsed().as_secs_f64());

        let functions_started = Instant::now();
        write_progress(
            &options,
            pe_path,
            "functions",
            &functions_started,
            &total_started,
        );
        function_rows = functions::discover_functions(
            image,
            &instructions,
            &exceptions,
            &exports,
            &disasm_output.direct_code_targets,
            options.max_functions,
        );
        xrefs::attach_function_refs(&mut function_rows, &xref_rows);
        profile.insert("functions", functions_started.elapsed().as_secs_f64());

        let cfg_started = Instant::now();
        write_progress(&options, pe_path, "cfg", &cfg_started, &total_started);
        cfg_rows = cfg::build_cfg(&function_rows, &instructions);
        profile.insert("cfg", cfg_started.elapsed().as_secs_f64());
    }

    let semantic_index_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "semantic_index",
        &semantic_index_started,
        &total_started,
    );
    let function_semantic_index = semantic_index::FunctionSemanticIndex::build(
        &function_rows,
        &instructions,
        &ir_rows,
        &xref_rows,
        &cfg_rows,
    );
    profile.insert(
        "semantic_index",
        semantic_index_started.elapsed().as_secs_f64(),
    );

    let cpp_started = Instant::now();
    write_progress(&options, pe_path, "cpp", &cpp_started, &total_started);
    let (mut vtables, rtti) = if options.deep {
        cpp::recover_cpp(image, &string_rows)
    } else {
        (Vec::new(), Vec::new())
    };
    profile.insert("cpp", cpp_started.elapsed().as_secs_f64());

    let eh_started = Instant::now();
    let eh_facts = crate::eh::extract_eh(image, image.exceptions(), &imports, &rtti);
    profile.insert("eh", eh_started.elapsed().as_secs_f64());

    let semantic_budget = semantic_index::SemanticBudget::from_name(&options.semantic_budget);
    let mut semantic_counters = semantic_index::SemanticCounters::default();
    let mut semantic_caps_hit = semantic_index::SemanticCapsHit::default();
    if options.semantic_level != "off" {
        semantic_counters.functions_semantically_scanned = function_semantic_index.slices.len();
    }

    let value_graph_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "value_graph",
        &value_graph_started,
        &total_started,
    );
    let value_graph_rows = if options.semantic_level == "off" {
        Vec::new()
    } else {
        value_graph::build_value_graph(
            &function_rows,
            &function_semantic_index,
            &ir_rows,
            &string_rows,
        )
    };
    profile.insert("value_graph", value_graph_started.elapsed().as_secs_f64());

    let empty_ssa_values: Vec<SsaValueRecord> = Vec::new();
    let empty_dataflow_edges: Vec<DataflowEdgeRecord> = Vec::new();

    let wrapper_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "wrapper_collapse",
        &wrapper_started,
        &total_started,
    );
    let mut resolved_calls = if options.semantic_level == "off" {
        Vec::new()
    } else {
        wrappers::resolve_calls(
            &function_rows,
            &function_semantic_index,
            &xref_rows,
            options.wrapper_collapse_depth,
        )
    };
    profile.insert("wrapper_collapse", wrapper_started.elapsed().as_secs_f64());

    let dataflow_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "dataflow",
        &dataflow_started,
        &total_started,
    );
    let (api_flows, callgraph) = if options.semantic_level == "off" {
        (Vec::new(), Vec::new())
    } else {
        (
            dataflow::build_api_flows(
                &function_rows,
                &function_semantic_index,
                &ir_rows,
                &xref_rows,
                &string_rows,
                &value_graph_rows,
                &resolved_calls,
                &semantic_budget,
                &mut semantic_counters,
                &mut semantic_caps_hit,
            ),
            dataflow::build_callgraph(
                &function_rows,
                &function_semantic_index,
                &xref_rows,
                &resolved_calls,
            ),
        )
    };
    profile.insert("dataflow", dataflow_started.elapsed().as_secs_f64());

    let deobfuscation_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "deobfuscation",
        &deobfuscation_started,
        &total_started,
    );
    let mut recovered_strings = if options.semantic_level == "off" {
        Vec::new()
    } else {
        deobfuscation::recover_strings(
            image,
            &function_rows,
            &function_semantic_index,
            &ir_rows,
            &semantic_budget,
            &mut semantic_counters,
            &mut semantic_caps_hit,
        )
    };
    profile.insert(
        "deobfuscation",
        deobfuscation_started.elapsed().as_secs_f64(),
    );

    let obfuscation_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "obfuscation_hints",
        &obfuscation_started,
        &total_started,
    );
    let obfuscation_hints = if options.semantic_level == "off" {
        Vec::new()
    } else {
        deobfuscation::obfuscation_hints(
            image,
            &function_rows,
            &function_semantic_index,
            &ir_rows,
            &semantic_budget,
            &mut semantic_counters,
            &mut semantic_caps_hit,
        )
    };
    profile.insert(
        "obfuscation_hints",
        obfuscation_started.elapsed().as_secs_f64(),
    );

    let structured_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "structured_flow",
        &structured_started,
        &total_started,
    );
    let mut structured_flow =
        structured::build_structured_flow(&function_rows, &cfg_rows, &instructions);
    profile.insert(
        "structured_flow",
        structured_started.elapsed().as_secs_f64(),
    );

    let pseudo_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "pseudo_ir",
        &pseudo_started,
        &total_started,
    );
    let pseudo_ir_rows = pseudo_ir::build_pseudo_ir(
        &function_rows,
        &value_graph_rows,
        &empty_ssa_values,
        &empty_dataflow_edges,
        &api_flows,
        &resolved_calls,
        &structured_flow,
        &[],
        &[],
        &[],
        &[],
        &options.pseudo_ir,
    );
    profile.insert("pseudo_ir", pseudo_started.elapsed().as_secs_f64());

    let dossiers_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "dossiers",
        &dossiers_started,
        &total_started,
    );
    let provisional_function_dossiers = dossiers::build_function_dossiers(
        &sha256,
        &function_rows,
        &cfg_rows,
        &function_semantic_index,
        &api_flows,
        &recovered_strings,
        &resolved_calls,
        &structured_flow,
        &pseudo_ir_rows,
        &[],
        &[],
        &[],
        &options.semantic_focus,
        &semantic_budget,
        &mut semantic_caps_hit,
    );
    profile.insert("dossiers", dossiers_started.elapsed().as_secs_f64());

    let pass1_profile = profile.clone();
    let second_pass_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "second_pass",
        &second_pass_started,
        &total_started,
    );
    let second_pass_result = second_pass::run_second_pass(second_pass::SecondPassInput {
        policy: &options.second_pass,
        budget_name: &semantic_budget.name,
        functions: &function_rows,
        semantic_index: &function_semantic_index,
        ir: &ir_rows,
        xrefs: &xref_rows,
        api_flows: &api_flows,
        function_dossiers: &provisional_function_dossiers,
        obfuscation_hints: &obfuscation_hints,
        recovered_strings: &recovered_strings,
        resolved_calls: &resolved_calls,
        structured_flow: &structured_flow,
    });
    profile.insert("second_pass", second_pass_started.elapsed().as_secs_f64());

    let mut pass2_profile = second_pass_result.profile.clone();
    let ssa_started = Instant::now();
    let ssa_result = if options.semantic_level == "off" || options.second_pass == "off" {
        ssa::SsaBuildResult {
            values: Vec::new(),
            dataflow_edges: Vec::new(),
            caps_hit: false,
        }
    } else {
        ssa::build_ssa_for_targets(
            &function_rows,
            &function_semantic_index,
            &ir_rows,
            &cfg_rows,
            &second_pass_result.targets,
            &semantic_budget.name,
        )
    };
    pass2_profile.insert("ssa".to_string(), ssa_started.elapsed().as_secs_f64());
    profile.insert("pass2_ssa", ssa_started.elapsed().as_secs_f64());

    let vsa_started = Instant::now();
    let vsa_values = if options.semantic_level == "off" || options.second_pass == "off" {
        Vec::new()
    } else {
        vsa::analyze_targets_with_cfg(
            &function_rows,
            &function_semantic_index,
            &ir_rows,
            &cfg_rows,
            &string_rows,
            &second_pass_result.targets,
            &semantic_budget.name,
        )
    };
    pass2_profile.insert("vsa".to_string(), vsa_started.elapsed().as_secs_f64());
    profile.insert("pass2_vsa", vsa_started.elapsed().as_secs_f64());

    let jump_started = Instant::now();
    let jump_tables = if options.semantic_level == "off" || options.second_pass == "off" {
        Vec::new()
    } else {
        jump_tables::build_jump_tables(
            image,
            &function_rows,
            &function_semantic_index,
            &ir_rows,
            &vsa_values,
            &second_pass_result.targets,
            &semantic_budget.name,
        )
    };
    pass2_profile.insert(
        "jump_tables".to_string(),
        jump_started.elapsed().as_secs_f64(),
    );
    profile.insert("pass2_jump_tables", jump_started.elapsed().as_secs_f64());

    let switches_started = Instant::now();
    let switches = crate::switches::build_switches(
        image,
        &function_rows,
        &function_semantic_index,
        &ir_rows,
        &jump_tables,
    );
    pass2_profile.insert(
        "switches".to_string(),
        switches_started.elapsed().as_secs_f64(),
    );
    profile.insert("pass2_switches", switches_started.elapsed().as_secs_f64());

    let hash_started = Instant::now();
    let api_hash_resolutions = if options.semantic_level == "off" || options.second_pass == "off" {
        Vec::new()
    } else {
        api_hash::resolve_api_hashes(&obfuscation_hints, &api_hash::import_symbols(&imports))
    };
    pass2_profile.insert("api_hash".to_string(), hash_started.elapsed().as_secs_f64());
    profile.insert("pass2_api_hash", hash_started.elapsed().as_secs_f64());

    let decoder_started = Instant::now();
    let decoded_strings = if options.semantic_level == "off" || options.second_pass == "off" {
        Vec::new()
    } else {
        decoder::recover_decoded_strings(image, &obfuscation_hints, &semantic_budget.name)
    };
    recovered_strings.extend(decoded_strings.iter().cloned());
    pass2_profile.insert(
        "decoder".to_string(),
        decoder_started.elapsed().as_secs_f64(),
    );
    profile.insert("pass2_decoder", decoder_started.elapsed().as_secs_f64());

    let type_started = Instant::now();
    let type_hints = if options.semantic_level == "off" || options.second_pass == "off" {
        Vec::new()
    } else {
        type_inference::infer_type_hints_for_targets(
            &api_flows,
            &second_pass_result.targets,
            &semantic_budget.name,
        )
    };
    pass2_profile.insert(
        "type_inference".to_string(),
        type_started.elapsed().as_secs_f64(),
    );
    profile.insert("pass2_type_inference", type_started.elapsed().as_secs_f64());

    let selected_functions: Vec<u64> = second_pass_result
        .targets
        .iter()
        .map(|row| row.function)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let structured_refine_started = Instant::now();
    let structured_refinements = if options.second_pass == "off" {
        0
    } else {
        structured::refine_selected_structured_flow(
            &mut structured_flow,
            &selected_functions,
            &jump_tables,
        )
    };
    pass2_profile.insert(
        "structured_refinement".to_string(),
        structured_refine_started.elapsed().as_secs_f64(),
    );
    profile.insert(
        "pass2_structured_refinement",
        structured_refine_started.elapsed().as_secs_f64(),
    );

    let cpp_refine_started = Instant::now();
    let rtti_ownership_refinements = if options.deep && options.second_pass != "off" {
        let (refined, count) = cpp::refine_vtable_ownership(
            vtables,
            &function_rows,
            &function_semantic_index,
            &ir_rows,
            &second_pass_result.targets,
        );
        vtables = refined;
        count
    } else {
        0
    };
    pass2_profile.insert(
        "rtti_ownership".to_string(),
        cpp_refine_started.elapsed().as_secs_f64(),
    );
    profile.insert(
        "pass2_rtti_ownership",
        cpp_refine_started.elapsed().as_secs_f64(),
    );

    let virtual_calls_started = Instant::now();
    let virtual_calls = if options.semantic_level == "off" || options.second_pass == "off" {
        Vec::new()
    } else {
        cpp::resolve_virtual_calls(
            &function_rows,
            &function_semantic_index,
            &ir_rows,
            &vtables,
            &second_pass_result.targets,
        )
    };
    let virtual_dispatch_resolutions = virtual_calls.len();
    resolved_calls.extend(virtual_calls);
    pass2_profile.insert(
        "virtual_dispatch".to_string(),
        virtual_calls_started.elapsed().as_secs_f64(),
    );
    profile.insert(
        "pass2_virtual_dispatch",
        virtual_calls_started.elapsed().as_secs_f64(),
    );

    let class_dossiers = dossiers::build_class_dossiers(&vtables);
    let behavior_started = Instant::now();
    let behavior_dossiers = if options.semantic_level == "off" {
        Vec::new()
    } else {
        behavior::build_behavior_dossiers(
            &sha256,
            &api_flows,
            &recovered_strings,
            &type_hints,
            &api_hash_resolutions,
            &semantic_budget.name,
        )
    };
    pass2_profile.insert(
        "behavior_dossiers".to_string(),
        behavior_started.elapsed().as_secs_f64(),
    );
    profile.insert(
        "pass2_behavior_dossiers",
        behavior_started.elapsed().as_secs_f64(),
    );

    let final_dossiers_started = Instant::now();
    let pseudo_ir_rows = pseudo_ir::build_pseudo_ir(
        &function_rows,
        &value_graph_rows,
        &ssa_result.values,
        &ssa_result.dataflow_edges,
        &api_flows,
        &resolved_calls,
        &structured_flow,
        &vsa_values,
        &type_hints,
        &jump_tables,
        &api_hash_resolutions,
        &options.pseudo_ir,
    );
    let function_dossiers = dossiers::build_function_dossiers(
        &sha256,
        &function_rows,
        &cfg_rows,
        &function_semantic_index,
        &api_flows,
        &recovered_strings,
        &resolved_calls,
        &structured_flow,
        &pseudo_ir_rows,
        &behavior_dossiers,
        &type_hints,
        &class_dossiers,
        &options.semantic_focus,
        &semantic_budget,
        &mut semantic_caps_hit,
    );
    let interesting_functions = dossiers::interesting_functions(&function_dossiers);
    pass2_profile.insert(
        "final_dossiers".to_string(),
        final_dossiers_started.elapsed().as_secs_f64(),
    );
    profile.insert(
        "pass2_final_dossiers",
        final_dossiers_started.elapsed().as_secs_f64(),
    );

    let mut second_pass_summary = second_pass_result.summary.clone();
    second_pass_summary.vsa_values = vsa_values.len();
    second_pass_summary.resolved_jump_tables = jump_tables.len();
    second_pass_summary.resolved_hashes = api_hash_resolutions.len();
    second_pass_summary.decoded_strings = decoded_strings.len();
    second_pass_summary.type_hints = type_hints.len();
    second_pass_summary.structured_refinements = structured_refinements;
    second_pass_summary.rtti_ownership_refinements = rtti_ownership_refinements;
    second_pass_summary.resolved_virtual_calls = virtual_dispatch_resolutions;
    second_pass_summary.ssa_values = ssa_result.values.len();
    second_pass_summary.dataflow_edges = ssa_result.dataflow_edges.len();
    second_pass_summary.behavior_dossiers = behavior_dossiers.len();
    second_pass_summary.caps_hit |= ssa_result.caps_hit;
    second_pass_summary.caps_hit |= vsa_values.iter().any(|row| row.work_budget_exhausted);
    let mut remaining_uncertainties = remaining_uncertainties_after_pass2(
        &second_pass_result.uncertainties,
        &jump_tables,
        &api_hash_resolutions,
        &decoded_strings,
        &vsa_values,
        &resolved_calls,
    );
    if disasm_capped {
        remaining_uncertainties.push(UncertaintyRecord {
            uncertainty_id: format!(
                "uncertainty:{:016X}:instruction_decode_cap:0000",
                image.base()
            ),
            function: image.base(),
            site_va: None,
            reason: "instruction_decode_cap".to_string(),
            details: format!(
                "normal portable budget decoded {} instructions and stopped at cap {}",
                instructions.len(),
                max_instructions
            ),
            tried: vec![
                "iced_x86_decode".to_string(),
                "portable_budget_cap".to_string(),
            ],
            recommended_action:
                "rerun with --semantic-budget high or max for broader instruction coverage"
                    .to_string(),
            severity_hint: "medium".to_string(),
            evidence: vec![image.base()],
        });
        second_pass_summary.caps_hit = true;
    }
    let portable_started = Instant::now();
    let trace_dir_path = options.trace_dir.as_ref().map(PathBuf::from);
    let portable_output = portable::build_portable_capabilities(portable::PortableInput {
        profile: &options.capability_profile,
        portable_tools_dir: &options.portable_tools_dir,
        emulation_budget: &options.emulation_budget,
        fuzz_mode: &options.fuzz_mode,
        fuzz_iterations: options.fuzz_iterations,
        trace_dir: trace_dir_path.as_deref(),
        decompile_c: &options.decompile_c,
        sha256: &sha256,
        source_path: pe_path,
        out_dir: &out_dir,
        bytes: image.bytes(),
        machine: image.machine(),
        file_size: image.bytes().len(),
        overlay_size: overlay_offset(image)
            .map(|off| image.bytes().len().saturating_sub(off))
            .unwrap_or(0),
        sections: image.sections(),
        imports: &imports,
        exports: &exports,
        strings: &string_rows,
        functions: &function_rows,
        instructions: &instructions,
        cfg: &cfg_rows,
        ssa_values: &ssa_result.values,
        dataflow_edges: &ssa_result.dataflow_edges,
        structured_flow: &structured_flow,
        xrefs: &xref_rows,
        api_flows: &api_flows,
    });
    remaining_uncertainties.extend(portable_output.uncertainties.clone());
    pass2_profile.insert(
        "portable_capabilities".to_string(),
        portable_started.elapsed().as_secs_f64(),
    );
    profile.insert(
        "portable_capabilities",
        portable_started.elapsed().as_secs_f64(),
    );

    let elapsed_seconds = total_started.elapsed().as_secs_f64();
    let unresolved_indirects = remaining_uncertainties
        .iter()
        .filter(|row| row.reason.contains("indirect"))
        .count();
    let selected_for_pass2: BTreeSet<u64> = second_pass_result
        .targets
        .iter()
        .map(|row| row.function)
        .collect();
    let typeable_api_flows = api_flows
        .iter()
        .filter(|flow| {
            selected_for_pass2.contains(&flow.function) && winapi::prototype(&flow.api).is_some()
        })
        .count();
    let jump_table_targets = jump_tables
        .iter()
        .map(|row| row.targets.len())
        .sum::<usize>();
    let jump_table_quality_failures = jump_tables
        .iter()
        .filter(|row| row.targets.len() < 2 || row.table_va.is_none())
        .count();
    let decoder_candidates = obfuscation_hints
        .iter()
        .filter(|row| row.candidate_kind == "encoded_blob_hint")
        .count();
    let rtti_classes = class_dossiers.len();
    let rtti_owned_classes = class_dossiers
        .iter()
        .filter(|row| row.ownership_confidence != "low")
        .count();
    let structured_region_functions = structured_flow
        .iter()
        .filter(|row| selected_for_pass2.contains(&row.function) && !row.regions.is_empty())
        .count();
    let scorecard = eval::build_scorecard(eval::ScorecardInput {
        functions: function_rows.len(),
        pdata_functions: function_rows
            .iter()
            .filter(|row| row.source == "pdata" || row.source == "entry" || row.source == "export")
            .count(),
        api_flows: typeable_api_flows,
        typed_api_args: type_hints.len(),
        jump_tables: jump_tables.len(),
        jump_table_targets,
        jump_table_quality_failures,
        unresolved_indirects,
        decoder_candidates,
        decoder_timeouts: 0,
        decoded_strings: decoded_strings.len(),
        prototype_known_api_flows: typeable_api_flows,
        prototype_typed_api_flows: type_hints.len(),
        behavior_dossiers: behavior_dossiers.len(),
        behavior_dossiers_with_evidence: behavior_dossiers
            .iter()
            .filter(|row| !row.evidence_vas.is_empty())
            .count(),
        rtti_classes,
        rtti_owned_classes,
        structured_functions: selected_for_pass2.len(),
        structured_region_functions,
        pass2_elapsed_seconds: second_pass_summary.elapsed_seconds,
        pass2_caps_hit: second_pass_summary.caps_hit,
        json_parseable: true,
        jsonl_parseable: true,
        ..eval::ScorecardInput::default()
    });
    let mut analysis = if let Some(pe) = image.as_pe() {
        analysis_json(
            pe,
            &sha256,
            elapsed_seconds,
            &imports,
            &exports,
            &exceptions,
            &string_rows,
            &instructions,
            &function_rows,
            &xref_rows,
            &vtables,
            &rtti,
            &api_flows,
            &callgraph,
            &recovered_strings,
            &obfuscation_hints,
            &value_graph_rows,
            &ssa_result.values,
            &ssa_result.dataflow_edges,
            &vsa_values,
            &jump_tables,
            &type_hints,
            &api_hash_resolutions,
            &resolved_calls,
            &structured_flow,
            &pseudo_ir_rows,
            &function_dossiers,
            &class_dossiers,
            &behavior_dossiers,
            &scorecard,
            &second_pass_summary,
            &second_pass_result.targets,
            &remaining_uncertainties,
            &options,
            &semantic_budget,
            &semantic_counters,
            &semantic_caps_hit,
            disasm_capped,
        )
    } else {
        analysis_json_non_pe(
            image,
            &sha256,
            elapsed_seconds,
            &imports,
            &exports,
            &string_rows,
            &instructions,
            &function_rows,
            &xref_rows,
            &api_flows,
            &recovered_strings,
            &obfuscation_hints,
            &value_graph_rows,
            &ssa_result.values,
            &ssa_result.dataflow_edges,
            &vsa_values,
            &jump_tables,
            &type_hints,
            &resolved_calls,
            &structured_flow,
            &pseudo_ir_rows,
            &function_dossiers,
            &class_dossiers,
            &behavior_dossiers,
            &scorecard,
            &second_pass_summary,
            &remaining_uncertainties,
            &options,
            &semantic_budget,
            &semantic_counters,
            &semantic_caps_hit,
            disasm_capped,
        )
    };
    if let Some(object) = analysis.as_object_mut() {
        if let Some(summary) = unpack_summary.clone() {
            object.insert("unpack".to_string(), summary);
        }
        object.insert(
            "capability_matrix".to_string(),
            serde_json::to_value(&portable_output.matrix)?,
        );
        object.insert(
            "cross_arch_summary".to_string(),
            serde_json::to_value(&portable_output.cross_arch_summary)?,
        );
        if let Some(counts) = object
            .get_mut("counts")
            .and_then(|value| value.as_object_mut())
        {
            counts.insert(
                "emulation_traces".to_string(),
                json!(portable_output.emulation_traces.len()),
            );
            counts.insert(
                "symbolic_paths".to_string(),
                json!(portable_output.symbolic_paths.len()),
            );
            counts.insert(
                "unpacked_artifacts".to_string(),
                json!(portable_output.unpacked_artifacts.len()),
            );
            counts.insert(
                "firmware_modules".to_string(),
                json!(portable_output.firmware_modules.len()),
            );
            counts.insert(
                "kernel_artifacts".to_string(),
                json!(portable_output.kernel_artifacts.len()),
            );
            counts.insert(
                "vuln_candidates".to_string(),
                json!(portable_output.vuln_candidates.len()),
            );
            counts.insert(
                "fuzz_runs".to_string(),
                json!(portable_output.fuzz_runs.len()),
            );
            counts.insert(
                "decompiled_c".to_string(),
                json!(portable_output.decompiled_c.len()),
            );
            counts.insert(
                "trace_events".to_string(),
                json!(portable_output.trace_events.len()),
            );
            counts.insert(
                "trace_correlations".to_string(),
                json!(portable_output.trace_correlations.len()),
            );
        }
        if let Some(score) = object
            .get_mut("level10_scores")
            .and_then(|value| value.as_object_mut())
        {
            score.insert(
                "capability_matrix".to_string(),
                serde_json::to_value(&portable_output.matrix)?,
            );
        }
    }
    let debug_symbol_output = debug_symbols::build_debug_symbols(debug_symbols::DebugSymbolInput {
        image,
        functions: &function_rows,
        mode: &options.symbols,
        symbol_paths: &options.symbol_paths,
        symbol_cache: options.symbol_cache.as_deref(),
    });
    let symbol_graph_artifacts =
        symbol_graph::build_symbol_graph(&debug_symbol_output, &options.symbol_packets);
    let class_facts = crate::cpp_classes::build_class_facts(
        &debug_symbol_output.debug_types,
        &vtables,
        &rtti,
        &function_rows,
        &function_semantic_index,
        &ir_rows,
        &string_rows,
        image.format(),
        &type_hints,
    );
    if let Some(object) = analysis.as_object_mut() {
        object.insert(
            "debug_symbols".to_string(),
            json!({
                "schema": "debug_symbols/1",
                "mode": options.symbols,
                "rust_only": true,
                "network_fetch": false,
                "providers": {
                    "dwarf": "gimli",
                    "pdb": "pdb",
                    "pdb_deep": "ms-pdb",
                    "inline_frames": "addr2line",
                    "object_symbols": "object",
                },
                "symbol_paths": options.symbol_paths,
                "symbol_cache": options.symbol_cache,
                "symbol_graph": &symbol_graph_artifacts.summary,
                "counts": {
                    "debug_modules": debug_symbol_output.modules.len(),
                    "debug_identities": debug_symbol_output.identities.len(),
                    "symbols": debug_symbol_output.symbols.len(),
                    "source_files": debug_symbol_output.source_files.len(),
                    "line_entries": debug_symbol_output.line_entries.len(),
                    "inline_scopes": debug_symbol_output.inline_scopes.len(),
                    "debug_types": debug_symbol_output.debug_types.len(),
                    "symbol_uncertainties": debug_symbol_output.uncertainties.len(),
                    "symbol_graph_records": symbol_graph_artifacts.rows.len(),
                    "symbol_address_ranges": symbol_graph_artifacts.indexes.address_range_index.len(),
                    "symbol_packets": symbol_graph_artifacts.packets.len(),
                },
            }),
        );
        if let Some(counts) = object
            .get_mut("counts")
            .and_then(|value| value.as_object_mut())
        {
            counts.insert(
                "debug_modules".to_string(),
                json!(debug_symbol_output.modules.len()),
            );
            counts.insert(
                "debug_identities".to_string(),
                json!(debug_symbol_output.identities.len()),
            );
            counts.insert(
                "symbols".to_string(),
                json!(debug_symbol_output.symbols.len()),
            );
            counts.insert(
                "source_files".to_string(),
                json!(debug_symbol_output.source_files.len()),
            );
            counts.insert(
                "line_entries".to_string(),
                json!(debug_symbol_output.line_entries.len()),
            );
            counts.insert(
                "symbol_uncertainties".to_string(),
                json!(debug_symbol_output.uncertainties.len()),
            );
            counts.insert(
                "symbol_graph_records".to_string(),
                json!(symbol_graph_artifacts.rows.len()),
            );
            counts.insert(
                "symbol_packets".to_string(),
                json!(symbol_graph_artifacts.packets.len()),
            );
            counts.insert("switches".to_string(), json!(switches.len()));
            counts.insert("eh_facts".to_string(), json!(eh_facts.len()));
            counts.insert("class_facts".to_string(), json!(class_facts.len()));
        }
    }
    let llm_format_label = match image.format() {
        crate::image::Format::Pe => "pe",
        crate::image::Format::Elf => "elf",
        crate::image::Format::MachO => "macho",
    };
    let llm_artifact_summary =
        llm_artifacts::write_llm_artifacts(llm_artifacts::LlmArtifactInput {
            sha256: &sha256,
            source_path: pe_path,
            format_label: llm_format_label,
            machine: image.machine(),
            out_dir,
            llm_artifacts_mode: &options.llm_artifacts,
            review_packs_mode: &options.review_packs,
            decompile_source_mode: &options.decompile_source,
            disasm_capped,
            semantic_caps_hit: serde_json::to_value(&semantic_caps_hit)?,
            functions: &function_rows,
            cfg: &cfg_rows,
            instructions: &instructions,
            ir: &ir_rows,
            imports: &imports,
            strings: &string_rows,
            xrefs: &xref_rows,
            callgraph: &callgraph,
            value_graph: &value_graph_rows,
            ssa_values: &ssa_result.values,
            dataflow_edges: &ssa_result.dataflow_edges,
            structured_flow: &structured_flow,
            type_hints: &type_hints,
            api_flows: &api_flows,
            pseudo_ir: &pseudo_ir_rows,
            function_dossiers: &function_dossiers,
            behavior_dossiers: &behavior_dossiers,
            vuln_candidates: &portable_output.vuln_candidates,
            decompiled_c: &portable_output.decompiled_c,
            uncertainties: &remaining_uncertainties,
            debug_modules: &debug_symbol_output.modules,
            debug_identities: &debug_symbol_output.identities,
            debug_symbols: &debug_symbol_output.symbols,
            source_files: &debug_symbol_output.source_files,
            line_entries: &debug_symbol_output.line_entries,
            inline_scopes: &debug_symbol_output.inline_scopes,
            debug_types: &debug_symbol_output.debug_types,
            symbol_uncertainties: &debug_symbol_output.uncertainties,
            symbol_graph_rows: &symbol_graph_artifacts.rows,
            symbol_packet_count: symbol_graph_artifacts.packets.len(),
            switches: &switches,
            eh_facts: &eh_facts,
            class_facts: &class_facts,
        })?;
    if let Some(object) = analysis.as_object_mut() {
        object.insert(
            "llm_artifacts".to_string(),
            serde_json::to_value(&llm_artifact_summary)?,
        );
        if let Some(counts) = object
            .get_mut("counts")
            .and_then(|value| value.as_object_mut())
        {
            counts.insert("graph_nodes".to_string(), json!(llm_artifact_summary.nodes));
            counts.insert("graph_edges".to_string(), json!(llm_artifact_summary.edges));
            counts.insert(
                "llm_review_packs".to_string(),
                json!(llm_artifact_summary.review_packs),
            );
            counts.insert(
                "decompiled_sources".to_string(),
                json!(llm_artifact_summary.decompiled_sources),
            );
        }
    }
    let triage = triage_report(image, &analysis, &string_rows, &imports, &function_rows);

    let write_started = Instant::now();
    write_progress(
        &options,
        pe_path,
        "write_outputs",
        &write_started,
        &total_started,
    );
    write_json(out_dir.join("analysis.json"), &analysis)?;
    write_json(
        out_dir.join("capability_matrix.json"),
        &serde_json::to_value(&portable_output.matrix)?,
    )?;
    write_json(
        out_dir.join("cross_arch_summary.json"),
        &serde_json::to_value(&portable_output.cross_arch_summary)?,
    )?;
    let mut scorecard_value = serde_json::to_value(&scorecard)?;
    if let Some(object) = scorecard_value.as_object_mut() {
        object.insert(
            "capability_matrix".to_string(),
            serde_json::to_value(&portable_output.matrix)?,
        );
    }
    write_json(out_dir.join("eval_scorecard.json"), &scorecard_value)?;
    write_jsonl(out_dir.join("functions.jsonl"), &function_rows)?;
    write_jsonl(out_dir.join("cfg.jsonl"), &cfg_rows)?;
    write_jsonl(out_dir.join("xrefs.jsonl"), &xref_rows)?;
    write_jsonl(out_dir.join("strings.jsonl"), &string_rows)?;
    write_jsonl(out_dir.join("imports.jsonl"), &imports)?;
    write_jsonl(out_dir.join("exports.jsonl"), &exports)?;
    write_jsonl(
        out_dir.join("debug_modules.jsonl"),
        &debug_symbol_output.modules,
    )?;
    write_jsonl(
        out_dir.join("debug_identities.jsonl"),
        &debug_symbol_output.identities,
    )?;
    write_jsonl(out_dir.join("symbols.jsonl"), &debug_symbol_output.symbols)?;
    write_jsonl(
        out_dir.join("source_files.jsonl"),
        &debug_symbol_output.source_files,
    )?;
    write_jsonl(
        out_dir.join("line_entries.jsonl"),
        &debug_symbol_output.line_entries,
    )?;
    write_jsonl(
        out_dir.join("inline_scopes.jsonl"),
        &debug_symbol_output.inline_scopes,
    )?;
    write_jsonl(
        out_dir.join("debug_types.jsonl"),
        &debug_symbol_output.debug_types,
    )?;
    write_jsonl(
        out_dir.join("symbol_uncertainty.jsonl"),
        &debug_symbol_output.uncertainties,
    )?;
    symbol_graph::write_symbol_artifacts(out_dir, &symbol_graph_artifacts)?;
    write_jsonl(out_dir.join("vtables.jsonl"), &vtables)?;
    write_jsonl(out_dir.join("eh.jsonl"), &eh_facts)?;
    write_jsonl(out_dir.join("rtti.jsonl"), &rtti)?;
    write_jsonl(out_dir.join("function_dossiers.jsonl"), &function_dossiers)?;
    write_jsonl(
        out_dir.join("interesting_functions.jsonl"),
        &interesting_functions,
    )?;
    write_jsonl(out_dir.join("api_flows.jsonl"), &api_flows)?;
    write_jsonl(out_dir.join("callgraph.jsonl"), &callgraph)?;
    write_jsonl(out_dir.join("value_graph.jsonl"), &value_graph_rows)?;
    write_jsonl(out_dir.join("ssa_values.jsonl"), &ssa_result.values)?;
    write_jsonl(
        out_dir.join("dataflow_edges.jsonl"),
        &ssa_result.dataflow_edges,
    )?;
    write_jsonl(out_dir.join("vsa_values.jsonl"), &vsa_values)?;
    write_jsonl(out_dir.join("jump_tables.jsonl"), &jump_tables)?;
    write_jsonl(out_dir.join("switches.jsonl"), &switches)?;
    write_jsonl(out_dir.join("classes.jsonl"), &class_facts)?;
    write_jsonl(out_dir.join("type_hints.jsonl"), &type_hints)?;
    write_jsonl(
        out_dir.join("api_hash_resolutions.jsonl"),
        &api_hash_resolutions,
    )?;
    write_jsonl(out_dir.join("resolved_calls.jsonl"), &resolved_calls)?;
    write_jsonl(out_dir.join("structured_flow.jsonl"), &structured_flow)?;
    write_jsonl(out_dir.join("pseudo_ir.jsonl"), &pseudo_ir_rows)?;
    write_jsonl(out_dir.join("recovered_strings.jsonl"), &recovered_strings)?;
    write_jsonl(out_dir.join("obfuscation_hints.jsonl"), &obfuscation_hints)?;
    let anti_analysis_records =
        crate::anti_analysis::detect(image, &imports, &string_rows, &instructions);
    write_jsonl(out_dir.join("anti_analysis.jsonl"), &anti_analysis_records)?;
    let attack_techniques = crate::attack::map_techniques(
        &imports,
        &api_flows,
        &behavior_dossiers,
        &anti_analysis_records,
    );
    write_jsonl(out_dir.join("attack_techniques.jsonl"), &attack_techniques)?;

    // ----- Vuln-discovery v1.0 -----
    // Wires the analysis records into the vuln-discovery EvidenceGraph
    // and runs the chain query / scoring / artifact emission. Gated on
    // `--vuln-discovery on` (default off). Errors here propagate
    // because the user explicitly opted in — silently dropping a
    // requested vuln run would mask real failures.
    #[cfg(feature = "vuln-discovery")]
    {
        if options.vuln_discovery_mode == "on" {
            let vuln_started = Instant::now();
            write_progress(&options, pe_path, "vuln", &vuln_started, &total_started);
            let vuln_out = options
                .vuln_out
                .as_deref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| out_dir.join("vuln"));
            let vuln_opts = crate::vuln::VulnOptions {
                out_dir: vuln_out,
                templates: options.vuln_templates.clone(),
                confidence_threshold: options.vuln_confidence_threshold,
                time_budget: None,
                seed: 0,
                include_lifetime: options.vuln_include_lifetime,
                enable_v1_1: options.vuln_dynamic_confirmation != "off"
                    || options.vuln_include_lifetime
                    || options.vuln_harness_tier != "skeleton",
                harness_tier: match options.vuln_harness_tier.as_str() {
                    "both" => crate::vuln::HarnessTierMode::Both,
                    _ => crate::vuln::HarnessTierMode::SkeletonOnly,
                },
                dynamic_evidence: options.vuln_dynamic_evidence.clone(),
                dynamic_confirmation_sources: options.vuln_dynamic_confirmation.clone(),
            };
            let vuln_inputs = crate::vuln::session::VulnInputs {
                run_id: &sha256,
                source_path: Some(pe_path),
                functions: &function_rows,
                cfgs: &cfg_rows,
                xrefs: &xref_rows,
                ssa: &ssa_result.values,
                dataflow: &ssa_result.dataflow_edges,
                value_graph: &value_graph_rows,
                vsa: &vsa_values,
                attack: &attack_techniques,
                behavior_dossiers: &behavior_dossiers,
                api_flows: &api_flows,
                imports: &imports,
            };
            crate::vuln::session::run(&vuln_opts, &vuln_inputs)
                .map_err(|e| Box::new(e) as Box<dyn Error>)?;
            profile.insert("vuln", vuln_started.elapsed().as_secs_f64());
        }
    }
    let crypto_constants = crate::crypto::detect_constants(image);
    write_jsonl(out_dir.join("crypto_constants.jsonl"), &crypto_constants)?;
    let resolved_indirect =
        crate::indirect_resolver::resolve_indirect(&function_rows, &ir_rows, &vsa_values, &imports);
    write_jsonl(out_dir.join("resolved_indirect.jsonl"), &resolved_indirect)?;
    write_jsonl(out_dir.join("class_dossiers.jsonl"), &class_dossiers)?;
    write_jsonl(out_dir.join("behavior_dossiers.jsonl"), &behavior_dossiers)?;
    write_jsonl(
        out_dir.join("emulation_traces.jsonl"),
        &portable_output.emulation_traces,
    )?;
    write_jsonl(
        out_dir.join("symbolic_paths.jsonl"),
        &portable_output.symbolic_paths,
    )?;
    write_jsonl(
        out_dir.join("unpacked_artifacts.jsonl"),
        &portable_output.unpacked_artifacts,
    )?;
    write_jsonl(
        out_dir.join("firmware_modules.jsonl"),
        &portable_output.firmware_modules,
    )?;
    write_jsonl(
        out_dir.join("kernel_artifacts.jsonl"),
        &portable_output.kernel_artifacts,
    )?;
    write_jsonl(
        out_dir.join("vuln_candidates.jsonl"),
        &portable_output.vuln_candidates,
    )?;
    write_jsonl(out_dir.join("fuzz_runs.jsonl"), &portable_output.fuzz_runs)?;
    write_jsonl(
        out_dir.join("decompiled_c.jsonl"),
        &portable_output.decompiled_c,
    )?;
    write_jsonl(
        out_dir.join("trace_events.jsonl"),
        &portable_output.trace_events,
    )?;
    write_jsonl(
        out_dir.join("trace_correlations.jsonl"),
        &portable_output.trace_correlations,
    )?;
    let fuzz_dir = out_dir.join("fuzz_harnesses");
    fs::create_dir_all(&fuzz_dir)?;
    write_json(
        fuzz_dir.join("manifest.json"),
        &serde_json::to_value(&portable_output.fuzz_manifest)?,
    )?;
    write_jsonl(
        out_dir.join("second_pass_targets.jsonl"),
        &second_pass_result.targets,
    )?;
    write_jsonl(out_dir.join("uncertainty.jsonl"), &remaining_uncertainties)?;
    fs::write(out_dir.join("triage_report.txt"), &triage)?;
    write_json(
        out_dir.join("case_brief.json"),
        &case_brief(
            image,
            &sha256,
            &analysis,
            &interesting_functions,
            &api_flows,
            &class_dossiers,
            &recovered_strings,
            &obfuscation_hints,
            &remaining_uncertainties,
        ),
    )?;
    if options.review_packs != "off" {
        write_review_packs(
            out_dir.join("review_packs"),
            &interesting_functions,
            &behavior_dossiers,
            &class_dossiers,
            &pseudo_ir_rows,
        )?;
    }
    let _ = crate::dossier_cards::write_dossier_cards(
        out_dir,
        &sha256,
        &function_rows,
        &function_dossiers,
        &portable_output.decompiled_c,
        &xref_rows,
        &recovered_strings,
        &remaining_uncertainties,
    );
    let format_label = match image.format() {
        crate::image::Format::Pe => "pe",
        crate::image::Format::Elf => "elf",
        crate::image::Format::MachO => "macho",
    };
    let _ = crate::summary::write_summary(
        out_dir,
        &sha256,
        format_label,
        image.machine(),
        image.bytes().len(),
        image.source_path(),
        &analysis,
        image.sections(),
        &imports,
        &string_rows,
        &function_rows,
        &function_dossiers,
        &behavior_dossiers,
        &api_flows,
        &recovered_strings,
        &obfuscation_hints,
        &portable_output.decompiled_c,
        image.entry_va(),
    );
    profile.insert("write_outputs", write_started.elapsed().as_secs_f64());
    if options.profile_analysis {
        write_json(
            out_dir.join("analysis_profile.json"),
            &json!({
                "engine": "rust",
                "elapsed_seconds": elapsed_seconds,
                "native_inner_workers": options.native_inner_workers,
                "semantic_level": options.semantic_level,
                "semantic_budget": semantic_budget.name.clone(),
                "semantic_focus": options.semantic_focus,
                "wrapper_collapse_depth": options.wrapper_collapse_depth,
                "pseudo_ir": options.pseudo_ir,
                "capability_profile": options.capability_profile,
                "portable_tools_dir": options.portable_tools_dir,
                "emulation_budget": options.emulation_budget,
                "fuzz_mode": options.fuzz_mode,
                "fuzz_iterations": options.fuzz_iterations,
                "trace_dir": options.trace_dir,
                "decompile_c": options.decompile_c,
                "llm_artifacts": options.llm_artifacts,
                "review_packs": options.review_packs,
                "decompile_source": options.decompile_source,
                "symbols": options.symbols,
                "symbol_paths": options.symbol_paths,
                "symbol_cache": options.symbol_cache,
                "semantic_counters": semantic_counters,
                "semantic_caps_hit": semantic_caps_hit,
                "second_pass": second_pass_summary,
                "pass1_profile": pass1_profile,
                "pass2_profile": pass2_profile,
                "phases": profile,
            }),
        )?;
    }
    write_progress(
        &options,
        pe_path,
        "completed",
        &total_started,
        &total_started,
    );

    let summary = json!({
        "sha256": sha256,
        "path": pe_path,
        "sample_dir": out_dir,
        "elapsed_seconds": elapsed_seconds,
        "analysis": analysis,
        "triage": triage,
        "imports": imports,
        "strings": string_rows,
    });
    Ok(serde_json::to_string(&summary)?)
}

impl PEImage {
    pub fn parse(path: &str) -> Result<Self, Box<dyn Error>> {
        let path_buf = PathBuf::from(path);
        let file = File::open(&path_buf)?;
        let map = unsafe { MmapOptions::new().map(&file)? };
        let bytes = &map[..];
        if bytes.len() < 0x100 || &bytes[0..2] != b"MZ" {
            return Err("not an MZ PE file".into());
        }
        let pe_offset = read_u32(bytes, 0x3c)? as usize;
        if pe_offset + 24 >= bytes.len() || &bytes[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err("invalid PE signature".into());
        }
        let coff = pe_offset + 4;
        let machine = read_u16(bytes, coff)?;
        let section_count = read_u16(bytes, coff + 2)? as usize;
        let optional_size = read_u16(bytes, coff + 16)? as usize;
        let opt = coff + 20;
        let magic = read_u16(bytes, opt)?;
        let is_pe64 = magic == 0x20b;
        if !is_pe64 {
            return Err("only PE32+ is supported by the native engine in this build".into());
        }
        let entry_rva = read_u32(bytes, opt + 16)?;
        let base = read_u64(bytes, opt + 24)?;
        let dll_characteristics = read_u16(bytes, opt + 70)?;
        let number_of_dirs = read_u32(bytes, opt + 108)? as usize;
        let dir_base = opt + 112;
        let mut data_directories = Vec::new();
        for index in 0..number_of_dirs.min(16) {
            let offset = dir_base + index * 8;
            if offset + 8 > bytes.len() {
                break;
            }
            data_directories.push(DataDirectory {
                rva: read_u32(bytes, offset)?,
                size: read_u32(bytes, offset + 4)?,
            });
        }
        let section_base = opt + optional_size;
        let mut sections = Vec::new();
        for idx in 0..section_count {
            let offset = section_base + idx * 40;
            if offset + 40 > bytes.len() {
                break;
            }
            let name_bytes = &bytes[offset..offset + 8];
            let nul = name_bytes
                .iter()
                .position(|b| *b == 0)
                .unwrap_or(name_bytes.len());
            let name = String::from_utf8_lossy(&name_bytes[..nul]).to_string();
            let virtual_size = read_u32(bytes, offset + 8)?;
            let rva = read_u32(bytes, offset + 12)?;
            let raw_size = read_u32(bytes, offset + 16)?;
            let raw_start = read_u32(bytes, offset + 20)?;
            let characteristics = read_u32(bytes, offset + 36)?;
            let start = raw_start as usize;
            let end = start.saturating_add(raw_size as usize).min(bytes.len());
            let data_size = end.saturating_sub(start);
            sections.push(SectionRecord {
                name,
                rva,
                va: base + rva as u64,
                virtual_size,
                raw_start,
                raw_size,
                data_size,
                executable: characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                readable: characteristics & IMAGE_SCN_MEM_READ != 0,
                writable: characteristics & IMAGE_SCN_MEM_WRITE != 0,
                entropy: entropy(&bytes[start..end]),
                data_range: start..end,
            });
        }
        sections.sort_by_key(|section| section.rva);
        let mut image = Self {
            path: path_buf,
            map,
            base,
            entry_va: if entry_rva == 0 {
                0
            } else {
                base + entry_rva as u64
            },
            machine,
            dll_characteristics,
            data_directories,
            sections,
            imports: Vec::new(),
            exports: Vec::new(),
            exceptions: Vec::new(),
            function_seeds_cache: Vec::new(),
            overlay_offset_cache: None,
        };
        let imports = parse_imports(&image);
        let exports = parse_exports(&image);
        let exceptions = parse_exceptions(&image);
        let overlay = overlay_offset(&image);
        let mut seeds: Vec<u64> = Vec::new();
        if image.entry_va != 0 {
            seeds.push(image.entry_va);
        }
        for exc in &exceptions {
            if exc.begin != 0 {
                seeds.push(exc.begin);
            }
        }
        for export in &exports {
            if image
                .section_for_va(export.va)
                .map(|s| s.executable)
                .unwrap_or(false)
            {
                seeds.push(export.va);
            }
        }
        seeds.sort();
        seeds.dedup();
        image.imports = imports;
        image.exports = exports;
        image.exceptions = exceptions;
        image.function_seeds_cache = seeds;
        image.overlay_offset_cache = overlay;
        Ok(image)
    }

    /// Parallel constructor for Aurora snapshot input. Reads the
    /// snapshot manifest at `manifest_path` and the region blobs it
    /// references, synthesizes an in-memory address space inside an
    /// anonymous mmap, and returns a `PEImage` with the same
    /// internal contract as `parse()` — so downstream analysis
    /// (functions, SSA, dataflow, vuln-discovery) does not care
    /// whether the input came from a real file or a snapshot.
    ///
    /// # Layout
    ///
    /// Regions are placed in the synthetic buffer in ascending VA
    /// order. Each region becomes a `SectionRecord` named
    /// `region_NN`. Section `rva = region.va_base - base`, so the
    /// live-process address layout is preserved. Section
    /// `raw_start` is the offset into the synthetic buffer, which
    /// is unrelated to the original VA — this is normal PE
    /// behavior (`.text` at RVA 0x1000 with file offset 0x400).
    ///
    /// # What is intentionally absent
    ///
    /// - **PE/MZ headers.** No header bytes are synthesized. Callers
    ///   that need header fields read them off the `PEImage`'s typed
    ///   fields (`base`, `entry_va`, `machine`, `sections`); they
    ///   never re-parse from `bytes()`.
    /// - **Imports / exports / exceptions.** Snapshot mode does not
    ///   reconstruct the IAT. The fields are empty; vuln-discovery
    ///   templates that depend on import detection will produce
    ///   weaker chains on snapshots. See `docs/unpack-capabilities.md`.
    /// - **Overlay.** No overlay concept for snapshots.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - the manifest is missing, unparseable, or has the wrong
    ///   schema string,
    /// - any region blob is missing on disk,
    /// - any region blob's size disagrees with `size_bytes`,
    /// - any region blob's BLAKE3 hash disagrees with
    ///   `blob_hash_blake3`,
    /// - the manifest has zero regions.
    #[cfg(feature = "unpack")]
    pub fn from_snapshot(manifest_path: &Path) -> Result<Self, Box<dyn Error>> {
        let manifest_bytes = fs::read(manifest_path)?;
        let manifest: crate::unpack::snapshot::SnapshotManifest =
            serde_json::from_slice(&manifest_bytes)?;
        if manifest.schema != crate::unpack::snapshot::SNAPSHOT_SCHEMA {
            return Err(format!(
                "unexpected snapshot schema: {} (expected {})",
                manifest.schema,
                crate::unpack::snapshot::SNAPSHOT_SCHEMA
            )
            .into());
        }
        if manifest.regions.is_empty() {
            return Err("snapshot manifest has no regions".into());
        }
        let manifest_dir = manifest_path
            .parent()
            .ok_or("snapshot manifest path has no parent directory")?;

        let mut sorted_regions = manifest.regions.clone();
        sorted_regions.sort_by_key(|r| parse_hex_va(&r.va_base));
        let base = parse_hex_va(&sorted_regions[0].va_base);

        let mut sections = Vec::with_capacity(sorted_regions.len());
        let mut region_blobs: Vec<Vec<u8>> = Vec::with_capacity(sorted_regions.len());
        let mut offset: usize = 0;
        for r in &sorted_regions {
            let blob_path = manifest_dir.join(&r.blob_path);
            let blob = fs::read(&blob_path)
                .map_err(|e| format!("region {} blob {} unreadable: {}", r.id, r.blob_path, e))?;
            if blob.len() as u64 != r.size_bytes {
                return Err(format!(
                    "region {} size mismatch: manifest says {} but blob is {}",
                    r.id,
                    r.size_bytes,
                    blob.len()
                )
                .into());
            }
            let actual_hash = blake3::hash(&blob).to_hex().to_string();
            if actual_hash != r.blob_hash_blake3 {
                return Err(format!(
                    "region {} hash mismatch: manifest says {} but blob hashes to {}",
                    r.id, r.blob_hash_blake3, actual_hash
                )
                .into());
            }
            let va = parse_hex_va(&r.va_base);
            let rva = (va.saturating_sub(base)) as u32;
            let (exec, read, write) = parse_permissions(&r.permissions);
            let raw_size = blob.len() as u32;
            let data_size = blob.len();
            let raw_start = offset as u32;
            sections.push(SectionRecord {
                name: format!("region_{:02}", r.id),
                rva,
                va,
                virtual_size: raw_size,
                raw_start,
                raw_size,
                data_size,
                executable: exec,
                readable: read,
                writable: write,
                entropy: r.entropy_final,
                data_range: offset..(offset + blob.len()),
            });
            offset += blob.len();
            region_blobs.push(blob);
        }
        sections.sort_by_key(|s| s.rva);

        let total_size = offset;
        let mut anon: MmapMut = MmapOptions::new().len(total_size).map_anon()?;
        let mut cursor = 0;
        for blob in &region_blobs {
            anon[cursor..cursor + blob.len()].copy_from_slice(blob);
            cursor += blob.len();
        }
        let map: Mmap = anon.make_read_only()?;

        // Pick entry_va from the highest-confidence OEP candidate;
        // ties break by the first-listed candidate (manifest order).
        let entry_va = manifest
            .oep_candidates
            .iter()
            .max_by(|a, b| {
                a.confidence_score
                    .partial_cmp(&b.confidence_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|oep| parse_hex_va(&oep.va))
            .unwrap_or(0);

        let seeds: Vec<u64> = if entry_va != 0 {
            vec![entry_va]
        } else {
            Vec::new()
        };

        Ok(Self {
            path: manifest_path.to_path_buf(),
            map,
            base,
            entry_va,
            machine: IMAGE_FILE_MACHINE_AMD64,
            dll_characteristics: 0,
            data_directories: Vec::new(),
            sections,
            imports: Vec::new(),
            exports: Vec::new(),
            exceptions: Vec::new(),
            function_seeds_cache: seeds,
            overlay_offset_cache: None,
        })
    }
}

/// Parse a manifest VA string like `"0x000000014001a000"` into a
/// `u64`. Tolerant of missing `0x` prefix and case.
#[cfg(feature = "unpack")]
fn parse_hex_va(s: &str) -> u64 {
    let trimmed = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(trimmed, 16).unwrap_or(0)
}

/// Parse a permission string from the snapshot manifest into the
/// `(executable, readable, writable)` triple `SectionRecord` uses.
/// Accepts the canonical forms `"RWX"`, `"R-X"`, `"RW-"`, `"R--"`.
/// Position-based: index 0 = R/-, index 1 = W/-, index 2 = X/-.
#[cfg(feature = "unpack")]
fn parse_permissions(perms: &str) -> (bool, bool, bool) {
    let chars: Vec<char> = perms.chars().collect();
    let read = chars.first().map(|&c| c == 'R').unwrap_or(false);
    let write = chars.get(1).map(|&c| c == 'W').unwrap_or(false);
    let exec = chars.get(2).map(|&c| c == 'X').unwrap_or(false);
    (exec, read, write)
}

#[cfg(all(feature = "unpack", test))]
mod snapshot_tests {
    use super::*;
    use crate::unpack::region_buffer::RegionBuffer;
    use crate::unpack::snapshot::{
        AntiVmProfile, ExecutionProvenance, OepCandidate, OepCorroboration, RegionDescriptor,
        RegionOrigin, SnapshotManifest, SourceBinary, SNAPSHOT_SCHEMA,
    };
    use std::fs;

    /// Build a snapshot on disk with the given regions + OEP
    /// candidates. Returns the manifest path.
    fn write_snapshot(
        dir: &Path,
        regions: Vec<(u64, Vec<u8>, &str)>,
        oeps: Vec<(u64, f64)>,
    ) -> std::path::PathBuf {
        fs::create_dir_all(dir.join("regions")).unwrap();
        let region_descriptors: Vec<RegionDescriptor> = regions
            .iter()
            .enumerate()
            .map(|(idx, (va, bytes, perms))| {
                let blob_name = format!("regions/region_{:02}.bin", idx);
                let blob_path = dir.join(&blob_name);
                fs::write(&blob_path, bytes).unwrap();
                let buf = RegionBuffer::from_bytes(*va, bytes.clone());
                buf.to_descriptor(
                    idx as u32,
                    perms,
                    RegionOrigin {
                        alloc_api: "initial".into(),
                        alloc_site_va: "0x0".into(),
                        alloc_size_requested: bytes.len() as u64,
                    },
                    &blob_name,
                )
            })
            .collect();
        let oep_candidates: Vec<OepCandidate> = oeps
            .iter()
            .enumerate()
            .map(|(i, (va, score))| OepCandidate {
                va: format!("0x{:016x}", va),
                region_id: 0,
                corroboration: OepCorroboration {
                    entropy_drop: true,
                    execute_from_newly_allocated: i == 0,
                    function_prologue_match: i == 0,
                    iat_call_pattern: i == 0,
                },
                confidence_score: *score,
                confidence_tier: if *score >= 0.75 {
                    "high"
                } else {
                    "best_effort"
                }
                .to_string(),
            })
            .collect();
        let manifest = SnapshotManifest {
            schema: SNAPSHOT_SCHEMA.to_string(),
            run_id: "test:0".to_string(),
            source_binary: SourceBinary {
                path: "synthetic".into(),
                hash_blake3: "0".into(),
                size_bytes: 0,
            },
            packer_detection: None,
            tracer_mode: "debug".into(),
            anti_vm_profile: AntiVmProfile::default(),
            regions: region_descriptors,
            oep_candidates,
            execution_provenance: ExecutionProvenance::in_progress(),
            uncertainties: Vec::new(),
        };
        let manifest_path = dir.join("unpack_provenance.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        manifest_path
    }

    #[test]
    fn from_snapshot_loads_single_region_with_correct_layout() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bytes: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![(0x140001000, bytes.clone(), "R-X")],
            vec![(0x140001100, 1.0)],
        );
        let image = PEImage::from_snapshot(&manifest_path).expect("load");
        assert_eq!(image.base, 0x140001000);
        assert_eq!(image.entry_va, 0x140001100);
        assert_eq!(image.sections.len(), 1);
        assert_eq!(image.sections[0].rva, 0);
        assert_eq!(image.sections[0].va, 0x140001000);
        assert_eq!(image.sections[0].data_size, 4096);
        assert!(image.sections[0].executable);
        assert!(image.sections[0].readable);
        assert!(!image.sections[0].writable);
        // The synthetic mmap returns the bytes we wrote.
        let live = image.bytes();
        assert_eq!(live.len(), 4096);
        assert_eq!(live, bytes.as_slice());
    }

    #[test]
    fn from_snapshot_concatenates_regions_in_va_order() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Intentionally insert in non-VA order — loader must sort.
        let r1 = vec![0xAAu8; 100];
        let r0 = vec![0xBBu8; 200];
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![
                (0x140002000, r1.clone(), "RW-"),
                (0x140001000, r0.clone(), "R-X"),
            ],
            vec![],
        );
        let image = PEImage::from_snapshot(&manifest_path).expect("load");
        assert_eq!(image.base, 0x140001000);
        assert_eq!(image.sections.len(), 2);
        // Sections sorted by rva: region at VA 0x140001000 first
        assert_eq!(image.sections[0].rva, 0);
        assert_eq!(image.sections[0].va, 0x140001000);
        assert_eq!(image.sections[1].rva, 0x1000);
        assert_eq!(image.sections[1].va, 0x140002000);
        // Bytes are concatenated VA-order: r0 first, then r1
        let live = image.bytes();
        assert_eq!(live[..200], r0[..]);
        assert_eq!(live[200..300], r1[..]);
    }

    #[test]
    fn from_snapshot_picks_highest_confidence_oep_as_entry_va() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bytes = vec![0u8; 4096];
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![(0x140001000, bytes, "RWX")],
            vec![
                (0x140001100, 0.25),
                (0x140001200, 0.75),
                (0x140001300, 0.50),
            ],
        );
        let image = PEImage::from_snapshot(&manifest_path).expect("load");
        // Highest-confidence (0.75) candidate wins
        assert_eq!(image.entry_va, 0x140001200);
        assert_eq!(image.function_seeds_cache, vec![0x140001200]);
    }

    #[test]
    fn from_snapshot_with_no_oep_candidates_has_zero_entry_va() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![(0x140001000, vec![0u8; 64], "R--")],
            vec![],
        );
        let image = PEImage::from_snapshot(&manifest_path).expect("load");
        assert_eq!(image.entry_va, 0);
        assert!(image.function_seeds_cache.is_empty());
    }

    #[test]
    fn from_snapshot_rejects_empty_regions() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest_path = write_snapshot(tmp.path(), vec![], vec![]);
        let err = PEImage::from_snapshot(&manifest_path)
            .err()
            .expect("must reject");
        assert!(err.to_string().contains("no regions"));
    }

    #[test]
    fn from_snapshot_rejects_wrong_schema() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![(0x140001000, vec![0u8; 64], "R--")],
            vec![],
        );
        // Mutate the schema on disk
        let mut text = fs::read_to_string(&manifest_path).unwrap();
        text = text.replace(SNAPSHOT_SCHEMA, "wrong.schema.v9");
        fs::write(&manifest_path, text).unwrap();
        let err = PEImage::from_snapshot(&manifest_path)
            .err()
            .expect("must reject");
        assert!(err.to_string().contains("unexpected snapshot schema"));
    }

    #[test]
    fn from_snapshot_rejects_blob_size_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![(0x140001000, vec![0u8; 64], "R--")],
            vec![],
        );
        // Truncate the blob to mismatch the manifest's size_bytes
        let blob_path = tmp.path().join("regions").join("region_00.bin");
        fs::write(&blob_path, vec![0u8; 32]).unwrap();
        let err = PEImage::from_snapshot(&manifest_path)
            .err()
            .expect("must reject");
        assert!(err.to_string().contains("size mismatch"));
    }

    #[test]
    fn from_snapshot_rejects_blob_hash_mismatch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![(0x140001000, vec![0u8; 64], "R--")],
            vec![],
        );
        // Replace blob with same-size but different-content bytes
        let blob_path = tmp.path().join("regions").join("region_00.bin");
        fs::write(&blob_path, vec![0xFFu8; 64]).unwrap();
        let err = PEImage::from_snapshot(&manifest_path)
            .err()
            .expect("must reject");
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn from_snapshot_rejects_missing_blob() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![(0x140001000, vec![0u8; 64], "R--")],
            vec![],
        );
        let blob_path = tmp.path().join("regions").join("region_00.bin");
        fs::remove_file(&blob_path).unwrap();
        let err = PEImage::from_snapshot(&manifest_path)
            .err()
            .expect("must reject");
        assert!(err.to_string().contains("unreadable"));
    }

    #[test]
    fn from_snapshot_machine_is_amd64() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![(0x140001000, vec![0u8; 64], "R--")],
            vec![],
        );
        let image = PEImage::from_snapshot(&manifest_path).expect("load");
        assert_eq!(image.machine, IMAGE_FILE_MACHINE_AMD64);
    }

    #[test]
    fn section_data_range_correctly_slices_into_bytes_buffer() {
        let tmp = tempfile::TempDir::new().unwrap();
        let r0: Vec<u8> = b"first-region-content".to_vec();
        let r1: Vec<u8> = b"second-region-payload".to_vec();
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![
                (0x140001000, r0.clone(), "R-X"),
                (0x140002000, r1.clone(), "RW-"),
            ],
            vec![],
        );
        let image = PEImage::from_snapshot(&manifest_path).expect("load");
        let live = image.bytes();
        let r0_section = &image.sections[0];
        let r1_section = &image.sections[1];
        assert_eq!(&live[r0_section.data_range.clone()], &r0[..]);
        assert_eq!(&live[r1_section.data_range.clone()], &r1[..]);
    }

    #[test]
    fn imports_exports_exceptions_are_empty_for_snapshots() {
        let tmp = tempfile::TempDir::new().unwrap();
        let manifest_path = write_snapshot(
            tmp.path(),
            vec![(0x140001000, vec![0u8; 64], "R-X")],
            vec![(0x140001000, 1.0)],
        );
        let image = PEImage::from_snapshot(&manifest_path).expect("load");
        assert!(image.imports.is_empty());
        assert!(image.exports.is_empty());
        assert!(image.exceptions.is_empty());
        assert!(image.overlay_offset_cache.is_none());
    }

    #[test]
    fn permissions_decode_to_correct_section_flags() {
        // R-X
        assert_eq!(parse_permissions("R-X"), (true, true, false));
        // RWX
        assert_eq!(parse_permissions("RWX"), (true, true, true));
        // RW-
        assert_eq!(parse_permissions("RW-"), (false, true, true));
        // R--
        assert_eq!(parse_permissions("R--"), (false, true, false));
        // ---
        assert_eq!(parse_permissions("---"), (false, false, false));
    }

    #[test]
    fn parse_hex_va_handles_prefixed_and_bare_hex() {
        assert_eq!(parse_hex_va("0x140001000"), 0x140001000);
        assert_eq!(parse_hex_va("0X140001000"), 0x140001000);
        assert_eq!(parse_hex_va("140001000"), 0x140001000);
        assert_eq!(parse_hex_va("0x000000014001a000"), 0x14001a000);
        assert_eq!(parse_hex_va("not_hex"), 0);
    }
}

fn parse_imports(image: &PEImage) -> Vec<ImportRecord> {
    let mut rows = Vec::new();
    let Some(dir) = image.directory(1) else {
        return rows;
    };
    let Some(mut offset) = image.rva_to_file_offset(dir.rva) else {
        return rows;
    };
    let bytes = image.bytes();
    for _ in 0..4096 {
        if offset + 20 > bytes.len() {
            break;
        }
        let original_first_thunk = read_u32(bytes, offset).unwrap_or(0);
        let name_rva = read_u32(bytes, offset + 12).unwrap_or(0);
        let first_thunk = read_u32(bytes, offset + 16).unwrap_or(0);
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break;
        }
        let dll = image.read_c_string_rva(name_rva).unwrap_or_default();
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        if let Some(mut thunk_offset) = image.rva_to_file_offset(thunk_rva) {
            for index in 0..65536usize {
                if thunk_offset + 8 > bytes.len() {
                    break;
                }
                let value = read_u64(bytes, thunk_offset).unwrap_or(0);
                if value == 0 {
                    break;
                }
                let (name, hint) = if value & 0x8000_0000_0000_0000 != 0 {
                    (format!("ord_{}", value & 0xffff), None)
                } else {
                    let name_rva = value as u32;
                    let hint = image
                        .rva_to_file_offset(name_rva)
                        .and_then(|off| read_u16(bytes, off).ok());
                    let name = image
                        .rva_to_file_offset(name_rva)
                        .and_then(|off| read_c_string(bytes, off + 2))
                        .unwrap_or_else(|| format!("ord_{}", index));
                    (name, hint)
                };
                let va = image.base + first_thunk as u64 + (index * 8) as u64;
                let symbol = format!("{}!{}", dll, name);
                rows.push(ImportRecord {
                    dll: dll.clone(),
                    name,
                    symbol: symbol.clone(),
                    va,
                    rva: va - image.base,
                    hint,
                    categories: strings::import_categories(&symbol),
                });
                thunk_offset += 8;
            }
        }
        offset += 20;
    }
    rows
}

fn parse_exports(image: &PEImage) -> Vec<ExportRecord> {
    let mut rows = Vec::new();
    let Some(dir) = image.directory(0) else {
        return rows;
    };
    let Some(offset) = image.rva_to_file_offset(dir.rva) else {
        return rows;
    };
    let bytes = image.bytes();
    if offset + 40 > bytes.len() {
        return rows;
    }
    let ordinal_base = read_u32(bytes, offset + 16).unwrap_or(0);
    let number_of_names = read_u32(bytes, offset + 24).unwrap_or(0);
    let address_functions = read_u32(bytes, offset + 28).unwrap_or(0);
    let address_names = read_u32(bytes, offset + 32).unwrap_or(0);
    let address_ordinals = read_u32(bytes, offset + 36).unwrap_or(0);
    let Some(names_off) = image.rva_to_file_offset(address_names) else {
        return rows;
    };
    let Some(ord_off) = image.rva_to_file_offset(address_ordinals) else {
        return rows;
    };
    let Some(func_off) = image.rva_to_file_offset(address_functions) else {
        return rows;
    };
    for index in 0..number_of_names as usize {
        let name_rva = read_u32(bytes, names_off + index * 4).unwrap_or(0);
        let name = image
            .read_c_string_rva(name_rva)
            .unwrap_or_else(|| format!("exp_{}", index));
        let ordinal_index = read_u16(bytes, ord_off + index * 2).unwrap_or(0) as usize;
        let function_rva = read_u32(bytes, func_off + ordinal_index * 4).unwrap_or(0);
        rows.push(ExportRecord {
            name,
            ordinal: ordinal_base + ordinal_index as u32,
            va: image.base + function_rva as u64,
            rva: function_rva,
        });
    }
    rows
}

fn parse_exceptions(image: &PEImage) -> Vec<ExceptionRecord> {
    let mut rows = Vec::new();
    let runtime = image
        .directory(3)
        .and_then(|dir| {
            image
                .rva_to_file_offset(dir.rva)
                .map(|off| (off, dir.size as usize))
        })
        .or_else(|| {
            image
                .sections
                .iter()
                .find(|section| section.name.eq_ignore_ascii_case(".pdata"))
                .map(|section| (section.raw_start as usize, section.data_size))
        });
    let Some((start, size)) = runtime else {
        return rows;
    };
    let bytes = image.bytes();
    let end = start.saturating_add(size).min(bytes.len());
    let mut offset = start;
    while offset + 12 <= end {
        let begin_rva = read_u32(bytes, offset).unwrap_or(0);
        let end_rva = read_u32(bytes, offset + 4).unwrap_or(0);
        let unwind_rva = read_u32(bytes, offset + 8).unwrap_or(0);
        if begin_rva != 0
            && end_rva > begin_rva
            && image
                .section_for_rva(begin_rva)
                .map(|section| section.executable)
                .unwrap_or(false)
        {
            rows.push(ExceptionRecord {
                begin_rva,
                end_rva,
                unwind_rva,
                begin: image.base + begin_rva as u64,
                end: image.base + end_rva as u64,
                unwind: image.base + unwind_rva as u64,
            });
        }
        offset += 12;
    }
    rows.sort_by_key(|row| row.begin);
    rows
}

fn disassembly_ranges(
    image: &dyn crate::image::BinaryImage,
    exceptions: &[ExceptionRecord],
) -> Vec<DisasmRange> {
    let executable: Vec<&SectionRecord> = image
        .sections()
        .iter()
        .filter(|section| section.executable)
        .collect();
    if exceptions.is_empty() {
        return executable
            .into_iter()
            .map(|section| DisasmRange {
                section_rva: section.rva,
                start: section.va,
                end: section.va + section.data_size as u64,
            })
            .collect();
    }
    let mut ranges = Vec::new();
    let mut covered: BTreeMap<u32, Vec<(u64, u64)>> = BTreeMap::new();
    for exc in exceptions {
        let Some(section) = image.section_for_va(exc.begin) else {
            continue;
        };
        if !section.executable {
            continue;
        }
        let start = exc.begin.max(section.va);
        let end = exc.end.min(section.va + section.data_size as u64);
        if end > start {
            ranges.push(DisasmRange {
                section_rva: section.rva,
                start,
                end,
            });
            covered.entry(section.rva).or_default().push((start, end));
        }
    }
    let orphan_cap = 0x20000u64;
    for section in executable {
        let mut cursor = section.va;
        let section_end = section.va + section.data_size as u64;
        if let Some(items) = covered.get_mut(&section.rva) {
            items.sort();
            for (start, end) in items {
                if *start > cursor {
                    ranges.push(DisasmRange {
                        section_rva: section.rva,
                        start: cursor,
                        end: (*start).min(cursor + orphan_cap),
                    });
                }
                cursor = cursor.max(*end);
            }
        }
        if cursor < section_end {
            ranges.push(DisasmRange {
                section_rva: section.rva,
                start: cursor,
                end: section_end.min(cursor + orphan_cap),
            });
        }
    }
    ranges.sort_by_key(|row| (row.section_rva, row.start, row.end));
    ranges
}

fn options_snapshot(options: &AnalysisOptions, effective_semantic_budget: &str) -> Value {
    json!({
        "preset": options.preset,
        "max_strings": options.max_strings,
        "max_functions": options.max_functions,
        "max_xrefs": options.max_xrefs,
        "deep": options.deep,
        "profile_analysis": options.profile_analysis,
        "semantic_level": options.semantic_level,
        "second_pass": options.second_pass,
        "semantic_budget": effective_semantic_budget,
        "semantic_focus": options.semantic_focus,
        "wrapper_collapse_depth": options.wrapper_collapse_depth,
        "pseudo_ir": options.pseudo_ir,
        "capability_profile": options.capability_profile,
        "portable_tools_dir": options.portable_tools_dir,
        "emulation_budget": options.emulation_budget,
        "fuzz_mode": options.fuzz_mode,
        "fuzz_iterations": options.fuzz_iterations,
        "trace_dir": options.trace_dir,
        "dynamic_trace": options.dynamic_trace_mode,
        "dynamic_trace_duration_secs": options.dynamic_trace_duration_secs,
        "dynamic_trace_target": options.dynamic_trace_target,
        "dynamic_trace_out": options.dynamic_trace_out,
        "dynamic_trace_providers": options.dynamic_trace_providers,
        "dynamic_trace_loss_policy": options.dynamic_trace_loss_policy,
        "vuln_discovery": options.vuln_discovery_mode,
        "vuln_templates": options.vuln_templates,
        "vuln_confidence_threshold": options.vuln_confidence_threshold,
        "vuln_out": options.vuln_out,
        "vuln_dynamic_confirmation": options.vuln_dynamic_confirmation,
        "vuln_dynamic_evidence_rows": options.vuln_dynamic_evidence.len(),
        "vuln_include_lifetime": options.vuln_include_lifetime,
        "vuln_harness_tier": options.vuln_harness_tier,
        "unpack": options.unpack_mode,
        "unpack_tracer": options.unpack_tracer,
        "unpack_timeout_secs": options.unpack_timeout_secs,
        "unpack_instr_budget": options.unpack_instr_budget,
        "unpack_out": options.unpack_out,
        "unpack_hooks_disable": options.unpack_hooks_disable,
        "unpack_include_devirt": options.unpack_include_devirt,
        "decompile_c": options.decompile_c,
        "llm_artifacts": options.llm_artifacts,
        "review_packs": options.review_packs,
        "decompile_source": options.decompile_source,
        "symbols": options.symbols,
        "symbol_packets": options.symbol_packets,
        "symbol_paths": options.symbol_paths,
        "symbol_cache": options.symbol_cache,
    })
}

fn analysis_json(
    image: &PEImage,
    sha256: &str,
    elapsed_seconds: f64,
    imports: &[ImportRecord],
    exports: &[ExportRecord],
    exceptions: &[ExceptionRecord],
    strings: &[StringRecord],
    instructions: &[InstructionRecord],
    functions: &[FunctionRecord],
    xrefs: &[XrefRecord],
    vtables: &[VTableRecord],
    rtti: &[RttiRecord],
    api_flows: &[ApiFlowRecord],
    callgraph: &[CallGraphRecord],
    recovered_strings: &[RecoveredStringRecord],
    obfuscation_hints: &[ObfuscationHintRecord],
    value_graph: &[ValueGraphRecord],
    ssa_values: &[SsaValueRecord],
    dataflow_edges: &[DataflowEdgeRecord],
    vsa_values: &[VsaValueRecord],
    jump_tables: &[JumpTableRecord],
    type_hints: &[TypeHintRecord],
    api_hash_resolutions: &[ApiHashResolutionRecord],
    resolved_calls: &[ResolvedCallRecord],
    structured_flow: &[StructuredFlowRecord],
    pseudo_ir: &[PseudoIrRecord],
    function_dossiers: &[FunctionDossierRecord],
    class_dossiers: &[ClassDossierRecord],
    behavior_dossiers: &[BehaviorDossierRecord],
    scorecard: &eval::EvalScorecardRecord,
    second_pass_summary: &SecondPassSummaryRecord,
    second_pass_targets: &[SecondPassTargetRecord],
    uncertainties: &[UncertaintyRecord],
    options: &AnalysisOptions,
    semantic_budget: &semantic_index::SemanticBudget,
    semantic_counters: &semantic_index::SemanticCounters,
    semantic_caps_hit: &semantic_index::SemanticCapsHit,
    disasm_capped: bool,
) -> Value {
    let mut suspicious: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for imp in imports {
        for category in &imp.categories {
            suspicious
                .entry(category.clone())
                .or_default()
                .insert(imp.symbol.clone());
        }
    }
    let suspicious_json: BTreeMap<String, Vec<String>> = suspicious
        .into_iter()
        .map(|(key, values)| (key, values.into_iter().collect()))
        .collect();
    let security_dir = image
        .directory(4)
        .cloned()
        .unwrap_or(DataDirectory { rva: 0, size: 0 });
    let overlay_offset = overlay_offset(image);
    json!({
        "path": image.path.to_string_lossy(),
        "file_size": image.bytes().len(),
        "sha256": sha256,
        "engine": {
            "name": "rust",
            "native": true,
            "version": env!("CARGO_PKG_VERSION"),
        },
        "image_base": image.base,
        "machine": image.machine,
        "x64": image.machine == IMAGE_FILE_MACHINE_AMD64,
        "elapsed_seconds": elapsed_seconds,
        "options": options_snapshot(options, &semantic_budget.name),
        "semantic_level": options.semantic_level,
        "semantic_budget": semantic_budget.name.clone(),
        "semantic_focus": options.semantic_focus,
        "wrapper_collapse_depth": options.wrapper_collapse_depth,
        "pseudo_ir": options.pseudo_ir,
        "semantic_caps_hit": semantic_caps_hit,
        "semantic_counters": semantic_counters,
        "sections": image.sections,
        "security": {
            "aslr": image.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0,
            "nx": image.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0,
            "cfg": image.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0,
            "signature_present": security_dir.size != 0,
            "signature_size": security_dir.size,
            "overlay_offset": overlay_offset,
            "overlay_size": overlay_offset.map(|off| image.bytes().len().saturating_sub(off)).unwrap_or(0),
            "tls_callbacks": tls_callbacks(image),
            "suspicious_imports": suspicious_json,
        },
        "counts": {
            "sections": image.sections.len(),
            "imports": imports.len(),
            "exports": exports.len(),
            "exceptions": exceptions.len(),
            "strings": strings.len(),
            "instructions": instructions.len(),
            "functions": functions.len(),
            "xrefs": xrefs.len(),
            "vtables": vtables.len(),
            "rtti": rtti.len(),
            "api_flows": api_flows.len(),
            "callgraph": callgraph.len(),
            "value_graph": value_graph.len(),
            "ssa_values": ssa_values.len(),
            "dataflow_edges": dataflow_edges.len(),
            "vsa_values": vsa_values.len(),
            "jump_tables": jump_tables.len(),
            "type_hints": type_hints.len(),
            "api_hash_resolutions": api_hash_resolutions.len(),
            "resolved_calls": resolved_calls.len(),
            "structured_flow": structured_flow.len(),
            "pseudo_ir": pseudo_ir.len(),
            "recovered_strings": recovered_strings.len(),
            "obfuscation_hints": obfuscation_hints.len(),
            "function_dossiers": function_dossiers.len(),
            "class_dossiers": class_dossiers.len(),
            "behavior_dossiers": behavior_dossiers.len(),
            "second_pass_targets": second_pass_targets.len(),
            "uncertainties": uncertainties.len(),
        },
        "caps_hit": {
            "strings": strings.len() >= options.max_strings,
            "instructions": disasm_capped,
            "functions": functions.len() >= options.max_functions,
            "xrefs": xrefs.len() >= options.max_xrefs,
        },
        "second_pass": second_pass_summary,
        "level10_scores": scorecard,
        "dossier_quality": dossier_quality_counts(function_dossiers),
        "packed_or_obfuscated": deobfuscation::packed_or_obfuscated(image, recovered_strings, obfuscation_hints),
        "uncertainty": {
            "static_limitations": [
                "Static-only native analysis. Runtime-generated code, packed payloads, and indirect call targets may need manual confirmation."
            ],
            "records": uncertainties.len(),
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn analysis_json_non_pe(
    image: &dyn crate::image::BinaryImage,
    sha256: &str,
    elapsed_seconds: f64,
    imports: &[ImportRecord],
    exports: &[ExportRecord],
    strings: &[StringRecord],
    instructions: &[InstructionRecord],
    functions: &[FunctionRecord],
    xrefs: &[XrefRecord],
    api_flows: &[ApiFlowRecord],
    recovered_strings: &[RecoveredStringRecord],
    obfuscation_hints: &[ObfuscationHintRecord],
    value_graph: &[ValueGraphRecord],
    ssa_values: &[SsaValueRecord],
    dataflow_edges: &[DataflowEdgeRecord],
    vsa_values: &[VsaValueRecord],
    jump_tables: &[JumpTableRecord],
    type_hints: &[TypeHintRecord],
    resolved_calls: &[ResolvedCallRecord],
    structured_flow: &[StructuredFlowRecord],
    pseudo_ir: &[PseudoIrRecord],
    function_dossiers: &[FunctionDossierRecord],
    class_dossiers: &[ClassDossierRecord],
    behavior_dossiers: &[BehaviorDossierRecord],
    scorecard: &eval::EvalScorecardRecord,
    second_pass_summary: &SecondPassSummaryRecord,
    uncertainties: &[UncertaintyRecord],
    options: &AnalysisOptions,
    semantic_budget: &semantic_index::SemanticBudget,
    semantic_counters: &semantic_index::SemanticCounters,
    semantic_caps_hit: &semantic_index::SemanticCapsHit,
    disasm_capped: bool,
) -> Value {
    let mut suspicious: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for imp in imports {
        for category in &imp.categories {
            suspicious
                .entry(category.clone())
                .or_default()
                .insert(imp.symbol.clone());
        }
    }
    let suspicious_json: BTreeMap<String, Vec<String>> = suspicious
        .into_iter()
        .map(|(key, values)| (key, values.into_iter().collect()))
        .collect();
    let overlay = image.overlay_range();
    let format_label = match image.format() {
        crate::image::Format::Pe => "pe",
        crate::image::Format::Elf => "elf",
        crate::image::Format::MachO => "macho",
    };
    json!({
        "path": image.source_path(),
        "file_size": image.bytes().len(),
        "sha256": sha256,
        "format": format_label,
        "engine": {
            "name": "rust",
            "native": true,
            "version": env!("CARGO_PKG_VERSION"),
        },
        "image_base": image.base(),
        "machine": image.machine(),
        "x64": image.machine() == IMAGE_FILE_MACHINE_AMD64,
        "elapsed_seconds": elapsed_seconds,
        "options": options_snapshot(options, &semantic_budget.name),
        "semantic_level": options.semantic_level,
        "semantic_budget": semantic_budget.name.clone(),
        "semantic_focus": options.semantic_focus,
        "wrapper_collapse_depth": options.wrapper_collapse_depth,
        "pseudo_ir": options.pseudo_ir,
        "semantic_caps_hit": semantic_caps_hit,
        "semantic_counters": semantic_counters,
        "sections": image.sections(),
        "security": {
            "overlay_offset": overlay.as_ref().map(|r| r.start),
            "overlay_size": overlay.map(|r| r.len()).unwrap_or(0),
            "suspicious_imports": suspicious_json,
            "non_pe_note": format!("DLL characteristics / security directory / TLS callbacks are PE-only and unavailable for {format_label}"),
        },
        "counts": {
            "sections": image.sections().len(),
            "imports": imports.len(),
            "exports": exports.len(),
            "exceptions": 0,
            "strings": strings.len(),
            "instructions": instructions.len(),
            "functions": functions.len(),
            "xrefs": xrefs.len(),
            "vtables": 0,
            "rtti": 0,
            "api_flows": api_flows.len(),
            "callgraph": 0,
            "value_graph": value_graph.len(),
            "ssa_values": ssa_values.len(),
            "dataflow_edges": dataflow_edges.len(),
            "vsa_values": vsa_values.len(),
            "jump_tables": jump_tables.len(),
            "type_hints": type_hints.len(),
            "api_hash_resolutions": 0,
            "resolved_calls": resolved_calls.len(),
            "structured_flow": structured_flow.len(),
            "pseudo_ir": pseudo_ir.len(),
            "recovered_strings": recovered_strings.len(),
            "obfuscation_hints": obfuscation_hints.len(),
            "function_dossiers": function_dossiers.len(),
            "class_dossiers": class_dossiers.len(),
            "behavior_dossiers": behavior_dossiers.len(),
            "uncertainties": uncertainties.len(),
        },
        "caps_hit": {
            "strings": strings.len() >= options.max_strings,
            "instructions": disasm_capped,
            "functions": functions.len() >= options.max_functions,
            "xrefs": xrefs.len() >= options.max_xrefs,
        },
        "second_pass": second_pass_summary,
        "level10_scores": scorecard,
        "dossier_quality": dossier_quality_counts(function_dossiers),
        "packed_or_obfuscated": deobfuscation::packed_or_obfuscated(image, recovered_strings, obfuscation_hints),
        "uncertainty": {
            "static_limitations": [
                format!("Static-only {format_label} analysis. Runtime-generated code and indirect call targets may need manual confirmation."),
            ],
            "records": uncertainties.len(),
        },
    })
}

fn triage_report(
    image: &dyn crate::image::BinaryImage,
    analysis: &Value,
    strings: &[StringRecord],
    imports: &[ImportRecord],
    functions: &[FunctionRecord],
) -> String {
    let mut lines = Vec::new();
    lines.push("=== FAST PE TRIAGE REPORT ===".to_string());
    lines.push(format!("Path: {}", image.source_path()));
    lines.push(format!("Engine: rust {}", env!("CARGO_PKG_VERSION")));
    lines.push(format!(
        "Elapsed: {:.3}s",
        analysis["elapsed_seconds"].as_f64().unwrap_or(0.0)
    ));
    lines.push(String::new());
    lines.push("Counts:".to_string());
    if let Some(counts) = analysis["counts"].as_object() {
        for (key, value) in counts {
            lines.push(format!("  {}: {}", key, value));
        }
    }
    lines.push(String::new());
    lines.push("Interesting strings:".to_string());
    for string in strings
        .iter()
        .filter(|row| !row.classifiers.is_empty())
        .take(50)
    {
        lines.push(format!(
            "  0x{:016X} {}: {}",
            string.va,
            string.classifiers.join(","),
            string.text
        ));
    }
    lines.push(String::new());
    lines.push("Suspicious imports:".to_string());
    for import in imports
        .iter()
        .filter(|row| !row.categories.is_empty())
        .take(100)
    {
        lines.push(format!(
            "  {} [{}]",
            import.symbol,
            import.categories.join(",")
        ));
    }
    lines.push(String::new());
    lines.push("Top functions:".to_string());
    let mut top = functions.to_vec();
    top.sort_by_key(|func| {
        std::cmp::Reverse(func.calls_imports.len() * 8 + func.strings.len() * 3 + func.xrefs)
    });
    for function in top.iter().take(50) {
        lines.push(format!(
            "  0x{:016X}-0x{:016X} {} imports={} strings={}",
            function.start,
            function.end,
            function.source,
            function.calls_imports.len(),
            function.strings.len()
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn dossier_quality_counts(dossiers: &[FunctionDossierRecord]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for row in dossiers {
        *counts.entry(row.dossier_quality.clone()).or_insert(0) += 1;
    }
    counts
}

fn instruction_budget(options: &AnalysisOptions) -> usize {
    match options.semantic_budget.as_str() {
        "max" => usize::MAX,
        "high" => 12_000_000,
        _ => 6_000_000,
    }
}

fn case_brief(
    image: &dyn crate::image::BinaryImage,
    sha256: &str,
    analysis: &Value,
    interesting: &[FunctionDossierRecord],
    api_flows: &[ApiFlowRecord],
    classes: &[ClassDossierRecord],
    recovered_strings: &[RecoveredStringRecord],
    obfuscation_hints: &[ObfuscationHintRecord],
    uncertainties: &[UncertaintyRecord],
) -> Value {
    json!({
        "path": image.source_path(),
        "sha256": sha256,
        "engine": analysis["engine"],
        "counts": analysis["counts"],
        "semantic_level": analysis["semantic_level"],
        "semantic_budget": analysis["semantic_budget"],
        "semantic_focus": analysis["semantic_focus"],
        "semantic_caps_hit": analysis["semantic_caps_hit"],
        "semantic_counters": analysis["semantic_counters"],
        "second_pass": analysis["second_pass"],
        "capability_matrix": analysis["capability_matrix"],
        "top_functions": interesting.iter().take(50).collect::<Vec<_>>(),
        "api_flow_summary": dossiers::flow_summary(api_flows),
        "class_count": classes.len(),
        "recovered_string_count": recovered_strings.len(),
        "obfuscation_hint_count": obfuscation_hints.len(),
        "uncertainty_count": uncertainties.len(),
        "packed_or_obfuscated": analysis["packed_or_obfuscated"],
        "uncertainty": analysis["uncertainty"],
    })
}

fn tls_callbacks(image: &PEImage) -> Vec<u64> {
    let Some(dir) = image.directory(9) else {
        return Vec::new();
    };
    let Some(offset) = image.rva_to_file_offset(dir.rva) else {
        return Vec::new();
    };
    if offset + 32 > image.bytes().len() {
        return Vec::new();
    }
    vec![read_u64(image.bytes(), offset + 24).unwrap_or(0)]
}

fn overlay_offset(image: &dyn crate::image::BinaryImage) -> Option<usize> {
    let end = image
        .sections()
        .iter()
        .map(|section| section.raw_start as usize + section.raw_size as usize)
        .max()
        .unwrap_or(0);
    (end > 0 && end < image.bytes().len()).then_some(end)
}

fn maybe_run_unpack(
    pe_path: &str,
    out_dir: &Path,
    options: &AnalysisOptions,
) -> Result<Option<Value>, Box<dyn Error>> {
    if options.unpack_mode != "on" {
        return Ok(None);
    }
    let unpack_out = options
        .unpack_out
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_else(|| out_dir.join("unpack"));
    fs::create_dir_all(&unpack_out)?;

    #[cfg(not(feature = "unpack"))]
    {
        let _ = pe_path;
        let status = json!({
            "schema": "unpack_run_status/1",
            "outcome": "skipped",
            "reason": "unpack_feature_not_compiled",
            "requested": true,
            "tracer": options.unpack_tracer,
            "timeout_secs": options.unpack_timeout_secs,
            "instr_budget": options.unpack_instr_budget,
        });
        write_json(unpack_out.join("run_status.json"), &status)?;
        return Ok(Some(json!({
            "schema": "axe_unpack_summary/1",
            "mode": "on",
            "out_dir": unpack_out.to_string_lossy(),
            "outcome": "skipped",
            "reason": "unpack_feature_not_compiled",
            "snapshot_path": null,
            "unpacked_static": null,
        })));
    }

    #[cfg(feature = "unpack")]
    {
        let unpack_options = crate::unpack::UnpackOptions {
            mode: crate::unpack::UnpackMode::On,
            tracer_mode: match options.unpack_tracer.as_str() {
                "whp" => crate::unpack::TracerMode::Whp,
                "driver" => crate::unpack::TracerMode::Driver,
                "auto" => crate::unpack::TracerMode::Auto,
                _ => crate::unpack::TracerMode::Debug,
            },
            timeout_secs: options.unpack_timeout_secs,
            instr_budget: options.unpack_instr_budget,
            out_dir: unpack_out.clone(),
            hooks_disable: options.unpack_hooks_disable,
            include_devirt: options.unpack_include_devirt,
        };
        match crate::unpack::session::run_session(Path::new(pe_path), &unpack_options) {
            Ok(report) => {
                let snapshot_path = report.snapshot_path.clone();
                let mut summary = json!({
                    "schema": "axe_unpack_summary/1",
                    "mode": "on",
                    "out_dir": unpack_out.to_string_lossy(),
                    "outcome": format!("{:?}", report.outcome).to_ascii_lowercase(),
                    "regions_dumped": report.regions_dumped,
                    "top_oep_confidence": report.top_oep_confidence,
                    "snapshot_path": snapshot_path.as_ref().map(|p| p.to_string_lossy().to_string()),
                    "unpacked_static": null,
                });
                if let Some(snapshot_path) = snapshot_path.filter(|path| path.is_file()) {
                    let unpacked_static = out_dir.join("unpacked_static");
                    match PEImage::from_snapshot(&snapshot_path) {
                        Ok(snapshot_image) => {
                            let mut recursive_options = options.clone();
                            recursive_options.unpack_mode = "off".to_string();
                            recursive_options.unpack_out = None;
                            recursive_options.progress_path = None;
                            recursive_options.precomputed_sha256 = None;
                            run_analysis(
                                &snapshot_image,
                                unpacked_static.to_str().ok_or_else(|| {
                                    std::io::Error::new(
                                        std::io::ErrorKind::InvalidInput,
                                        "unpacked_static path is not UTF-8",
                                    )
                                })?,
                                recursive_options,
                            )?;
                            if let Some(object) = summary.as_object_mut() {
                                object.insert(
                                    "unpacked_static".to_string(),
                                    json!(unpacked_static.to_string_lossy()),
                                );
                            }
                        }
                        Err(err) => {
                            if let Some(object) = summary.as_object_mut() {
                                object.insert(
                                    "unpacked_static_error".to_string(),
                                    json!(err.to_string()),
                                );
                            }
                        }
                    }
                }
                Ok(Some(summary))
            }
            Err(err) => {
                let status = json!({
                    "schema": "unpack_run_status/1",
                    "outcome": "skipped",
                    "reason": err.to_string(),
                    "requested": true,
                    "tracer": options.unpack_tracer,
                });
                write_json(unpack_out.join("run_status.json"), &status)?;
                Ok(Some(json!({
                    "schema": "axe_unpack_summary/1",
                    "mode": "on",
                    "out_dir": unpack_out.to_string_lossy(),
                    "outcome": "skipped",
                    "reason": err.to_string(),
                    "snapshot_path": null,
                    "unpacked_static": null,
                })))
            }
        }
    }
}

fn write_json(path: PathBuf, value: &Value) -> Result<(), Box<dyn Error>> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(BufWriter::new(file), value)?;
    Ok(())
}

fn write_progress(
    options: &AnalysisOptions,
    pe_path: &str,
    phase: &str,
    phase_started: &Instant,
    total_started: &Instant,
) {
    let Some(path) = &options.progress_path else {
        return;
    };
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let updated_at_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0);
    let payload = json!({
        "engine": "rust",
        "path": pe_path,
        "phase": phase,
        "phase_elapsed_seconds": phase_started.elapsed().as_secs_f64(),
        "elapsed_seconds": total_started.elapsed().as_secs_f64(),
        "updated_at_epoch": updated_at_epoch,
    });
    if let Ok(bytes) = serde_json::to_vec(&payload) {
        let _ = fs::write(path, bytes);
    }
}

fn write_jsonl<T: Serialize>(path: PathBuf, rows: &[T]) -> Result<(), Box<dyn Error>> {
    write_jsonl_iter(path, rows.iter())
}

/// Stream records to JSONL on disk. Avoids the temporary `Vec<String>` you'd
/// build with `rows.iter().map(serde_json::to_string)`; each record is
/// serialized straight into the BufWriter.
pub(crate) fn write_jsonl_iter<T, I>(path: PathBuf, rows: I) -> Result<(), Box<dyn Error>>
where
    T: Serialize,
    I: IntoIterator<Item = T>,
{
    let mut writer = BufWriter::with_capacity(256 * 1024, File::create(path)?);
    for row in rows {
        serde_json::to_writer(&mut writer, &row)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    Ok(())
}

fn remaining_uncertainties_after_pass2(
    uncertainties: &[UncertaintyRecord],
    jump_tables: &[JumpTableRecord],
    api_hashes: &[ApiHashResolutionRecord],
    decoded_strings: &[RecoveredStringRecord],
    vsa_values: &[VsaValueRecord],
    resolved_calls: &[ResolvedCallRecord],
) -> Vec<UncertaintyRecord> {
    let mut rows = uncertainties
        .iter()
        .filter(|row| {
            if row.reason == "api_hash_unresolved"
                && api_hashes.iter().any(|hash| hash.function == row.function)
            {
                return false;
            }
            if row.reason == "packed_or_encoded_blob"
                && decoded_strings
                    .iter()
                    .any(|string| string.function == row.function)
            {
                return false;
            }
            if row.reason == "indirect_jump_unresolved"
                && jump_tables.iter().any(|table| {
                    table.function == row.function
                        && row.site_va.is_some_and(|site| table.jump_va == site)
                })
            {
                return false;
            }
            true
        })
        .cloned()
        .collect::<Vec<_>>();
    for value in vsa_values.iter().filter(|row| row.work_budget_exhausted) {
        rows.push(UncertaintyRecord {
            uncertainty_id: format!(
                "uncertainty:{:016X}:vsa_precision_loss:{:016X}",
                value.function, value.site_va
            ),
            function: value.function,
            site_va: Some(value.site_va),
            reason: "vsa_precision_loss".to_string(),
            details: value
                .value
                .clone()
                .unwrap_or_else(|| "bounded VSA precision was dropped at cap".to_string()),
            tried: vec![
                "ssa_cfg_worklist".to_string(),
                "loop_widening".to_string(),
                "bounded_backslice".to_string(),
            ],
            recommended_action: "increase --semantic-budget or inspect review pack".to_string(),
            severity_hint: "medium".to_string(),
            evidence: value.evidence.clone(),
        });
    }
    for call in resolved_calls
        .iter()
        .filter(|row| row.resolution_kind.as_deref() == Some("ambiguous_virtual_dispatch"))
    {
        rows.push(UncertaintyRecord {
            uncertainty_id: format!(
                "uncertainty:{:016X}:ambiguous_virtual_dispatch:{:016X}",
                call.caller, call.callsite
            ),
            function: call.caller,
            site_va: Some(call.callsite),
            reason: "ambiguous_virtual_dispatch".to_string(),
            details: format!(
                "virtual call slot {:?} has {} candidate targets",
                call.vtable_slot,
                call.candidate_targets.len()
            ),
            tried: vec![
                "rtti_vftable_scan".to_string(),
                "constructor_vtable_store_refinement".to_string(),
                "virtual_slot_resolution".to_string(),
            ],
            recommended_action: "review candidate_targets and class ownership evidence".to_string(),
            severity_hint: "medium".to_string(),
            evidence: vec![call.callsite],
        });
    }
    rows.sort_by(|left, right| {
        left.function
            .cmp(&right.function)
            .then_with(|| left.site_va.cmp(&right.site_va))
            .then_with(|| left.reason.cmp(&right.reason))
    });
    rows.dedup_by(|left, right| {
        left.function == right.function
            && left.site_va == right.site_va
            && left.reason == right.reason
    });
    rows
}

fn write_review_packs(
    dir: PathBuf,
    interesting: &[FunctionDossierRecord],
    behaviors: &[BehaviorDossierRecord],
    classes: &[ClassDossierRecord],
    pseudo_ir: &[PseudoIrRecord],
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(&dir)?;
    let behavior_by_id: BTreeMap<&str, &BehaviorDossierRecord> = behaviors
        .iter()
        .map(|row| (row.behavior_id.as_str(), row))
        .collect();
    let class_by_id: BTreeMap<&str, &ClassDossierRecord> = classes
        .iter()
        .map(|row| (row.class_id.as_str(), row))
        .collect();
    let pseudo_by_id: BTreeMap<&str, &PseudoIrRecord> = pseudo_ir
        .iter()
        .map(|row| (row.pseudo_ir_id.as_str(), row))
        .collect();
    let mut manifest = Vec::new();
    for (index, function) in interesting.iter().take(25).enumerate() {
        let behaviors = function
            .behavior_refs
            .iter()
            .filter_map(|id| behavior_by_id.get(id.as_str()).copied())
            .collect::<Vec<_>>();
        let classes = function
            .class_refs
            .iter()
            .filter_map(|id| class_by_id.get(id.as_str()).copied())
            .collect::<Vec<_>>();
        let pseudo = function
            .pseudo_ir_id
            .as_deref()
            .and_then(|id| pseudo_by_id.get(id).copied());
        let filename = format!("{index:03}_0x{:016X}.json", function.function);
        let payload = json!({
            "schema": "review_pack/1",
            "function": function,
            "behaviors": behaviors,
            "classes": classes,
            "pseudo_ir": pseudo,
        });
        write_json(dir.join(&filename), &payload)?;
        manifest.push(json!({
            "file": filename,
            "function": function.function,
            "score": function.score,
            "dossier_quality": function.dossier_quality,
        }));
    }
    write_json(
        dir.join("manifest.json"),
        &json!({ "schema": "review_pack_manifest/1", "packs": manifest }),
    )?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn entropy(data: &[u8]) -> f64 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_uncertainties_filters_facts_resolved_by_pass2() {
        let uncertainties = vec![
            uncertainty(0x1000, Some(0x1010), "indirect_jump_unresolved"),
            uncertainty(0x2000, Some(0x2010), "api_hash_unresolved"),
            uncertainty(0x3000, Some(0x3010), "packed_or_encoded_blob"),
            uncertainty(0x4000, Some(0x4010), "indirect_call_unresolved"),
        ];
        let jump_tables = vec![JumpTableRecord {
            table_id: "jt".to_string(),
            function: 0x1000,
            jump_va: 0x1010,
            table_va: Some(0x8000),
            entry_size: 8,
            targets: vec![0x5000, 0x5010],
            confidence: "high".to_string(),
            evidence: vec![0x1010],
        }];
        let hashes = vec![ApiHashResolutionRecord {
            resolution_id: "hash".to_string(),
            function: 0x2000,
            site_va: Some(0x2010),
            algorithm: "ror13".to_string(),
            hash_value: "0x1".to_string(),
            resolved_api: "KERNEL32.dll!CreateFileW".to_string(),
            confidence: "medium".to_string(),
            evidence: vec![0x2010],
        }];
        let decoded = vec![RecoveredStringRecord {
            recovered_id: "str".to_string(),
            function: 0x3000,
            kind: "decoded_string".to_string(),
            text: "CreateFileW".to_string(),
            tags: vec!["api".to_string()],
            confidence: "medium".to_string(),
            evidence: vec![0x3010],
        }];

        let remaining = remaining_uncertainties_after_pass2(
            &uncertainties,
            &jump_tables,
            &hashes,
            &decoded,
            &[],
            &[],
        );

        assert_eq!(1, remaining.len());
        assert_eq!("indirect_call_unresolved", remaining[0].reason);
    }

    fn uncertainty(function: u64, site_va: Option<u64>, reason: &str) -> UncertaintyRecord {
        UncertaintyRecord {
            uncertainty_id: format!("u:{function:X}:{reason}"),
            function,
            site_va,
            reason: reason.to_string(),
            details: reason.to_string(),
            tried: vec!["test".to_string()],
            recommended_action: "manual review".to_string(),
            severity_hint: "low".to_string(),
            evidence: site_va.into_iter().collect(),
        }
    }
}

fn read_c_string(bytes: &[u8], start: usize) -> Option<String> {
    if start >= bytes.len() {
        return None;
    }
    let mut end = start;
    while end < bytes.len() && bytes[end] != 0 {
        end += 1;
    }
    Some(String::from_utf8_lossy(&bytes[start..end]).to_string())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Box<dyn Error>> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or("read_u16 out of bounds")?
            .try_into()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Box<dyn Error>> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or("read_u32 out of bounds")?
            .try_into()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, Box<dyn Error>> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or("read_u64 out of bounds")?
            .try_into()?,
    ))
}
