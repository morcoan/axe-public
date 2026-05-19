#![allow(dead_code)]

use crate::pe::{
    ApiFlowRecord, CfgRecord, DataflowEdgeRecord, ExportRecord, FunctionRecord, ImportRecord,
    InstructionRecord, SectionRecord, SsaValueRecord, StringRecord, StructuredFlowRecord,
    UncertaintyRecord, XrefRecord,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Serialize)]
pub struct CapabilityStatusRecord {
    pub capability: String,
    pub status: String,
    pub available: bool,
    pub ran: bool,
    pub skipped: bool,
    pub unsupported_portable: bool,
    pub truthfulness_level: String,
    pub claim: String,
    pub evidence_files: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct CapabilityMatrixRecord {
    pub schema: String,
    pub profile: String,
    pub portable_mode: bool,
    pub portable_tools_dir: String,
    pub emulation_budget: String,
    pub capabilities: Vec<CapabilityStatusRecord>,
}

#[derive(Clone, Serialize)]
pub struct EmulationTraceRecord {
    pub trace_id: String,
    pub function: u64,
    pub start_va: u64,
    pub status: String,
    pub step_count: usize,
    pub supported_steps: usize,
    pub unsupported_instructions: Vec<String>,
    pub cap_hit: bool,
    pub budget: String,
    pub api_stubs: Vec<String>,
    pub api_stub_events: Vec<String>,
    pub memory_events: Vec<String>,
    pub exit_reason: String,
    pub registers: BTreeMap<String, u64>,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct SymbolicPathRecord {
    pub path_id: String,
    pub function: u64,
    pub site_va: u64,
    pub predicate: String,
    pub status: String,
    pub reason: String,
    pub constraints: Vec<String>,
    pub satisfiability: String,
    pub model: BTreeMap<String, u64>,
    pub cap_hit: bool,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct UnpackedArtifactRecord {
    pub artifact_id: String,
    pub parent_sha256: String,
    pub method: String,
    pub confidence: String,
    pub output_path: String,
    pub failure_reason: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct CrossArchSummaryRecord {
    pub schema: String,
    pub detected_format: String,
    pub machine: u16,
    pub arch: String,
    pub depth: String,
    pub notes: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct FirmwareModuleRecord {
    pub module_id: String,
    pub module_type: String,
    pub classification: String,
    pub smm_indicator: bool,
    pub guid: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct KernelArtifactRecord {
    pub artifact_id: String,
    pub artifact_type: String,
    pub kernel_imports: Vec<String>,
    pub signals: Vec<String>,
    pub dispatch_routines: Vec<String>,
    pub ioctl_codes: Vec<String>,
    pub device_names: Vec<String>,
    pub confidence: String,
    pub evidence: Vec<String>,
}

#[derive(Clone, Serialize)]
pub struct VulnCandidateRecord {
    pub candidate_id: String,
    pub function: Option<u64>,
    pub site_va: Option<u64>,
    pub kind: String,
    pub summary: String,
    pub confidence: String,
    pub evidence: Vec<u64>,
    pub fuzz_harness_ref: String,
}

#[derive(Clone, Serialize)]
pub struct FuzzHarnessRecord {
    pub harness_id: String,
    pub candidate_id: String,
    pub kind: String,
    pub status: String,
    pub output_path: String,
}

#[derive(Clone, Serialize)]
pub struct FuzzHarnessManifestRecord {
    pub schema: String,
    pub generated: bool,
    pub harnesses: Vec<FuzzHarnessRecord>,
}

#[derive(Clone, Serialize)]
pub struct FuzzRunRecord {
    pub run_id: String,
    pub harness_id: String,
    pub candidate_id: String,
    pub status: String,
    pub iteration: usize,
    pub seed: u64,
    pub exercised_va: Option<u64>,
    pub exit_reason: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct DecompiledCRecord {
    pub decompile_id: String,
    pub function: u64,
    pub status: String,
    pub output_path: String,
    pub lines: Vec<String>,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct TraceEventRecord {
    pub event_id: String,
    pub source_path: String,
    pub event_type: String,
    pub timestamp: Option<String>,
    pub va: Option<u64>,
    pub api: Option<String>,
    pub registers: BTreeMap<String, String>,
    pub evidence: Vec<u64>,
}

#[derive(Clone, Serialize)]
pub struct TraceCorrelationRecord {
    pub correlation_id: String,
    pub event_id: String,
    pub function: Option<u64>,
    pub import: Option<String>,
    pub confidence: String,
    pub evidence: Vec<u64>,
}

pub struct PortableInput<'a> {
    pub profile: &'a str,
    pub portable_tools_dir: &'a str,
    pub emulation_budget: &'a str,
    pub fuzz_mode: &'a str,
    pub fuzz_iterations: usize,
    pub trace_dir: Option<&'a Path>,
    pub decompile_c: &'a str,
    pub sha256: &'a str,
    pub source_path: &'a str,
    pub out_dir: &'a Path,
    pub bytes: &'a [u8],
    pub machine: u16,
    pub file_size: usize,
    pub overlay_size: usize,
    pub sections: &'a [SectionRecord],
    pub imports: &'a [ImportRecord],
    pub exports: &'a [ExportRecord],
    pub strings: &'a [StringRecord],
    pub functions: &'a [FunctionRecord],
    pub instructions: &'a [InstructionRecord],
    pub cfg: &'a [CfgRecord],
    pub ssa_values: &'a [SsaValueRecord],
    pub dataflow_edges: &'a [DataflowEdgeRecord],
    pub structured_flow: &'a [StructuredFlowRecord],
    pub xrefs: &'a [XrefRecord],
    pub api_flows: &'a [ApiFlowRecord],
}

pub struct PortableOutput {
    pub matrix: CapabilityMatrixRecord,
    pub emulation_traces: Vec<EmulationTraceRecord>,
    pub symbolic_paths: Vec<SymbolicPathRecord>,
    pub unpacked_artifacts: Vec<UnpackedArtifactRecord>,
    pub cross_arch_summary: CrossArchSummaryRecord,
    pub firmware_modules: Vec<FirmwareModuleRecord>,
    pub kernel_artifacts: Vec<KernelArtifactRecord>,
    pub vuln_candidates: Vec<VulnCandidateRecord>,
    pub fuzz_manifest: FuzzHarnessManifestRecord,
    pub fuzz_runs: Vec<FuzzRunRecord>,
    pub decompiled_c: Vec<DecompiledCRecord>,
    pub trace_events: Vec<TraceEventRecord>,
    pub trace_correlations: Vec<TraceCorrelationRecord>,
    pub uncertainties: Vec<UncertaintyRecord>,
}

pub fn build_portable_capabilities(input: PortableInput<'_>) -> PortableOutput {
    let native_mode = input.profile == "native-max";
    let emulation_result = crate::native_emulator::emulate(&input);
    let emulation_traces = emulation_result
        .as_ref()
        .map(|result| vec![result.trace.clone()])
        .unwrap_or_default();
    let symbolic_paths =
        crate::symbolic_solver::build_symbolic_paths(&input, emulation_result.as_ref());
    let unpacked_artifacts = build_unpacked_artifacts(&input);
    let (firmware_modules, firmware_artifacts) =
        crate::firmware_unpacker::build_firmware_modules(&input);
    let mut unpacked_artifacts = unpacked_artifacts;
    unpacked_artifacts.extend(firmware_artifacts);
    let cross_arch_summary = cross_arch_summary(&input);
    let kernel_artifacts = crate::driver_triage::build_kernel_artifacts(&input);
    let vuln_candidates = build_vuln_candidates(&input);
    let fuzz_records = build_fuzz_harnesses(&input, &vuln_candidates);
    let fuzz_runs =
        crate::native_fuzzer::run_fuzz(&input, &vuln_candidates, emulation_result.as_ref());
    let fuzz_manifest = FuzzHarnessManifestRecord {
        schema: "fuzz_harness_manifest/1".to_string(),
        generated: !fuzz_records.is_empty(),
        harnesses: fuzz_records,
    };
    let decompiled_c = crate::c_decompiler::build_decompiled_c(&input);
    let (trace_events, trace_correlations) = crate::trace_ingest::ingest_traces(&input);
    let matrix = capability_matrix(
        &input,
        emulation_result.as_ref(),
        !symbolic_paths.is_empty(),
        !unpacked_artifacts.is_empty(),
        !firmware_modules.is_empty(),
        !kernel_artifacts.is_empty(),
        !fuzz_manifest.harnesses.is_empty(),
        !fuzz_runs.is_empty(),
        !decompiled_c.is_empty(),
        !trace_events.is_empty(),
        native_mode,
    );
    let uncertainties = portable_uncertainties(&input, &matrix, emulation_result.as_ref());
    PortableOutput {
        matrix,
        emulation_traces,
        symbolic_paths,
        unpacked_artifacts,
        cross_arch_summary,
        firmware_modules,
        kernel_artifacts,
        vuln_candidates,
        fuzz_manifest,
        fuzz_runs,
        decompiled_c,
        trace_events,
        trace_correlations,
        uncertainties,
    }
}

fn capability_matrix(
    input: &PortableInput<'_>,
    emulation: Option<&crate::native_emulator::NativeEmulationResult>,
    symbolic_executed: bool,
    unpacked_extracted: bool,
    firmware_ran: bool,
    kernel_ran: bool,
    fuzz_generated: bool,
    fuzz_executed: bool,
    decompiled: bool,
    traces_ingested: bool,
    native_mode: bool,
) -> CapabilityMatrixRecord {
    let mut rows = Vec::new();
    rows.push(capability(
        "static_pe_re",
        "executed",
        true,
        true,
        false,
        false,
        "executed_bytes",
        "parsed PE metadata, imports, strings, functions, and decoded instruction evidence from the input file",
        &["analysis.json", "functions.jsonl"],
        &[],
    ));
    let emulation_status = match emulation {
        Some(result) if result.cap_hit => "failed_capped",
        Some(_) => "executed",
        None => "skipped_no_evidence",
    };
    rows.push(capability(
        "bounded_offline_emulation",
        emulation_status,
        true,
        emulation_status == "executed",
        emulation_status == "skipped_no_evidence",
        false,
        if emulation.is_some() {
            "executed_bytes"
        } else {
            "metadata_only"
        },
        if emulation.is_some() {
            if native_mode {
                "stepped decoded basic blocks in a native bounded register, stack, memory, branch, and API-stub model"
            } else {
                "stepped a bounded subset of decoded user-mode instructions in a sandboxed register/stack model"
            }
        } else {
            "no supported instruction sequence was available for portable emulation"
        },
        &["emulation_traces.jsonl"],
        &[],
    ));
    let symbolic_status = if symbolic_executed {
        "executed"
    } else {
        "skipped_no_evidence"
    };
    rows.push(capability(
        "bounded_symbolic_paths",
        symbolic_status,
        true,
        symbolic_executed,
        !symbolic_executed,
        false,
        if symbolic_executed {
            "executed_bytes"
        } else {
            "metadata_only"
        },
        if symbolic_executed {
            if native_mode {
                "solved bounded native branch constraints over register/input symbols without external SMT dependencies"
            } else {
                "forked supported conditional branch predicates from the bounded emulator; no SMT solver or host execution was used"
            }
        } else {
            "no supported conditional branch predicates were reached by the bounded symbolic engine"
        },
        &["symbolic_paths.jsonl"],
        &[],
    ));
    let unpack_status = if unpacked_extracted {
        "executed"
    } else {
        "skipped_no_evidence"
    };
    rows.push(capability(
        "portable_unpacking",
        unpack_status,
        true,
        unpacked_extracted,
        !unpacked_extracted,
        false,
        if unpacked_extracted {
            "executed_bytes"
        } else {
            "metadata_only"
        },
        if unpacked_extracted {
            "copied overlay or suspicious section bytes into portable_artifacts without modifying the source file"
        } else {
            "no overlay or suspicious extractable section bytes were found"
        },
        &["unpacked_artifacts.jsonl"],
        &[],
    ));
    rows.push(capability(
        "cross_arch_triage",
        "triaged",
        true,
        true,
        false,
        false,
        "metadata_only",
        "classified the input architecture from PE machine metadata",
        &["cross_arch_summary.json"],
        &[],
    ));
    let firmware_status = if firmware_ran && native_mode {
        "executed"
    } else if firmware_ran {
        "triaged"
    } else {
        "not_applicable"
    };
    rows.push(capability(
        "firmware_uefi_triage",
        firmware_status,
        true,
        firmware_ran,
        !firmware_ran,
        false,
        if firmware_ran {
            "static_artifact_triage"
        } else {
            "metadata_only"
        },
        if firmware_ran {
            if native_mode {
                "parsed TE/UEFI firmware indicators and extracted bounded module bytes into portable_artifacts"
            } else {
                "matched UEFI/firmware indicators and emitted module triage records"
            }
        } else {
            "input did not match EFI, TE, PEI/DXE, SMM, or firmware container indicators"
        },
        &["firmware_modules.jsonl"],
        &[],
    ));
    let kernel_status = if kernel_ran && native_mode {
        "executed"
    } else if kernel_ran {
        "triaged"
    } else {
        "not_applicable"
    };
    rows.push(capability(
        "kernel_driver_static_triage",
        kernel_status,
        true,
        kernel_ran,
        !kernel_ran,
        false,
        if kernel_ran {
            "static_artifact_triage"
        } else {
            "metadata_only"
        },
        if kernel_ran {
            if native_mode {
                "analyzed driver imports, dispatch-style kernel APIs, device names, and IOCTL constants"
            } else {
                "matched driver/kernel import indicators and emitted static driver triage records"
            }
        } else {
            "input did not match .sys or kernel-driver import indicators"
        },
        &["kernel_artifacts.jsonl"],
        &[],
    ));
    let fuzz_status = if fuzz_executed {
        "executed"
    } else if fuzz_generated {
        "generated"
    } else {
        "skipped_no_evidence"
    };
    rows.push(capability(
        "vuln_fuzz_prep",
        fuzz_status,
        true,
        fuzz_executed,
        !fuzz_generated,
        false,
        if fuzz_executed {
            "executed_fuzz_with_classification"
        } else if fuzz_generated {
            "generated_stub"
        } else {
            "metadata_only"
        },
        if fuzz_executed {
            "drove the bounded native emulator with mutated Win64 register inputs per iteration, classified each exit (normal/loop_guard/branch_exit/budget_cap/oob_write), and flagged divergence vs an all-zero baseline"
        } else if fuzz_generated {
            "generated static fuzz harness stubs for VA-cited candidate sinks; fuzzing was not executed"
        } else {
            "no supported VA-cited sink was found for fuzz harness generation"
        },
        &[
            "vuln_candidates.jsonl",
            "fuzz_harnesses/manifest.json",
            "fuzz_runs.jsonl",
        ],
        if fuzz_generated {
            &[]
        } else {
            &["No VA-cited vuln candidates found in portable static pass."]
        },
    ));
    let decompile_status = if decompiled {
        "executed"
    } else {
        "skipped_no_evidence"
    };
    rows.push(capability(
        "native_c_decompilation",
        decompile_status,
        native_mode,
        decompiled,
        !decompiled,
        false,
        if decompiled {
            "lifted_c_with_types"
        } else {
            "metadata_only"
        },
        if decompiled {
            "lifted typed C-99 statements per instruction with SSA-derived locals, WinAPI-prototype-driven argument types at callsites, register-width type inference, and goto-form control flow for irreducible regions"
        } else if native_mode {
            "native C-like decompilation was enabled but no selected function was available"
        } else {
            "portable-max does not emit native C-like decompiler output"
        },
        &["decompiled_c.jsonl"],
        &[],
    ));
    let trace_status = if traces_ingested {
        "executed"
    } else {
        "skipped_no_evidence"
    };
    rows.push(capability(
        "offline_trace_ingest",
        trace_status,
        native_mode,
        traces_ingested,
        !traces_ingested,
        false,
        if traces_ingested {
            "ingested_trace"
        } else {
            "metadata_only"
        },
        if traces_ingested {
            "ingested supplied offline hypervisor/kernel trace events and correlated them to static functions/imports; no live collection was performed"
        } else if native_mode {
            "no --trace-dir JSONL events were supplied for offline hypervisor/kernel trace ingestion"
        } else {
            "portable-max has no supplied trace corpus to ingest"
        },
        &["trace_events.jsonl", "trace_correlations.jsonl"],
        &[],
    ));
    rows.push(capability(
        "live_hypervisor_introspection",
        "unsupported_portable",
        false,
        false,
        false,
        true,
        "unsupported",
        "portable offline mode cannot perform live hypervisor introspection",
        &[],
        &["Requires a configured hypervisor/VM backend; portable offline mode will not execute host introspection."],
    ));
    rows.push(capability(
        "live_kernel_telemetry",
        "unsupported_portable",
        false,
        false,
        false,
        true,
        "unsupported",
        "portable offline mode cannot collect live kernel telemetry",
        &[],
        &["Requires live kernel telemetry or supplied traces; portable offline mode only analyzes artifacts."],
    ));
    CapabilityMatrixRecord {
        schema: "capability_matrix/1".to_string(),
        profile: input.profile.to_string(),
        portable_mode: true,
        portable_tools_dir: input.portable_tools_dir.to_string(),
        emulation_budget: input.emulation_budget.to_string(),
        capabilities: rows,
    }
}

fn capability(
    name: &str,
    status: &str,
    available: bool,
    ran: bool,
    skipped: bool,
    unsupported: bool,
    truthfulness_level: &str,
    claim: &str,
    evidence: &[&str],
    notes: &[&str],
) -> CapabilityStatusRecord {
    CapabilityStatusRecord {
        capability: name.to_string(),
        status: status.to_string(),
        available,
        ran,
        skipped,
        unsupported_portable: unsupported,
        truthfulness_level: truthfulness_level.to_string(),
        claim: claim.to_string(),
        evidence_files: evidence.iter().map(|value| value.to_string()).collect(),
        notes: notes.iter().map(|value| value.to_string()).collect(),
    }
}

#[derive(Clone)]
struct PortableEmulationResult {
    function: u64,
    start_va: u64,
    steps: usize,
    supported_steps: usize,
    unsupported_instructions: Vec<String>,
    cap_hit: bool,
    registers: BTreeMap<String, u64>,
    predicates: Vec<(u64, String)>,
}

fn emulate_portable_function(input: &PortableInput<'_>) -> Option<PortableEmulationResult> {
    let function = input.functions.first()?;
    let cap = match input.emulation_budget {
        "max" => 256,
        "high" => 128,
        _ => 64,
    };
    let mut state = PortableEmuState::default();
    let mut steps = 0usize;
    let mut supported_steps = 0usize;
    let mut unsupported = Vec::new();
    let mut predicates = Vec::new();
    let mut cap_hit = false;

    for row in input
        .instructions
        .iter()
        .filter(|row| row.address >= function.start && row.address < function.end)
    {
        if steps >= cap {
            cap_hit = true;
            break;
        }
        steps += 1;
        match emulate_instruction(row, &mut state) {
            EmuStep::Supported => supported_steps += 1,
            EmuStep::Branch(predicate) => {
                supported_steps += 1;
                predicates.push((row.address, predicate));
            }
            EmuStep::Unsupported(reason) => {
                if unsupported.len() < 8 {
                    unsupported.push(format!(
                        "0x{:016X}: {} {} ({reason})",
                        row.address, row.mnemonic, row.op_str
                    ));
                }
            }
        }
    }

    if supported_steps == 0 {
        return None;
    }
    Some(PortableEmulationResult {
        function: function.start,
        start_va: function.start,
        steps,
        supported_steps,
        unsupported_instructions: unsupported,
        cap_hit,
        registers: state.registers,
        predicates,
    })
}

fn build_emulation_traces(
    input: &PortableInput<'_>,
    result: Option<&PortableEmulationResult>,
) -> Vec<EmulationTraceRecord> {
    let Some(result) = result else {
        return Vec::new();
    };
    vec![EmulationTraceRecord {
        trace_id: format!("emu:{:016X}:0000", result.function),
        function: result.function,
        start_va: result.start_va,
        status: if result.cap_hit {
            "failed_capped".to_string()
        } else {
            "executed".to_string()
        },
        step_count: result.steps,
        supported_steps: result.supported_steps,
        unsupported_instructions: result.unsupported_instructions.clone(),
        cap_hit: result.cap_hit,
        budget: input.emulation_budget.to_string(),
        api_stubs: input
            .imports
            .iter()
            .take(16)
            .map(|row| row.symbol.clone())
            .collect(),
        api_stub_events: Vec::new(),
        memory_events: Vec::new(),
        exit_reason: if result.cap_hit {
            "budget_cap".to_string()
        } else {
            "linear_scan_complete".to_string()
        },
        registers: result.registers.clone(),
        evidence: vec![result.start_va],
    }]
}

fn build_symbolic_paths(
    input: &PortableInput<'_>,
    result: Option<&PortableEmulationResult>,
) -> Vec<SymbolicPathRecord> {
    let Some(result) = result else {
        return Vec::new();
    };
    let cap = match input.emulation_budget {
        "max" => 256,
        "high" => 128,
        _ => 64,
    };
    result
        .predicates
        .iter()
        .take(cap)
        .enumerate()
        .map(|(index, (site_va, predicate))| SymbolicPathRecord {
            path_id: format!("sym:{site_va:016X}:{index:04X}"),
            function: result.function,
            site_va: *site_va,
            predicate: predicate.clone(),
            status: if result.cap_hit {
                "failed_capped".to_string()
            } else {
                "executed".to_string()
            },
            reason:
                "bounded symbolic predicate fork from sandboxed emulator; no SMT solver or host execution"
                    .to_string(),
            constraints: vec![predicate.clone()],
            satisfiability: "unknown".to_string(),
            model: BTreeMap::new(),
            cap_hit: result.cap_hit,
            evidence: vec![*site_va],
        })
        .collect()
}

#[derive(Default)]
struct PortableEmuState {
    registers: BTreeMap<String, u64>,
    stack: BTreeMap<i64, u64>,
    symbols: BTreeMap<String, String>,
    last_compare: Option<String>,
}

enum EmuStep {
    Supported,
    Branch(String),
    Unsupported(String),
}

fn emulate_instruction(row: &InstructionRecord, state: &mut PortableEmuState) -> EmuStep {
    let mnemonic = row.mnemonic.to_ascii_lowercase();
    let operands = split_operands(&row.op_str);
    match mnemonic.as_str() {
        "mov" => emulate_mov(&operands, state),
        "lea" => emulate_lea(&operands, state),
        "xor" | "add" | "sub" | "rol" | "ror" => emulate_binary(&mnemonic, &operands, state),
        "cmp" | "test" => {
            if operands.len() >= 2 {
                state.last_compare = Some(format!("{} {}", mnemonic, operands.join(", ")));
                EmuStep::Supported
            } else {
                EmuStep::Unsupported("missing comparison operands".to_string())
            }
        }
        "call" => EmuStep::Supported,
        "ret" | "nop" => EmuStep::Supported,
        _ if mnemonic.starts_with('j') && row.branch_target.is_some() => {
            let predicate = state
                .last_compare
                .clone()
                .unwrap_or_else(|| "unknown_condition".to_string());
            EmuStep::Branch(format!(
                "{} if {} -> 0x{:016X}",
                mnemonic,
                predicate,
                row.branch_target.unwrap_or_default()
            ))
        }
        _ => EmuStep::Unsupported("unsupported mnemonic in portable emulator".to_string()),
    }
}

fn emulate_mov(operands: &[String], state: &mut PortableEmuState) -> EmuStep {
    if operands.len() < 2 {
        return EmuStep::Unsupported("missing mov operands".to_string());
    }
    let dst = normalize_operand(&operands[0]);
    let src = normalize_operand(&operands[1]);
    if let Some(reg) = register_name(&dst) {
        if let Some(value) = value_of(&src, state) {
            state.registers.insert(reg.to_string(), value);
        } else if let Some(slot) = stack_slot(&src) {
            if let Some(value) = state.stack.get(&slot).copied() {
                state.registers.insert(reg.to_string(), value);
            }
        } else {
            state.symbols.insert(reg.to_string(), src);
        }
        return EmuStep::Supported;
    }
    if let Some(slot) = stack_slot(&dst) {
        if let Some(value) = value_of(&src, state) {
            state.stack.insert(slot, value);
        }
        return EmuStep::Supported;
    }
    EmuStep::Unsupported("unsupported mov operand form".to_string())
}

fn emulate_lea(operands: &[String], state: &mut PortableEmuState) -> EmuStep {
    if operands.len() < 2 {
        return EmuStep::Unsupported("missing lea operands".to_string());
    }
    let dst = normalize_operand(&operands[0]);
    let src = normalize_operand(&operands[1]);
    let Some(reg) = register_name(&dst) else {
        return EmuStep::Unsupported("lea destination is not a register".to_string());
    };
    if let Some(value) = parse_effective_address(&src) {
        state.registers.insert(reg.to_string(), value);
    } else {
        state.symbols.insert(reg.to_string(), src);
    }
    EmuStep::Supported
}

fn emulate_binary(mnemonic: &str, operands: &[String], state: &mut PortableEmuState) -> EmuStep {
    if operands.len() < 2 {
        return EmuStep::Unsupported("missing binary operands".to_string());
    }
    let dst = normalize_operand(&operands[0]);
    let src = normalize_operand(&operands[1]);
    let Some(reg) = register_name(&dst) else {
        return EmuStep::Unsupported("binary destination is not a register".to_string());
    };
    let lhs = state.registers.get(reg).copied().unwrap_or_default();
    let rhs = value_of(&src, state).unwrap_or_default();
    let value = match mnemonic {
        "xor" if normalize_operand(&operands[0]) == normalize_operand(&operands[1]) => 0,
        "xor" => lhs ^ rhs,
        "add" => lhs.wrapping_add(rhs),
        "sub" => lhs.wrapping_sub(rhs),
        "rol" => lhs.rotate_left((rhs & 63) as u32),
        "ror" => lhs.rotate_right((rhs & 63) as u32),
        _ => lhs,
    };
    state.registers.insert(reg.to_string(), value);
    EmuStep::Supported
}

fn split_operands(op_str: &str) -> Vec<String> {
    op_str
        .split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalize_operand(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("qword ptr")
        .trim_start_matches("dword ptr")
        .trim_start_matches("word ptr")
        .trim_start_matches("byte ptr")
        .trim()
        .to_ascii_lowercase()
}

fn register_name(value: &str) -> Option<&str> {
    const REGISTERS: &[&str] = &[
        "rax", "eax", "ax", "al", "rbx", "ebx", "rcx", "ecx", "rdx", "edx", "rsi", "esi", "rdi",
        "edi", "rsp", "esp", "rbp", "ebp", "r8", "r8d", "r9", "r9d", "r10", "r10d", "r11", "r11d",
        "r12", "r12d", "r13", "r13d", "r14", "r14d", "r15", "r15d",
    ];
    REGISTERS.iter().copied().find(|reg| *reg == value)
}

fn value_of(value: &str, state: &PortableEmuState) -> Option<u64> {
    parse_int(value)
        .or_else(|| register_name(value).and_then(|reg| state.registers.get(reg).copied()))
}

pub(crate) fn parse_int(value: &str) -> Option<u64> {
    let trimmed = value.trim().trim_end_matches('h');
    if let Some(hex) = trimmed.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else if value.ends_with('h') {
        u64::from_str_radix(trimmed, 16).ok()
    } else {
        trimmed.parse::<u64>().ok()
    }
}

fn stack_slot(value: &str) -> Option<i64> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    if !(inner.starts_with("rsp") || inner.starts_with("rbp")) {
        return None;
    }
    if inner == "rsp" || inner == "rbp" {
        return Some(0);
    }
    let sign_index = inner
        .find('+')
        .or_else(|| inner[1..].find('-').map(|idx| idx + 1))?;
    let sign = inner.as_bytes()[sign_index] as char;
    let amount = parse_int(&inner[sign_index + 1..])? as i64;
    Some(if sign == '-' { -amount } else { amount })
}

fn parse_effective_address(value: &str) -> Option<u64> {
    let inner = value.strip_prefix('[')?.strip_suffix(']')?;
    if let Some(rest) = inner.strip_prefix("rip+") {
        return parse_int(rest);
    }
    if let Some(rest) = inner.strip_prefix("rip-") {
        return parse_int(rest).map(|amount| 0u64.wrapping_sub(amount));
    }
    parse_int(inner)
}

fn build_unpacked_artifacts(input: &PortableInput<'_>) -> Vec<UnpackedArtifactRecord> {
    let mut rows = Vec::new();
    if input.overlay_size > 0 {
        let overlay_offset = input.bytes.len().saturating_sub(input.overlay_size);
        let data = input.bytes.get(overlay_offset..).unwrap_or_default();
        let (output_path, failure_reason) =
            write_portable_artifact(input.out_dir, "overlay.bin", data);
        rows.push(UnpackedArtifactRecord {
            artifact_id: "artifact:overlay:0000".to_string(),
            parent_sha256: input.sha256.to_string(),
            method: "overlay_extract".to_string(),
            confidence: "medium".to_string(),
            output_path,
            failure_reason,
            evidence: vec!["security.overlay_size".to_string()],
        });
    }
    for (index, section) in input
        .sections
        .iter()
        .filter(|section| section.entropy > 7.2 || (section.writable && section.executable))
        .take(16)
        .enumerate()
    {
        let safe_name = safe_file_component(&section.name);
        let file_name = format!("section_{index:04X}_{safe_name}.bin");
        let data = input
            .bytes
            .get(section.data_range.clone())
            .unwrap_or_default();
        let (output_path, write_failure) = write_portable_artifact(input.out_dir, &file_name, data);
        rows.push(UnpackedArtifactRecord {
            artifact_id: format!("artifact:section:{index:04X}"),
            parent_sha256: input.sha256.to_string(),
            method: "section_extract".to_string(),
            confidence: if section.entropy > 7.6 {
                "medium"
            } else {
                "low"
            }
            .to_string(),
            output_path,
            failure_reason: write_failure,
            evidence: vec![section.name.clone()],
        });
    }
    rows
}

pub(crate) fn write_portable_artifact(
    out_dir: &Path,
    file_name: &str,
    data: &[u8],
) -> (String, Option<String>) {
    let relative = PathBuf::from("portable_artifacts").join(file_name);
    let path = out_dir.join(&relative);
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            return (
                relative.to_string_lossy().replace('\\', "/"),
                Some(format!("create artifact directory failed: {err}")),
            );
        }
    }
    match fs::write(&path, data) {
        Ok(()) => (relative.to_string_lossy().replace('\\', "/"), None),
        Err(err) => (
            relative.to_string_lossy().replace('\\', "/"),
            Some(format!("write artifact failed: {err}")),
        ),
    }
}

pub(crate) fn safe_file_component(value: &str) -> String {
    let safe: String = value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    if safe.is_empty() {
        "section".to_string()
    } else {
        safe
    }
}

fn cross_arch_summary(input: &PortableInput<'_>) -> CrossArchSummaryRecord {
    let arch = match input.machine {
        0x8664 => "x86_64",
        0x014c => "x86",
        0xaa64 => "arm64",
        0x01c0 | 0x01c4 => "arm",
        _ => "unknown",
    };
    CrossArchSummaryRecord {
        schema: "cross_arch_summary/1".to_string(),
        detected_format: "pe".to_string(),
        machine: input.machine,
        arch: arch.to_string(),
        depth: if matches!(input.machine, 0x8664 | 0x014c) {
            "full_or_native".to_string()
        } else {
            "portable_triage".to_string()
        },
        notes: vec![
            format!("file_size={}", input.file_size),
            "x86/x64 PE receives full native depth when disassembly backend supports it."
                .to_string(),
            "Other machine types receive metadata/import/string/seed triage in portable mode."
                .to_string(),
        ],
    }
}

fn build_firmware_modules(input: &PortableInput<'_>) -> Vec<FirmwareModuleRecord> {
    let source_lower = input.source_path.to_ascii_lowercase();
    let is_efi = source_lower.ends_with(".efi");
    let efi_hint = input
        .exports
        .iter()
        .any(|row| row.name.eq_ignore_ascii_case("efi_main"))
        || input.strings.iter().any(|row| {
            let text = row.text.to_ascii_lowercase();
            text.contains("uefi")
                || text.contains("dxe")
                || text.contains("pei")
                || text.contains("smm")
        });
    let te_hint = input
        .bytes
        .get(0..2)
        .map(|bytes| bytes == b"VZ")
        .unwrap_or(false);
    if !(is_efi || efi_hint || te_hint) {
        return Vec::new();
    }
    vec![FirmwareModuleRecord {
        module_id: "firmware:pe:0000".to_string(),
        module_type: if te_hint { "te_image" } else { "efi_pe" }.to_string(),
        classification: "uefi_module".to_string(),
        smm_indicator: input
            .strings
            .iter()
            .any(|row| row.text.to_ascii_lowercase().contains("smm")),
        guid: first_guid(input.strings),
        evidence: vec!["exports_or_strings".to_string()],
    }]
}

fn build_kernel_artifacts(input: &PortableInput<'_>) -> Vec<KernelArtifactRecord> {
    let is_driver_path = input.source_path.to_ascii_lowercase().ends_with(".sys");
    let kernel_imports: Vec<String> = input
        .imports
        .iter()
        .filter(|row| {
            let symbol = row.symbol.to_ascii_lowercase();
            symbol.starts_with("ntoskrnl")
                || symbol.starts_with("hal.dll")
                || symbol.starts_with("fltmgr")
                || symbol.contains("iocompletedrequest")
                || symbol.contains("psset")
                || symbol.contains("obregister")
        })
        .map(|row| row.symbol.clone())
        .collect();
    if !is_driver_path && kernel_imports.is_empty() {
        return Vec::new();
    }
    let mut signals = Vec::new();
    if is_driver_path {
        signals.push("driver_extension".to_string());
    }
    if !kernel_imports.is_empty() {
        signals.push("kernel_imports".to_string());
    }
    if input
        .sections
        .iter()
        .any(|section| section.writable && section.executable)
    {
        signals.push("rwx_section".to_string());
    }
    vec![KernelArtifactRecord {
        artifact_id: "kernel:driver:0000".to_string(),
        artifact_type: "windows_driver".to_string(),
        kernel_imports: kernel_imports.iter().take(64).cloned().collect(),
        signals,
        dispatch_routines: Vec::new(),
        ioctl_codes: Vec::new(),
        device_names: Vec::new(),
        confidence: if kernel_imports.is_empty() {
            "low"
        } else {
            "medium"
        }
        .to_string(),
        evidence: kernel_imports.iter().take(8).cloned().collect(),
    }]
}

fn build_vuln_candidates(input: &PortableInput<'_>) -> Vec<VulnCandidateRecord> {
    let mut candidates = Vec::new();
    for (index, flow) in input
        .api_flows
        .iter()
        .filter(|row| dangerous_api(&row.api))
        .take(64)
        .enumerate()
    {
        candidates.push(VulnCandidateRecord {
            candidate_id: format!("vuln:{index:04X}"),
            function: Some(flow.function),
            site_va: Some(flow.callsite),
            kind: "dangerous_api_chain".to_string(),
            summary: format!("Portable static triage flagged {}", flow.api),
            confidence: "low".to_string(),
            evidence: flow.evidence.clone(),
            fuzz_harness_ref: format!("harness:{index:04X}"),
        });
    }
    for (index, xref) in input
        .xrefs
        .iter()
        .filter(|row| {
            row.role == "call" && row.symbol.as_deref().map(dangerous_api).unwrap_or(false)
        })
        .take(64)
        .enumerate()
    {
        if candidates.iter().any(|row| row.site_va == Some(xref.from)) {
            continue;
        }
        candidates.push(VulnCandidateRecord {
            candidate_id: format!("vuln:xref:{index:04X}"),
            function: function_for(input.functions, xref.from),
            site_va: Some(xref.from),
            kind: "dangerous_api_chain".to_string(),
            summary: format!(
                "Portable static triage flagged {}",
                xref.symbol.clone().unwrap_or_default()
            ),
            confidence: "low".to_string(),
            evidence: vec![xref.from],
            fuzz_harness_ref: format!("harness:xref:{index:04X}"),
        });
    }
    candidates
}

fn build_fuzz_harnesses(
    input: &PortableInput<'_>,
    candidates: &[VulnCandidateRecord],
) -> Vec<FuzzHarnessRecord> {
    candidates
        .iter()
        .filter(|row| row.site_va.is_some() && !row.evidence.is_empty())
        .take(64)
        .map(|row| {
            let file_name = format!("{}.rs", safe_file_component(&row.fuzz_harness_ref));
            let relative = PathBuf::from("fuzz_harnesses").join(&file_name);
            let path = input.out_dir.join(&relative);
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let body = format!(
                "// Generated portable static fuzz harness stub.\n// Candidate: {}\n// Site VA: {}\n// This stub is not executed by re_full.cmd.\nfn main() {{\n    let _seed = include_bytes!(\"seed.bin\");\n}}\n",
                row.candidate_id,
                row.site_va
                    .map(|value| format!("0x{value:016X}"))
                    .unwrap_or_else(|| "unknown".to_string())
            );
            let _ = fs::write(&path, body);
            FuzzHarnessRecord {
                harness_id: row.fuzz_harness_ref.clone(),
                candidate_id: row.candidate_id.clone(),
                kind: row.kind.clone(),
                status: "stub_only_not_executed".to_string(),
                output_path: relative.to_string_lossy().replace('\\', "/"),
            }
        })
        .collect()
}

fn portable_uncertainties(
    input: &PortableInput<'_>,
    matrix: &CapabilityMatrixRecord,
    emulation: Option<&crate::native_emulator::NativeEmulationResult>,
) -> Vec<UncertaintyRecord> {
    let mut rows: Vec<UncertaintyRecord> = matrix
        .capabilities
        .iter()
        .filter(|row| row.unsupported_portable)
        .enumerate()
        .map(|(index, row)| UncertaintyRecord {
            uncertainty_id: format!("uncertainty:portable:{index:04X}"),
            function: input.functions.first().map(|row| row.start).unwrap_or(0),
            site_va: input.functions.first().map(|row| row.start),
            reason: format!("unsupported_portable_{}", row.capability),
            details: row.notes.join(" "),
            tried: vec!["portable_offline_capability_registry".to_string()],
            recommended_action:
                "provide offline artifacts or configure an external sandbox outside portable mode"
                    .to_string(),
            severity_hint: "info".to_string(),
            evidence: input
                .functions
                .first()
                .map(|row| vec![row.start])
                .unwrap_or_default(),
        })
        .collect();
    let base_function = input.functions.first().map(|row| row.start).unwrap_or(0);
    if let Some(result) = emulation {
        if !result.unsupported_instructions.is_empty() {
            rows.push(portable_uncertainty(
                rows.len(),
                base_function,
                Some(result.start_va),
                "unsupported_instruction",
                format!(
                    "portable emulator skipped unsupported instructions: {}",
                    result.unsupported_instructions.join("; ")
                ),
                "manual review",
                "low",
            ));
        }
        if result.cap_hit {
            rows.push(portable_uncertainty(
                rows.len(),
                base_function,
                Some(result.start_va),
                "path_cap_hit",
                "portable emulator or symbolic path budget was capped".to_string(),
                "rerun with --emulation-budget high or max",
                "medium",
            ));
        }
    } else if !input.functions.is_empty() {
        rows.push(portable_uncertainty(
            rows.len(),
            base_function,
            Some(base_function),
            "unsupported_instruction",
            "no supported instruction was stepped by the portable emulator".to_string(),
            "manual review",
            "low",
        ));
    }
    for capability in &matrix.capabilities {
        if capability.status == "not_applicable" || capability.status == "skipped_no_evidence" {
            rows.push(portable_uncertainty(
                rows.len(),
                base_function,
                Some(base_function),
                "no_matching_artifact",
                format!("{}: {}", capability.capability, capability.claim),
                "none",
                "info",
            ));
        }
        if capability.truthfulness_level == "metadata_only" {
            rows.push(portable_uncertainty(
                rows.len(),
                base_function,
                Some(base_function),
                "metadata_only_summary",
                format!("{}: {}", capability.capability, capability.claim),
                "none",
                "info",
            ));
        }
        if capability.capability == "vuln_fuzz_prep" && capability.status == "generated" {
            rows.push(portable_uncertainty(
                rows.len(),
                base_function,
                Some(base_function),
                "fuzz_harness_not_executed",
                "portable mode generated fuzz harness stubs but did not run fuzzing".to_string(),
                "run the harnesses manually in an isolated fuzzing environment",
                "info",
            ));
        }
    }
    rows
}

fn portable_uncertainty(
    index: usize,
    function: u64,
    site_va: Option<u64>,
    reason: &str,
    details: String,
    recommended_action: &str,
    severity_hint: &str,
) -> UncertaintyRecord {
    UncertaintyRecord {
        uncertainty_id: format!("uncertainty:portable:{index:04X}:{reason}"),
        function,
        site_va,
        reason: reason.to_string(),
        details,
        tried: vec!["portable_capability_backend".to_string()],
        recommended_action: recommended_action.to_string(),
        severity_hint: severity_hint.to_string(),
        evidence: site_va.map(|value| vec![value]).unwrap_or_default(),
    }
}

pub(crate) fn function_for(functions: &[FunctionRecord], va: u64) -> Option<u64> {
    functions
        .iter()
        .find(|row| row.start <= va && va < row.end)
        .map(|row| row.start)
}

/// **Single source of truth** for the back-compat dangerous-API
/// list (Codex finding 4 fix from the vuln-discovery plan).
///
/// When `--features vuln-discovery` is on, delegates to
/// `crate::vuln::sinks::SinkCatalog::is_legacy_dangerous`. The
/// parity test in `src/vuln/sinks.rs::tests` asserts byte-identical
/// behavior against the original hardcoded list, so existing
/// `vuln_candidates.jsonl` output is unchanged.
///
/// When the feature is off, falls back to the legacy hardcoded list
/// so the default build is byte-identical to the pre-vuln-discovery
/// behavior.
fn dangerous_api(symbol: &str) -> bool {
    #[cfg(feature = "vuln-discovery")]
    {
        return crate::vuln::sinks::SinkCatalog::v1_0().is_legacy_dangerous(symbol);
    }
    #[cfg(not(feature = "vuln-discovery"))]
    {
        let lower = symbol.to_ascii_lowercase();
        [
            "strcpy",
            "sprintf",
            "memcpy",
            "rtlcopymemory",
            "deviceiocontrol",
            "virtualprotect",
            "virtualallocex",
            "writeprocessmemory",
            "createremotethread",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
    }
}

pub(crate) fn first_guid(strings: &[StringRecord]) -> Option<String> {
    strings
        .iter()
        .find(|row| {
            let text = row.text.as_str();
            text.len() >= 36
                && text.chars().filter(|ch| *ch == '-').count() >= 4
                && text.chars().any(|ch| ch.is_ascii_hexdigit())
        })
        .map(|row| row.text.clone())
}
