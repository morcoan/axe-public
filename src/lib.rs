#![recursion_limit = "256"]

mod anti_analysis;
mod api_hash;
pub mod archive_extract;
pub mod atomic_write;
mod attack;
mod behavior;
mod c_decompiler;
mod cfg;
#[cfg(feature = "concolic")]
pub mod concolic;
mod cpp;
mod cpp_classes;
mod crypto;
mod dataflow;
mod debug_symbols;
mod decoder;
mod deobfuscation;
pub mod diff;
mod disasm;
mod dossier_cards;
mod dossiers;
mod driver_triage;
#[cfg(feature = "dynamic-trace")]
pub mod dynamic_trace;
mod eh;
mod elf;
mod eval;
mod facts;
mod firmware_unpacker;
pub mod folder_scan;
mod functions;
#[cfg(feature = "fuzzer")]
pub mod fuzzer;
mod image;
mod indirect_resolver;
mod ir;
mod jump_tables;
mod llm_artifacts;
mod macho;
mod native_emulator;
mod native_fuzzer;
mod pe;
mod portable;
mod pseudo_ir;
pub mod run_status;
mod second_pass;
mod semantic_index;
mod ssa;
mod strings;
mod structured;
mod summary;
mod switches;
mod symbol_graph;
mod symbolic_solver;
mod trace_ingest;
mod type_inference;
#[cfg(feature = "unpack")]
pub mod unpack;
mod value_graph;
mod vsa;
#[cfg(feature = "vuln-discovery")]
pub mod vuln;
mod winapi;
mod wrappers;
mod xrefs;

pub use image::Format;
pub use pe::AnalysisOptions;
#[cfg(feature = "concolic")]
pub use pe::InstructionRecord;
#[cfg(feature = "unpack")]
pub use pe::PEImage;

#[cfg(feature = "fuzzer")]
pub use llm_artifacts::{fuzzer_artifact_index_entries, ArtifactIndexRecord};

#[cfg(feature = "concolic")]
pub use llm_artifacts::concolic_artifact_index_entries;

#[cfg(feature = "dynamic-trace")]
pub use llm_artifacts::dynamic_trace_artifact_index_entries;

#[cfg(feature = "vuln-discovery")]
pub use llm_artifacts::vuln_artifact_index_entries;

#[cfg(feature = "unpack")]
pub use llm_artifacts::unpack_artifact_index_entries;

/// Re-export commonly-used analysis records so integration tests
/// (e.g. `tests/vuln_smoke.rs`, `tests/vuln_template_coverage.rs`)
/// can build synthetic fixtures without re-deriving each record's
/// shape.
#[cfg(feature = "vuln-discovery")]
pub use pe::{
    ApiFlowRecord, BasicBlockRecord, CfgRecord, DataflowEdgeRecord, EdgeRecord, FunctionRecord,
    SsaValueRecord,
};

pub fn analyze_path(
    path: &str,
    out_dir: &str,
    options: AnalysisOptions,
) -> Result<String, Box<dyn std::error::Error>> {
    let format = image::detect_format_at_path(std::path::Path::new(path))?;
    match format {
        Format::Pe => {
            let image = pe::PEImage::parse(path)?;
            pe::run_analysis(&image, out_dir, options)
        }
        Format::Elf => {
            let parsed = elf::parse_elf(path)?;
            pe::run_analysis(&parsed, out_dir, options)
        }
        Format::MachO => {
            let parsed = macho::parse_macho(path)?;
            pe::run_analysis(&parsed, out_dir, options)
        }
    }
}

pub fn query_symbol_packet(
    out_dir: &str,
    query_kind: &str,
    query_value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let packet =
        symbol_graph::query_symbol_packet(std::path::Path::new(out_dir), query_kind, query_value)?;
    Ok(serde_json::to_string_pretty(&packet)?)
}

#[cfg(test)]
mod semantic_upgrade_tests {
    use crate::ir::IrInstruction;
    use crate::pe::{
        ApiFlowRecord, BasicBlockRecord, CfgRecord, EdgeRecord, FunctionRecord,
        ObfuscationHintRecord, ResolvedCallRecord, StringRecord, VTableRecord, XrefRecord,
    };
    use crate::semantic_index::FunctionSemanticIndex;

    #[test]
    fn api_tier_classifies_os_and_runtime_symbols() {
        let create_file = crate::winapi::classify_api("KERNEL32.dll!CreateFileW");
        assert_eq!("os_api", create_file.tier);
        assert_eq!("file", create_file.family);
        assert_eq!("high", create_file.semantic_relevance);

        let qt = crate::winapi::classify_api("Qt5Core.dll!??1QString@@QEAA@XZ");
        assert_eq!("runtime_api", qt.tier);
        assert_eq!("qt", qt.family);
        assert_eq!("low", qt.semantic_relevance);
        assert!(qt.noise_reason.is_some());
    }

    #[test]
    fn value_graph_traces_string_through_register_copy() {
        let functions = vec![function(0x1000, 0x1030, "pdata")];
        let strings = vec![string_record(0x3000, "C:\\Temp\\payload.bin")];
        let ir = vec![
            ir_write(0x1000, "lea", Some("rax"), None, Some(0x3000), None, false),
            ir_write(0x1007, "mov", Some("rcx"), Some("rax"), None, None, false),
        ];
        let index = FunctionSemanticIndex::build(&functions, &[], &ir, &[], &[]);

        let values = crate::value_graph::build_value_graph(&functions, &index, &ir, &strings);
        let rcx = values
            .iter()
            .find(|row| row.function == 0x1000 && row.location == "rcx")
            .expect("rcx value graph record");

        assert_eq!("string_pointer", rcx.inferred_type);
        assert_eq!(Some("C:\\Temp\\payload.bin".to_string()), rcx.value);
        assert!(rcx.evidence.contains(&0x1000));
        assert!(rcx.evidence.contains(&0x1007));
    }

    #[test]
    fn wrapper_collapse_resolves_direct_import_wrapper() {
        let functions = vec![
            function(0x1000, 0x1010, "call"),
            function(0x2000, 0x2010, "pdata"),
        ];
        let xrefs = vec![
            import_xref(0x1004, "KERNEL32.dll!CreateFileW"),
            code_call(0x2004, 0x1000),
        ];
        let index = FunctionSemanticIndex::build(&functions, &[], &[], &xrefs, &[]);

        let resolved = crate::wrappers::resolve_calls(&functions, &index, &xrefs, 4);
        let caller = resolved
            .iter()
            .find(|row| row.caller == 0x2000 && row.callsite == 0x2004)
            .expect("resolved wrapper call");

        assert_eq!("KERNEL32.dll!CreateFileW", caller.resolved_api);
        assert_eq!(vec![0x1000], caller.wrapper_chain);
        assert_eq!("high", caller.confidence);
    }

    #[test]
    fn structured_flow_marks_loop_backedge() {
        let functions = vec![function(0x1000, 0x1020, "pdata")];
        let cfg = vec![CfgRecord {
            function: 0x1000,
            blocks: Vec::new(),
            edges: vec![EdgeRecord {
                from: 0x1018,
                to: 0x1004,
                edge_type: "branch".to_string(),
            }],
        }];

        let structured = crate::structured::build_structured_flow(&functions, &cfg, &[]);
        assert_eq!(1, structured.len());
        assert_eq!(true, structured[0].has_loop_like_backedge);
        assert_eq!(1, structured[0].backedges.len());
    }

    #[test]
    fn level10_structured_flow_requires_dominating_target_for_natural_loop() {
        let functions = vec![function(0x1100, 0x1140, "pdata")];
        let cfg = vec![CfgRecord {
            function: 0x1100,
            blocks: vec![
                BasicBlockRecord {
                    start: 0x1100,
                    end: 0x1110,
                    instruction_count: 1,
                },
                BasicBlockRecord {
                    start: 0x1110,
                    end: 0x1120,
                    instruction_count: 1,
                },
                BasicBlockRecord {
                    start: 0x1120,
                    end: 0x1130,
                    instruction_count: 1,
                },
            ],
            edges: vec![
                EdgeRecord {
                    from: 0x1100,
                    to: 0x1120,
                    edge_type: "branch".to_string(),
                },
                EdgeRecord {
                    from: 0x1120,
                    to: 0x1110,
                    edge_type: "branch".to_string(),
                },
            ],
        }];

        let structured = crate::structured::build_structured_flow(&functions, &cfg, &[]);

        assert!(!structured[0].has_loop_like_backedge);
        assert!(structured[0].backedges.is_empty());
    }

    #[test]
    fn second_pass_off_disables_without_targets() {
        let functions = vec![function(0x1000, 0x1020, "pdata")];
        let index = FunctionSemanticIndex::build(&functions, &[], &[], &[], &[]);

        let result = crate::second_pass::run_second_pass(crate::second_pass::SecondPassInput {
            policy: "off",
            budget_name: "normal",
            functions: &functions,
            semantic_index: &index,
            ir: &[],
            xrefs: &[],
            api_flows: &[],
            function_dossiers: &[],
            obfuscation_hints: &[],
            recovered_strings: &[],
            resolved_calls: &[],
            structured_flow: &[],
        });

        assert_eq!("disabled", result.summary.status);
        assert_eq!(0, result.summary.eligible_functions);
        assert!(result.targets.is_empty());
        assert!(result.uncertainties.is_empty());
    }

    #[test]
    fn second_pass_auto_selects_unresolved_indirect_call() {
        let functions = vec![function(0x1000, 0x1030, "pdata")];
        let ir = vec![IrInstruction {
            address: 0x1010,
            size: 2,
            mnemonic: "call".to_string(),
            write_reg: None,
            read_regs: vec!["rax".to_string()],
            immediate: None,
            rip_target: None,
            stack_slot: None,
            memory_base: None,
            memory_index: None,
            memory_scale: 0,
            memory_displacement: 0,
            operand_width: 0,
            indirect_target_register: Some("rax".to_string()),
            indirect_target_memory: false,
            memory_write: false,
            memory_read: false,
            direct_target: None,
            is_call: true,
            is_jump: false,
        }];
        let index = FunctionSemanticIndex::build(&functions, &[], &ir, &[], &[]);

        let result = crate::second_pass::run_second_pass(crate::second_pass::SecondPassInput {
            policy: "auto",
            budget_name: "normal",
            functions: &functions,
            semantic_index: &index,
            ir: &ir,
            xrefs: &[],
            api_flows: &[],
            function_dossiers: &[],
            obfuscation_hints: &[],
            recovered_strings: &[],
            resolved_calls: &[],
            structured_flow: &[],
        });

        assert_eq!("completed", result.summary.status);
        assert_eq!(1, result.summary.eligible_functions);
        assert_eq!(1, result.summary.analyzed_functions);
        assert_eq!(0, result.summary.skipped_by_budget);
        assert_eq!(
            Some(&1),
            result.summary.reason_counts.get("unresolved_indirect_call")
        );
        assert_eq!(0x1000, result.targets[0].function);
        assert_eq!("unresolved_indirect_call", result.targets[0].reason);
        assert_eq!("analyzed", result.targets[0].result_status);
        assert_eq!("indirect_call_unresolved", result.uncertainties[0].reason);
        assert_eq!(Some(0x1010), result.uncertainties[0].site_va);
    }

    #[test]
    fn second_pass_all_runs_every_eligible_function() {
        let functions = vec![
            function(0x1000, 0x1030, "pdata"),
            function(0x2000, 0x2030, "call"),
        ];
        let index = FunctionSemanticIndex::build(&functions, &[], &[], &[], &[]);

        let result = crate::second_pass::run_second_pass(crate::second_pass::SecondPassInput {
            policy: "all",
            budget_name: "normal",
            functions: &functions,
            semantic_index: &index,
            ir: &[],
            xrefs: &[],
            api_flows: &[],
            function_dossiers: &[],
            obfuscation_hints: &[],
            recovered_strings: &[],
            resolved_calls: &[],
            structured_flow: &[],
        });

        assert_eq!("completed", result.summary.status);
        assert_eq!(2, result.summary.eligible_functions);
        assert_eq!(2, result.summary.analyzed_functions);
        assert_eq!(
            vec![0x1000, 0x2000],
            result
                .targets
                .iter()
                .map(|row| row.function)
                .collect::<Vec<_>>()
        );
        assert!(result
            .targets
            .iter()
            .all(|row| row.reason == "policy_all" && row.result_status == "analyzed"));
    }

    #[test]
    fn second_pass_auto_selects_api_hash_candidate() {
        let functions = vec![function(0x3000, 0x3050, "pdata")];
        let index = FunctionSemanticIndex::build(&functions, &[], &[], &[], &[]);
        let hints = vec![ObfuscationHintRecord {
            hint_id: "recovered:0000000000003000:api_hash_candidate:0000".to_string(),
            function: 0x3000,
            candidate_kind: "api_hash_candidate".to_string(),
            description: "0x12345678,0x87654321".to_string(),
            tags: vec!["api_hash".to_string()],
            confidence: "low".to_string(),
            evidence: vec![0x3010, 0x3020],
            uncertainty_reason:
                "hash-like arithmetic with import-resolution context; static candidate only"
                    .to_string(),
        }];

        let result = crate::second_pass::run_second_pass(crate::second_pass::SecondPassInput {
            policy: "auto",
            budget_name: "normal",
            functions: &functions,
            semantic_index: &index,
            ir: &[],
            xrefs: &[],
            api_flows: &[],
            function_dossiers: &[],
            obfuscation_hints: &hints,
            recovered_strings: &[],
            resolved_calls: &[],
            structured_flow: &[],
        });

        assert_eq!(1, result.summary.eligible_functions);
        assert_eq!(
            Some(&1),
            result.summary.reason_counts.get("api_hash_candidate")
        );
        assert_eq!("api_hash_candidate", result.targets[0].reason);
        assert_eq!("api_hash_unresolved", result.uncertainties[0].reason);
    }

    #[test]
    fn pass2_vsa_tracks_string_stack_spill_and_constant_math() {
        let functions = vec![function(0x4000, 0x4050, "pdata")];
        let strings = vec![string_record(0x9000, "C:\\Temp\\stage.bin")];
        let ir = vec![
            ir_write(0x4000, "lea", Some("rax"), None, Some(0x9000), None, false),
            IrInstruction {
                address: 0x4007,
                size: 4,
                mnemonic: "mov".to_string(),
                write_reg: None,
                read_regs: vec!["rax".to_string()],
                immediate: None,
                rip_target: None,
                stack_slot: Some(0x20),
                memory_base: Some("rsp".to_string()),
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0x20,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: true,
                memory_read: false,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
            IrInstruction {
                address: 0x400c,
                size: 4,
                mnemonic: "mov".to_string(),
                write_reg: Some("rcx".to_string()),
                read_regs: Vec::new(),
                immediate: None,
                rip_target: None,
                stack_slot: Some(0x20),
                memory_base: Some("rsp".to_string()),
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0x20,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: false,
                memory_read: true,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
            ir_write(0x4010, "mov", Some("r8"), None, None, Some(0x1000), false),
            ir_write(
                0x4015,
                "add",
                Some("r8"),
                Some("r8"),
                None,
                Some(0x20),
                false,
            ),
        ];
        let index = FunctionSemanticIndex::build(&functions, &[], &ir, &[], &[]);
        let target = second_pass_target(0x4000, "unresolved_indirect_call");

        let values =
            crate::vsa::analyze_targets(&functions, &index, &ir, &strings, &[target], "normal");

        let rcx = values
            .iter()
            .find(|row| row.function == 0x4000 && row.location == "rcx")
            .expect("rcx VSA value");
        assert_eq!("string_pointer", rcx.kind);
        assert_eq!(Some("C:\\Temp\\stage.bin".to_string()), rcx.value);

        let r8 = values
            .iter()
            .find(|row| row.function == 0x4000 && row.location == "r8" && row.site_va == 0x4015)
            .expect("r8 VSA value after add");
        assert_eq!("constant", r8.kind);
        assert_eq!(Some(0x1020), r8.lo);
        assert_eq!(Some(0x1020), r8.hi);
    }

    #[test]
    fn pass2_vsa_resolves_indexed_pointer_expression_and_caps_loops() {
        let functions = vec![function(0x4100, 0x4200, "pdata")];
        let strings = vec![];
        let mut ir = vec![
            ir_write(0x4100, "mov", Some("rax"), None, None, Some(0x9000), false),
            ir_write(0x4105, "mov", Some("rcx"), None, None, Some(2), false),
            IrInstruction {
                address: 0x410a,
                size: 4,
                mnemonic: "lea".to_string(),
                write_reg: Some("rdx".to_string()),
                read_regs: vec!["rax".to_string(), "rcx".to_string()],
                immediate: None,
                rip_target: None,
                stack_slot: None,
                memory_base: Some("rax".to_string()),
                memory_index: Some("rcx".to_string()),
                memory_scale: 8,
                memory_displacement: 0x10,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: false,
                memory_read: false,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
        ];
        for offset in 0..160 {
            ir.push(ir_write(
                0x4120 + offset,
                "add",
                Some("r8"),
                Some("r8"),
                None,
                Some(1),
                false,
            ));
        }
        let index = FunctionSemanticIndex::build(&functions, &[], &ir, &[], &[]);
        let target = second_pass_target(0x4100, "unresolved_indirect_jump");

        let values =
            crate::vsa::analyze_targets(&functions, &index, &ir, &strings, &[target], "normal");

        let rdx = values
            .iter()
            .find(|row| row.function == 0x4100 && row.location == "rdx")
            .expect("rdx VSA value");
        assert_eq!("pointer_expression", rdx.kind);
        assert_eq!("data", rdx.region);
        assert_eq!(Some(0x9020), rdx.target_va);
        assert!(values.iter().any(|row| row.work_budget_exhausted));
    }

    #[test]
    fn level10_vsa_cfg_worklist_joins_constants_and_reports_loop_widening() {
        let functions = vec![function(0xA000, 0xA090, "pdata")];
        let cfg = vec![CfgRecord {
            function: 0xA000,
            blocks: vec![
                BasicBlockRecord {
                    start: 0xA000,
                    end: 0xA010,
                    instruction_count: 1,
                },
                BasicBlockRecord {
                    start: 0xA020,
                    end: 0xA030,
                    instruction_count: 1,
                },
                BasicBlockRecord {
                    start: 0xA040,
                    end: 0xA050,
                    instruction_count: 1,
                },
                BasicBlockRecord {
                    start: 0xA060,
                    end: 0xA070,
                    instruction_count: 1,
                },
            ],
            edges: vec![
                EdgeRecord {
                    from: 0xA000,
                    to: 0xA040,
                    edge_type: "branch".to_string(),
                },
                EdgeRecord {
                    from: 0xA020,
                    to: 0xA040,
                    edge_type: "branch".to_string(),
                },
                EdgeRecord {
                    from: 0xA060,
                    to: 0xA060,
                    edge_type: "branch".to_string(),
                },
            ],
        }];
        let ir = vec![
            ir_write(0xA000, "mov", Some("rax"), None, None, Some(1), false),
            ir_write(0xA020, "mov", Some("rax"), None, None, Some(3), false),
            ir_write(0xA040, "mov", Some("rcx"), Some("rax"), None, None, false),
            ir_write(0xA060, "add", Some("r8"), Some("r8"), None, Some(1), false),
        ];
        let index = FunctionSemanticIndex::build(&functions, &[], &ir, &[], &cfg);
        let target = second_pass_target(0xA000, "unresolved_indirect_jump");

        let values = crate::vsa::analyze_targets_with_cfg(
            &functions,
            &index,
            &ir,
            &cfg,
            &[],
            &[target],
            "normal",
        );

        let joined = values
            .iter()
            .find(|row| row.function == 0xA000 && row.location == "rcx" && row.site_va == 0xA040)
            .expect("joined rcx VSA value");
        assert_eq!("constant_set", joined.kind);
        assert_eq!(vec![1, 3], joined.possible_values);
        assert!(values.iter().any(|row| {
            row.function == 0xA000
                && row.location == "analysis_budget"
                && row.value.as_deref() == Some("loop_widening_cap")
        }));
    }

    #[test]
    fn true10_vsa_refines_conditional_branch_ranges() {
        let functions = vec![function(0xB000, 0xB060, "pdata")];
        let cfg = vec![CfgRecord {
            function: 0xB000,
            blocks: vec![
                BasicBlockRecord {
                    start: 0xB000,
                    end: 0xB020,
                    instruction_count: 4,
                },
                BasicBlockRecord {
                    start: 0xB020,
                    end: 0xB030,
                    instruction_count: 1,
                },
                BasicBlockRecord {
                    start: 0xB040,
                    end: 0xB050,
                    instruction_count: 1,
                },
            ],
            edges: vec![
                EdgeRecord {
                    from: 0xB00A,
                    to: 0xB040,
                    edge_type: "branch".to_string(),
                },
                EdgeRecord {
                    from: 0xB00A,
                    to: 0xB020,
                    edge_type: "fallthrough".to_string(),
                },
            ],
        }];
        let ir = vec![
            ir_write(0xB000, "mov", Some("rcx"), None, None, Some(0xFF), false),
            ir_write(
                0xB004,
                "and",
                Some("rcx"),
                Some("rcx"),
                None,
                Some(0x0F),
                false,
            ),
            IrInstruction {
                address: 0xB008,
                size: 2,
                mnemonic: "cmp".to_string(),
                write_reg: None,
                read_regs: vec!["rcx".to_string()],
                immediate: Some(4),
                rip_target: None,
                stack_slot: None,
                memory_base: None,
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0,
                operand_width: 4,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: false,
                memory_read: false,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
            IrInstruction {
                address: 0xB00A,
                size: 2,
                mnemonic: "jbe".to_string(),
                write_reg: None,
                read_regs: Vec::new(),
                immediate: None,
                rip_target: None,
                stack_slot: None,
                memory_base: None,
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0,
                operand_width: 0,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: false,
                memory_read: false,
                direct_target: Some(0xB040),
                is_call: false,
                is_jump: true,
            },
            ir_write(0xB040, "mov", Some("rax"), Some("rcx"), None, None, false),
        ];
        let index = FunctionSemanticIndex::build(&functions, &[], &ir, &[], &cfg);
        let target = second_pass_target(0xB000, "unresolved_indirect_jump");

        let values = crate::vsa::analyze_targets_with_cfg(
            &functions,
            &index,
            &ir,
            &cfg,
            &[],
            &[target],
            "normal",
        );

        let refined = values
            .iter()
            .find(|row| row.function == 0xB000 && row.location == "rax" && row.site_va == 0xB040)
            .expect("branch-refined rax value");
        assert_eq!(Some(0), refined.lo);
        assert_eq!(Some(4), refined.hi);
    }

    #[test]
    fn pass2_jump_table_resolver_handles_absolute_rva_and_relative_tables() {
        let abs = [0x1000_u64, 0x1010, 0x1020, 0x5000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        let rva = [0x1000_u32, 0x1010, 0x1020, 0x5000]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let rel = [0x100_i32, 0x120, 0x140, 0x5000]
            .into_iter()
            .flat_map(i32::to_le_bytes)
            .collect::<Vec<_>>();
        let executable =
            |va: u64| (0x1000..=0x2000).contains(&va) || (0x3100..=0x3200).contains(&va);

        let abs_targets =
            crate::jump_tables::resolve_table_entries(0x3000, &abs, 0, executable, 16)
                .expect("absolute table");
        assert_eq!("absolute", abs_targets.kind);
        assert_eq!(vec![0x1000, 0x1010, 0x1020], abs_targets.targets);

        let rva_targets =
            crate::jump_tables::resolve_table_entries(0x3000, &rva, 0, executable, 16)
                .expect("rva table");
        assert_eq!("rva", rva_targets.kind);
        assert_eq!(vec![0x1000, 0x1010, 0x1020], rva_targets.targets);

        let rel_targets =
            crate::jump_tables::resolve_table_entries(0x3000, &rel, 0, executable, 16)
                .expect("relative table");
        assert_eq!("relative", rel_targets.kind);
        assert_eq!(vec![0x3100, 0x3120, 0x3140], rel_targets.targets);

        let capped = crate::jump_tables::resolve_table_entries(0x3000, &abs, 0, executable, 2)
            .expect("capped table");
        assert_eq!(vec![0x1000, 0x1010], capped.targets);

        let bad = [0x7000_u64, 0x7010]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>();
        assert!(
            crate::jump_tables::resolve_table_entries(0x3000, &bad, 0, executable, 16).is_none()
        );
    }

    #[test]
    fn pass2_api_hash_resolver_matches_only_with_context() {
        let hash = crate::api_hash::ror13_hash_name("CreateFileW");
        let contextual_hint = ObfuscationHintRecord {
            hint_id: "hash:context".to_string(),
            function: 0x5000,
            candidate_kind: "api_hash_candidate".to_string(),
            description: format!("0x{hash:08X}"),
            tags: vec!["api_hash".to_string()],
            confidence: "low".to_string(),
            evidence: vec![0x5010],
            uncertainty_reason:
                "hash-like arithmetic with import-resolution context; static candidate only"
                    .to_string(),
        };
        let generic_hint = ObfuscationHintRecord {
            hint_id: "hash:no-context".to_string(),
            uncertainty_reason: "generic arithmetic constants only".to_string(),
            ..contextual_hint.clone()
        };

        let resolved = crate::api_hash::resolve_api_hashes(
            &[contextual_hint, generic_hint],
            &["KERNEL32.dll!CreateFileW".to_string()],
        );

        assert_eq!(1, resolved.len());
        assert_eq!("ror13", resolved[0].algorithm);
        assert_eq!("KERNEL32.dll!CreateFileW", resolved[0].resolved_api);
    }

    #[test]
    fn pass2_decoder_recovers_xor_ascii_blob_within_step_cap() {
        let encoded = b"InternetReadFile"
            .iter()
            .map(|byte| byte ^ 0x55)
            .collect::<Vec<_>>();

        let decoded = crate::decoder::decode_xor_ascii(&encoded, 0x55, 128).expect("decoded");
        let add_decoded =
            crate::decoder::decode_transform_ascii(&encoded, "xor", 0x55, 128).expect("decoded");
        let timeout = crate::decoder::decode_transform_ascii(&encoded, "xor", 0x55, 4);

        assert_eq!("InternetReadFile", decoded);
        assert_eq!("InternetReadFile", add_decoded.text);
        assert_eq!("timeout", timeout.expect_err("timeout").reason);
    }

    #[test]
    fn pass2_type_inference_tags_winapi_arguments_and_hresult_tests() {
        let flows = vec![
            api_flow(
                0x6000,
                0x6010,
                "KERNEL32.dll!CreateFileW",
                "filename",
                Some("rcx"),
            ),
            api_flow_arg(
                0x6000,
                0x6018,
                "KERNEL32.dll!VirtualAllocEx",
                "size",
                Some("r8"),
                2,
            ),
            api_flow_arg(
                0x6000,
                0x6020,
                "ADVAPI32.dll!RegSetValueExW",
                "value_type",
                Some("r9"),
                3,
            ),
            api_flow_arg(
                0x6000,
                0x6028,
                "WINHTTP.dll!WinHttpSendRequest",
                "headers",
                Some("rdx"),
                1,
            ),
            api_flow_arg(0x6000, 0x6030, "WS2_32.dll!connect", "addr", Some("rdx"), 1),
            api_flow_arg(
                0x6000,
                0x6038,
                "BCRYPT.dll!BCryptEncrypt",
                "input",
                Some("rdx"),
                1,
            ),
        ];
        let ir = vec![IrInstruction {
            address: 0x6040,
            size: 2,
            mnemonic: "test".to_string(),
            write_reg: None,
            read_regs: vec!["rax".to_string()],
            immediate: None,
            rip_target: None,
            stack_slot: None,
            memory_base: None,
            memory_index: None,
            memory_scale: 0,
            memory_displacement: 0,
            operand_width: 0,
            indirect_target_register: None,
            indirect_target_memory: false,
            memory_write: false,
            memory_read: false,
            direct_target: None,
            is_call: false,
            is_jump: false,
        }];

        let hints = crate::type_inference::infer_type_hints(&flows, &ir);

        assert!(hints.iter().any(|row| {
            row.function == 0x6000 && row.location == "rcx" && row.type_tag == "LPCWSTR"
        }));
        assert!(hints.iter().any(|row| {
            row.function == 0x6000 && row.location == "r8" && row.type_tag == "SIZE_T"
        }));
        assert!(hints.iter().any(|row| {
            row.function == 0x6000 && row.location == "r9" && row.type_tag == "DWORD"
        }));
        assert!(hints.iter().any(|row| {
            row.function == 0x6000 && row.location == "rdx" && row.type_tag == "LPCWSTR"
        }));
        assert!(hints.iter().any(|row| {
            row.function == 0x6000 && row.location == "rdx" && row.type_tag == "SOCKADDR_PTR"
        }));
        assert!(hints.iter().any(|row| {
            row.function == 0x6000 && row.location == "rdx" && row.type_tag == "PUCHAR"
        }));
        assert!(hints.iter().any(|row| {
            row.function == 0x6000 && row.location == "rax" && row.type_tag == "HRESULT"
        }));
    }

    #[test]
    fn level10_winapi_prototype_database_covers_ntapi_com_service_network_crypto() {
        for (symbol, return_type, arg0) in [
            ("NTDLL.dll!NtProtectVirtualMemory", "NTSTATUS", "HANDLE"),
            ("NTDLL.dll!RtlDecompressBuffer", "NTSTATUS", "USHORT"),
            (
                "OLE32.dll!CoInitializeSecurity",
                "HRESULT",
                "PSECURITY_DESCRIPTOR",
            ),
            ("OLE32.dll!CoSetProxyBlanket", "HRESULT", "IUnknown"),
            ("WININET.dll!InternetReadFile", "BOOL", "HINTERNET"),
            ("WS2_32.dll!WSAConnect", "INT", "SOCKET"),
            ("CRYPT32.dll!CryptDecodeObjectEx", "BOOL", "DWORD"),
            ("ADVAPI32.dll!StartServiceW", "BOOL", "SC_HANDLE"),
            ("KERNEL32.dll!CreateToolhelp32Snapshot", "HANDLE", "DWORD"),
        ] {
            let proto = crate::winapi::prototype(symbol).expect(symbol);
            assert_eq!(return_type, proto.return_type, "{symbol}");
            assert_eq!(Some(&arg0), proto.args.first(), "{symbol}");
        }
    }

    #[test]
    fn pass2_cpp_parser_recovers_msvc_col_class_name_and_base_hierarchy() {
        let base = 0x140000000;
        let mut bytes = vec![0_u8; 0x800];
        let col = 0x100usize;
        let type_desc = 0x200usize;
        let chd = 0x300usize;
        let bca = 0x380usize;
        let bcd = 0x400usize;
        let base_type_desc = 0x500usize;
        bytes[col..col + 4].copy_from_slice(&1_u32.to_le_bytes());
        bytes[col + 12..col + 16].copy_from_slice(&(type_desc as u32).to_le_bytes());
        bytes[col + 16..col + 20].copy_from_slice(&(chd as u32).to_le_bytes());
        bytes[type_desc + 16..type_desc + 29].copy_from_slice(b".?AVWidget@@\0");
        bytes[chd + 4..chd + 8].copy_from_slice(&1_u32.to_le_bytes());
        bytes[chd + 8..chd + 12].copy_from_slice(&1_u32.to_le_bytes());
        bytes[chd + 12..chd + 16].copy_from_slice(&(bca as u32).to_le_bytes());
        bytes[bca..bca + 4].copy_from_slice(&(bcd as u32).to_le_bytes());
        bytes[bcd..bcd + 4].copy_from_slice(&(base_type_desc as u32).to_le_bytes());
        bytes[base_type_desc + 16..base_type_desc + 31].copy_from_slice(b".?AVBaseType@@\0");

        let parsed = crate::cpp::parse_msvc_col(&bytes, base, base + col as u64).expect("COL");

        assert_eq!(base + type_desc as u64, parsed.type_descriptor_va);
        assert_eq!(Some(".?AVWidget@@".to_string()), parsed.class_name);
        assert_eq!(1, parsed.class_attributes);
        assert_eq!(vec![".?AVBaseType@@".to_string()], parsed.base_classes);
    }

    #[test]
    fn pass2_structured_refinement_adds_switch_cases_and_goto_edges() {
        let functions = vec![function(0x7000, 0x7080, "pdata")];
        let cfg = vec![CfgRecord {
            function: 0x7000,
            blocks: Vec::new(),
            edges: vec![
                EdgeRecord {
                    from: 0x7010,
                    to: 0x7040,
                    edge_type: "branch".to_string(),
                },
                EdgeRecord {
                    from: 0x7010,
                    to: 0x7020,
                    edge_type: "fallthrough".to_string(),
                },
                EdgeRecord {
                    from: 0x7060,
                    to: 0x7030,
                    edge_type: "branch".to_string(),
                },
            ],
        }];
        let mut structured = crate::structured::build_structured_flow(&functions, &cfg, &[]);
        let jump_tables = vec![crate::pe::JumpTableRecord {
            table_id: "jt:7000".to_string(),
            function: 0x7000,
            jump_va: 0x7010,
            table_va: Some(0x9000),
            entry_size: 8,
            targets: vec![0x7020, 0x7040, 0x7060],
            confidence: "medium".to_string(),
            evidence: vec![0x7010, 0x9000],
        }];

        crate::structured::refine_selected_structured_flow(
            &mut structured,
            &[0x7000],
            &jump_tables,
        );

        assert!(structured[0].refined);
        assert_eq!(vec![0x7020, 0x7040, 0x7060], structured[0].switch_cases);
        assert!(!structured[0].goto_edges.is_empty());
        assert!(structured[0].regions.contains(&"switch".to_string()));
        assert!(structured[0].regions.contains(&"goto".to_string()));
        assert!(structured[0]
            .structuring_notes
            .contains(&"tail_merge_or_backward_branch".to_string()));
    }

    #[test]
    fn level10_ssa_versions_registers_flags_stack_and_memory_edges() {
        let functions = vec![function(0x8000, 0x8040, "pdata")];
        let cfg = vec![CfgRecord {
            function: 0x8000,
            blocks: vec![],
            edges: vec![],
        }];
        let ir = vec![
            ir_write(0x8000, "mov", Some("rax"), None, None, Some(1), false),
            ir_write(
                0x8004,
                "add",
                Some("rax"),
                Some("rax"),
                None,
                Some(2),
                false,
            ),
            IrInstruction {
                address: 0x8008,
                size: 4,
                mnemonic: "mov".to_string(),
                write_reg: None,
                read_regs: vec!["rax".to_string()],
                immediate: None,
                rip_target: None,
                stack_slot: Some(0x20),
                memory_base: Some("rsp".to_string()),
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0x20,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: true,
                memory_read: false,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
            IrInstruction {
                address: 0x800c,
                size: 2,
                mnemonic: "cmp".to_string(),
                write_reg: None,
                read_regs: vec!["rax".to_string()],
                immediate: Some(3),
                rip_target: None,
                stack_slot: None,
                memory_base: None,
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0,
                operand_width: 0,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: false,
                memory_read: false,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
        ];
        let index = FunctionSemanticIndex::build(&functions, &[], &ir, &[], &cfg);

        let result = crate::ssa::build_ssa(&functions, &index, &ir, &cfg, "normal");

        assert!(result
            .values
            .iter()
            .any(|row| row.storage == "rax" && row.version == 2));
        assert!(result
            .values
            .iter()
            .any(|row| row.storage == "stack[+32]" && row.kind == "stack_slot"));
        assert!(result
            .values
            .iter()
            .any(|row| row.storage == "zf" && row.kind == "flag"));
        assert!(result
            .dataflow_edges
            .iter()
            .any(|row| row.to_storage == "rax" && row.edge_kind == "use_def"));
        assert!(result
            .dataflow_edges
            .iter()
            .any(|row| row.edge_kind == "memory_store"));
    }

    #[test]
    fn level10_ssa_inserts_register_and_stack_phis_at_cfg_join() {
        let functions = vec![function(0x8100, 0x8180, "pdata")];
        let cfg = vec![CfgRecord {
            function: 0x8100,
            blocks: vec![
                BasicBlockRecord {
                    start: 0x8100,
                    end: 0x8110,
                    instruction_count: 2,
                },
                BasicBlockRecord {
                    start: 0x8120,
                    end: 0x8130,
                    instruction_count: 2,
                },
                BasicBlockRecord {
                    start: 0x8140,
                    end: 0x8150,
                    instruction_count: 1,
                },
            ],
            edges: vec![
                EdgeRecord {
                    from: 0x8108,
                    to: 0x8140,
                    edge_type: "branch".to_string(),
                },
                EdgeRecord {
                    from: 0x8128,
                    to: 0x8140,
                    edge_type: "branch".to_string(),
                },
            ],
        }];
        let ir = vec![
            ir_write(0x8100, "mov", Some("rax"), None, None, Some(1), false),
            IrInstruction {
                address: 0x8104,
                size: 4,
                mnemonic: "mov".to_string(),
                write_reg: None,
                read_regs: vec!["rax".to_string()],
                immediate: None,
                rip_target: None,
                stack_slot: Some(0x20),
                memory_base: Some("rsp".to_string()),
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0x20,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: true,
                memory_read: false,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
            ir_write(0x8120, "mov", Some("rax"), None, None, Some(2), false),
            IrInstruction {
                address: 0x8124,
                size: 4,
                mnemonic: "mov".to_string(),
                write_reg: None,
                read_regs: vec!["rax".to_string()],
                immediate: None,
                rip_target: None,
                stack_slot: Some(0x20),
                memory_base: Some("rsp".to_string()),
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0x20,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: true,
                memory_read: false,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
            IrInstruction {
                address: 0x8140,
                size: 4,
                mnemonic: "mov".to_string(),
                write_reg: Some("rcx".to_string()),
                read_regs: Vec::new(),
                immediate: None,
                rip_target: None,
                stack_slot: Some(0x20),
                memory_base: Some("rsp".to_string()),
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0x20,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: false,
                memory_read: true,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
        ];
        let index = FunctionSemanticIndex::build(&functions, &[], &ir, &[], &cfg);

        let result = crate::ssa::build_ssa(&functions, &index, &ir, &cfg, "normal");

        assert!(result.values.iter().any(|row| {
            row.block == Some(0x8140) && row.storage == "rax" && row.source == "phi"
        }));
        assert!(result.values.iter().any(|row| {
            row.block == Some(0x8140) && row.storage == "stack[+32]" && row.source == "phi"
        }));
        assert!(
            result
                .dataflow_edges
                .iter()
                .filter(|row| row.to_storage == "rax" && row.edge_kind == "phi")
                .count()
                >= 2
        );
    }

    #[test]
    fn level10_behavior_dossier_requires_va_evidence_for_process_injection() {
        let flows = vec![
            api_flow(
                0x9000,
                0x9010,
                "KERNEL32.dll!VirtualAllocEx",
                "address",
                Some("rdx"),
            ),
            api_flow(
                0x9000,
                0x9020,
                "KERNEL32.dll!WriteProcessMemory",
                "buffer",
                Some("r8"),
            ),
            api_flow(
                0x9000,
                0x9030,
                "KERNEL32.dll!CreateRemoteThread",
                "start_address",
                Some("rdx"),
            ),
        ];

        let dossiers =
            crate::behavior::build_behavior_dossiers("sample", &flows, &[], &[], &[], "normal");

        let injection = dossiers
            .iter()
            .find(|row| row.capability.contains("process/inject"))
            .expect("process injection behavior dossier");
        assert_eq!(0x9000, injection.function);
        assert!(injection.confidence >= 0.80);
        assert!(injection
            .supporting_features
            .iter()
            .all(|feature| feature.va.is_some()));
        assert!(injection.evidence_vas.contains(&0x9010));
        assert!(injection.evidence_vas.contains(&0x9020));
        assert!(injection.evidence_vas.contains(&0x9030));
    }

    #[test]
    fn level10_eval_scorecard_scores_outputs_and_flags_missing_evidence() {
        let good = crate::eval::build_scorecard(crate::eval::ScorecardInput {
            functions: 10,
            pdata_functions: 8,
            api_flows: 4,
            typed_api_args: 3,
            jump_tables: 2,
            jump_table_targets: 6,
            jump_table_quality_failures: 0,
            unresolved_indirects: 1,
            decoder_candidates: 2,
            decoder_timeouts: 0,
            decoded_strings: 2,
            prototype_known_api_flows: 3,
            prototype_typed_api_flows: 3,
            behavior_dossiers: 1,
            behavior_dossiers_with_evidence: 1,
            rtti_classes: 1,
            rtti_owned_classes: 1,
            structured_functions: 2,
            structured_region_functions: 2,
            pass2_elapsed_seconds: 0.25,
            pass2_caps_hit: false,
            json_parseable: true,
            jsonl_parseable: true,
            ..crate::eval::ScorecardInput::default()
        });
        assert!(good.overall_score >= 80.0);
        assert!(good.gates.iter().all(|gate| gate.passed));

        let bad = crate::eval::build_scorecard(crate::eval::ScorecardInput {
            behavior_dossiers: 2,
            behavior_dossiers_with_evidence: 1,
            json_parseable: true,
            jsonl_parseable: true,
            ..crate::eval::ScorecardInput::default()
        });
        assert!(bad.overall_score < good.overall_score);
        assert!(bad
            .gates
            .iter()
            .any(|gate| gate.name == "behavior_citation_integrity" && !gate.passed));
        assert!(good
            .gates
            .iter()
            .any(|gate| gate.name == "prototype_coverage"));
        assert!(good
            .gates
            .iter()
            .any(|gate| gate.name == "structured_region_quality"));
    }

    #[test]
    fn level10_eval_scorecard_has_ground_truth_backed_gates() {
        let card = crate::eval::build_scorecard(crate::eval::ScorecardInput {
            ground_truth_functions_expected: 10,
            ground_truth_functions_recovered: 9,
            ground_truth_api_args_expected: 8,
            ground_truth_api_args_correct: 7,
            ground_truth_jump_tables_expected: 4,
            ground_truth_jump_tables_correct: 4,
            ground_truth_type_hints_expected: 6,
            ground_truth_type_hints_correct: 5,
            ground_truth_decoded_strings_expected: 3,
            ground_truth_decoded_strings_correct: 3,
            ground_truth_rtti_expected: 2,
            ground_truth_rtti_correct: 2,
            ground_truth_structured_expected: 5,
            ground_truth_structured_correct: 4,
            behavior_claims_expected: 6,
            behavior_claims_with_valid_va: 6,
            json_parseable: true,
            jsonl_parseable: true,
            ..crate::eval::ScorecardInput::default()
        });

        assert!(card.ground_truth_available);
        assert!(card.ground_truth_metrics.contains_key("function_recall"));
        assert!(card
            .gates
            .iter()
            .any(|gate| gate.name == "ground_truth_function_recall"));
        assert!(card
            .gates
            .iter()
            .any(|gate| gate.name == "ground_truth_behavior_citation_integrity"));
        assert!(card.failed_gates.is_empty());
    }

    #[test]
    fn true10_cpp_resolves_vtable_slot_calls() {
        let functions = vec![function(0xC000, 0xC040, "pdata")];
        let ir = vec![
            IrInstruction {
                address: 0xC000,
                size: 3,
                mnemonic: "mov".to_string(),
                write_reg: Some("rax".to_string()),
                read_regs: vec!["rcx".to_string()],
                immediate: None,
                rip_target: None,
                stack_slot: None,
                memory_base: Some("rcx".to_string()),
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: false,
                memory_read: true,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
            IrInstruction {
                address: 0xC008,
                size: 3,
                mnemonic: "call".to_string(),
                write_reg: None,
                read_regs: vec!["rax".to_string()],
                immediate: None,
                rip_target: None,
                stack_slot: None,
                memory_base: Some("rax".to_string()),
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0x10,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: true,
                memory_write: false,
                memory_read: true,
                direct_target: None,
                is_call: true,
                is_jump: false,
            },
        ];
        let index = FunctionSemanticIndex::build(&functions, &[], &ir, &[], &[]);
        let vtables = vec![VTableRecord {
            va: 0xD000,
            rva: 0xD000,
            section: ".rdata".to_string(),
            method_count: 3,
            methods: vec![0xE000, 0xE010, 0xE020],
            probable_class: Some(".?AVFixture@@".to_string()),
            col_va: Some(0xCF00),
            class_descriptor_va: Some(0xCF40),
            base_classes: vec![".?AVBase@@".to_string()],
            constructor_candidates: vec![0xC100],
            ownership_confidence: "high".to_string(),
        }];
        let target = second_pass_target(0xC000, "unresolved_vtable_dispatch");

        let resolved =
            crate::cpp::resolve_virtual_calls(&functions, &index, &ir, &vtables, &[target]);

        let call = resolved.first().expect("resolved virtual dispatch");
        assert_eq!(0xC000, call.caller);
        assert_eq!(0xC008, call.callsite);
        assert_eq!(
            Some("virtual_dispatch".to_string()),
            call.resolution_kind.clone()
        );
        assert_eq!(Some(2), call.vtable_slot);
        assert_eq!(Some(0xE020), call.target);
        assert_eq!(
            Some("class:000000000000D000".to_string()),
            call.class_id.clone()
        );
    }

    #[test]
    fn true10_pseudo_ir_uses_virtual_calls_and_explicit_unknowns() {
        let functions = vec![
            function(0xD000, 0xD020, "pdata"),
            function(0xD100, 0xD120, "pdata"),
        ];
        let calls = vec![ResolvedCallRecord {
            caller: 0xD000,
            callsite: 0xD008,
            original_callee: 0,
            resolved_api: "virtual:.?AVFixture@@::slot_2".to_string(),
            wrapper_chain: Vec::new(),
            chain_depth: 0,
            confidence: "medium".to_string(),
            resolution_kind: Some("virtual_dispatch".to_string()),
            class_id: Some("class:000000000000D000".to_string()),
            vtable_va: Some(0xF000),
            vtable_slot: Some(2),
            target: Some(0xE020),
            candidate_targets: Vec::new(),
            candidate_classes: Vec::new(),
        }];

        let rows = crate::pseudo_ir::build_pseudo_ir(
            &functions,
            &[],
            &[],
            &[],
            &[],
            &calls,
            &[],
            &[],
            &[],
            &[],
            &[],
            "basic",
        );

        let virtual_function = rows.iter().find(|row| row.function == 0xD000).unwrap();
        assert!(virtual_function
            .lines
            .iter()
            .any(|line| line.contains("call virtual") && line.contains("slot=2")));
        let unknown_function = rows.iter().find(|row| row.function == 0xD100).unwrap();
        assert!(unknown_function
            .lines
            .iter()
            .any(|line| line.starts_with("unknown(")));
    }

    #[test]
    fn true10_cpp_reports_ambiguous_virtual_dispatch_candidates() {
        let functions = vec![function(0xCA00, 0xCA40, "pdata")];
        let ir = vec![
            IrInstruction {
                address: 0xCA00,
                size: 3,
                mnemonic: "mov".to_string(),
                write_reg: Some("rax".to_string()),
                read_regs: vec!["rcx".to_string()],
                immediate: None,
                rip_target: None,
                stack_slot: None,
                memory_base: Some("rcx".to_string()),
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: false,
                memory_write: false,
                memory_read: true,
                direct_target: None,
                is_call: false,
                is_jump: false,
            },
            IrInstruction {
                address: 0xCA08,
                size: 3,
                mnemonic: "call".to_string(),
                write_reg: None,
                read_regs: vec!["rax".to_string()],
                immediate: None,
                rip_target: None,
                stack_slot: None,
                memory_base: Some("rax".to_string()),
                memory_index: None,
                memory_scale: 0,
                memory_displacement: 0,
                operand_width: 8,
                indirect_target_register: None,
                indirect_target_memory: true,
                memory_write: false,
                memory_read: true,
                direct_target: None,
                is_call: true,
                is_jump: false,
            },
        ];
        let index = FunctionSemanticIndex::build(&functions, &[], &ir, &[], &[]);
        let mut vtables = Vec::new();
        for (va, class, target) in [
            (0xD100, ".?AVFirst@@", 0xE100),
            (0xD200, ".?AVSecond@@", 0xE200),
        ] {
            vtables.push(VTableRecord {
                va,
                rva: va,
                section: ".rdata".to_string(),
                method_count: 1,
                methods: vec![target],
                probable_class: Some(class.to_string()),
                col_va: Some(va - 0x20),
                class_descriptor_va: Some(va - 0x10),
                base_classes: Vec::new(),
                constructor_candidates: vec![0xCB00],
                ownership_confidence: "high".to_string(),
            });
        }
        let target = second_pass_target(0xCA00, "unresolved_vtable_dispatch");

        let resolved =
            crate::cpp::resolve_virtual_calls(&functions, &index, &ir, &vtables, &[target]);

        let call = resolved.first().expect("ambiguous virtual dispatch");
        assert_eq!(
            Some("ambiguous_virtual_dispatch".to_string()),
            call.resolution_kind.clone()
        );
        assert_eq!(Some(0), call.vtable_slot);
        assert_eq!(None, call.target);
        assert_eq!(vec![0xE100, 0xE200], call.candidate_targets);
        assert_eq!(2, call.candidate_classes.len());
    }

    #[test]
    fn portable_capability_matrix_marks_live_telemetry_unsupported() {
        let functions = vec![function(0x1000, 0x1040, "pdata")];
        let instructions = vec![instruction(0x1000, "mov", "rax, rcx", false, false, false)];
        let sha256 = "0".repeat(64);
        let out_dir = portable_test_dir("telemetry_unsupported");
        let imports = vec![crate::pe::ImportRecord {
            dll: "KERNEL32.dll".to_string(),
            name: "CreateFileW".to_string(),
            symbol: "KERNEL32.dll!CreateFileW".to_string(),
            va: 0x3000,
            rva: 0x3000,
            hint: None,
            categories: vec!["file".to_string()],
        }];
        let output = crate::portable::build_portable_capabilities(crate::portable::PortableInput {
            profile: "portable-max",
            portable_tools_dir: "tools",
            emulation_budget: "normal",
            fuzz_mode: "off",
            fuzz_iterations: 0,
            trace_dir: None,
            decompile_c: "off",
            sha256: &sha256,
            source_path: "sample.exe",
            out_dir: &out_dir,
            bytes: &[],
            machine: 0x8664,
            file_size: 4096,
            overlay_size: 0,
            sections: &[],
            imports: &imports,
            exports: &[],
            strings: &[],
            functions: &functions,
            instructions: &instructions,
            cfg: &[],
            ssa_values: &[],
            dataflow_edges: &[],
            structured_flow: &[],
            xrefs: &[],
            api_flows: &[],
        });

        assert_eq!("portable-max", output.matrix.profile);
        assert!(output.emulation_traces.len() <= 1);
        assert!(output
            .matrix
            .capabilities
            .iter()
            .all(|row| row.status != "ran"));
        let emulation = output
            .matrix
            .capabilities
            .iter()
            .find(|row| row.capability == "bounded_offline_emulation")
            .expect("emulation capability");
        assert_eq!("executed", emulation.status);
        assert_eq!("executed_bytes", emulation.truthfulness_level);
        assert!(emulation.ran);
        assert!(!emulation.claim.is_empty());
        assert!(output.matrix.capabilities.iter().any(|row| {
            row.capability == "live_hypervisor_introspection"
                && row.status == "unsupported_portable"
                && row.truthfulness_level == "unsupported"
        }));
        assert!(output.matrix.capabilities.iter().any(|row| {
            row.capability == "live_kernel_telemetry" && row.status == "unsupported_portable"
        }));
    }

    #[test]
    fn portable_capabilities_do_not_claim_execution_for_non_applicable_backends() {
        let functions = vec![function(0x2000, 0x2040, "pdata")];
        let instructions = vec![instruction(0x2000, "cpuid", "", false, false, false)];
        let sha256 = "1".repeat(64);
        let out_dir = portable_test_dir("non_applicable_backends");
        let output = crate::portable::build_portable_capabilities(crate::portable::PortableInput {
            profile: "portable-max",
            portable_tools_dir: "tools",
            emulation_budget: "normal",
            fuzz_mode: "off",
            fuzz_iterations: 0,
            trace_dir: None,
            decompile_c: "off",
            sha256: &sha256,
            source_path: "normal.dll",
            out_dir: &out_dir,
            bytes: &[],
            machine: 0x8664,
            file_size: 4096,
            overlay_size: 0,
            sections: &[],
            imports: &[],
            exports: &[],
            strings: &[],
            functions: &functions,
            instructions: &instructions,
            cfg: &[],
            ssa_values: &[],
            dataflow_edges: &[],
            structured_flow: &[],
            xrefs: &[],
            api_flows: &[],
        });

        assert!(output.emulation_traces.is_empty());
        let statuses: std::collections::BTreeMap<_, _> = output
            .matrix
            .capabilities
            .iter()
            .map(|row| (row.capability.as_str(), row.status.as_str()))
            .collect();
        assert_eq!(
            Some(&"skipped_no_evidence"),
            statuses.get("bounded_offline_emulation")
        );
        assert_eq!(
            Some(&"skipped_no_evidence"),
            statuses.get("bounded_symbolic_paths")
        );
        assert_eq!(
            Some(&"not_applicable"),
            statuses.get("firmware_uefi_triage")
        );
        assert_eq!(
            Some(&"not_applicable"),
            statuses.get("kernel_driver_static_triage")
        );
        assert_eq!(Some(&"skipped_no_evidence"), statuses.get("vuln_fuzz_prep"));
        assert!(output
            .uncertainties
            .iter()
            .any(|row| row.reason == "unsupported_instruction"));
    }

    #[test]
    fn portable_fuzz_prep_generates_stub_but_never_claims_it_ran() {
        let functions = vec![function(0x3000, 0x3040, "pdata")];
        let instructions = vec![instruction(0x3000, "mov", "rax, rcx", false, false, false)];
        let sha256 = "2".repeat(64);
        let out_dir = portable_test_dir("fuzz_generated");
        let api_flows = vec![ApiFlowRecord {
            flow_id: "flow:1".to_string(),
            function: 0x3000,
            callsite: 0x3010,
            api: "KERNEL32.dll!VirtualProtect".to_string(),
            normalized_api: "VirtualProtect".to_string(),
            api_tier: "tier1".to_string(),
            api_family: "memory".to_string(),
            semantic_relevance: "high".to_string(),
            noise_reason: None,
            api_categories: vec!["memory".to_string()],
            value: "PAGE_EXECUTE_READWRITE".to_string(),
            value_tags: Vec::new(),
            argument: "flProtect".to_string(),
            argument_register: Some("r9".to_string()),
            argument_index: Some(3),
            argument_name: Some("flProtect".to_string()),
            confidence: "high".to_string(),
            mode: "direct".to_string(),
            resolved_api: Some("VirtualProtect".to_string()),
            wrapper_chain: Vec::new(),
            evidence: vec![0x3010],
        }];
        let output = crate::portable::build_portable_capabilities(crate::portable::PortableInput {
            profile: "portable-max",
            portable_tools_dir: "tools",
            emulation_budget: "normal",
            fuzz_mode: "off",
            fuzz_iterations: 0,
            trace_dir: None,
            decompile_c: "off",
            sha256: &sha256,
            source_path: "sample.exe",
            out_dir: &out_dir,
            bytes: &[],
            machine: 0x8664,
            file_size: 4096,
            overlay_size: 0,
            sections: &[],
            imports: &[],
            exports: &[],
            strings: &[],
            functions: &functions,
            instructions: &instructions,
            cfg: &[],
            ssa_values: &[],
            dataflow_edges: &[],
            structured_flow: &[],
            xrefs: &[],
            api_flows: &api_flows,
        });

        let fuzz = output
            .matrix
            .capabilities
            .iter()
            .find(|row| row.capability == "vuln_fuzz_prep")
            .expect("fuzz capability");
        assert_eq!("generated", fuzz.status);
        assert_eq!("generated_stub", fuzz.truthfulness_level);
        assert!(!fuzz.ran);
        assert_eq!(
            "stub_only_not_executed",
            output.fuzz_manifest.harnesses[0].status
        );
        assert!(output.fuzz_manifest.harnesses[0]
            .output_path
            .ends_with(".rs"));
        assert!(out_dir
            .join(&output.fuzz_manifest.harnesses[0].output_path)
            .is_file());
        assert!(output
            .uncertainties
            .iter()
            .any(|row| row.reason == "fuzz_harness_not_executed"));
    }

    #[test]
    fn native_max_executes_solver_fuzzer_decompiler_and_trace_ingest() {
        let functions = vec![function(0x4000, 0x4040, "pdata")];
        let instructions = vec![
            instruction(0x4000, "mov", "rcx, 4", false, false, false),
            instruction(0x4001, "cmp", "rcx, 4", false, false, false),
            branch_instruction(0x4002, "je", "0x4010", 0x4010),
            instruction(
                0x4010,
                "call",
                "KERNEL32.dll!VirtualProtect",
                true,
                false,
                false,
            ),
            instruction(0x4011, "ret", "", false, false, true),
        ];
        let sha256 = "4".repeat(64);
        let out_dir = portable_test_dir("native_max");
        let trace_dir = out_dir.join("trace_input");
        std::fs::create_dir_all(&trace_dir).expect("trace dir");
        std::fs::write(
            trace_dir.join("events.jsonl"),
            "{\"event_type\":\"api_call\",\"va\":\"0x4010\",\"api\":\"KERNEL32.dll!VirtualProtect\",\"registers\":{\"rcx\":\"0x1000\"}}\n",
        )
        .expect("trace event");
        let api_flows = vec![ApiFlowRecord {
            flow_id: "flow:native".to_string(),
            function: 0x4000,
            callsite: 0x4010,
            api: "KERNEL32.dll!VirtualProtect".to_string(),
            normalized_api: "VirtualProtect".to_string(),
            api_tier: "tier1".to_string(),
            api_family: "memory".to_string(),
            semantic_relevance: "high".to_string(),
            noise_reason: None,
            api_categories: vec!["memory".to_string()],
            value: "PAGE_EXECUTE_READWRITE".to_string(),
            value_tags: Vec::new(),
            argument: "flProtect".to_string(),
            argument_register: Some("r9".to_string()),
            argument_index: Some(3),
            argument_name: Some("flProtect".to_string()),
            confidence: "high".to_string(),
            mode: "direct".to_string(),
            resolved_api: Some("VirtualProtect".to_string()),
            wrapper_chain: Vec::new(),
            evidence: vec![0x4010],
        }];
        let output = crate::portable::build_portable_capabilities(crate::portable::PortableInput {
            profile: "native-max",
            portable_tools_dir: "tools",
            emulation_budget: "normal",
            fuzz_mode: "execute",
            fuzz_iterations: 4,
            trace_dir: Some(&trace_dir),
            decompile_c: "selected",
            sha256: &sha256,
            source_path: "sample.exe",
            out_dir: &out_dir,
            bytes: &[0x4D, 0x5A],
            machine: 0x8664,
            file_size: 4096,
            overlay_size: 0,
            sections: &[],
            imports: &[],
            exports: &[],
            strings: &[],
            functions: &functions,
            instructions: &instructions,
            cfg: &[],
            ssa_values: &[],
            dataflow_edges: &[],
            structured_flow: &[],
            xrefs: &[],
            api_flows: &api_flows,
        });

        let statuses: std::collections::BTreeMap<_, _> = output
            .matrix
            .capabilities
            .iter()
            .map(|row| (row.capability.as_str(), row.status.as_str()))
            .collect();
        assert_eq!(Some(&"executed"), statuses.get("bounded_offline_emulation"));
        assert_eq!(Some(&"executed"), statuses.get("bounded_symbolic_paths"));
        assert_eq!(Some(&"executed"), statuses.get("vuln_fuzz_prep"));
        assert_eq!(Some(&"executed"), statuses.get("native_c_decompilation"));
        assert_eq!(Some(&"executed"), statuses.get("offline_trace_ingest"));
        assert_eq!("satisfiable", output.symbolic_paths[0].satisfiability);
        assert_eq!(Some(&4), output.symbolic_paths[0].model.get("rcx"));
        assert!(!output.fuzz_runs.is_empty());
        assert!(output.fuzz_runs.iter().all(|row| row.status == "executed"));
        assert!(!output.decompiled_c.is_empty());
        assert!(out_dir.join(&output.decompiled_c[0].output_path).is_file());
        assert_eq!(1, output.trace_events.len());
        assert_eq!(Some(0x4000), output.trace_correlations[0].function);
    }

    #[test]
    fn native_max_expands_firmware_and_driver_artifacts() {
        let functions = vec![function(0x5000, 0x5040, "pdata")];
        let instructions = vec![instruction(0x5000, "ret", "", false, false, true)];
        let sha256 = "5".repeat(64);
        let out_dir = portable_test_dir("native_fw_driver");
        let imports = vec![crate::pe::ImportRecord {
            dll: "ntoskrnl.exe".to_string(),
            name: "IoCreateDevice".to_string(),
            symbol: "ntoskrnl.exe!IoCreateDevice".to_string(),
            va: 0x7000,
            rva: 0x7000,
            hint: None,
            categories: vec!["kernel".to_string()],
        }];
        let strings = vec![
            string_record(0x6000, "\\Device\\NativeRecon"),
            string_record(0x6010, "IOCTL_NATIVE_RECON 0x222004"),
            string_record(0x6020, "SMM DXE"),
        ];
        let output = crate::portable::build_portable_capabilities(crate::portable::PortableInput {
            profile: "native-max",
            portable_tools_dir: "tools",
            emulation_budget: "normal",
            fuzz_mode: "dry-run",
            fuzz_iterations: 2,
            trace_dir: None,
            decompile_c: "off",
            sha256: &sha256,
            source_path: "driver.sys",
            out_dir: &out_dir,
            bytes: b"VZ\x40\x00\x00\x00_FVHfixture",
            machine: 0x8664,
            file_size: 4096,
            overlay_size: 0,
            sections: &[],
            imports: &imports,
            exports: &[],
            strings: &strings,
            functions: &functions,
            instructions: &instructions,
            cfg: &[],
            ssa_values: &[],
            dataflow_edges: &[],
            structured_flow: &[],
            xrefs: &[],
            api_flows: &[],
        });

        assert!(output
            .firmware_modules
            .iter()
            .any(|row| row.module_type == "te_image"));
        assert!(output
            .unpacked_artifacts
            .iter()
            .any(|row| row.method == "firmware_module_extract"));
        let driver = output.kernel_artifacts.first().expect("driver artifact");
        assert!(driver
            .dispatch_routines
            .iter()
            .any(|row| row == "IoCreateDevice"));
        assert!(driver.ioctl_codes.iter().any(|row| row == "0x222004"));
        assert!(driver
            .device_names
            .iter()
            .any(|row| row == "\\Device\\NativeRecon"));
    }

    fn instruction(
        address: u64,
        mnemonic: &str,
        op_str: &str,
        is_call: bool,
        is_jump: bool,
        is_ret: bool,
    ) -> crate::pe::InstructionRecord {
        crate::pe::InstructionRecord {
            address,
            size: 1,
            mnemonic: mnemonic.to_string(),
            op_str: op_str.to_string(),
            section: ".text".to_string(),
            groups: Vec::new(),
            is_call,
            is_jump,
            is_ret,
            branch_target: None,
        }
    }

    fn branch_instruction(
        address: u64,
        mnemonic: &str,
        op_str: &str,
        branch_target: u64,
    ) -> crate::pe::InstructionRecord {
        crate::pe::InstructionRecord {
            branch_target: Some(branch_target),
            is_jump: true,
            ..instruction(address, mnemonic, op_str, false, true, false)
        }
    }

    fn function(start: u64, end: u64, source: &str) -> FunctionRecord {
        FunctionRecord {
            start,
            end,
            size: end - start,
            source: source.to_string(),
            calls: Vec::new(),
            calls_imports: Vec::new(),
            strings: Vec::new(),
            xrefs: 0,
        }
    }

    fn portable_test_dir(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("analysis_native_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create portable test dir");
        path
    }

    fn string_record(va: u64, text: &str) -> StringRecord {
        StringRecord {
            va,
            rva: va,
            file_offset: 0,
            encoding: "ASCII".to_string(),
            size: text.len(),
            text: text.to_string(),
            classifiers: crate::strings::classify_string(text),
            section: Some(".rdata".to_string()),
        }
    }

    fn ir_write(
        address: u64,
        mnemonic: &str,
        write_reg: Option<&str>,
        read_reg: Option<&str>,
        rip_target: Option<u64>,
        immediate: Option<u64>,
        is_call: bool,
    ) -> IrInstruction {
        IrInstruction {
            address,
            size: 1,
            mnemonic: mnemonic.to_string(),
            write_reg: write_reg.map(str::to_string),
            read_regs: read_reg
                .map(|reg| vec![reg.to_string()])
                .unwrap_or_default(),
            immediate,
            rip_target,
            stack_slot: None,
            memory_base: None,
            memory_index: None,
            memory_scale: 0,
            memory_displacement: 0,
            operand_width: 0,
            indirect_target_register: None,
            indirect_target_memory: false,
            memory_write: false,
            memory_read: rip_target.is_some(),
            direct_target: None,
            is_call,
            is_jump: false,
        }
    }

    fn second_pass_target(function: u64, reason: &str) -> crate::pe::SecondPassTargetRecord {
        crate::pe::SecondPassTargetRecord {
            target_id: format!("target:{function:016X}:{reason}"),
            function,
            reason: reason.to_string(),
            priority_score: 10,
            pass1_uncertainty: reason.to_string(),
            result_status: "analyzed".to_string(),
            evidence: vec![function],
        }
    }

    fn api_flow(
        function: u64,
        callsite: u64,
        api: &str,
        argument: &str,
        register: Option<&str>,
    ) -> crate::pe::ApiFlowRecord {
        api_flow_arg(function, callsite, api, argument, register, 0)
    }

    fn api_flow_arg(
        function: u64,
        callsite: u64,
        api: &str,
        argument: &str,
        register: Option<&str>,
        argument_index: usize,
    ) -> crate::pe::ApiFlowRecord {
        let classification = crate::winapi::classify_api(api);
        crate::pe::ApiFlowRecord {
            flow_id: format!("flow:{function:016X}:{callsite:016X}:0000"),
            function,
            callsite,
            api: api.to_string(),
            normalized_api: classification.normalized_symbol,
            api_tier: classification.tier,
            api_family: classification.family,
            semantic_relevance: classification.semantic_relevance,
            noise_reason: classification.noise_reason,
            api_categories: vec!["file".to_string()],
            value: "C:\\Temp\\x.bin".to_string(),
            value_tags: vec!["path".to_string()],
            argument: argument.to_string(),
            argument_register: register.map(str::to_string),
            argument_index: Some(argument_index),
            argument_name: Some(argument.to_string()),
            confidence: "high".to_string(),
            mode: "proven".to_string(),
            resolved_api: None,
            wrapper_chain: Vec::new(),
            evidence: vec![callsite],
        }
    }

    fn import_xref(from: u64, symbol: &str) -> XrefRecord {
        XrefRecord {
            kind: "import".to_string(),
            from,
            target: 0,
            role: "call".to_string(),
            symbol: Some(symbol.to_string()),
            text: None,
            encoding: None,
            section: None,
        }
    }

    fn code_call(from: u64, target: u64) -> XrefRecord {
        XrefRecord {
            kind: "code".to_string(),
            from,
            target,
            role: "call".to_string(),
            symbol: None,
            text: None,
            encoding: None,
            section: Some(".text".to_string()),
        }
    }
}
