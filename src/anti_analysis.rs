//! Anti-analysis detection: packers (UPX/Themida/VMProtect/ASPack/MPRESS),
//! anti-debug API patterns, anti-VM probes, anti-sandbox timing checks.
//!
//! Emits `anti_analysis.jsonl` with one record per indicator + confidence.

use crate::image::BinaryImage;
use crate::pe::{ImportRecord, InstructionRecord, SectionRecord, StringRecord};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct AntiAnalysisRecord {
    pub schema: &'static str,
    pub indicator_id: String,
    pub category: &'static str, // "packer" | "anti_debug" | "anti_vm" | "anti_sandbox"
    pub name: String,           // e.g. "UPX", "IsDebuggerPresent", "CPUID_hypervisor"
    pub confidence: &'static str, // "high" | "medium" | "low"
    pub description: String,
    pub evidence: Vec<String>,
    pub site_va: Option<u64>,
}

pub fn detect(
    image: &dyn BinaryImage,
    imports: &[ImportRecord],
    strings: &[StringRecord],
    instructions: &[InstructionRecord],
) -> Vec<AntiAnalysisRecord> {
    let mut out = Vec::new();
    detect_packers(image, imports, strings, &mut out);
    detect_anti_debug(imports, instructions, &mut out);
    detect_anti_vm(imports, strings, instructions, &mut out);
    detect_anti_sandbox(imports, strings, instructions, &mut out);
    out
}

fn detect_packers(
    image: &dyn BinaryImage,
    imports: &[ImportRecord],
    strings: &[StringRecord],
    out: &mut Vec<AntiAnalysisRecord>,
) {
    let sections = image.sections();
    let import_sparsity = imports.len();
    let high_entropy_exec: Vec<&SectionRecord> = sections
        .iter()
        .filter(|s| s.executable && s.entropy >= 7.2)
        .collect();
    let total_exec_size: u64 = sections
        .iter()
        .filter(|s| s.executable)
        .map(|s| s.virtual_size as u64)
        .sum();

    let names: Vec<&str> = sections.iter().map(|s| s.name.as_str()).collect();
    let lower_names: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();

    // UPX: section names "UPX0"/"UPX1" or `.upx` markers
    if lower_names
        .iter()
        .any(|n| n.starts_with("upx") || n == ".upx")
    {
        out.push(AntiAnalysisRecord {
            schema: "anti_analysis/1",
            indicator_id: format!("packer:upx:{}", out.len()),
            category: "packer",
            name: "UPX".to_string(),
            confidence: "high",
            description: "section name suggests UPX (Ultimate Packer for eXecutables)".to_string(),
            evidence: lower_names
                .iter()
                .filter(|n| n.starts_with("upx") || n.as_str() == ".upx")
                .cloned()
                .collect(),
            site_va: None,
        });
    }

    // ASPack: section ".aspack" / ".adata"
    if lower_names.iter().any(|n| n == ".aspack" || n == ".adata") {
        out.push(AntiAnalysisRecord {
            schema: "anti_analysis/1",
            indicator_id: format!("packer:aspack:{}", out.len()),
            category: "packer",
            name: "ASPack".to_string(),
            confidence: "high",
            description: "section name suggests ASPack".to_string(),
            evidence: lower_names
                .iter()
                .filter(|n| n.as_str() == ".aspack" || n.as_str() == ".adata")
                .cloned()
                .collect(),
            site_va: None,
        });
    }

    // PECompact / MPRESS / Themida / VMProtect / ASProtect
    let suspect_table: &[(&str, &str, &str, &str)] = &[
        (
            ".mpress1",
            "MPRESS",
            "high",
            "MPRESS packer section signature",
        ),
        (
            ".mpress2",
            "MPRESS",
            "high",
            "MPRESS packer section signature",
        ),
        (".pec1", "PECompact", "high", "PECompact section signature"),
        (".pec2", "PECompact", "high", "PECompact section signature"),
        (".themida", "Themida", "high", "Themida section signature"),
        (".vmp0", "VMProtect", "high", "VMProtect section signature"),
        (".vmp1", "VMProtect", "high", "VMProtect section signature"),
        (".vmp2", "VMProtect", "high", "VMProtect section signature"),
        (
            ".enigma",
            "Enigma",
            "high",
            "Enigma Protector section signature",
        ),
        (
            ".asprotect",
            "ASProtect",
            "high",
            "ASProtect section signature",
        ),
        (".pelock", "PELock", "high", "PELock section signature"),
        (
            ".petite",
            "Petite",
            "high",
            "Petite packer section signature",
        ),
        (
            ".y0da",
            "yoda's Crypter",
            "high",
            "yoda's Crypter section signature",
        ),
        (".nsp1", "NsPack", "high", "NsPack section signature"),
        (".nsp2", "NsPack", "high", "NsPack section signature"),
    ];
    for (needle, name, conf, desc) in suspect_table {
        if lower_names.iter().any(|n| n.contains(needle)) {
            let conf_static: &'static str = match *conf {
                "high" => "high",
                "medium" => "medium",
                _ => "low",
            };
            out.push(AntiAnalysisRecord {
                schema: "anti_analysis/1",
                indicator_id: format!("packer:{}:{}", name.to_ascii_lowercase(), out.len()),
                category: "packer",
                name: name.to_string(),
                confidence: conf_static,
                description: desc.to_string(),
                evidence: lower_names
                    .iter()
                    .filter(|n| n.contains(needle))
                    .cloned()
                    .collect(),
                site_va: None,
            });
        }
    }

    // Generic packer heuristic: very few imports + a high-entropy executable section + small total exec size relative to file
    if import_sparsity > 0
        && import_sparsity < 8
        && !high_entropy_exec.is_empty()
        && total_exec_size > 0
    {
        out.push(AntiAnalysisRecord {
            schema: "anti_analysis/1",
            indicator_id: format!("packer:generic:{}", out.len()),
            category: "packer",
            name: "generic_packed".to_string(),
            confidence: "medium",
            description: format!(
                "sparse imports ({}) + high-entropy executable section ({:.2} bits) suggests packing",
                import_sparsity,
                high_entropy_exec[0].entropy
            ),
            evidence: high_entropy_exec.iter().map(|s| s.name.clone()).collect(),
            site_va: None,
        });
    }

    // String-based packer probes: "UPX!" magic in overlay; "Themida " banner
    for s in strings.iter().take(8192) {
        let t = s.text.as_str();
        if t.starts_with("UPX!") {
            out.push(AntiAnalysisRecord {
                schema: "anti_analysis/1",
                indicator_id: format!("packer:upx-magic:{}", out.len()),
                category: "packer",
                name: "UPX".to_string(),
                confidence: "high",
                description: "UPX! signature byte sequence found in strings".to_string(),
                evidence: vec![t.to_string()],
                site_va: Some(s.va),
            });
            break;
        }
        if t.contains("Themida") {
            out.push(AntiAnalysisRecord {
                schema: "anti_analysis/1",
                indicator_id: format!("packer:themida-string:{}", out.len()),
                category: "packer",
                name: "Themida".to_string(),
                confidence: "medium",
                description: "string contains 'Themida'".to_string(),
                evidence: vec![t.to_string()],
                site_va: Some(s.va),
            });
            break;
        }
    }
}

fn detect_anti_debug(
    imports: &[ImportRecord],
    instructions: &[InstructionRecord],
    out: &mut Vec<AntiAnalysisRecord>,
) {
    // API patterns
    let api_indicators: &[(&str, &str, &str, &str)] = &[
        (
            "isdebuggerpresent",
            "IsDebuggerPresent",
            "high",
            "kernel32 anti-debug API: returns true if a debugger is attached",
        ),
        (
            "checkremotedebuggerpresent",
            "CheckRemoteDebuggerPresent",
            "high",
            "kernel32 anti-debug API: probes for remote debugger",
        ),
        (
            "ntqueryinformationprocess",
            "NtQueryInformationProcess",
            "medium",
            "ntdll probe — often used to query ProcessDebugPort / ProcessDebugObjectHandle",
        ),
        (
            "ntsetinformationthread",
            "NtSetInformationThread",
            "medium",
            "ntdll — used with ThreadHideFromDebugger to hide threads",
        ),
        (
            "dbgbreakpoint",
            "DbgBreakPoint",
            "low",
            "ntdll DbgBreakPoint — often used in anti-debug self-checks",
        ),
        (
            "outputdebugstring",
            "OutputDebugString",
            "low",
            "anti-debug trick: OutputDebugString + GetLastError differential",
        ),
        (
            "getthreadcontext",
            "GetThreadContext",
            "medium",
            "may inspect hardware breakpoint debug registers (DR0-DR7)",
        ),
        (
            "zwsetinformationthread",
            "ZwSetInformationThread",
            "medium",
            "ntdll Zw variant of NtSetInformationThread; ThreadHideFromDebugger",
        ),
    ];
    for (needle, name, conf, desc) in api_indicators {
        if let Some(import) = imports
            .iter()
            .find(|i| i.symbol.to_ascii_lowercase().contains(needle))
        {
            let c: &'static str = match *conf {
                "high" => "high",
                "medium" => "medium",
                _ => "low",
            };
            out.push(AntiAnalysisRecord {
                schema: "anti_analysis/1",
                indicator_id: format!("anti_debug:{}:{}", name, out.len()),
                category: "anti_debug",
                name: name.to_string(),
                confidence: c,
                description: desc.to_string(),
                evidence: vec![import.symbol.clone()],
                site_va: Some(import.va),
            });
        }
    }

    // PEB.BeingDebugged probe: `mov rax, gs:[0x60]; movzx eax, byte ptr [rax+2]`
    // Detect: any read of `gs:` segment override (only PEB-style access on Windows x64).
    // iced-x86 doesn't surface seg prefix in our InstructionRecord, but op_str strings like
    // "mov rax, gs:[0x60]" do appear. Heuristic: search op_str for `gs:` or `gs:[`.
    let gs_hits: Vec<&InstructionRecord> = instructions
        .iter()
        .filter(|ins| ins.op_str.contains("gs:["))
        .take(8)
        .collect();
    if !gs_hits.is_empty() {
        out.push(AntiAnalysisRecord {
            schema: "anti_analysis/1",
            indicator_id: format!("anti_debug:peb_probe:{}", out.len()),
            category: "anti_debug",
            name: "PEB_access".to_string(),
            confidence: "medium",
            description: "GS segment access (gs:[...]) likely reads PEB.BeingDebugged or other TIB/PEB fields"
                .to_string(),
            evidence: gs_hits
                .iter()
                .take(3)
                .map(|ins| format!("0x{:016X}: {} {}", ins.address, ins.mnemonic, ins.op_str))
                .collect(),
            site_va: gs_hits.first().map(|i| i.address),
        });
    }

    // INT 3 / INT 2D detection — common anti-debug instructions
    let int_hits: Vec<&InstructionRecord> = instructions
        .iter()
        .filter(|ins| {
            let m = ins.mnemonic.to_ascii_lowercase();
            (m == "int3") || (m == "int" && ins.op_str.trim() == "2dh")
        })
        .take(16)
        .collect();
    if int_hits
        .iter()
        .filter(|i| i.mnemonic.eq_ignore_ascii_case("int") && i.op_str.contains("2d"))
        .count()
        > 0
    {
        out.push(AntiAnalysisRecord {
            schema: "anti_analysis/1",
            indicator_id: format!("anti_debug:int2d:{}", out.len()),
            category: "anti_debug",
            name: "INT_2D".to_string(),
            confidence: "high",
            description: "INT 2D — kernel-mode debugger break; if no debugger attached this falls through, if attached it triggers a debug exception"
                .to_string(),
            evidence: int_hits
                .iter()
                .map(|ins| format!("0x{:016X}: {} {}", ins.address, ins.mnemonic, ins.op_str))
                .collect(),
            site_va: int_hits.first().map(|i| i.address),
        });
    }
}

fn detect_anti_vm(
    imports: &[ImportRecord],
    strings: &[StringRecord],
    instructions: &[InstructionRecord],
    out: &mut Vec<AntiAnalysisRecord>,
) {
    // CPUID 0x40000000 (hypervisor leaf) — detect MOV EAX, 0x40000000 followed nearby by CPUID
    let mut prior_eax_imm: Option<u64> = None;
    for ins in instructions.iter().take(50_000) {
        let mnem = ins.mnemonic.to_ascii_lowercase();
        if mnem == "mov" {
            let op = ins.op_str.to_ascii_lowercase();
            if op.starts_with("eax,") || op.starts_with("rax,") {
                if op.contains("0x40000000") || op.contains("40000000h") {
                    prior_eax_imm = Some(ins.address);
                    continue;
                }
            }
        }
        if mnem == "cpuid" {
            if prior_eax_imm.is_some() {
                let site = prior_eax_imm.take();
                out.push(AntiAnalysisRecord {
                    schema: "anti_analysis/1",
                    indicator_id: format!("anti_vm:cpuid_hypervisor:{}", out.len()),
                    category: "anti_vm",
                    name: "CPUID_hypervisor_leaf".to_string(),
                    confidence: "high",
                    description:
                        "CPUID with EAX=0x40000000 — hypervisor presence/identification leaf"
                            .to_string(),
                    evidence: vec![format!(
                        "setup at 0x{:016X}, cpuid at 0x{:016X}",
                        site.unwrap_or(0),
                        ins.address
                    )],
                    site_va: Some(ins.address),
                });
                break;
            }
        } else {
            // Only keep prior_eax_imm valid within a small window
            if let Some(prev) = prior_eax_imm {
                if ins.address.saturating_sub(prev) > 0x40 {
                    prior_eax_imm = None;
                }
            }
        }
    }

    // String probes: VMware/VBox/QEMU/Xen indicators
    let vm_string_indicators: &[(&str, &str)] = &[
        ("vmware", "VMware"),
        ("vboxservice", "VirtualBox"),
        ("vboxtray", "VirtualBox"),
        ("vbox", "VirtualBox"),
        ("qemu", "QEMU"),
        ("xen", "Xen"),
        ("parallels", "Parallels"),
        ("sandboxie", "Sandboxie"),
        ("vmwaretray", "VMware"),
        ("vmwareuser", "VMware"),
        ("vmtoolsd", "VMware"),
        ("virtualbox guest", "VirtualBox"),
    ];
    let mut seen_vm: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for s in strings.iter().take(8192) {
        let t = s.text.to_ascii_lowercase();
        for (needle, name) in vm_string_indicators {
            if t.contains(needle) && seen_vm.insert(name) {
                out.push(AntiAnalysisRecord {
                    schema: "anti_analysis/1",
                    indicator_id: format!(
                        "anti_vm:string:{}:{}",
                        name.to_ascii_lowercase(),
                        out.len()
                    ),
                    category: "anti_vm",
                    name: format!("{}_string_probe", name),
                    confidence: "medium",
                    description: format!("string contains '{}' — likely VM detection", needle),
                    evidence: vec![s.text.clone()],
                    site_va: Some(s.va),
                });
            }
        }
    }

    // Registry-key string probes (VBox/VMware keys)
    let reg_probes: &[(&str, &str)] = &[
        ("SOFTWARE\\Oracle\\VirtualBox Guest Additions", "VirtualBox"),
        ("SYSTEM\\ControlSet001\\Services\\VBox", "VirtualBox"),
        ("SOFTWARE\\VMware, Inc.\\VMware Tools", "VMware"),
        ("HARDWARE\\Description\\System\\BIOS", "VM_BIOS_check"),
    ];
    for s in strings.iter().take(8192) {
        for (needle, name) in reg_probes {
            if s.text.contains(needle) {
                out.push(AntiAnalysisRecord {
                    schema: "anti_analysis/1",
                    indicator_id: format!(
                        "anti_vm:registry:{}:{}",
                        name.to_ascii_lowercase(),
                        out.len()
                    ),
                    category: "anti_vm",
                    name: format!("{}_registry_probe", name),
                    confidence: "high",
                    description: format!("registry probe for {} key — VM detection", name),
                    evidence: vec![s.text.clone()],
                    site_va: Some(s.va),
                });
                break;
            }
        }
    }

    let _ = imports; // reserved for future API-based VM probes (e.g. wmi queries)
}

fn detect_anti_sandbox(
    imports: &[ImportRecord],
    strings: &[StringRecord],
    instructions: &[InstructionRecord],
    out: &mut Vec<AntiAnalysisRecord>,
) {
    // RDTSC timing checks: paired rdtsc instructions within a small window
    let mut rdtsc_addrs: Vec<u64> = Vec::new();
    for ins in instructions.iter().take(50_000) {
        if ins.mnemonic.eq_ignore_ascii_case("rdtsc") {
            rdtsc_addrs.push(ins.address);
        }
    }
    if rdtsc_addrs.len() >= 2 {
        // pair-up adjacent rdtsc calls
        let pairs: Vec<(u64, u64)> = rdtsc_addrs
            .windows(2)
            .filter(|w| w[1].saturating_sub(w[0]) < 0x200)
            .map(|w| (w[0], w[1]))
            .take(8)
            .collect();
        if !pairs.is_empty() {
            out.push(AntiAnalysisRecord {
                schema: "anti_analysis/1",
                indicator_id: format!("anti_sandbox:rdtsc_timing:{}", out.len()),
                category: "anti_sandbox",
                name: "RDTSC_timing".to_string(),
                confidence: "high",
                description: "paired RDTSC instructions within a small VA window suggest timing-based sandbox detection"
                    .to_string(),
                evidence: pairs
                    .iter()
                    .map(|(a, b)| format!("0x{:016X} → 0x{:016X}", a, b))
                    .collect(),
                site_va: pairs.first().map(|(a, _)| *a),
            });
        }
    }

    // GetTickCount / QueryPerformanceCounter imports (timing-check candidates)
    let timing_apis: &[(&str, &str)] = &[
        ("gettickcount", "GetTickCount"),
        ("queryperformancecounter", "QueryPerformanceCounter"),
        ("ntdelayexecution", "NtDelayExecution"),
    ];
    for (needle, name) in timing_apis {
        if let Some(import) = imports
            .iter()
            .find(|i| i.symbol.to_ascii_lowercase().contains(needle))
        {
            out.push(AntiAnalysisRecord {
                schema: "anti_analysis/1",
                indicator_id: format!("anti_sandbox:timing_api:{}:{}", name, out.len()),
                category: "anti_sandbox",
                name: format!("{}_timing", name),
                confidence: "low",
                description: format!("imports {} — common in sandbox timing checks", name),
                evidence: vec![import.symbol.clone()],
                site_va: Some(import.va),
            });
        }
    }

    // Sandbox username/hostname probes
    let sandbox_strings: &[(&str, &str)] = &[
        ("sandbox", "generic_sandbox"),
        ("cuckoo", "Cuckoo"),
        ("anubis", "Anubis"),
        ("threatexpert", "ThreatExpert"),
        ("joebox", "JoeBox"),
        ("malware-test", "generic_sandbox"),
        ("sandboxie", "Sandboxie"),
    ];
    let mut seen_sandbox: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for s in strings.iter().take(8192) {
        let t = s.text.to_ascii_lowercase();
        for (needle, name) in sandbox_strings {
            if t.contains(needle) && seen_sandbox.insert(name) {
                out.push(AntiAnalysisRecord {
                    schema: "anti_analysis/1",
                    indicator_id: format!(
                        "anti_sandbox:string:{}:{}",
                        name.to_ascii_lowercase(),
                        out.len()
                    ),
                    category: "anti_sandbox",
                    name: format!("{}_string_probe", name),
                    confidence: "medium",
                    description: format!("string contains '{}' — likely sandbox detection", needle),
                    evidence: vec![s.text.clone()],
                    site_va: Some(s.va),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_upx_by_section_name() {
        // we need a real BinaryImage stub for sections().
        // Use a barebones fake via ParsedImage.
        use crate::image::{Format, ParsedImage};
        use crate::pe::SectionRecord;
        let sec = SectionRecord {
            name: "UPX0".to_string(),
            rva: 0x1000,
            va: 0x1000,
            virtual_size: 0x1000,
            raw_start: 0x400,
            raw_size: 0x1000,
            data_size: 0x1000,
            executable: true,
            readable: true,
            writable: true,
            entropy: 7.5,
            data_range: 0x400..0x1400,
        };
        let image = ParsedImage {
            format: Format::Pe,
            bytes: vec![0u8; 0x1400],
            base: 0,
            entry_va: 0x1000,
            machine: 0x8664,
            sections: vec![sec],
            imports: Vec::new(),
            exports: Vec::new(),
            function_seeds: Vec::new(),
            source_path: "test".to_string(),
        };
        let records = detect(&image, &[], &[], &[]);
        assert!(
            records
                .iter()
                .any(|r| r.name == "UPX" && r.category == "packer"),
            "expected UPX packer detection, got {records:?}"
        );
    }

    #[test]
    fn detects_isdebuggerpresent_import() {
        let imports = vec![crate::pe::ImportRecord {
            dll: "kernel32.dll".to_string(),
            name: "IsDebuggerPresent".to_string(),
            symbol: "kernel32.dll!IsDebuggerPresent".to_string(),
            va: 0x1000,
            rva: 0x1000,
            hint: None,
            categories: vec![],
        }];
        use crate::image::{Format, ParsedImage};
        let image = ParsedImage {
            format: Format::Pe,
            bytes: vec![],
            base: 0,
            entry_va: 0,
            machine: 0x8664,
            sections: Vec::new(),
            imports: imports.clone(),
            exports: Vec::new(),
            function_seeds: Vec::new(),
            source_path: "test".to_string(),
        };
        let records = detect(&image, &imports, &[], &[]);
        assert!(
            records
                .iter()
                .any(|r| r.name == "IsDebuggerPresent" && r.category == "anti_debug"),
            "expected IsDebuggerPresent detection"
        );
    }
}
