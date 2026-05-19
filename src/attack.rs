//! MITRE ATT&CK technique mapping. Table-driven: each indicator (import, API
//! flow value, behavior dossier capability, anti-analysis record) maps to one
//! or more ATT&CK technique IDs.
//!
//! Emits `attack_techniques.jsonl`. Each record cites the evidence that
//! triggered the mapping so downstream LLM workflows can chain provenance.

use crate::anti_analysis::AntiAnalysisRecord;
use crate::pe::{ApiFlowRecord, BehaviorDossierRecord, ImportRecord};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct AttackTechniqueRecord {
    pub schema: &'static str,
    pub technique_id: String, // e.g. "T1055", "T1027.007"
    pub name: String,
    pub tactic: String,
    pub confidence: &'static str, // "high" | "medium" | "low"
    pub evidence: Vec<String>,
    pub evidence_vas: Vec<u64>,
    pub source: String, // "import" | "api_flow" | "behavior" | "anti_analysis"
}

pub fn map_techniques(
    imports: &[ImportRecord],
    api_flows: &[ApiFlowRecord],
    behavior_dossiers: &[BehaviorDossierRecord],
    anti_analysis: &[AntiAnalysisRecord],
) -> Vec<AttackTechniqueRecord> {
    let mut grouped: BTreeMap<String, AttackTechniqueRecord> = BTreeMap::new();

    map_imports(imports, &mut grouped);
    map_api_flows(api_flows, &mut grouped);
    map_behaviors(behavior_dossiers, &mut grouped);
    map_anti_analysis(anti_analysis, &mut grouped);

    grouped.into_values().collect()
}

fn upsert(
    grouped: &mut BTreeMap<String, AttackTechniqueRecord>,
    tid: &str,
    name: &str,
    tactic: &str,
    confidence: &'static str,
    source: &str,
    evidence: String,
    evidence_va: Option<u64>,
) {
    let entry = grouped
        .entry(tid.to_string())
        .or_insert_with(|| AttackTechniqueRecord {
            schema: "attack_technique/1",
            technique_id: tid.to_string(),
            name: name.to_string(),
            tactic: tactic.to_string(),
            confidence,
            evidence: Vec::new(),
            evidence_vas: Vec::new(),
            source: source.to_string(),
        });
    if !entry.evidence.contains(&evidence) {
        entry.evidence.push(evidence);
    }
    if let Some(va) = evidence_va {
        if !entry.evidence_vas.contains(&va) {
            entry.evidence_vas.push(va);
        }
    }
    // Promote confidence if a stronger signal triggers the same technique
    if rank(confidence) > rank(entry.confidence) {
        entry.confidence = confidence;
    }
}

fn rank(c: &str) -> u8 {
    match c {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Map dangerous imports to ATT&CK techniques.
///
/// Reference: https://attack.mitre.org/techniques/enterprise/
fn map_imports(imports: &[ImportRecord], grouped: &mut BTreeMap<String, AttackTechniqueRecord>) {
    let rules: &[(&str, &str, &str, &str, &'static str)] = &[
        // (lowercase symbol substring, technique_id, name, tactic, confidence)
        (
            "virtualallocex",
            "T1055.002",
            "Portable Executable Injection",
            "Defense Evasion",
            "high",
        ),
        (
            "writeprocessmemory",
            "T1055",
            "Process Injection",
            "Defense Evasion",
            "high",
        ),
        (
            "createremotethread",
            "T1055.002",
            "Portable Executable Injection",
            "Defense Evasion",
            "high",
        ),
        (
            "ntcreatethreadex",
            "T1055.002",
            "Portable Executable Injection",
            "Defense Evasion",
            "high",
        ),
        (
            "rtlcreateuserthread",
            "T1055.002",
            "Portable Executable Injection",
            "Defense Evasion",
            "high",
        ),
        (
            "setwindowshookex",
            "T1056.004",
            "Credential API Hooking",
            "Credential Access",
            "medium",
        ),
        (
            "getasynckeystate",
            "T1056.001",
            "Keylogging",
            "Collection",
            "medium",
        ),
        (
            "getkeyboardstate",
            "T1056.001",
            "Keylogging",
            "Collection",
            "medium",
        ),
        (
            "getforegroundwindow",
            "T1010",
            "Application Window Discovery",
            "Discovery",
            "medium",
        ),
        (
            "findwindow",
            "T1010",
            "Application Window Discovery",
            "Discovery",
            "medium",
        ),
        (
            "regopenkey",
            "T1112",
            "Modify Registry",
            "Defense Evasion",
            "low",
        ),
        (
            "regsetvalue",
            "T1112",
            "Modify Registry",
            "Defense Evasion",
            "medium",
        ),
        (
            "regcreatekey",
            "T1112",
            "Modify Registry",
            "Defense Evasion",
            "medium",
        ),
        (
            "createservice",
            "T1543.003",
            "Windows Service",
            "Persistence",
            "high",
        ),
        (
            "startservice",
            "T1543.003",
            "Windows Service",
            "Persistence",
            "medium",
        ),
        (
            "schtasks",
            "T1053.005",
            "Scheduled Task",
            "Persistence",
            "medium",
        ),
        (
            "createtoolhelp32snapshot",
            "T1057",
            "Process Discovery",
            "Discovery",
            "medium",
        ),
        (
            "process32first",
            "T1057",
            "Process Discovery",
            "Discovery",
            "medium",
        ),
        (
            "process32next",
            "T1057",
            "Process Discovery",
            "Discovery",
            "medium",
        ),
        (
            "enumprocesses",
            "T1057",
            "Process Discovery",
            "Discovery",
            "medium",
        ),
        (
            "getcomputername",
            "T1082",
            "System Information Discovery",
            "Discovery",
            "low",
        ),
        (
            "getusername",
            "T1033",
            "System Owner/User Discovery",
            "Discovery",
            "low",
        ),
        (
            "getversion",
            "T1082",
            "System Information Discovery",
            "Discovery",
            "low",
        ),
        (
            "getsysteminfo",
            "T1082",
            "System Information Discovery",
            "Discovery",
            "low",
        ),
        (
            "getmodulefilename",
            "T1083",
            "File and Directory Discovery",
            "Discovery",
            "low",
        ),
        (
            "findfirstfile",
            "T1083",
            "File and Directory Discovery",
            "Discovery",
            "low",
        ),
        (
            "inetreaddata",
            "T1071.001",
            "Web Protocols",
            "Command and Control",
            "medium",
        ),
        (
            "internetopen",
            "T1071.001",
            "Web Protocols",
            "Command and Control",
            "medium",
        ),
        (
            "httpsendrequest",
            "T1071.001",
            "Web Protocols",
            "Command and Control",
            "high",
        ),
        (
            "wininet",
            "T1071.001",
            "Web Protocols",
            "Command and Control",
            "medium",
        ),
        (
            "winhttp",
            "T1071.001",
            "Web Protocols",
            "Command and Control",
            "medium",
        ),
        (
            "urldownloadtofile",
            "T1105",
            "Ingress Tool Transfer",
            "Command and Control",
            "high",
        ),
        (
            "ws2_32",
            "T1095",
            "Non-Application Layer Protocol",
            "Command and Control",
            "low",
        ),
        (
            "wsasocket",
            "T1095",
            "Non-Application Layer Protocol",
            "Command and Control",
            "medium",
        ),
        (
            "getprocaddress",
            "T1027.007",
            "Dynamic API Resolution",
            "Defense Evasion",
            "medium",
        ),
        ("loadlibrary", "T1129", "Shared Modules", "Execution", "low"),
        (
            "ldrloaddll",
            "T1129",
            "Shared Modules",
            "Execution",
            "medium",
        ),
        (
            "ldrgetprocedureaddress",
            "T1027.007",
            "Dynamic API Resolution",
            "Defense Evasion",
            "high",
        ),
        (
            "virtualprotect",
            "T1055",
            "Process Injection",
            "Defense Evasion",
            "medium",
        ),
        (
            "ntunmapviewofsection",
            "T1055.012",
            "Process Hollowing",
            "Defense Evasion",
            "high",
        ),
        (
            "zwunmapviewofsection",
            "T1055.012",
            "Process Hollowing",
            "Defense Evasion",
            "high",
        ),
        (
            "createprocess",
            "T1059",
            "Command and Scripting Interpreter",
            "Execution",
            "low",
        ),
        (
            "shellexecute",
            "T1059",
            "Command and Scripting Interpreter",
            "Execution",
            "low",
        ),
        (
            "winexec",
            "T1059",
            "Command and Scripting Interpreter",
            "Execution",
            "low",
        ),
        (
            "cryptencrypt",
            "T1486",
            "Data Encrypted for Impact",
            "Impact",
            "high",
        ),
        (
            "cryptdecrypt",
            "T1140",
            "Deobfuscate/Decode Files or Information",
            "Defense Evasion",
            "high",
        ),
        (
            "cryptgenrandom",
            "T1027",
            "Obfuscated Files or Information",
            "Defense Evasion",
            "low",
        ),
        (
            "cryptacquirecontext",
            "T1486",
            "Data Encrypted for Impact",
            "Impact",
            "medium",
        ),
        (
            "bcryptencrypt",
            "T1486",
            "Data Encrypted for Impact",
            "Impact",
            "high",
        ),
        (
            "findresource",
            "T1027.009",
            "Embedded Payloads",
            "Defense Evasion",
            "medium",
        ),
        (
            "loadresource",
            "T1027.009",
            "Embedded Payloads",
            "Defense Evasion",
            "medium",
        ),
        (
            "openscmanager",
            "T1543.003",
            "Windows Service",
            "Persistence",
            "medium",
        ),
        (
            "setvalueex",
            "T1547.001",
            "Registry Run Keys",
            "Persistence",
            "medium",
        ),
        (
            "regsetvalueex",
            "T1547.001",
            "Registry Run Keys",
            "Persistence",
            "medium",
        ),
        (
            "samr",
            "T1003",
            "OS Credential Dumping",
            "Credential Access",
            "medium",
        ),
        (
            "lsa",
            "T1003.001",
            "LSASS Memory",
            "Credential Access",
            "high",
        ),
        (
            "getsystem",
            "T1134",
            "Access Token Manipulation",
            "Privilege Escalation",
            "high",
        ),
        (
            "adjusttokenprivileges",
            "T1134.002",
            "Create Process with Token",
            "Privilege Escalation",
            "medium",
        ),
        (
            "openprocesstoken",
            "T1134",
            "Access Token Manipulation",
            "Privilege Escalation",
            "medium",
        ),
    ];

    for import in imports {
        let lower = import.symbol.to_ascii_lowercase();
        for (needle, tid, name, tactic, conf) in rules {
            if lower.contains(needle) {
                upsert(
                    grouped,
                    tid,
                    name,
                    tactic,
                    conf,
                    "import",
                    import.symbol.clone(),
                    Some(import.va),
                );
            }
        }
    }
}

fn map_api_flows(
    api_flows: &[ApiFlowRecord],
    grouped: &mut BTreeMap<String, AttackTechniqueRecord>,
) {
    for flow in api_flows {
        let lower_api = flow.normalized_api.to_ascii_lowercase();
        let value_lower = flow.value.to_ascii_lowercase();

        // VirtualAlloc + PAGE_EXECUTE_READWRITE → process injection setup
        if lower_api.contains("virtualalloc") && value_lower.contains("page_execute_readwrite") {
            upsert(
                grouped,
                "T1055.002",
                "Portable Executable Injection",
                "Defense Evasion",
                "high",
                "api_flow",
                format!(
                    "VirtualAlloc with PAGE_EXECUTE_READWRITE at 0x{:016X}",
                    flow.callsite
                ),
                Some(flow.callsite),
            );
        }
        // VirtualProtect → PAGE_EXECUTE_READWRITE on existing memory
        if lower_api.contains("virtualprotect") && value_lower.contains("page_execute_readwrite") {
            upsert(
                grouped,
                "T1055",
                "Process Injection",
                "Defense Evasion",
                "high",
                "api_flow",
                format!("VirtualProtect → RWX at 0x{:016X}", flow.callsite),
                Some(flow.callsite),
            );
        }
        // CreateFile with kernel device — possible driver IO
        if lower_api.contains("createfile") && value_lower.starts_with("\\\\.\\") {
            upsert(
                grouped,
                "T1068",
                "Exploitation for Privilege Escalation",
                "Privilege Escalation",
                "medium",
                "api_flow",
                format!(
                    "CreateFile kernel device target at 0x{:016X}: {}",
                    flow.callsite, flow.value
                ),
                Some(flow.callsite),
            );
        }
    }
}

fn map_behaviors(
    behavior_dossiers: &[BehaviorDossierRecord],
    grouped: &mut BTreeMap<String, AttackTechniqueRecord>,
) {
    for behavior in behavior_dossiers {
        let cap_lower = behavior.capability.to_ascii_lowercase();
        let confidence = if behavior.confidence >= 0.7 {
            "high"
        } else if behavior.confidence >= 0.4 {
            "medium"
        } else {
            "low"
        };
        let pairs: &[(&str, &str, &str, &str)] = &[
            (
                "process_injection",
                "T1055",
                "Process Injection",
                "Defense Evasion",
            ),
            (
                "process_hollow",
                "T1055.012",
                "Process Hollowing",
                "Defense Evasion",
            ),
            (
                "apc_injection",
                "T1055.004",
                "Asynchronous Procedure Call",
                "Defense Evasion",
            ),
            ("keylog", "T1056.001", "Keylogging", "Collection"),
            (
                "registry_persistence",
                "T1547.001",
                "Registry Run Keys",
                "Persistence",
            ),
            (
                "service_install",
                "T1543.003",
                "Windows Service",
                "Persistence",
            ),
            (
                "scheduled_task",
                "T1053.005",
                "Scheduled Task",
                "Persistence",
            ),
            ("anti_debug", "T1622", "Debugger Evasion", "Defense Evasion"),
            ("anti_vm", "T1497.001", "System Checks", "Defense Evasion"),
            (
                "api_hash",
                "T1027.007",
                "Dynamic API Resolution",
                "Defense Evasion",
            ),
            (
                "stack_string",
                "T1027.013",
                "Encrypted/Encoded File",
                "Defense Evasion",
            ),
            (
                "file_encrypt",
                "T1486",
                "Data Encrypted for Impact",
                "Impact",
            ),
            (
                "data_exfil",
                "T1041",
                "Exfiltration Over C2 Channel",
                "Exfiltration",
            ),
            (
                "http_c2",
                "T1071.001",
                "Web Protocols",
                "Command and Control",
            ),
            ("dns_c2", "T1071.004", "DNS", "Command and Control"),
        ];
        for (needle, tid, name, tactic) in pairs {
            if cap_lower.contains(needle) || behavior.title.to_ascii_lowercase().contains(needle) {
                let conf_static: &'static str = match confidence {
                    "high" => "high",
                    "medium" => "medium",
                    _ => "low",
                };
                let va_evidence = behavior.evidence_vas.first().copied();
                upsert(
                    grouped,
                    tid,
                    name,
                    tactic,
                    conf_static,
                    "behavior",
                    format!(
                        "behavior_dossier `{}` (capability={}, conf={:.2})",
                        behavior.title, behavior.capability, behavior.confidence
                    ),
                    va_evidence,
                );
            }
        }
    }
}

fn map_anti_analysis(
    records: &[AntiAnalysisRecord],
    grouped: &mut BTreeMap<String, AttackTechniqueRecord>,
) {
    for r in records {
        let (tid, name, tactic) = match r.category {
            "packer" => ("T1027.002", "Software Packing", "Defense Evasion"),
            "anti_debug" => ("T1622", "Debugger Evasion", "Defense Evasion"),
            "anti_vm" => ("T1497.001", "System Checks", "Defense Evasion"),
            "anti_sandbox" => ("T1497.003", "Time Based Evasion", "Defense Evasion"),
            _ => continue,
        };
        let conf_static: &'static str = match r.confidence {
            "high" => "high",
            "medium" => "medium",
            _ => "low",
        };
        upsert(
            grouped,
            tid,
            name,
            tactic,
            conf_static,
            "anti_analysis",
            format!("{}:{} ({})", r.category, r.name, r.indicator_id),
            r.site_va,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_writeprocessmemory_to_t1055() {
        let imports = vec![ImportRecord {
            dll: "kernel32.dll".to_string(),
            name: "WriteProcessMemory".to_string(),
            symbol: "kernel32.dll!WriteProcessMemory".to_string(),
            va: 0x1000,
            rva: 0x1000,
            hint: None,
            categories: vec![],
        }];
        let techniques = map_techniques(&imports, &[], &[], &[]);
        assert!(
            techniques.iter().any(|t| t.technique_id == "T1055"),
            "expected T1055 for WriteProcessMemory"
        );
    }

    #[test]
    fn maps_anti_analysis_to_attack() {
        let records = vec![AntiAnalysisRecord {
            schema: "anti_analysis/1",
            indicator_id: "packer:upx:0".to_string(),
            category: "packer",
            name: "UPX".to_string(),
            confidence: "high",
            description: "test".to_string(),
            evidence: vec!["UPX0".to_string()],
            site_va: None,
        }];
        let techniques = map_techniques(&[], &[], &[], &records);
        assert!(
            techniques
                .iter()
                .any(|t| t.technique_id == "T1027.002" && t.confidence == "high"),
            "expected T1027.002 for UPX packer"
        );
    }
}
