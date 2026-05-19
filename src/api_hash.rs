use crate::pe::{ApiHashResolutionRecord, ImportRecord, ObfuscationHintRecord};
use std::collections::BTreeSet;

pub fn ror13_hash_name(name: &str) -> u32 {
    name.bytes().fold(0_u32, |hash, byte| {
        hash.rotate_right(13).wrapping_add(byte as u32)
    })
}

pub fn djb2_hash_name(name: &str) -> u32 {
    name.bytes().fold(5381_u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(byte as u32)
    })
}

pub fn fnv1a_hash_name(name: &str) -> u32 {
    name.bytes().fold(0x811C9DC5_u32, |hash, byte| {
        (hash ^ byte as u32).wrapping_mul(0x0100_0193)
    })
}

pub fn crc32_hash_name(name: &str) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for byte in name.bytes() {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

pub fn resolve_api_hashes(
    hints: &[ObfuscationHintRecord],
    api_symbols: &[String],
) -> Vec<ApiHashResolutionRecord> {
    let seeds = api_seed_symbols(api_symbols);
    let mut rows = Vec::new();
    for hint in hints {
        if hint.candidate_kind != "api_hash_candidate" || !has_import_resolution_context(hint) {
            continue;
        }
        for hash in parse_hashes(&hint.description) {
            if let Some((algorithm, resolved_api)) = resolve_hash(hash, &seeds) {
                rows.push(ApiHashResolutionRecord {
                    resolution_id: format!(
                        "api-hash:{:016X}:{algorithm}:{hash:08X}:{}",
                        hint.function,
                        rows.len()
                    ),
                    function: hint.function,
                    site_va: hint.evidence.first().copied(),
                    algorithm,
                    hash_value: format!("0x{hash:08X}"),
                    resolved_api,
                    confidence: "medium".to_string(),
                    evidence: hint.evidence.clone(),
                });
            }
        }
    }
    rows
}

pub fn import_symbols(imports: &[ImportRecord]) -> Vec<String> {
    imports.iter().map(|row| row.symbol.clone()).collect()
}

fn resolve_hash(hash: u32, seeds: &[String]) -> Option<(String, String)> {
    for symbol in seeds {
        let name = api_name(symbol);
        let algorithms = [
            ("ror13", ror13_hash_name(name)),
            ("djb2", djb2_hash_name(name)),
            ("fnv1a", fnv1a_hash_name(name)),
            ("crc32", crc32_hash_name(name)),
        ];
        for (algorithm, candidate) in algorithms {
            if candidate == hash {
                return Some((algorithm.to_string(), symbol.clone()));
            }
        }
    }
    None
}

fn parse_hashes(description: &str) -> Vec<u32> {
    description
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == 'x' || ch == 'X'))
        .filter_map(|part| {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                return None;
            }
            u32::from_str_radix(
                trimmed.trim_start_matches("0x").trim_start_matches("0X"),
                16,
            )
            .ok()
        })
        .collect()
}

fn has_import_resolution_context(hint: &ObfuscationHintRecord) -> bool {
    let lower = hint.uncertainty_reason.to_ascii_lowercase();
    lower.contains("import-resolution")
        || lower.contains("getprocaddress")
        || lower.contains("peb")
        || lower.contains("ldr")
}

fn api_seed_symbols(api_symbols: &[String]) -> Vec<String> {
    let mut rows: BTreeSet<String> = api_symbols.iter().cloned().collect();
    let referenced_modules: BTreeSet<String> = api_symbols
        .iter()
        .filter_map(|symbol| symbol.split_once('!').map(|(dll, _)| normalize_dll(dll)))
        .collect();
    for symbol in [
        "KERNEL32.dll!CreateFileW",
        "KERNEL32.dll!CreateFileA",
        "KERNEL32.dll!ReadFile",
        "KERNEL32.dll!WriteFile",
        "KERNEL32.dll!VirtualAlloc",
        "KERNEL32.dll!VirtualAllocEx",
        "KERNEL32.dll!VirtualProtect",
        "KERNEL32.dll!CreateToolhelp32Snapshot",
        "KERNEL32.dll!CreateFileMappingW",
        "KERNEL32.dll!MapViewOfFile",
        "KERNEL32.dll!WriteProcessMemory",
        "KERNEL32.dll!ReadProcessMemory",
        "KERNEL32.dll!CreateRemoteThread",
        "KERNEL32.dll!LoadLibraryA",
        "KERNEL32.dll!LoadLibraryW",
        "KERNEL32.dll!GetProcAddress",
        "NTDLL.dll!LdrGetProcedureAddress",
        "NTDLL.dll!NtQueryInformationProcess",
        "NTDLL.dll!NtProtectVirtualMemory",
        "NTDLL.dll!NtAllocateVirtualMemory",
        "NTDLL.dll!NtWriteVirtualMemory",
        "NTDLL.dll!RtlCreateUserThread",
        "NTDLL.dll!RtlDecompressBuffer",
        "ADVAPI32.dll!RegOpenKeyExW",
        "ADVAPI32.dll!RegSetValueExW",
        "ADVAPI32.dll!CreateServiceW",
        "ADVAPI32.dll!StartServiceW",
        "WS2_32.dll!connect",
        "WS2_32.dll!WSAConnect",
        "WS2_32.dll!send",
        "WS2_32.dll!recv",
        "WINHTTP.dll!WinHttpSendRequest",
        "WININET.dll!InternetReadFile",
        "WININET.dll!HttpSendRequestW",
        "BCRYPT.dll!BCryptEncrypt",
        "BCRYPT.dll!BCryptDecrypt",
        "ADVAPI32.dll!CryptHashData",
        "CRYPT32.dll!CryptDecodeObjectEx",
        "OLE32.dll!CoCreateInstance",
    ] {
        if symbol
            .split_once('!')
            .map(|(dll, _)| referenced_modules.contains(&normalize_dll(dll)))
            .unwrap_or(false)
        {
            rows.insert(symbol.to_string());
        }
    }
    rows.into_iter().collect()
}

fn api_name(symbol: &str) -> &str {
    symbol
        .rsplit_once('!')
        .map(|(_, name)| name)
        .unwrap_or(symbol)
}

fn normalize_dll(dll: &str) -> String {
    dll.trim_end_matches(".dll")
        .trim_end_matches(".DLL")
        .to_ascii_lowercase()
}
