//! Cross-binary diff: compare two analysis output directories and emit a
//! JSONL/Markdown report of what changed. Used to track malware family
//! evolution (sample A vs sample B), to A/B-test analyzer changes, or to
//! confirm that two related samples share most of their code.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct DiffReport {
    pub schema: &'static str,
    pub left: BinaryHeader,
    pub right: BinaryHeader,
    pub imports_added: Vec<String>,
    pub imports_removed: Vec<String>,
    pub imports_shared: usize,
    pub functions_added: Vec<FunctionDelta>,
    pub functions_removed: Vec<FunctionDelta>,
    pub functions_modified: Vec<FunctionDelta>,
    pub functions_unchanged: usize,
    pub capabilities_added: Vec<String>,
    pub capabilities_removed: Vec<String>,
    pub capability_status_changes: Vec<CapabilityStatusChange>,
    pub strings_added: Vec<String>,
    pub strings_removed: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BinaryHeader {
    pub path: String,
    pub sha256: String,
    pub format: String,
    pub size: u64,
    pub functions: usize,
}

#[derive(Debug, Serialize)]
pub struct FunctionDelta {
    pub fingerprint: String,
    pub left_va: Option<u64>,
    pub right_va: Option<u64>,
    pub size: u64,
    pub imports: Vec<String>,
    pub strings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CapabilityStatusChange {
    pub capability: String,
    pub left_status: String,
    pub right_status: String,
}

pub fn run_diff(
    left_dir: &Path,
    right_dir: &Path,
    output_md: Option<&Path>,
) -> std::io::Result<DiffReport> {
    let left = load_side(left_dir)?;
    let right = load_side(right_dir)?;

    let left_imports: BTreeSet<String> = left.imports.iter().cloned().collect();
    let right_imports: BTreeSet<String> = right.imports.iter().cloned().collect();
    let imports_added: Vec<String> = right_imports.difference(&left_imports).cloned().collect();
    let imports_removed: Vec<String> = left_imports.difference(&right_imports).cloned().collect();
    let imports_shared = left_imports.intersection(&right_imports).count();

    let mut left_by_fp: BTreeMap<String, &FunctionFingerprint> = BTreeMap::new();
    let mut left_by_va: BTreeMap<u64, &FunctionFingerprint> = BTreeMap::new();
    for f in &left.functions {
        left_by_fp.entry(f.fingerprint.clone()).or_insert(f);
        left_by_va.insert(f.va, f);
    }
    let mut right_by_fp: BTreeMap<String, &FunctionFingerprint> = BTreeMap::new();
    let mut right_by_va: BTreeMap<u64, &FunctionFingerprint> = BTreeMap::new();
    for f in &right.functions {
        right_by_fp.entry(f.fingerprint.clone()).or_insert(f);
        right_by_va.insert(f.va, f);
    }

    let mut functions_added = Vec::new();
    let mut functions_removed = Vec::new();
    let mut functions_modified = Vec::new();
    let mut functions_unchanged = 0usize;

    for (fp, right_fn) in &right_by_fp {
        if let Some(left_fn) = left_by_fp.get(fp) {
            // same fingerprint → unchanged
            functions_unchanged += 1;
            let _ = left_fn;
        } else {
            // new fingerprint in right
            functions_added.push(FunctionDelta {
                fingerprint: fp.clone(),
                left_va: None,
                right_va: Some(right_fn.va),
                size: right_fn.size,
                imports: right_fn.imports.clone(),
                strings: right_fn.strings.clone(),
            });
        }
    }
    for (fp, left_fn) in &left_by_fp {
        if !right_by_fp.contains_key(fp) {
            // try to find a "modified" match: same VA in right but different fingerprint
            if let Some(right_at_va) = right_by_va.get(&left_fn.va) {
                if right_at_va.fingerprint != *fp {
                    functions_modified.push(FunctionDelta {
                        fingerprint: format!("{} → {}", fp, right_at_va.fingerprint),
                        left_va: Some(left_fn.va),
                        right_va: Some(right_at_va.va),
                        size: right_at_va.size,
                        imports: right_at_va.imports.clone(),
                        strings: right_at_va.strings.clone(),
                    });
                    continue;
                }
            }
            functions_removed.push(FunctionDelta {
                fingerprint: fp.clone(),
                left_va: Some(left_fn.va),
                right_va: None,
                size: left_fn.size,
                imports: left_fn.imports.clone(),
                strings: left_fn.strings.clone(),
            });
        }
    }
    // Dedup modifieds against functions_added (a modified function shows up in both lists otherwise)
    let modified_fingerprints: BTreeSet<&str> = functions_modified
        .iter()
        .map(|f| f.fingerprint.as_str())
        .collect();
    functions_added.retain(|f| !modified_fingerprints.contains(f.fingerprint.as_str()));

    // Capabilities
    let left_caps = capability_map(&left.capabilities);
    let right_caps = capability_map(&right.capabilities);
    let left_cap_names: BTreeSet<&String> = left_caps.keys().collect();
    let right_cap_names: BTreeSet<&String> = right_caps.keys().collect();
    let capabilities_added: Vec<String> = right_cap_names
        .difference(&left_cap_names)
        .map(|s| (*s).clone())
        .collect();
    let capabilities_removed: Vec<String> = left_cap_names
        .difference(&right_cap_names)
        .map(|s| (*s).clone())
        .collect();
    let capability_status_changes: Vec<CapabilityStatusChange> = left_caps
        .iter()
        .filter_map(|(name, left_status)| {
            right_caps.get(name).and_then(|right_status| {
                if left_status != right_status {
                    Some(CapabilityStatusChange {
                        capability: name.clone(),
                        left_status: left_status.clone(),
                        right_status: right_status.clone(),
                    })
                } else {
                    None
                }
            })
        })
        .collect();

    // Strings
    let left_strings: BTreeSet<&String> = left.strings.iter().collect();
    let right_strings: BTreeSet<&String> = right.strings.iter().collect();
    let strings_added: Vec<String> = right_strings
        .difference(&left_strings)
        .map(|s| (*s).clone())
        .take(200)
        .collect();
    let strings_removed: Vec<String> = left_strings
        .difference(&right_strings)
        .map(|s| (*s).clone())
        .take(200)
        .collect();

    let report = DiffReport {
        schema: "binary_diff/1",
        left: BinaryHeader {
            path: left.path.clone(),
            sha256: left.sha256.clone(),
            format: left.format.clone(),
            size: left.size,
            functions: left.functions.len(),
        },
        right: BinaryHeader {
            path: right.path.clone(),
            sha256: right.sha256.clone(),
            format: right.format.clone(),
            size: right.size,
            functions: right.functions.len(),
        },
        imports_added,
        imports_removed,
        imports_shared,
        functions_added,
        functions_removed,
        functions_modified,
        functions_unchanged,
        capabilities_added,
        capabilities_removed,
        capability_status_changes,
        strings_added,
        strings_removed,
    };

    if let Some(md_path) = output_md {
        let md = render_md(&report);
        fs::write(md_path, md.as_bytes())?;
    }
    Ok(report)
}

#[derive(Debug)]
struct SideData {
    path: String,
    sha256: String,
    format: String,
    size: u64,
    imports: Vec<String>,
    functions: Vec<FunctionFingerprint>,
    capabilities: Vec<(String, String)>,
    strings: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FunctionFingerprint {
    fingerprint: String,
    va: u64,
    size: u64,
    imports: Vec<String>,
    strings: Vec<String>,
}

fn load_side(dir: &Path) -> std::io::Result<SideData> {
    // Locate the actual run dir if a parent was passed.
    let run_dir = find_run_dir(dir);
    let analysis_path = run_dir.join("analysis.json");
    let analysis: Value = serde_json::from_slice(&fs::read(&analysis_path)?)?;

    let sha256 = analysis
        .get("sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let format = analysis
        .get("format")
        .and_then(|v| v.as_str())
        .unwrap_or("pe")
        .to_string();
    let path = analysis
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let size = analysis
        .get("file_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let imports: Vec<String> = read_jsonl(&run_dir.join("imports.jsonl"))?
        .filter_map(|row| {
            row.get("symbol")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    let strings: Vec<String> = read_jsonl(&run_dir.join("strings.jsonl"))?
        .filter_map(|row| {
            row.get("text")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    let mut imports_by_va: BTreeMap<u64, String> = BTreeMap::new();
    for row in read_jsonl(&run_dir.join("imports.jsonl"))? {
        if let (Some(va), Some(symbol)) = (
            row.get("va").and_then(|v| v.as_u64()),
            row.get("symbol").and_then(|v| v.as_str()),
        ) {
            imports_by_va.insert(va, symbol.to_string());
        }
    }

    let dossiers: Vec<Value> = read_jsonl(&run_dir.join("function_dossiers.jsonl"))?.collect();
    let functions: Vec<FunctionFingerprint> = dossiers
        .iter()
        .filter_map(|row| {
            let va = row.get("function")?.as_u64()?;
            let size = row.get("size")?.as_u64().unwrap_or(0);
            let imports: Vec<String> = row
                .get("imports")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let strings: Vec<String> = row
                .get("strings")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            // Content-hash fingerprint: imports + strings + size + tags. Avoids
            // VA dependence so functions move within the binary without showing
            // as "modified".
            let mut hasher_input = String::new();
            hasher_input.push_str(&size.to_string());
            hasher_input.push('|');
            let mut sorted_imports = imports.clone();
            sorted_imports.sort();
            hasher_input.push_str(&sorted_imports.join(","));
            hasher_input.push('|');
            let mut sorted_strings = strings.clone();
            sorted_strings.sort();
            hasher_input.push_str(&sorted_strings.join(","));
            let fp = sha256_short(&hasher_input);
            Some(FunctionFingerprint {
                fingerprint: fp,
                va,
                size,
                imports,
                strings,
            })
        })
        .collect();

    let capabilities: Vec<(String, String)> = analysis
        .get("capability_matrix")
        .and_then(|v| v.get("capabilities"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|row| {
                    let name = row.get("capability")?.as_str()?.to_string();
                    let status = row.get("status")?.as_str()?.to_string();
                    Some((name, status))
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(SideData {
        path,
        sha256,
        format,
        size,
        imports,
        functions,
        capabilities,
        strings,
    })
}

fn find_run_dir(dir: &Path) -> PathBuf {
    if dir.join("analysis.json").is_file() {
        return dir.to_path_buf();
    }
    // Look for run_* subdirectory
    if let Ok(read) = fs::read_dir(dir) {
        for entry in read.flatten() {
            let p = entry.path();
            if p.is_dir() && p.join("analysis.json").is_file() {
                return p;
            }
        }
    }
    dir.to_path_buf()
}

fn read_jsonl(path: &Path) -> std::io::Result<impl Iterator<Item = Value>> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Box::new(std::iter::empty()) as Box<dyn Iterator<Item = Value>>);
        }
        Err(e) => return Err(e),
    };
    let reader = BufReader::new(file);
    let iter = reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(&line).ok());
    Ok(Box::new(iter) as Box<dyn Iterator<Item = Value>>)
}

fn capability_map(caps: &[(String, String)]) -> BTreeMap<String, String> {
    caps.iter().cloned().collect()
}

fn sha256_short(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn render_md(report: &DiffReport) -> String {
    let mut out = String::with_capacity(8_000);
    out.push_str("---\n");
    out.push_str("schema: binary_diff_report/1\n");
    out.push_str("---\n\n");
    out.push_str("# Binary diff\n\n");
    out.push_str(&format!(
        "- **Left:** `{}` (sha256 `{}…`, {} bytes, {} functions)\n",
        report.left.path,
        &report.left.sha256.get(..16).unwrap_or(&report.left.sha256),
        report.left.size,
        report.left.functions
    ));
    out.push_str(&format!(
        "- **Right:** `{}` (sha256 `{}…`, {} bytes, {} functions)\n\n",
        report.right.path,
        &report
            .right
            .sha256
            .get(..16)
            .unwrap_or(&report.right.sha256),
        report.right.size,
        report.right.functions
    ));

    out.push_str("## Functions\n\n");
    out.push_str(&format!(
        "- Unchanged: **{}**\n- Added: **{}**\n- Removed: **{}**\n- Modified (same VA, different fingerprint): **{}**\n\n",
        report.functions_unchanged,
        report.functions_added.len(),
        report.functions_removed.len(),
        report.functions_modified.len()
    ));
    if !report.functions_added.is_empty() {
        out.push_str("### Added\n\n");
        for f in report.functions_added.iter().take(30) {
            out.push_str(&format!(
                "- 0x{:016X} ({} bytes) — imports: {}\n",
                f.right_va.unwrap_or(0),
                f.size,
                f.imports
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        out.push('\n');
    }
    if !report.functions_removed.is_empty() {
        out.push_str("### Removed\n\n");
        for f in report.functions_removed.iter().take(30) {
            out.push_str(&format!(
                "- 0x{:016X} ({} bytes) — imports: {}\n",
                f.left_va.unwrap_or(0),
                f.size,
                f.imports
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        out.push('\n');
    }
    if !report.functions_modified.is_empty() {
        out.push_str("### Modified\n\n");
        for f in report.functions_modified.iter().take(30) {
            out.push_str(&format!(
                "- 0x{:016X} (now {} bytes) — {}\n",
                f.right_va.unwrap_or(0),
                f.size,
                f.fingerprint
            ));
        }
        out.push('\n');
    }

    out.push_str("## Imports\n\n");
    out.push_str(&format!(
        "- Shared: **{}**\n- Added: **{}**\n- Removed: **{}**\n\n",
        report.imports_shared,
        report.imports_added.len(),
        report.imports_removed.len()
    ));
    if !report.imports_added.is_empty() {
        out.push_str("**New imports:**\n");
        for s in report.imports_added.iter().take(30) {
            out.push_str(&format!("- `{}`\n", s));
        }
        out.push('\n');
    }
    if !report.imports_removed.is_empty() {
        out.push_str("**Dropped imports:**\n");
        for s in report.imports_removed.iter().take(30) {
            out.push_str(&format!("- `{}`\n", s));
        }
        out.push('\n');
    }

    if !report.capability_status_changes.is_empty()
        || !report.capabilities_added.is_empty()
        || !report.capabilities_removed.is_empty()
    {
        out.push_str("## Capability deltas\n\n");
        for cap in &report.capabilities_added {
            out.push_str(&format!("- ➕ `{}` newly available\n", cap));
        }
        for cap in &report.capabilities_removed {
            out.push_str(&format!("- ➖ `{}` no longer available\n", cap));
        }
        for ch in &report.capability_status_changes {
            out.push_str(&format!(
                "- 🔄 `{}`: `{}` → `{}`\n",
                ch.capability, ch.left_status, ch.right_status
            ));
        }
        out.push('\n');
    }

    if !report.strings_added.is_empty() {
        out.push_str("## New strings\n\n");
        for s in report.strings_added.iter().take(30) {
            out.push_str(&format!("- `{}`\n", s.replace('`', "\\`")));
        }
        out.push('\n');
    }
    if !report.strings_removed.is_empty() {
        out.push_str("## Dropped strings\n\n");
        for s in report.strings_removed.iter().take(30) {
            out.push_str(&format!("- `{}`\n", s.replace('`', "\\`")));
        }
        out.push('\n');
    }

    out
}
