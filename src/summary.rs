//! Binary-level `summary.md` — one self-contained Markdown digest per analysis,
//! sized to drop into an LLM system prompt (≤16K tokens ≈ 64 KB).
//!
//! Pulls hash/format/machine, top capabilities, suspicious indicators,
//! largest functions, network/file/registry/process behaviour, and the
//! decompiled entry point. Output is a single file: `<out_dir>/summary.md`.

use crate::pe::{
    ApiFlowRecord, BehaviorDossierRecord, FunctionDossierRecord, FunctionRecord, ImportRecord,
    ObfuscationHintRecord, RecoveredStringRecord, SectionRecord, StringRecord,
};
use crate::portable::DecompiledCRecord;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const MAX_SUMMARY_BYTES: usize = 60_000; // ~15K tokens

pub fn write_summary(
    out_dir: &Path,
    sha256: &str,
    format_label: &str,
    machine: u16,
    file_size: usize,
    source_path: &str,
    analysis: &Value,
    sections: &[SectionRecord],
    imports: &[ImportRecord],
    strings: &[StringRecord],
    functions: &[FunctionRecord],
    function_dossiers: &[FunctionDossierRecord],
    behavior_dossiers: &[BehaviorDossierRecord],
    api_flows: &[ApiFlowRecord],
    recovered_strings: &[RecoveredStringRecord],
    obfuscation_hints: &[ObfuscationHintRecord],
    decompiled: &[DecompiledCRecord],
    entry_va: u64,
) -> std::io::Result<()> {
    let mut out = String::with_capacity(16_000);
    let sha8 = sha256.get(..8).unwrap_or("00000000");

    // Frontmatter
    out.push_str("---\n");
    out.push_str(&format!("id: bin:{}\n", sha8));
    out.push_str(&format!("sha256: {}\n", sha256));
    out.push_str(&format!("format: {}\n", format_label));
    out.push_str(&format!("machine: 0x{:04X}\n", machine));
    out.push_str(&format!("file_size: {}\n", file_size));
    out.push_str(&format!("entry_va: 0x{:016X}\n", entry_va));
    out.push_str("schema: binary_summary/1\n");
    out.push_str("---\n\n");

    out.push_str(&format!("# Binary summary — {}\n\n", sha256));
    out.push_str(&format!("- **Path:** `{}`\n", source_path));
    out.push_str(&format!(
        "- **Format:** {} (machine 0x{:04X})\n",
        format_label, machine
    ));
    out.push_str(&format!("- **Size:** {} bytes\n", file_size));
    out.push_str(&format!("- **Entry VA:** 0x{:016X}\n", entry_va));
    out.push_str(&format!(
        "- **Functions:** {} discovered\n",
        functions.len()
    ));
    out.push_str(&format!("- **Imports:** {} symbols\n", imports.len()));
    out.push_str(&format!("- **Strings:** {} extracted\n", strings.len()));
    out.push_str(&format!(
        "- **Behavior dossiers:** {} ({})\n\n",
        behavior_dossiers.len(),
        behavior_dossier_confidence_distribution(behavior_dossiers)
    ));

    // Capabilities (from analysis.json's capability_matrix)
    if let Some(caps) = analysis
        .get("capability_matrix")
        .and_then(|v| v.get("capabilities"))
        .and_then(|v| v.as_array())
    {
        out.push_str("## Top capabilities\n\n");
        let executed: Vec<&Value> = caps
            .iter()
            .filter(|c| c.get("status").and_then(|v| v.as_str()) == Some("executed"))
            .collect();
        for cap in executed.iter().take(20) {
            let name = cap
                .get("capability")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let truth = cap
                .get("truthfulness_level")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let claim = cap.get("claim").and_then(|v| v.as_str()).unwrap_or("");
            out.push_str(&format!("- **{}** ({}) — {}\n", name, truth, claim));
        }
        out.push('\n');
    }

    // Suspicious indicators
    out.push_str("## Suspicious indicators\n\n");
    let mut any_indicator = false;
    if let Some(packed) = analysis
        .get("packed_or_obfuscated")
        .and_then(|v| v.as_object())
    {
        if packed.get("packed_like") == Some(&Value::Bool(true)) {
            any_indicator = true;
            out.push_str("- **Likely packed** — ");
            if let Some(reasons) = packed.get("reasons").and_then(|v| v.as_array()) {
                let labels: Vec<String> = reasons
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                out.push_str(&labels.join(", "));
                out.push('\n');
            } else {
                out.push_str("entropy/section signals\n");
            }
        }
        if packed.get("obfuscated_like") == Some(&Value::Bool(true)) {
            any_indicator = true;
            out.push_str("- **Obfuscation hints present**");
            if let Some(hints) = packed.get("obfuscation_hints").and_then(|v| v.as_array()) {
                let labels: Vec<String> = hints
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if !labels.is_empty() {
                    out.push_str(&format!(": {}", labels.join(", ")));
                }
            }
            out.push('\n');
        }
    }
    let rwx_sections: Vec<&SectionRecord> = sections
        .iter()
        .filter(|s| s.executable && s.writable)
        .collect();
    if !rwx_sections.is_empty() {
        any_indicator = true;
        out.push_str("- **RWX sections present**: ");
        out.push_str(
            &rwx_sections
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push('\n');
    }
    let high_entropy: Vec<&SectionRecord> = sections.iter().filter(|s| s.entropy >= 7.2).collect();
    if !high_entropy.is_empty() {
        any_indicator = true;
        out.push_str("- **High-entropy sections** (≥7.2 bits): ");
        out.push_str(
            &high_entropy
                .iter()
                .map(|s| format!("`{}` ({:.2})", s.name, s.entropy))
                .collect::<Vec<_>>()
                .join(", "),
        );
        out.push('\n');
    }
    if !obfuscation_hints.is_empty() {
        any_indicator = true;
        out.push_str(&format!(
            "- **Obfuscation hint records:** {} (kinds: {})\n",
            obfuscation_hints.len(),
            kind_counts(obfuscation_hints.iter().map(|h| h.candidate_kind.as_str()))
        ));
    }
    if !recovered_strings.is_empty() {
        any_indicator = true;
        let stack_strings = recovered_strings
            .iter()
            .filter(|s| s.kind == "stack_string")
            .count();
        if stack_strings > 0 {
            out.push_str(&format!(
                "- **Stack strings recovered:** {}\n",
                stack_strings
            ));
        }
    }
    if !any_indicator {
        out.push_str("_None detected at current depth._\n");
    }
    out.push('\n');

    // Sections table
    out.push_str("## Sections\n\n");
    out.push_str("| Name | VA | Size | Entropy | R | W | X |\n");
    out.push_str("|------|----|------|---------|---|---|---|\n");
    for s in sections.iter().take(20) {
        out.push_str(&format!(
            "| `{}` | 0x{:016X} | {} | {:.2} | {} | {} | {} |\n",
            s.name,
            s.va,
            s.virtual_size,
            s.entropy,
            if s.readable { "✓" } else { " " },
            if s.writable { "✓" } else { " " },
            if s.executable { "✓" } else { " " },
        ));
    }
    out.push('\n');

    // Suspicious imports (categorised)
    if let Some(suspicious) = analysis
        .get("security")
        .and_then(|v| v.get("suspicious_imports"))
        .and_then(|v| v.as_object())
    {
        if !suspicious.is_empty() {
            out.push_str("## Suspicious imports (by category)\n\n");
            for (category, syms) in suspicious.iter().take(12) {
                if let Some(arr) = syms.as_array() {
                    let names: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .take(10)
                        .collect();
                    out.push_str(&format!("- **{}**: {}\n", category, names.join(", ")));
                }
            }
            out.push('\n');
        }
    }

    // Behavior dossiers
    if !behavior_dossiers.is_empty() {
        out.push_str("## Behaviors observed\n\n");
        let mut by_capability: BTreeMap<&str, Vec<&BehaviorDossierRecord>> = BTreeMap::new();
        for b in behavior_dossiers {
            by_capability.entry(&b.capability).or_default().push(b);
        }
        for (cap, list) in by_capability.iter().take(20) {
            let max_conf = list.iter().map(|b| b.confidence).fold(0.0f64, f64::max);
            out.push_str(&format!(
                "- **{}** — {} dossier(s), top confidence {:.2}\n",
                cap,
                list.len(),
                max_conf
            ));
            for dossier in list.iter().take(2) {
                if !dossier.title.is_empty() {
                    out.push_str(&format!(
                        "  - `{}` @ 0x{:016X}\n",
                        dossier.title, dossier.function
                    ));
                }
            }
        }
        out.push('\n');
    }

    // Largest / most-interesting functions
    let mut ranked: Vec<&FunctionDossierRecord> = function_dossiers.iter().collect();
    ranked.sort_by_key(|d| std::cmp::Reverse(d.score));
    if !ranked.is_empty() {
        out.push_str("## Top functions (by dossier score)\n\n");
        out.push_str("| Score | VA | Size | Confidence | Imports | Behaviour |\n");
        out.push_str("|-------|----|------|------------|---------|-----------|\n");
        for d in ranked.iter().take(15) {
            let behavior = d
                .behavior_summary
                .chars()
                .take(60)
                .collect::<String>()
                .replace('|', "\\|");
            out.push_str(&format!(
                "| {} | 0x{:016X} | {} | {} | {} | {} |\n",
                d.score,
                d.function,
                d.size,
                d.confidence,
                d.imports.len(),
                behavior,
            ));
        }
        out.push('\n');
    }

    // API flow snapshot
    if !api_flows.is_empty() {
        out.push_str("## API flow snapshot\n\n");
        for flow in api_flows.iter().take(20) {
            out.push_str(&format!(
                "- 0x{:016X} `{}` arg `{}` ⇐ `{}` ({})\n",
                flow.callsite, flow.api, flow.argument, flow.value, flow.confidence
            ));
        }
        if api_flows.len() > 20 {
            out.push_str(&format!("_(+{} more)_\n", api_flows.len() - 20));
        }
        out.push('\n');
    }

    // Entry-point decompilation inline
    let entry_decompiled = decompiled
        .iter()
        .find(|d| d.function == entry_va)
        .or_else(|| decompiled.first());
    if let Some(d) = entry_decompiled {
        out.push_str(&format!(
            "## Decompilation (function 0x{:016X})\n\n```c\n",
            d.function
        ));
        for line in d.lines.iter().take(150) {
            out.push_str(line);
            out.push('\n');
        }
        if d.lines.len() > 150 {
            out.push_str(&format!(
                "/* +{} more lines; see {} */\n",
                d.lines.len() - 150,
                d.output_path
            ));
        }
        out.push_str("```\n\n");
    }

    out.push_str("## Where to look next\n\n");
    out.push_str("- LLM artifact manifest: `analysis_manifest.json`\n");
    out.push_str("- LLM evidence graph: `graph/nodes.jsonl` + `graph/edges.jsonl`\n");
    out.push_str("- Rust-only debug symbols: `symbols.jsonl`, `debug_identities.jsonl`, `symbol_uncertainty.jsonl`\n");
    out.push_str("- LLM review-pack manifest: `review_packs/llm_manifest.json`\n");
    out.push_str("- Per-function dossier cards: `dossiers/function_<sha8>_<va>.md`\n");
    out.push_str("- Full decompilation: `decompiled_c/function_<va>.c`\n");
    out.push_str("- Capability matrix (machine-readable): `analysis.json` → `capability_matrix`\n");
    out.push_str("- Cross-references: `xrefs.jsonl`\n");
    out.push_str("- Behavior dossiers: `behavior_dossiers.jsonl`\n");
    out.push_str("- API flows: `api_flows.jsonl`\n");

    let truncated = if out.len() > MAX_SUMMARY_BYTES {
        let mut cut = MAX_SUMMARY_BYTES;
        while cut > 0 && !out.is_char_boundary(cut) {
            cut -= 1;
        }
        let mut t = String::with_capacity(cut + 64);
        t.push_str(&out[..cut]);
        t.push_str("\n\n<!-- truncated to ~16K tokens -->\n");
        t
    } else {
        out
    };

    fs::write(out_dir.join("summary.md"), truncated.as_bytes())
}

fn behavior_dossier_confidence_distribution(records: &[BehaviorDossierRecord]) -> String {
    if records.is_empty() {
        return "no behaviors".into();
    }
    let high = records.iter().filter(|r| r.confidence >= 0.7).count();
    let med = records
        .iter()
        .filter(|r| r.confidence >= 0.4 && r.confidence < 0.7)
        .count();
    let low = records.iter().filter(|r| r.confidence < 0.4).count();
    format!("{} high / {} med / {} low confidence", high, med, low)
}

fn kind_counts<'a, I>(iter: I) -> String
where
    I: Iterator<Item = &'a str>,
{
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for kind in iter {
        *counts.entry(kind).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(k, v)| format!("{}×{}", k, v))
        .collect::<Vec<_>>()
        .join(", ")
}
