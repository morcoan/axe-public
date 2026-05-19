//! Per-function Markdown dossier cards optimized for LLM context windows.
//!
//! Each card is a self-contained ~4-8K-token Markdown document with YAML
//! frontmatter, behavioral summary, calls/strings/xrefs cross-reference, and
//! the C-like decompilation inline. LLMs can ingest one card → reason about
//! that function in isolation without sweeping the whole JSONL corpus.

use crate::pe::{
    FunctionDossierRecord, FunctionRecord, RecoveredStringRecord, UncertaintyRecord, XrefRecord,
};
use crate::portable::DecompiledCRecord;
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

const MAX_CARD_BYTES: usize = 32_000; // ~8K tokens at 4 bytes/token average
const MAX_DECOMPILED_LINES: usize = 200;
const MAX_LISTED_CALLS: usize = 25;
const MAX_LISTED_STRINGS: usize = 25;
const MAX_LISTED_XREFS: usize = 25;
const MAX_LISTED_BEHAVIORS: usize = 20;
const MAX_LISTED_UNCERTAINTIES: usize = 10;

pub struct DossierCardSummary {
    pub function: u64,
    pub path: String,
    pub bytes: usize,
}

pub fn write_dossier_cards(
    out_dir: &Path,
    sha256: &str,
    functions: &[FunctionRecord],
    function_dossiers: &[FunctionDossierRecord],
    decompiled: &[DecompiledCRecord],
    xrefs: &[XrefRecord],
    recovered_strings: &[RecoveredStringRecord],
    uncertainties: &[UncertaintyRecord],
) -> std::io::Result<Vec<DossierCardSummary>> {
    let dossier_dir = out_dir.join("dossiers");
    fs::create_dir_all(&dossier_dir)?;
    let sha8 = &sha256.get(..8).unwrap_or("00000000");

    let dossier_by_fn: BTreeMap<u64, &FunctionDossierRecord> = function_dossiers
        .iter()
        .map(|row| (row.function, row))
        .collect();
    let decompiled_by_fn: BTreeMap<u64, &DecompiledCRecord> =
        decompiled.iter().map(|row| (row.function, row)).collect();
    let function_index: BTreeMap<u64, &FunctionRecord> =
        functions.iter().map(|row| (row.start, row)).collect();

    let mut callers_by_target: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for xref in xrefs.iter().filter(|row| row.role == "call") {
        callers_by_target
            .entry(xref.target)
            .or_default()
            .push(xref.from);
    }

    // recovered_strings are keyed by function; per-VA mapping not needed for v1.
    let _ = recovered_strings;

    let summaries: Vec<DossierCardSummary> = function_dossiers
        .par_iter()
        .filter_map(|dossier| {
            let card = render_card(
                sha256,
                sha8,
                dossier,
                function_index.get(&dossier.function).copied(),
                decompiled_by_fn.get(&dossier.function).copied(),
                &callers_by_target,
                uncertainties,
                &dossier_by_fn,
            );
            let truncated = truncate_to_budget(&card, MAX_CARD_BYTES);
            let file_name = format!("function_{}_{:016X}.md", sha8, dossier.function);
            let path = dossier_dir.join(&file_name);
            fs::write(&path, truncated.as_bytes()).ok()?;
            Some(DossierCardSummary {
                function: dossier.function,
                path: format!("dossiers/{}", file_name),
                bytes: truncated.len(),
            })
        })
        .collect();
    Ok(summaries)
}

fn render_card(
    sha256: &str,
    sha8: &str,
    dossier: &FunctionDossierRecord,
    function: Option<&FunctionRecord>,
    decompiled: Option<&DecompiledCRecord>,
    callers_by_target: &BTreeMap<u64, Vec<u64>>,
    uncertainties: &[UncertaintyRecord],
    dossier_by_fn: &BTreeMap<u64, &FunctionDossierRecord>,
) -> String {
    let mut out = String::with_capacity(8192);
    let id = format!("func:{}:{:016X}", sha8, dossier.function);
    out.push_str("---\n");
    out.push_str(&format!("id: {}\n", id));
    out.push_str(&format!("binary: {}\n", sha256));
    out.push_str(&format!("va: 0x{:016X}\n", dossier.function));
    out.push_str(&format!("end_va: 0x{:016X}\n", dossier.end));
    out.push_str(&format!("size: {}\n", dossier.size));
    out.push_str(&format!("source: {}\n", dossier.source));
    out.push_str(&format!("score: {}\n", dossier.score));
    out.push_str(&format!("confidence: {}\n", dossier.confidence));
    out.push_str(&format!("dossier_quality: {}\n", dossier.dossier_quality));
    out.push_str("schema: function_dossier_card/1\n");
    out.push_str("---\n\n");

    out.push_str(&format!("# function_{:016X}\n\n", dossier.function));

    if !dossier.intent_summary.is_empty() {
        out.push_str(&format!("**Intent:** {}\n\n", dossier.intent_summary));
    }
    if !dossier.behavior_summary.is_empty() {
        out.push_str(&format!("**Behavior:** {}\n\n", dossier.behavior_summary));
    }

    if !dossier.imports.is_empty() {
        let calls = dossier
            .imports
            .iter()
            .take(MAX_LISTED_CALLS)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if dossier.imports.len() > MAX_LISTED_CALLS {
            format!(", +{} more", dossier.imports.len() - MAX_LISTED_CALLS)
        } else {
            String::new()
        };
        out.push_str(&format!("**Imports called:** {}{}\n\n", calls, suffix));
    }

    if !dossier.strings.is_empty() {
        let strings = dossier
            .strings
            .iter()
            .take(MAX_LISTED_STRINGS)
            .map(|s| format!("`{}`", s.replace('`', "\\`")))
            .collect::<Vec<_>>()
            .join(", ");
        let suffix = if dossier.strings.len() > MAX_LISTED_STRINGS {
            format!(", +{} more", dossier.strings.len() - MAX_LISTED_STRINGS)
        } else {
            String::new()
        };
        out.push_str(&format!(
            "**Strings referenced:** {}{}\n\n",
            strings, suffix
        ));
    }

    if !dossier.tags.is_empty() {
        out.push_str(&format!("**Tags:** {}\n\n", dossier.tags.join(", ")));
    }
    if !dossier.semantic_tags.is_empty() {
        out.push_str(&format!(
            "**Semantic tags:** {}\n\n",
            dossier.semantic_tags.join(", ")
        ));
    }
    if !dossier.side_effects.is_empty() {
        let effects = dossier
            .side_effects
            .iter()
            .take(MAX_LISTED_BEHAVIORS)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("**Side effects:** {}\n\n", effects));
    }
    if !dossier.inputs.is_empty() {
        out.push_str(&format!("**Inputs:** {}\n\n", dossier.inputs.join(", ")));
    }
    if !dossier.outputs.is_empty() {
        out.push_str(&format!("**Outputs:** {}\n\n", dossier.outputs.join(", ")));
    }

    if !dossier.resolved_api_summaries.is_empty() {
        out.push_str("## Resolved API callsites\n\n");
        for summary in dossier.resolved_api_summaries.iter().take(MAX_LISTED_CALLS) {
            out.push_str(&format!(
                "- 0x{:016X} → {} (chain_depth={}, confidence={})\n",
                summary.callsite, summary.resolved_api, summary.chain_depth, summary.confidence
            ));
        }
        out.push('\n');
    }

    if !dossier.api_flow_summaries.is_empty() {
        out.push_str("## API flows\n\n");
        for flow in dossier.api_flow_summaries.iter().take(MAX_LISTED_CALLS) {
            out.push_str(&format!(
                "- 0x{:016X} `{}` arg `{}` ⇐ `{}` ({})\n",
                flow.callsite, flow.api, flow.argument, flow.value, flow.confidence
            ));
        }
        out.push('\n');
    }

    if !dossier.type_summaries.is_empty() {
        out.push_str("## Recovered types\n\n");
        for ty in dossier.type_summaries.iter().take(MAX_LISTED_BEHAVIORS) {
            out.push_str(&format!(
                "- {} → `{}` ({})\n",
                ty.location, ty.type_tag, ty.confidence
            ));
        }
        out.push('\n');
    }

    if !dossier.claim_evidence.is_empty() {
        out.push_str("## Claim evidence\n\n");
        for claim in dossier.claim_evidence.iter().take(MAX_LISTED_BEHAVIORS) {
            out.push_str(&format!(
                "- **{}** ({}) — evidence: {}\n",
                claim.claim,
                claim.confidence,
                claim
                    .evidence_vas
                    .iter()
                    .take(4)
                    .map(|v| format!("0x{:X}", v))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        out.push('\n');
    }

    out.push_str("## C-like reconstruction\n\n");
    if let Some(c) = decompiled {
        out.push_str("```c\n");
        for line in c.lines.iter().take(MAX_DECOMPILED_LINES) {
            out.push_str(line);
            out.push('\n');
        }
        if c.lines.len() > MAX_DECOMPILED_LINES {
            out.push_str(&format!(
                "/* +{} more lines truncated; see {} for full output */\n",
                c.lines.len() - MAX_DECOMPILED_LINES,
                c.output_path
            ));
        }
        out.push_str("```\n\n");
    } else {
        out.push_str("_No C-like reconstruction available (decompile-c disabled or function not selected)._\n\n");
    }

    out.push_str("## Cross-references\n\n");
    let callers = callers_by_target.get(&dossier.function);
    if let Some(callers) = callers {
        if !callers.is_empty() {
            out.push_str("**Called by:**\n");
            for caller_va in callers.iter().take(MAX_LISTED_XREFS) {
                let resolved = dossier_by_fn
                    .keys()
                    .filter(|fn_va| **fn_va <= *caller_va)
                    .max()
                    .copied();
                match resolved {
                    Some(fn_va) if fn_va != dossier.function => {
                        out.push_str(&format!(
                            "- 0x{:016X} (inside func:{}:{:016X})\n",
                            caller_va, sha8, fn_va
                        ));
                    }
                    _ => out.push_str(&format!("- 0x{:016X}\n", caller_va)),
                }
            }
            if callers.len() > MAX_LISTED_XREFS {
                out.push_str(&format!("_(+{} more)_\n", callers.len() - MAX_LISTED_XREFS));
            }
            out.push('\n');
        }
    }

    if !dossier.calls.is_empty() {
        out.push_str("**Calls:**\n");
        for target in dossier.calls.iter().take(MAX_LISTED_XREFS) {
            out.push_str(&format!("- 0x{:016X}\n", target));
        }
        if dossier.calls.len() > MAX_LISTED_XREFS {
            out.push_str(&format!(
                "_(+{} more)_\n",
                dossier.calls.len() - MAX_LISTED_XREFS
            ));
        }
        out.push('\n');
    }

    let function_uncertainties: Vec<&UncertaintyRecord> = uncertainties
        .iter()
        .filter(|row| {
            row.function == dossier.function
                || (function.is_some()
                    && row
                        .site_va
                        .map(|va| {
                            let f = function.unwrap();
                            va >= f.start && va < f.end
                        })
                        .unwrap_or(false))
        })
        .take(MAX_LISTED_UNCERTAINTIES)
        .collect();
    if !function_uncertainties.is_empty() {
        out.push_str("## Uncertainties\n\n");
        for u in function_uncertainties {
            let site = u
                .site_va
                .map(|va| format!(" at 0x{:016X}", va))
                .unwrap_or_default();
            out.push_str(&format!(
                "- **{}**{}: {} (recommended: {})\n",
                u.reason, site, u.details, u.recommended_action
            ));
        }
        out.push('\n');
    }

    out
}

fn truncate_to_budget(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut cut = max_bytes;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut truncated = String::with_capacity(cut + 80);
    truncated.push_str(&text[..cut]);
    truncated.push_str("\n\n<!-- truncated to ~");
    truncated.push_str(&max_bytes.to_string());
    truncated.push_str(" bytes for LLM context window -->\n");
    truncated
}
