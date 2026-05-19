//! Pick an unpack strategy from existing packer-detection records.
//!
//! axe-core already produces `AntiAnalysisRecord` rows for known
//! packer families via `src/anti_analysis.rs:36-190` (UPX, ASPack,
//! MPRESS, PECompact, Themida, VMProtect, Enigma, ASProtect,
//! PELock, Petite, yoda's Crypter, NsPack, plus a generic
//! sparse-imports + high-entropy heuristic). Aurora **reads**
//! those records; it never re-implements packer detection. This
//! module is the dispatch table that maps a detected family to
//! the strategy `session.rs` (Step 54) will run.
//!
//! # Strategies
//!
//! - `Generic` — the default. Works for any packer whose
//!   unpacking stub writes payload bytes to a new memory region
//!   and jumps to it. UPX, MPRESS, PECompact, ASPack, NsPack
//!   reliably fall here.
//! - `LegacyVmProtect` / `LegacyThemida` — opt-in via
//!   `--unpack-include-devirt` AND the `unpack-emulation`
//!   feature. Marked `best_effort` in the snapshot. Modern
//!   variants (≥3.x) are explicit non-goals.
//! - `Unknown` — no packer-category record found. Aurora will
//!   still run `Generic`; the LLM consumer is informed via the
//!   strategy field that the binary did not match any known
//!   signature.

use crate::anti_analysis::AntiAnalysisRecord;

/// Outcome of dispatch. Carries the chosen strategy plus the
/// concrete record that drove the decision (or `None` if no
/// packer record was found and we defaulted to `Generic`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchOutcome {
    pub strategy: UnpackStrategy,
    /// Name of the matched family ("UPX", "Themida", etc.) or
    /// `"none"` if dispatch defaulted from an empty input. The
    /// snapshot's `packer_detection.type` field is populated
    /// from this.
    pub matched_family: String,
    /// `"high"` / `"medium"` / `"low"` mirroring the confidence
    /// in the underlying `AntiAnalysisRecord`. `"none"` when no
    /// packer record was found.
    pub matched_confidence: String,
    /// Free-form notes the strategy generator wants surfaced in
    /// the snapshot uncertainties (e.g. "Themida detected; only
    /// legacy variants (≤2.x) supported, best_effort tier").
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnpackStrategy {
    /// Debugger + guard pages + entropy + OEP. The workhorse —
    /// reliable for ~80% of mass-market packers (UPX, MPRESS,
    /// PECompact, ASPack, NsPack, simple custom stubs).
    Generic,
    /// Legacy VMProtect (≤2.x): `Generic` plus invocation of
    /// `devirt/vmprotect.rs` (Step 49) for handler-stepping.
    /// Requires `unpack-emulation` feature; produces
    /// `best_effort`-tier output.
    LegacyVmProtect,
    /// Legacy Themida (≤2.x): same shape as `LegacyVmProtect`
    /// with a different handler-pattern table.
    LegacyThemida,
    /// Themida 3.x (partial recovery, capped at `best_effort` per
    /// Phase B5's 0.40 confidence-score rule). Selected when the
    /// detected family is Themida AND `check_themida_3x_markers`
    /// returns `Themida3xPartial`. Modern Themida defeats the
    /// generic dispatcher-walking technique; the strategy is opt-
    /// in via the `--devirt-allow-best-effort-3x` CLI flag (B5).
    Themida3xPartial,
}

/// Pick a strategy from the existing anti-analysis output.
///
/// Records with `category == "packer"` are considered. If
/// multiple packer records fire (e.g. UPX magic + section name),
/// the strongest-confidence record wins; ties break in the order
/// the records appear (which mirrors `src/anti_analysis.rs`'s
/// signature-table order).
///
/// This is the context-free entry point — it can't tell legacy
/// Themida from Themida 3.x. Use [`dispatch_with_context`] (B4.1) for
/// modern-protector discrimination via the marker analysis.
pub fn dispatch(records: &[AntiAnalysisRecord]) -> DispatchOutcome {
    let packer_records: Vec<&AntiAnalysisRecord> =
        records.iter().filter(|r| r.category == "packer").collect();

    if packer_records.is_empty() {
        return DispatchOutcome {
            strategy: UnpackStrategy::Generic,
            matched_family: "none".to_string(),
            matched_confidence: "none".to_string(),
            notes: vec![
                "no packer signature matched; falling back to Generic strategy. \
                 OEP detection may produce zero candidates if the binary is \
                 not actually packed."
                    .to_string(),
            ],
        };
    }

    let best = packer_records
        .iter()
        .min_by_key(|r| confidence_rank(r.confidence))
        .copied()
        .expect("non-empty after empty check");
    strategy_for_family(&best.name, best.confidence)
}

/// Context-aware dispatch (B4.1). For Themida-family matches, runs the
/// 3.x marker analysis and routes to `Themida3xPartial` when ≥3 of 4
/// markers fire. Falls through to `dispatch` for everything else.
///
/// `text_window` is the first 4 KiB of `.text` (or shorter); `entry_stub`
/// is the first 256 bytes of code at the entry point (or shorter);
/// `sections` describes every section in the image. Callers map from
/// their PE/ELF/Mach-O section table to `SectionMarker` once.
pub fn dispatch_with_context(
    records: &[AntiAnalysisRecord],
    text_window: &[u8],
    entry_stub: &[u8],
    sections: &[SectionMarker],
) -> DispatchOutcome {
    let base = dispatch(records);
    // Only Themida-family decisions can upgrade to Themida3xPartial.
    if !matches!(base.strategy, UnpackStrategy::LegacyThemida) {
        return base;
    }
    let report = check_themida_3x_markers(text_window, entry_stub, sections);
    match report.decision {
        ThemidaDecision::LegacyThemida => base,
        ThemidaDecision::Themida3xPartial => DispatchOutcome {
            strategy: UnpackStrategy::Themida3xPartial,
            matched_family: base.matched_family,
            matched_confidence: base.matched_confidence,
            notes: vec![format!(
                "Themida 3.x markers fired ({} of 4: large_stub={}, \
                 no_pushfq_popfq={}, multi_themida_or_wx_high_entropy={}, \
                 rdtsc_plus_cpuid_preamble={}). Output is capped at \
                 best_effort tier (Phase B5 0.40 cap). Trace emission \
                 requires --devirt-allow-best-effort-3x.",
                report.triggered_count(),
                report.large_stub,
                report.no_pushfq_popfq_window,
                report.multi_themida_or_wx_high_entropy,
                report.rdtsc_plus_cpuid_preamble,
            )],
        },
    }
}

fn strategy_for_family(name: &str, confidence: &str) -> DispatchOutcome {
    let lower = name.to_ascii_lowercase();
    if lower.contains("vmprotect") {
        return DispatchOutcome {
            strategy: UnpackStrategy::LegacyVmProtect,
            matched_family: name.to_string(),
            matched_confidence: confidence.to_string(),
            notes: vec![
                "VMProtect detected. Aurora supports LEGACY VMProtect (≤2.x) \
                 in best_effort tier via --unpack-include-devirt. Modern \
                 VMProtect (3.x+) is an explicit non-goal."
                    .to_string(),
            ],
        };
    }
    if lower.contains("themida") {
        return DispatchOutcome {
            strategy: UnpackStrategy::LegacyThemida,
            matched_family: name.to_string(),
            matched_confidence: confidence.to_string(),
            notes: vec![
                "Themida detected. Aurora supports LEGACY Themida (≤2.x) in \
                 best_effort tier via --unpack-include-devirt. Modern \
                 Themida (3.x+) is an explicit non-goal."
                    .to_string(),
            ],
        };
    }
    // Everything else routes to Generic. A note records the
    // detected family so the snapshot's uncertainties field
    // names the protector class even when the strategy is
    // uniform.
    DispatchOutcome {
        strategy: UnpackStrategy::Generic,
        matched_family: name.to_string(),
        matched_confidence: confidence.to_string(),
        notes: Vec::new(),
    }
}

/// Lower rank = higher confidence. Used by `min_by_key` to pick
/// the strongest packer signal.
fn confidence_rank(confidence: &str) -> u8 {
    match confidence {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

// =====================================================================
// B4 — Themida 3.x detection markers
// =====================================================================
//
// Heuristic byte/section-pattern checks (no execution required) that
// distinguish modern Themida 3.x from legacy Themida ≤2.x. Returns a
// `ThemidaDecision` so the caller can route to the Themida3xPartial
// strategy with `best_effort`-capped confidence. Decision rule:
// ≥3 of the 4 markers fire → 3.x; else stay LegacyThemida.

/// Minimal section descriptor used by the markers. The caller maps from
/// whatever section-table type is already in scope (PE / ELF / Mach-O).
#[derive(Clone, Debug)]
pub struct SectionMarker {
    pub name: String,
    pub size: u64,
    pub entropy: f64,
    /// Permission triple like "RWX" / "RW-" / "R-X". Same shape as
    /// `RegionDescriptor.permissions`.
    pub permissions: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThemidaDecision {
    LegacyThemida,
    Themida3xPartial,
}

/// Result of marker analysis. Carries the boolean state of each marker so
/// callers (and tests) can introspect *why* the decision went the way it
/// did — important for the honest-tier docs in `docs/unpack-capabilities.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThemidaMarkerReport {
    pub decision: ThemidaDecision,
    pub large_stub: bool,
    pub no_pushfq_popfq_window: bool,
    pub multi_themida_or_wx_high_entropy: bool,
    pub rdtsc_plus_cpuid_preamble: bool,
}

impl ThemidaMarkerReport {
    pub fn triggered_count(&self) -> u32 {
        self.large_stub as u32
            + self.no_pushfq_popfq_window as u32
            + self.multi_themida_or_wx_high_entropy as u32
            + self.rdtsc_plus_cpuid_preamble as u32
    }
}

/// Run the four heuristic markers and decide between Legacy and 3.x.
/// Inputs:
///   * `text_window`: first 4 KiB (or less) of the binary's `.text` section.
///     Used by marker 2 (absence of `9C ... 9D`).
///   * `entry_stub_window`: first 256 bytes (or less) of code at the entry
///     point. Used by marker 4 (`0F 31` rdtsc + `0F A2` cpuid combo).
///   * `sections`: all sections (used by markers 1 and 3).
///
/// Decision: ≥3 markers → `Themida3xPartial`; else `LegacyThemida`.
pub fn check_themida_3x_markers(
    text_window: &[u8],
    entry_stub_window: &[u8],
    sections: &[SectionMarker],
) -> ThemidaMarkerReport {
    let m1 = marker_large_themida_stub(sections);
    let m2 = marker_no_pushfq_popfq_window(text_window);
    let m3 = marker_multi_themida_or_wx_high_entropy(sections);
    let m4 = marker_rdtsc_plus_cpuid(entry_stub_window);
    let triggered = m1 as u32 + m2 as u32 + m3 as u32 + m4 as u32;
    let decision = if triggered >= 3 {
        ThemidaDecision::Themida3xPartial
    } else {
        ThemidaDecision::LegacyThemida
    };
    ThemidaMarkerReport {
        decision,
        large_stub: m1,
        no_pushfq_popfq_window: m2,
        multi_themida_or_wx_high_entropy: m3,
        rdtsc_plus_cpuid_preamble: m4,
    }
}

/// Marker 1: any section named `.themida*` (or `.boot`, used by some
/// older Themida 3.x builds) whose size is ≥ 64 KiB. Legacy stubs are
/// typically < 32 KiB.
fn marker_large_themida_stub(sections: &[SectionMarker]) -> bool {
    sections.iter().any(|s| {
        let n = s.name.to_ascii_lowercase();
        (n.starts_with(".themida") || n == ".boot") && s.size >= 64 * 1024
    })
}

/// Marker 2: no literal `9C ... 9D` (pushfq → … → popfq) window in the
/// first 4 KiB of `.text`. Legacy Themida 2.x had this pair as a literal
/// signature; 3.x mutated it away. Returns `true` when the pair is
/// ABSENT (= 3.x indicator).
fn marker_no_pushfq_popfq_window(text_window: &[u8]) -> bool {
    let window = &text_window[..text_window.len().min(4096)];
    !has_pushfq_popfq_window(window, 64)
}

fn has_pushfq_popfq_window(bytes: &[u8], max_dist: usize) -> bool {
    for i in 0..bytes.len() {
        if bytes[i] == 0x9C {
            let end = bytes.len().min(i + max_dist + 1);
            for j in (i + 1)..end {
                if bytes[j] == 0x9D {
                    return true;
                }
            }
        }
    }
    false
}

/// Marker 3: ≥ 2 sections matching either (a) name starts with
/// `.themida`, or (b) `W` + `X` permissions AND entropy > 7.5. Modern
/// Themida 3.x typically ships multiple obfuscated sections.
fn marker_multi_themida_or_wx_high_entropy(sections: &[SectionMarker]) -> bool {
    let count = sections
        .iter()
        .filter(|s| {
            let n = s.name.to_ascii_lowercase();
            n.starts_with(".themida")
                || (s.permissions.contains('W') && s.permissions.contains('X') && s.entropy > 7.5)
        })
        .count();
    count >= 2
}

/// Marker 4: `0F 31` (rdtsc) + `0F A2` (cpuid) both appear in the first
/// 256 bytes of the entry stub. Themida 3.x's stock anti-emulation guard.
fn marker_rdtsc_plus_cpuid(stub_window: &[u8]) -> bool {
    let window = &stub_window[..stub_window.len().min(256)];
    let has_rdtsc = window.windows(2).any(|w| w == [0x0F, 0x31]);
    let has_cpuid = window.windows(2).any(|w| w == [0x0F, 0xA2]);
    has_rdtsc && has_cpuid
}

#[cfg(test)]
mod themida_3x_tests {
    use super::*;

    fn section(name: &str, size: u64, entropy: f64, perms: &str) -> SectionMarker {
        SectionMarker {
            name: name.to_string(),
            size,
            entropy,
            permissions: perms.to_string(),
        }
    }

    #[test]
    fn legacy_themida_2x_baseline_triggers_zero_markers() {
        // Small .themida section, has pushfq/popfq pair, no anti-emu preamble.
        let sections = vec![section(".themida", 16 * 1024, 6.5, "R-X")];
        let mut text = vec![0u8; 4096];
        text[0x100] = 0x9C; // pushfq
        text[0x110] = 0x9D; // popfq
        let stub = vec![0u8; 256];
        let report = check_themida_3x_markers(&text, &stub, &sections);
        assert_eq!(report.decision, ThemidaDecision::LegacyThemida);
        assert_eq!(
            report.triggered_count(),
            0,
            "expected 0 markers, got {:?}",
            report
        );
    }

    #[test]
    fn three_of_four_markers_routes_to_3x() {
        // Marker 1: large .themida stub (>= 64 KiB).
        // Marker 3: 2 themida-named sections with WX + high entropy.
        // Marker 4: rdtsc + cpuid in entry stub.
        // Marker 2 NOT triggered: pushfq/popfq window present.
        let sections = vec![
            section(".themida", 80 * 1024, 7.8, "RWX"),
            section(".themida2", 10 * 1024, 7.9, "RWX"),
        ];
        let mut text = vec![0u8; 4096];
        text[0x100] = 0x9C;
        text[0x110] = 0x9D;
        let stub = vec![0x0F, 0x31, 0x90, 0x0F, 0xA2, 0xC3];
        let report = check_themida_3x_markers(&text, &stub, &sections);
        assert_eq!(report.decision, ThemidaDecision::Themida3xPartial);
        assert_eq!(report.triggered_count(), 3);
        assert!(report.large_stub);
        assert!(report.multi_themida_or_wx_high_entropy);
        assert!(report.rdtsc_plus_cpuid_preamble);
        assert!(!report.no_pushfq_popfq_window);
    }

    #[test]
    fn two_of_four_markers_stays_legacy() {
        // Only markers 1 and 4 fire.
        let sections = vec![section(".themida", 80 * 1024, 6.0, "R-X")];
        let mut text = vec![0u8; 4096];
        text[0x100] = 0x9C;
        text[0x110] = 0x9D;
        let stub = vec![0x0F, 0x31, 0x0F, 0xA2];
        let report = check_themida_3x_markers(&text, &stub, &sections);
        assert_eq!(report.decision, ThemidaDecision::LegacyThemida);
        assert_eq!(report.triggered_count(), 2);
    }

    #[test]
    fn pushfq_window_marker_fires_when_pair_absent() {
        // Empty text → no 9C/9D → marker 2 fires.
        let sections = vec![];
        let text = vec![0u8; 4096];
        let stub = vec![];
        let report = check_themida_3x_markers(&text, &stub, &sections);
        assert!(report.no_pushfq_popfq_window);
    }

    #[test]
    fn pushfq_window_marker_does_not_fire_with_pair_in_range() {
        // 9C and 9D within 64 bytes → marker 2 does NOT fire (= legacy
        // indicator).
        let sections = vec![];
        let mut text = vec![0u8; 4096];
        text[100] = 0x9C;
        text[150] = 0x9D;
        let stub = vec![];
        let report = check_themida_3x_markers(&text, &stub, &sections);
        assert!(!report.no_pushfq_popfq_window);
    }

    #[test]
    fn rdtsc_only_or_cpuid_only_does_not_fire_marker_4() {
        let sections = vec![];
        let text = vec![0u8; 4096];
        let stub_rdtsc_only = vec![0x0F, 0x31];
        let stub_cpuid_only = vec![0x0F, 0xA2];
        let stub_both = vec![0x0F, 0x31, 0xCC, 0x0F, 0xA2];
        assert!(
            !check_themida_3x_markers(&text, &stub_rdtsc_only, &sections).rdtsc_plus_cpuid_preamble
        );
        assert!(
            !check_themida_3x_markers(&text, &stub_cpuid_only, &sections).rdtsc_plus_cpuid_preamble
        );
        assert!(check_themida_3x_markers(&text, &stub_both, &sections).rdtsc_plus_cpuid_preamble);
    }

    #[test]
    fn boot_section_with_large_size_triggers_marker_1() {
        let sections = vec![section(".boot", 100 * 1024, 6.0, "RWX")];
        let mut text = vec![0u8; 4096];
        text[0] = 0x9C;
        text[10] = 0x9D;
        let stub = vec![];
        let report = check_themida_3x_markers(&text, &stub, &sections);
        assert!(report.large_stub);
    }

    #[test]
    fn small_themida_section_does_not_trigger_marker_1() {
        let sections = vec![section(".themida", 16 * 1024, 7.8, "RWX")];
        let mut text = vec![0u8; 4096];
        text[0] = 0x9C;
        text[10] = 0x9D;
        let stub = vec![];
        let report = check_themida_3x_markers(&text, &stub, &sections);
        assert!(!report.large_stub);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkr(name: &str, confidence: &'static str) -> AntiAnalysisRecord {
        AntiAnalysisRecord {
            schema: "anti_analysis/1",
            indicator_id: format!("packer:{}:0", name.to_ascii_lowercase()),
            category: "packer",
            name: name.to_string(),
            confidence,
            description: format!("test fixture for {}", name),
            evidence: Vec::new(),
            site_va: None,
        }
    }

    fn non_packer(name: &str) -> AntiAnalysisRecord {
        AntiAnalysisRecord {
            schema: "anti_analysis/1",
            indicator_id: format!("anti_debug:{}:0", name),
            category: "anti_debug",
            name: name.to_string(),
            confidence: "high",
            description: format!("test fixture for {}", name),
            evidence: Vec::new(),
            site_va: None,
        }
    }

    #[test]
    fn empty_input_falls_back_to_generic_with_note() {
        let outcome = dispatch(&[]);
        assert_eq!(outcome.strategy, UnpackStrategy::Generic);
        assert_eq!(outcome.matched_family, "none");
        assert_eq!(outcome.matched_confidence, "none");
        assert!(!outcome.notes.is_empty());
    }

    #[test]
    fn upx_routes_to_generic() {
        let outcome = dispatch(&[pkr("UPX", "high")]);
        assert_eq!(outcome.strategy, UnpackStrategy::Generic);
        assert_eq!(outcome.matched_family, "UPX");
        assert_eq!(outcome.matched_confidence, "high");
    }

    #[test]
    fn mpress_aspack_pecompact_route_to_generic() {
        for name in &["MPRESS", "ASPack", "PECompact", "NsPack", "Petite"] {
            let outcome = dispatch(&[pkr(name, "high")]);
            assert_eq!(
                outcome.strategy,
                UnpackStrategy::Generic,
                "{} should map to Generic",
                name
            );
        }
    }

    #[test]
    fn vmprotect_routes_to_legacy_vmprotect_with_modern_non_goal_note() {
        let outcome = dispatch(&[pkr("VMProtect", "high")]);
        assert_eq!(outcome.strategy, UnpackStrategy::LegacyVmProtect);
        assert_eq!(outcome.matched_family, "VMProtect");
        assert!(outcome.notes.iter().any(|n| n.contains("non-goal")));
    }

    #[test]
    fn themida_routes_to_legacy_themida_with_modern_non_goal_note() {
        let outcome = dispatch(&[pkr("Themida", "medium")]);
        assert_eq!(outcome.strategy, UnpackStrategy::LegacyThemida);
        assert_eq!(outcome.matched_family, "Themida");
        assert!(outcome.notes.iter().any(|n| n.contains("non-goal")));
    }

    #[test]
    fn non_packer_records_are_ignored() {
        let outcome = dispatch(&[non_packer("IsDebuggerPresent")]);
        assert_eq!(outcome.strategy, UnpackStrategy::Generic);
        assert_eq!(outcome.matched_family, "none");
    }

    #[test]
    fn highest_confidence_record_wins_when_multiple_packers_fire() {
        let outcome = dispatch(&[pkr("generic_packed", "medium"), pkr("UPX", "high")]);
        assert_eq!(outcome.matched_family, "UPX");
        assert_eq!(outcome.matched_confidence, "high");
    }

    #[test]
    fn case_insensitive_family_match() {
        // anti_analysis emits "VMProtect" verbatim, but defensively
        // exercise variants so a future change in the producer
        // cannot silently break dispatch.
        let outcome = dispatch(&[pkr("vmprotect", "high")]);
        assert_eq!(outcome.strategy, UnpackStrategy::LegacyVmProtect);
    }

    // ----- B4.1 dispatch_with_context tests -----

    fn section_marker(name: &str, size: u64, entropy: f64, perms: &str) -> SectionMarker {
        SectionMarker {
            name: name.to_string(),
            size,
            entropy,
            permissions: perms.to_string(),
        }
    }

    /// Themida record + 3.x-shaped context → Themida3xPartial.
    #[test]
    fn dispatch_with_context_routes_themida_3x() {
        let records = vec![pkr("Themida", "high")];
        let sections = vec![
            section_marker(".themida", 96 * 1024, 7.9, "RWX"),
            section_marker(".themida2", 32 * 1024, 7.8, "RWX"),
        ];
        let mut text = vec![0u8; 4096];
        text[0x100] = 0x9C;
        text[0x110] = 0x9D; // marker 2 NOT triggered
        let stub = vec![0x0F, 0x31, 0x90, 0x0F, 0xA2];

        let outcome = dispatch_with_context(&records, &text, &stub, &sections);
        assert_eq!(outcome.strategy, UnpackStrategy::Themida3xPartial);
        assert!(!outcome.notes.is_empty());
        let note = &outcome.notes[0];
        assert!(note.contains("3 of 4"), "note should report marker count");
        assert!(note.contains("best_effort"), "note should mention tier cap");
        assert!(
            note.contains("devirt-allow-best-effort-3x"),
            "note should call out the opt-in flag"
        );
    }

    /// Themida record + 2.x-shaped context → LegacyThemida (unchanged from
    /// the context-free dispatch).
    #[test]
    fn dispatch_with_context_keeps_legacy_themida_when_markers_quiet() {
        let records = vec![pkr("Themida", "high")];
        let sections = vec![section_marker(".themida", 16 * 1024, 6.5, "R-X")];
        let mut text = vec![0u8; 4096];
        text[0x100] = 0x9C;
        text[0x110] = 0x9D;
        let stub = vec![0x55, 0x48, 0x89, 0xE5];

        let outcome = dispatch_with_context(&records, &text, &stub, &sections);
        assert_eq!(outcome.strategy, UnpackStrategy::LegacyThemida);
    }

    /// Non-Themida records pass through unchanged — context-aware dispatch
    /// must not accidentally upgrade UPX / VMProtect / Generic strategies.
    #[test]
    fn dispatch_with_context_does_not_upgrade_non_themida() {
        let records = vec![pkr("UPX", "high")];
        let sections = vec![section_marker(".themida", 96 * 1024, 7.9, "RWX")];
        let mut text = vec![0u8; 4096];
        let stub = vec![0x0F, 0x31, 0x90, 0x0F, 0xA2];

        let outcome = dispatch_with_context(&records, &text, &stub, &sections);
        // Even though the Themida 3.x markers fire, UPX detection wins.
        assert_eq!(outcome.strategy, UnpackStrategy::Generic);
        assert_eq!(outcome.matched_family, "UPX");
    }

    /// VMProtect doesn't get a 3.x upgrade today (out of B4 scope). Future
    /// work could mirror Themida — for now confirm dispatch_with_context
    /// passes VMProtect through unchanged.
    #[test]
    fn dispatch_with_context_passes_vmprotect_through() {
        let records = vec![pkr("VMProtect", "high")];
        let sections = vec![section_marker(".vmp", 96 * 1024, 7.9, "RWX")];
        let mut text = vec![0u8; 4096];
        let stub = vec![0x0F, 0x31, 0x0F, 0xA2];

        let outcome = dispatch_with_context(&records, &text, &stub, &sections);
        assert_eq!(outcome.strategy, UnpackStrategy::LegacyVmProtect);
    }
}
