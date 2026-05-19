//! Per-chain harness synthesis — **Codex round-1 finding 2 fix**.
//!
//! The plan's round-1 review flagged the harness contract as
//! over-promised: the fuzzer's in-process harness is
//! `fn(&[u8]) -> ExitKind` (`src/fuzzer/harness.rs:29`), NOT an
//! arbitrary PE export with loader state, imports, sockets, IOCTL
//! buffers, and init reproduced. Treating every chain as
//! "Runnable" would have produced a `harnesses/F-*.runnable.rs` for
//! binary-only PE entries that could not possibly execute, then
//! waited for the fuzzer to find a crash that would never arrive.
//!
//! The fix is structural: this module synthesizes harnesses with
//! **`Skeleton` tier by default** and only allows promotion to
//! `Runnable` after [`crate::vuln::harness_verify::verify_runnable`]
//! returns [`HarnessVerification::Passed`] with an `observed_sink_va`
//! that matches the chain's `sink_site_va`.
//!
//! Eligibility for promotion is itself a type-level property:
//! [`HarnessKind`] partitions chains into
//! - [`HarnessKind::BinaryOnlyPeEntry`] — verification cannot run;
//!   the synthesized harness MUST stay at Skeleton tier. Producers
//!   always get a Markdown skeleton with ABI / loader / init notes
//!   so the human or LLM consumer can hand-author a real harness
//!   later.
//! - [`HarnessKind::SourceAvailableFnByteSlice`] — the target is a
//!   Rust crate with a registered `fn(&[u8])`. Synthesis emits both
//!   a Skeleton (always) and a Runnable Rust template (always);
//!   tier remains `Skeleton` until verification passes.
//! - [`HarnessKind::UserSuppliedEntryPoint`] — the user told the
//!   orchestrator how to call an entry point. Same shape as
//!   `SourceAvailableFnByteSlice`.
//!
//! v1.1 Step 27 ([`crate::vuln::fuzz_bridge`], gated
//! `vuln-discovery-fuzz`) is the primary consumer: it locates the
//! synthesized harness for a chain, runs it, and on crash produces a
//! [`crate::vuln::dynamic_evidence::DynamicEvidence`] record only
//! when the crash PC matches the harness's `intended_sink_va`.

#![allow(dead_code)]

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::vuln::query::CandidateChain;
use crate::vuln::sinks::SinkCatalog;

/// Structural classification of a chain's verification eligibility.
///
/// **Codex finding 2 invariant** is encoded here: `BinaryOnlyPeEntry`
/// is a type-level signal that verification CANNOT run, so
/// [`crate::vuln::harness_verify::verify_runnable`] short-circuits to
/// [`HarnessVerification::SkippedBinaryOnly`] without invoking the
/// runner. The other two variants are eligible for verification and
/// can be promoted to [`HarnessTier::Runnable`] on PASS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessKind {
    /// Target is a binary-only PE entry with loader / imports / IOCTL
    /// state that axe cannot synthesize. Verification is structurally
    /// impossible; the harness ALWAYS stays at `Skeleton` tier.
    BinaryOnlyPeEntry,
    /// Target is a Rust crate (or other source-available codebase)
    /// with a registered `fn(&[u8])` harness the orchestrator can
    /// drive directly. Eligible for verification.
    SourceAvailableFnByteSlice,
    /// User supplied an entry point the orchestrator can call (e.g.,
    /// via `--vuln-harness-entry-point`). Eligible for verification.
    UserSuppliedEntryPoint,
}

impl HarnessKind {
    /// `true` iff a runnable Rust template should be emitted and
    /// verification is allowed to run.
    pub fn is_runnable_eligible(&self) -> bool {
        !matches!(self, Self::BinaryOnlyPeEntry)
    }
}

/// Synthesized-harness tier.
///
/// The promotion rule is one-way: a harness starts at `Skeleton` and
/// only flips to `Runnable` after
/// [`crate::vuln::harness_verify::try_promote_to_runnable`] returns
/// `true`. There is no demotion path — once verification has proven
/// the harness reaches the intended sink, the verification record
/// stays attached as evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HarnessTier {
    /// Markdown-only artifact: chain provenance + ABI / loader / init
    /// notes + suggested inputs. The default tier for ALL synthesized
    /// harnesses; binary-only chains stay here forever.
    Skeleton,
    /// Rust-compileable harness whose verification has PASSED. The
    /// `runnable_rust` field of the [`Harness`] is populated and the
    /// `verification` is [`HarnessVerification::Passed`].
    Runnable,
}

/// Outcome of the verification attempt.
///
/// `wire_label()` exposes the snake_case string that the v1.1 plan's
/// `findings.jsonl::harness::runnable_verification` field carries.
/// Step 34 (llm_pack v1.1) serializes only the label, while the full
/// record stays in-memory so other v1.1 modules (fuzz_bridge,
/// trace_join, concolic_query) can inspect the rich data.
#[derive(Clone, Debug, PartialEq)]
pub enum HarnessVerification {
    /// Default state — no verification has been attempted yet.
    NotAttempted,
    /// Verification was structurally impossible because the harness
    /// kind is [`HarnessKind::BinaryOnlyPeEntry`]. Not a failure —
    /// just an attestation that the runner was never invoked.
    SkippedBinaryOnly,
    /// Verification PASSED: the runner observed the intended sink VA.
    Passed {
        /// The observed sink VA that matched `harness.intended_sink_va`.
        observed_sink_va: u64,
        /// How many input vectors were tried before the match.
        inputs_tried: usize,
    },
    /// Verification ran (one or more inputs were tried) but the
    /// intended sink VA was never observed.
    Failed {
        /// Short machine-readable reason code:
        /// `"sink_va_not_reached"`, `"no_inputs_provided"`,
        /// `"observed_va_mismatch"`.
        reason: String,
        /// How many input vectors were tried.
        inputs_tried: usize,
    },
}

impl HarnessVerification {
    /// Snake-case label for the wire shape on
    /// `findings.jsonl::harness::runnable_verification`.
    pub fn wire_label(&self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::SkippedBinaryOnly => "skipped_binary_only",
            Self::Passed { .. } => "passed",
            Self::Failed { .. } => "failed",
        }
    }

    /// `true` iff this verification result is the unique state that
    /// authorizes promotion to [`HarnessTier::Runnable`].
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Passed { .. })
    }
}

/// An in-memory synthesized harness for one [`CandidateChain`].
///
/// Step 34 (llm_pack v1.1) will serialize a small `HarnessRef`
/// sub-shape into `findings.jsonl`; the full `Harness` lives in
/// memory and is consumed by Steps 27-29 (fuzz_bridge / trace_join /
/// concolic_query).
#[derive(Clone, Debug)]
pub struct Harness {
    /// `H-{chain_id}` by construction. Used as the join key by
    /// fuzz_bridge for per-chain attribution.
    pub harness_id: String,
    /// The [`CandidateChain::chain_id`] this harness targets.
    pub chain_id: String,
    /// Bug class for the chain (e.g. `"unchecked_copy_length"`) —
    /// duplicated here so the harness file on disk is self-contained.
    pub bug_class: String,
    /// Source-callsite VA from the chain. Surfaced in the Skeleton
    /// markdown so the consumer knows which entry path to drive.
    pub source_site_va: u64,
    /// Source-function VA from the chain.
    pub source_function_va: u64,
    /// Sink-callsite VA from the chain. This is the `intended_sink_va`
    /// verification will compare against; named here for clarity in
    /// the on-disk artifact.
    pub sink_site_va: u64,
    /// Sink-function VA from the chain.
    pub sink_function_va: u64,
    /// Sink API name from the chain (e.g. `"memcpy"`).
    pub sink_api: String,
    /// Source kind from the chain (e.g. `"network_recv"`).
    pub source_kind: String,
    /// Structural verification eligibility — see [`HarnessKind`].
    pub kind: HarnessKind,
    /// Current tier. Defaults to [`HarnessTier::Skeleton`]; flipped
    /// to [`HarnessTier::Runnable`] only by
    /// [`crate::vuln::harness_verify::try_promote_to_runnable`].
    pub tier: HarnessTier,
    /// The VA verification must observe to authorize promotion. By
    /// construction this is `sink_site_va`; named separately so the
    /// verification path reads naturally.
    pub intended_sink_va: u64,
    /// Always populated. Markdown describing chain provenance + ABI /
    /// loader / init notes + suggested inputs. Step 34 writes this to
    /// `vuln/harnesses/{harness_id}.skeleton.md`.
    pub skeleton_markdown: String,
    /// Populated iff [`HarnessKind::is_runnable_eligible`] returns
    /// `true`. Rust source for a `fn(&[u8])` harness. Step 34 writes
    /// this to `vuln/harnesses/{harness_id}.runnable.rs` only after
    /// the tier flips to `Runnable`.
    pub runnable_rust: Option<String>,
    /// Per-line setup notes the consumer should follow before
    /// invoking the harness (load PE, locate function, reproduce
    /// init state, etc.). Empty for source-available chains.
    pub setup_notes: Vec<String>,
    /// Current verification state. See [`HarnessVerification`].
    pub verification: HarnessVerification,
}

impl Harness {
    /// Construct the canonical `harness_id` for a chain.
    pub fn harness_id_for(chain_id: &str) -> String {
        format!("H-{chain_id}")
    }
}

/// Synthesize a [`Harness`] for one chain.
///
/// The returned harness is ALWAYS at [`HarnessTier::Skeleton`] (Codex
/// finding 2 — Runnable is verification-gated). `skeleton_markdown` is
/// always populated; `runnable_rust` is populated only when
/// `kind.is_runnable_eligible()` returns `true`.
pub fn synthesize(
    chain: &CandidateChain,
    sink_catalog: &SinkCatalog,
    kind: HarnessKind,
) -> Harness {
    let harness_id = Harness::harness_id_for(&chain.chain_id);
    let skeleton_markdown = render_skeleton_markdown(chain, sink_catalog, kind);
    let runnable_rust = if kind.is_runnable_eligible() {
        Some(render_runnable_rust(chain))
    } else {
        None
    };
    let setup_notes = if matches!(kind, HarnessKind::BinaryOnlyPeEntry) {
        render_binary_only_setup_notes(chain)
    } else {
        Vec::new()
    };
    Harness {
        harness_id,
        chain_id: chain.chain_id.clone(),
        bug_class: chain.template_id.clone(),
        source_site_va: chain.source_site_va,
        source_function_va: chain.source_function_va,
        sink_site_va: chain.sink_site_va,
        sink_function_va: chain.sink_function_va,
        sink_api: chain.sink_api.clone(),
        source_kind: chain.source_kind.clone(),
        kind,
        tier: HarnessTier::Skeleton,
        intended_sink_va: chain.sink_site_va,
        skeleton_markdown,
        runnable_rust,
        setup_notes,
        verification: HarnessVerification::NotAttempted,
    }
}

/// Best-effort default kind for a chain when the caller has no
/// out-of-band knowledge. v1.1 axe consumes binary PE files, so the
/// default is [`HarnessKind::BinaryOnlyPeEntry`]. The CLI flag
/// `--vuln-harness-tier {skeleton,both}` (Step 35) plus a future
/// `--vuln-harness-entry-point` flag are how a caller upgrades a
/// chain to one of the runnable-eligible kinds.
pub fn default_kind_for_chain(_chain: &CandidateChain) -> HarnessKind {
    HarnessKind::BinaryOnlyPeEntry
}

fn render_skeleton_markdown(
    chain: &CandidateChain,
    sink_catalog: &SinkCatalog,
    kind: HarnessKind,
) -> String {
    let mut out = String::with_capacity(2048);
    let _ = writeln!(
        out,
        "# Harness Skeleton: {}",
        Harness::harness_id_for(&chain.chain_id)
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "- **Chain**: `{}`", chain.chain_id);
    let _ = writeln!(out, "- **Bug class**: `{}`", chain.template_id);
    let _ = writeln!(
        out,
        "- **Kind**: `{}`",
        match kind {
            HarnessKind::BinaryOnlyPeEntry => "binary_only_pe_entry",
            HarnessKind::SourceAvailableFnByteSlice => "source_available_fn_byte_slice",
            HarnessKind::UserSuppliedEntryPoint => "user_supplied_entry_point",
        }
    );
    let _ = writeln!(
        out,
        "- **Source**: `{}` at function `0x{:016x}`, callsite `0x{:016x}`",
        chain.source_kind, chain.source_function_va, chain.source_site_va
    );
    let _ = writeln!(
        out,
        "- **Sink**: `{}` at function `0x{:016x}`, callsite `0x{:016x}`",
        chain.sink_api, chain.sink_function_va, chain.sink_site_va
    );
    let _ = writeln!(
        out,
        "- **Propagation mode**: `{:?}`",
        chain.propagation_mode
    );
    let _ = writeln!(out, "- **Hop count**: `{}`", chain.hop_count);
    let _ = writeln!(
        out,
        "- **Dominating guard count**: `{}`",
        chain.dominating_guard_count
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## Sink argument roles");
    let _ = writeln!(out);
    if let Some(sink) = sink_catalog.lookup(&chain.sink_api) {
        let _ = writeln!(out, "| Index | Role |");
        let _ = writeln!(out, "|-------|------|");
        for (idx, role) in sink.args.iter().enumerate() {
            let _ = writeln!(out, "| {} | `{:?}` |", idx, role);
        }
    } else {
        let _ = writeln!(
            out,
            "_Sink `{}` not in v1.0 catalog; consult the binary._",
            chain.sink_api
        );
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "## Suggested inputs");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- Empty buffer (0 bytes) — exercise null-path branches."
    );
    let _ = writeln!(out, "- Small valid buffer (16 bytes).");
    let _ = writeln!(
        out,
        "- Boundary buffer at typical destination capacity (1024 bytes)."
    );
    let _ = writeln!(
        out,
        "- Oversized buffer (65536 bytes) — likely to trigger bound-violation sinks."
    );
    let _ = writeln!(
        out,
        "- Integer-overflow neighborhood values (0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF)."
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "## ABI / loader notes (x86_64 Windows)");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "- First 4 args in `rcx`, `rdx`, `r8`, `r9`; remainder on stack (Microsoft x64 ABI)."
    );
    let _ = writeln!(
        out,
        "- Shadow store of 32 bytes is allocated by the caller before the call."
    );
    let _ = writeln!(out, "- To reach sink `0x{:016x}`:", chain.sink_site_va);
    let _ = writeln!(
        out,
        "  1. Load the target PE in-process or under a controlled loader."
    );
    let _ = writeln!(
        out,
        "  2. Reach `{}` at `0x{:016x}` from the source entry.",
        chain.sink_api, chain.sink_function_va
    );
    let _ = writeln!(
        out,
        "  3. Feed taint-reachable bytes through the source at `0x{:016x}`.",
        chain.source_site_va
    );
    let _ = writeln!(out);

    match kind {
        HarnessKind::BinaryOnlyPeEntry => {
            let _ = writeln!(out, "## Why this stays Skeleton (Codex finding 2)");
            let _ = writeln!(out);
            let _ = writeln!(out, "This chain targets a binary-only PE entry. Axe cannot synthesize a self-contained `fn(&[u8])` harness without source access, so verification cannot run and the tier stays `Skeleton` by construction. Hand-author a LibAFL harness using the notes above; only then can the tier flip to `Runnable` via verification.");
        }
        HarnessKind::SourceAvailableFnByteSlice => {
            let _ = writeln!(out, "## Why this is verification-eligible");
            let _ = writeln!(out);
            let _ = writeln!(out, "Target is a source-available crate with a registered `fn(&[u8])` harness. See the companion `.runnable.rs` for the generated entry; the tier flips to `Runnable` after `verify_runnable` observes `intended_sink_va` `0x{:016x}`.", chain.sink_site_va);
        }
        HarnessKind::UserSuppliedEntryPoint => {
            let _ = writeln!(out, "## Why this is verification-eligible");
            let _ = writeln!(out);
            let _ = writeln!(out, "User supplied an entry point. See the companion `.runnable.rs` for the generated entry; the tier flips to `Runnable` after `verify_runnable` observes `intended_sink_va` `0x{:016x}`.", chain.sink_site_va);
        }
    }

    out
}

fn render_runnable_rust(chain: &CandidateChain) -> String {
    let mut out = String::with_capacity(512);
    let _ = writeln!(
        out,
        "// Generated harness for chain {} ({})",
        chain.chain_id, chain.template_id
    );
    let _ = writeln!(
        out,
        "// Intended sink VA: 0x{:016x} ({})",
        chain.sink_site_va, chain.sink_api
    );
    let _ = writeln!(
        out,
        "// Source kind: {} @ 0x{:016x}",
        chain.source_kind, chain.source_site_va
    );
    let _ = writeln!(out, "//");
    let _ = writeln!(
        out,
        "// This is a TEMPLATE: replace `target_crate::registered_entry`"
    );
    let _ = writeln!(
        out,
        "// with the actual entry function. Verification asserts the"
    );
    let _ = writeln!(
        out,
        "// intended_sink_va is reached when this harness is invoked."
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "pub fn harness(input: &[u8]) -> u32 {{");
    let _ = writeln!(
        out,
        "    // ExitKind::Ok == 0 in LibAFL's conventional encoding."
    );
    let _ = writeln!(out, "    target_crate::registered_entry(input);");
    let _ = writeln!(out, "    0");
    let _ = writeln!(out, "}}");
    out
}

fn render_binary_only_setup_notes(chain: &CandidateChain) -> Vec<String> {
    vec![
        format!(
            "Load the target PE in-process (LoadLibrary or a controlled in-proc loader)."
        ),
        format!(
            "Resolve function 0x{:016x} ({}) and locate sink callsite 0x{:016x}.",
            chain.sink_function_va, chain.sink_api, chain.sink_site_va
        ),
        format!(
            "Reproduce caller-frame state up to source callsite 0x{:016x} ({}).",
            chain.source_site_va, chain.source_kind
        ),
        "Feed taint-reachable bytes through the source; observe whether the intended sink VA is reached.".to_string(),
        "On reach: invoke verify_runnable with observed_sink_va = intended_sink_va to promote tier to Runnable.".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::taint::PropagationMode;

    fn fixture_chain() -> CandidateChain {
        CandidateChain {
            chain_id: "C-000042".into(),
            template_id: "unchecked_copy_length".into(),
            source_kind: "network_recv".into(),
            source_function_va: 0x140001000,
            source_site_va: 0x140001100,
            sink_api: "memcpy".into(),
            sink_function_va: 0x140002000,
            sink_site_va: 0x1400022a4,
            propagation_mode: PropagationMode::Summary,
            hop_count: 2,
            dominating_guard_count: 1,
            matched_integer_pattern: false,
        }
    }

    // ----- HarnessKind -----

    #[test]
    fn binary_only_is_not_runnable_eligible() {
        assert!(!HarnessKind::BinaryOnlyPeEntry.is_runnable_eligible());
    }

    #[test]
    fn source_available_and_user_supplied_are_runnable_eligible() {
        assert!(HarnessKind::SourceAvailableFnByteSlice.is_runnable_eligible());
        assert!(HarnessKind::UserSuppliedEntryPoint.is_runnable_eligible());
    }

    #[test]
    fn harness_kind_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&HarnessKind::BinaryOnlyPeEntry).unwrap(),
            "\"binary_only_pe_entry\""
        );
        assert_eq!(
            serde_json::to_string(&HarnessKind::SourceAvailableFnByteSlice).unwrap(),
            "\"source_available_fn_byte_slice\""
        );
        assert_eq!(
            serde_json::to_string(&HarnessKind::UserSuppliedEntryPoint).unwrap(),
            "\"user_supplied_entry_point\""
        );
    }

    // ----- HarnessTier -----

    #[test]
    fn harness_tier_serializes_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&HarnessTier::Skeleton).unwrap(),
            "\"skeleton\""
        );
        assert_eq!(
            serde_json::to_string(&HarnessTier::Runnable).unwrap(),
            "\"runnable\""
        );
    }

    // ----- HarnessVerification -----

    #[test]
    fn verification_wire_labels_match_plan_spec() {
        assert_eq!(
            HarnessVerification::NotAttempted.wire_label(),
            "not_attempted"
        );
        assert_eq!(
            HarnessVerification::SkippedBinaryOnly.wire_label(),
            "skipped_binary_only"
        );
        assert_eq!(
            HarnessVerification::Passed {
                observed_sink_va: 0x1000,
                inputs_tried: 1
            }
            .wire_label(),
            "passed"
        );
        assert_eq!(
            HarnessVerification::Failed {
                reason: "x".into(),
                inputs_tried: 1
            }
            .wire_label(),
            "failed"
        );
    }

    #[test]
    fn only_passed_authorizes_promotion() {
        assert!(!HarnessVerification::NotAttempted.is_pass());
        assert!(!HarnessVerification::SkippedBinaryOnly.is_pass());
        assert!(HarnessVerification::Passed {
            observed_sink_va: 0x1000,
            inputs_tried: 1
        }
        .is_pass());
        assert!(!HarnessVerification::Failed {
            reason: "x".into(),
            inputs_tried: 1
        }
        .is_pass());
    }

    // ----- synthesize() -----

    #[test]
    fn synthesize_always_defaults_to_skeleton_tier() {
        // Codex finding 2 invariant: tier is never `Runnable` at synth
        // time, regardless of HarnessKind. Promotion happens ONLY via
        // `try_promote_to_runnable`.
        let chain = fixture_chain();
        let sinks = SinkCatalog::v1_0();
        for kind in [
            HarnessKind::BinaryOnlyPeEntry,
            HarnessKind::SourceAvailableFnByteSlice,
            HarnessKind::UserSuppliedEntryPoint,
        ] {
            let h = synthesize(&chain, &sinks, kind);
            assert_eq!(
                h.tier,
                HarnessTier::Skeleton,
                "kind {kind:?} must default to Skeleton"
            );
            assert_eq!(h.verification, HarnessVerification::NotAttempted);
        }
    }

    #[test]
    fn synthesize_uses_canonical_harness_id_format() {
        let chain = fixture_chain();
        let sinks = SinkCatalog::v1_0();
        let h = synthesize(&chain, &sinks, HarnessKind::BinaryOnlyPeEntry);
        assert_eq!(h.harness_id, "H-C-000042");
        assert_eq!(h.chain_id, "C-000042");
        // The Step 25 DynamicEvidence consumer uses this id pattern
        // as the join key.
        assert_eq!(Harness::harness_id_for("F-2026-000173"), "H-F-2026-000173");
    }

    #[test]
    fn synthesize_intended_sink_va_equals_chain_sink_site_va() {
        // verify_runnable compares observed_sink_va against
        // intended_sink_va, so it MUST equal sink_site_va by
        // construction.
        let chain = fixture_chain();
        let sinks = SinkCatalog::v1_0();
        let h = synthesize(&chain, &sinks, HarnessKind::SourceAvailableFnByteSlice);
        assert_eq!(h.intended_sink_va, chain.sink_site_va);
        assert_eq!(h.intended_sink_va, 0x1400022a4);
    }

    #[test]
    fn binary_only_synthesis_omits_runnable_rust() {
        let chain = fixture_chain();
        let sinks = SinkCatalog::v1_0();
        let h = synthesize(&chain, &sinks, HarnessKind::BinaryOnlyPeEntry);
        assert!(h.runnable_rust.is_none());
        // Skeleton is always present.
        assert!(!h.skeleton_markdown.is_empty());
        // Setup notes guide the human harness writer.
        assert!(!h.setup_notes.is_empty());
    }

    #[test]
    fn source_available_synthesis_emits_runnable_rust() {
        let chain = fixture_chain();
        let sinks = SinkCatalog::v1_0();
        let h = synthesize(&chain, &sinks, HarnessKind::SourceAvailableFnByteSlice);
        let rust = h
            .runnable_rust
            .as_ref()
            .expect("source-available must emit runnable rust");
        assert!(rust.contains("pub fn harness(input: &[u8])"));
        assert!(rust.contains("C-000042"));
        // Tier still Skeleton even though runnable_rust exists — only
        // verification can promote it.
        assert_eq!(h.tier, HarnessTier::Skeleton);
    }

    #[test]
    fn user_supplied_synthesis_emits_runnable_rust() {
        let chain = fixture_chain();
        let sinks = SinkCatalog::v1_0();
        let h = synthesize(&chain, &sinks, HarnessKind::UserSuppliedEntryPoint);
        assert!(h.runnable_rust.is_some());
        assert_eq!(h.tier, HarnessTier::Skeleton);
    }

    #[test]
    fn skeleton_markdown_carries_full_chain_provenance() {
        let chain = fixture_chain();
        let sinks = SinkCatalog::v1_0();
        let h = synthesize(&chain, &sinks, HarnessKind::BinaryOnlyPeEntry);
        let md = &h.skeleton_markdown;
        assert!(md.contains("C-000042"), "skeleton must reference chain id");
        assert!(
            md.contains("unchecked_copy_length"),
            "skeleton must reference bug class"
        );
        assert!(
            md.contains("network_recv"),
            "skeleton must reference source kind"
        );
        assert!(md.contains("memcpy"), "skeleton must reference sink api");
        // Sink VAs surface so the LLM consumer / human author knows
        // exactly which address verification will assert on.
        assert!(
            md.contains("0x00000001400022a4"),
            "skeleton must reference sink_site_va in canonical 16-hex form"
        );
        assert!(
            md.contains("0x0000000140001100"),
            "skeleton must reference source_site_va in canonical 16-hex form"
        );
    }

    #[test]
    fn skeleton_lists_sink_argument_roles_from_catalog() {
        let chain = fixture_chain();
        let sinks = SinkCatalog::v1_0();
        let h = synthesize(&chain, &sinks, HarnessKind::BinaryOnlyPeEntry);
        // memcpy is (Destination, Source, ByteCount).
        assert!(h.skeleton_markdown.contains("Destination"));
        assert!(h.skeleton_markdown.contains("Source"));
        assert!(h.skeleton_markdown.contains("ByteCount"));
    }

    #[test]
    fn skeleton_handles_unknown_sink_gracefully() {
        let mut chain = fixture_chain();
        chain.sink_api = "completely_unknown_sink".into();
        let sinks = SinkCatalog::v1_0();
        let h = synthesize(&chain, &sinks, HarnessKind::BinaryOnlyPeEntry);
        assert!(h.skeleton_markdown.contains("not in v1.0 catalog"));
    }

    #[test]
    fn binary_only_skeleton_includes_codex_finding_2_rationale() {
        // Self-documenting: the skeleton tells the consumer WHY this
        // chain stays Skeleton. This is what makes "honest output"
        // honest rather than just incomplete.
        let chain = fixture_chain();
        let sinks = SinkCatalog::v1_0();
        let h = synthesize(&chain, &sinks, HarnessKind::BinaryOnlyPeEntry);
        assert!(h.skeleton_markdown.contains("Codex finding 2"));
        assert!(h.skeleton_markdown.contains("binary-only"));
    }

    #[test]
    fn source_available_skeleton_points_at_companion_runnable() {
        let chain = fixture_chain();
        let sinks = SinkCatalog::v1_0();
        let h = synthesize(&chain, &sinks, HarnessKind::SourceAvailableFnByteSlice);
        assert!(h.skeleton_markdown.contains(".runnable.rs"));
        assert!(h.skeleton_markdown.contains("verify_runnable"));
    }

    // ----- default_kind_for_chain() -----

    #[test]
    fn default_kind_is_binary_only_for_v1_1() {
        // Axe consumes PE binaries; the default must NOT promise a
        // runnable harness without explicit opt-in.
        let chain = fixture_chain();
        assert_eq!(
            default_kind_for_chain(&chain),
            HarnessKind::BinaryOnlyPeEntry
        );
    }
}
