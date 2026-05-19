//! Aurora snapshot wire types — serializes to
//! `out/unpack/unpack_provenance.json` with schema
//! `vuln_discovery.unpack_snapshot.v1`.
//!
//! The snapshot manifest is the contract between the live Aurora
//! session (which produces it) and `PEImage::from_snapshot()` /
//! axe-core's static + vuln-discovery pipeline (which consumes
//! it). Every field is deliberately small and primitive so the
//! file is human-auditable and `serde_json`-stable.
//!
//! # Schema invariants
//!
//! - `schema` is the fixed string `vuln_discovery.unpack_snapshot.v1`.
//!   Any change to the wire shape requires a v2 schema and a
//!   parallel consumer (the existing v1 consumer must continue to
//!   read v1 files unchanged).
//! - `regions[].blob_path` is **always relative** to the directory
//!   that holds `unpack_provenance.json`. The consumer joins
//!   `manifest_dir.join(blob_path)`. Absolute paths in this field
//!   are an error.
//! - `oep_candidates[].confidence_score` is in `[0.0, 1.0]`. The
//!   producer computes it as `signals_present / 4` (4-signal
//!   corroboration); the consumer treats anything ≥0.75 as `high`.
//! - `execution_provenance.outcome` mirrors `UnpackOutcome` in
//!   `mod.rs` but is serialized snake_case for the JSON consumer.

use serde::{Deserialize, Serialize};

/// Fixed schema string emitted in every snapshot manifest.
pub const SNAPSHOT_SCHEMA: &str = "vuln_discovery.unpack_snapshot.v1";

/// The top-level wire shape for `unpack_provenance.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub schema: String,
    pub run_id: String,
    pub source_binary: SourceBinary,
    pub packer_detection: Option<PackerDetectionLite>,
    pub tracer_mode: String,
    pub anti_vm_profile: AntiVmProfile,
    pub regions: Vec<RegionDescriptor>,
    pub oep_candidates: Vec<OepCandidate>,
    pub execution_provenance: ExecutionProvenance,
    pub uncertainties: Vec<String>,
}

impl SnapshotManifest {
    /// Build an empty manifest with the schema string pre-filled.
    /// Used by `session.rs` (Step 54) to construct a manifest
    /// incrementally as regions land + OEP signals corroborate.
    pub fn new(run_id: &str, source: SourceBinary, tracer_mode: &str) -> Self {
        Self {
            schema: SNAPSHOT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            source_binary: source,
            packer_detection: None,
            tracer_mode: tracer_mode.to_string(),
            anti_vm_profile: AntiVmProfile::default(),
            regions: Vec::new(),
            oep_candidates: Vec::new(),
            execution_provenance: ExecutionProvenance::in_progress(),
            uncertainties: Vec::new(),
        }
    }
}

/// The packed binary Aurora was asked to unpack. The hash gates
/// snapshot caching — if `path` is unchanged but `hash_blake3`
/// differs, the snapshot is stale.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceBinary {
    pub path: String,
    pub hash_blake3: String,
    pub size_bytes: u64,
}

/// Projection of an `AntiAnalysisRecord` (category="packer") — the
/// snapshot does not duplicate the full record, only the dispatch
/// signal that drove strategy selection. The full anti-analysis
/// output is in `out/anti_analysis.jsonl` (already produced by the
/// existing pipeline).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackerDetectionLite {
    /// Family name as `anti_analysis.rs` emits it ("UPX",
    /// "Themida", "VMProtect", "generic_packed", etc.).
    #[serde(rename = "type")]
    pub type_: String,
    /// Mirrors `AntiAnalysisRecord::confidence` ("high" / "medium"
    /// / "low").
    pub confidence: String,
    /// Provenance pointer so the LLM consumer can find the full
    /// record. Always `src/anti_analysis.rs` for v1.
    pub source: String,
}

/// Which anti-anti-VM and anti-debug surfaces Aurora actively
/// suppressed during the run. The LLM consumer uses this to
/// understand whether a finding is reliable (e.g. a missing
/// `CreateToolhelp32Snapshot` hook means VM-tooling-process
/// enumeration may have terminated the run early).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AntiVmProfile {
    pub user_mode_hooks_installed: Vec<String>,
    pub anti_debug_hooks_installed: Vec<String>,
    pub whp_used: bool,
    pub driver_used: bool,
    pub devirt_used: bool,
    /// Path (relative to the snapshot directory) of the `devirt_trace.jsonl`
    /// artifact emitted by `unpack/devirt/`, if the devirt path produced one
    /// during this run. `None` when devirt was skipped, faulted before any
    /// trace was written, or ran in a mode that doesn't emit the artifact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devirt_trace_path: Option<String>,
}

/// One captured memory region from the target process. The actual
/// bytes live in `blob_path`; this descriptor carries the metadata
/// the consumer needs to place it in the synthetic address space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegionDescriptor {
    pub id: u32,
    pub va_base: String,
    pub size_bytes: u64,
    /// Compact "RWX" / "RW-" / "R-X" / "R--" string. Mirrors the
    /// `PAGE_*` constants the OS reported via `VirtualQueryEx`.
    pub permissions: String,
    pub origin: RegionOrigin,
    /// Always relative to the directory that holds the manifest.
    pub blob_path: String,
    pub blob_hash_blake3: String,
    /// Shannon entropy of the final captured bytes (0.0-8.0).
    pub entropy_final: f64,
    /// Number of write hits observed via `PAGE_GUARD` (Step 14)
    /// during the run. `0` for regions captured without write
    /// tracing (e.g. snapshot at exit, no instrumentation).
    pub writes_observed: u64,
    /// Number of distinct instruction-pointer hits observed
    /// inside this region. Used by OEP detection (Step 21).
    pub executions_observed: u64,
}

/// Where this region came from. For regions that existed at
/// process creation (image, stack, initial heap), `alloc_api` is
/// `"initial"` and `alloc_site_va` is `0`. For dynamically
/// allocated regions, `alloc_api` is the name of the call that
/// produced it ("VirtualAlloc" / "NtAllocateVirtualMemory" /
/// "VirtualAllocEx" — process-injection targets).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegionOrigin {
    pub alloc_api: String,
    pub alloc_site_va: String,
    pub alloc_size_requested: u64,
}

/// One Original Entry Point candidate. Multiple candidates may
/// fire during a single run; the consumer picks by descending
/// `confidence_score`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OepCandidate {
    pub va: String,
    pub region_id: u32,
    pub corroboration: OepCorroboration,
    /// `signals_present / 4`. The 4 signals are: entropy drop,
    /// execute-from-newly-allocated, function-prologue match,
    /// IAT-call pattern. See `oep_detector.rs` (Steps 21-24).
    pub confidence_score: f64,
    /// `"high"` for ≥0.75, `"medium"` for ≥0.50, `"best_effort"`
    /// otherwise. Mirrors the protector-class tiering documented
    /// in `docs/unpack-capabilities.md`.
    pub confidence_tier: String,
}

/// The 4 OEP-detection signals. Each is a boolean — the producer
/// is responsible for the per-signal threshold logic; the
/// consumer just reads the booleans.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OepCorroboration {
    pub entropy_drop: bool,
    pub execute_from_newly_allocated: bool,
    pub function_prologue_match: bool,
    pub iat_call_pattern: bool,
}

impl OepCorroboration {
    /// Count of true signals (0..=4). Used by `confidence_score`.
    pub fn signal_count(&self) -> u32 {
        [
            self.entropy_drop,
            self.execute_from_newly_allocated,
            self.function_prologue_match,
            self.iat_call_pattern,
        ]
        .iter()
        .filter(|b| **b)
        .count() as u32
    }
}

/// How the run terminated and the cost budget consumed. Used by
/// the LLM consumer to understand whether the snapshot is
/// "complete" (OEP reached, dump captured) or "truncated"
/// (timeout / instr-budget / crash before OEP).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionProvenance {
    pub wall_clock_ms: u64,
    pub instructions_estimated: u64,
    /// `"oep_reached"` / `"timeout"` / `"instr_budget"` / `"crash"`
    /// / `"in_progress"`. The in-progress variant is the initial
    /// state set by `new()`; finalize must overwrite it.
    pub outcome: String,
    pub termination_reason: String,
    /// Process exit code if the target exited cleanly; `None`
    /// otherwise.
    pub exit_code: Option<i32>,
    pub hit_instruction_budget: bool,
    pub hit_wall_clock_timeout: bool,
    pub child_processes_observed: Vec<String>,
}

impl ExecutionProvenance {
    /// Initial state set by `SnapshotManifest::new`. Must be
    /// overwritten before serialization.
    pub fn in_progress() -> Self {
        Self {
            wall_clock_ms: 0,
            instructions_estimated: 0,
            outcome: "in_progress".to_string(),
            termination_reason: "session not yet finalized".to_string(),
            exit_code: None,
            hit_instruction_budget: false,
            hit_wall_clock_timeout: false,
            child_processes_observed: Vec::new(),
        }
    }
}

/// Map a 4-signal corroboration score to a tier string. Mirrors
/// the rule documented at `OepCandidate::confidence_tier`.
pub fn tier_for_score(score: f64) -> &'static str {
    if score >= 0.75 {
        "high"
    } else if score >= 0.50 {
        "medium"
    } else {
        "best_effort"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> SnapshotManifest {
        let mut m = SnapshotManifest::new(
            "blake3:9b2e",
            SourceBinary {
                path: "C:/samples/m.upx.exe".into(),
                hash_blake3: "9b2e".into(),
                size_bytes: 24576,
            },
            "debug",
        );
        m.regions.push(RegionDescriptor {
            id: 0,
            va_base: "0x140001000".into(),
            size_bytes: 16384,
            permissions: "RWX".into(),
            origin: RegionOrigin {
                alloc_api: "VirtualAlloc".into(),
                alloc_site_va: "0x140001234".into(),
                alloc_size_requested: 16384,
            },
            blob_path: "regions/region_00.bin".into(),
            blob_hash_blake3: "a1c2".into(),
            entropy_final: 6.21,
            writes_observed: 142,
            executions_observed: 23,
        });
        m.oep_candidates.push(OepCandidate {
            va: "0x140005678".into(),
            region_id: 0,
            corroboration: OepCorroboration {
                entropy_drop: true,
                execute_from_newly_allocated: true,
                function_prologue_match: true,
                iat_call_pattern: true,
            },
            confidence_score: 1.0,
            confidence_tier: "high".into(),
        });
        m
    }

    #[test]
    fn schema_string_is_pinned() {
        assert_eq!(SNAPSHOT_SCHEMA, "vuln_discovery.unpack_snapshot.v1");
    }

    #[test]
    fn round_trip_preserves_all_fields() {
        let m = sample_manifest();
        let json = serde_json::to_string_pretty(&m).expect("serialize");
        let back: SnapshotManifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.schema, m.schema);
        assert_eq!(back.run_id, m.run_id);
        assert_eq!(back.source_binary.path, m.source_binary.path);
        assert_eq!(back.regions.len(), 1);
        assert_eq!(back.regions[0].va_base, "0x140001000");
        assert_eq!(back.oep_candidates.len(), 1);
        assert_eq!(back.oep_candidates[0].confidence_score, 1.0);
        assert!(back.oep_candidates[0].corroboration.entropy_drop);
    }

    #[test]
    fn signal_count_zero_through_four() {
        let none = OepCorroboration {
            entropy_drop: false,
            execute_from_newly_allocated: false,
            function_prologue_match: false,
            iat_call_pattern: false,
        };
        assert_eq!(none.signal_count(), 0);

        let two = OepCorroboration {
            entropy_drop: true,
            execute_from_newly_allocated: false,
            function_prologue_match: true,
            iat_call_pattern: false,
        };
        assert_eq!(two.signal_count(), 2);

        let all = OepCorroboration {
            entropy_drop: true,
            execute_from_newly_allocated: true,
            function_prologue_match: true,
            iat_call_pattern: true,
        };
        assert_eq!(all.signal_count(), 4);
    }

    #[test]
    fn tier_for_score_boundaries() {
        assert_eq!(tier_for_score(1.00), "high");
        assert_eq!(tier_for_score(0.75), "high");
        assert_eq!(tier_for_score(0.74), "medium");
        assert_eq!(tier_for_score(0.50), "medium");
        assert_eq!(tier_for_score(0.49), "best_effort");
        assert_eq!(tier_for_score(0.00), "best_effort");
    }

    #[test]
    fn new_manifest_has_in_progress_outcome() {
        let m = SnapshotManifest::new(
            "r",
            SourceBinary {
                path: "p".into(),
                hash_blake3: "h".into(),
                size_bytes: 0,
            },
            "debug",
        );
        assert_eq!(m.execution_provenance.outcome, "in_progress");
    }

    #[test]
    fn anti_vm_profile_default_has_no_hooks() {
        let p = AntiVmProfile::default();
        assert!(p.user_mode_hooks_installed.is_empty());
        assert!(p.anti_debug_hooks_installed.is_empty());
        assert!(!p.whp_used);
        assert!(!p.driver_used);
        assert!(!p.devirt_used);
    }
}
