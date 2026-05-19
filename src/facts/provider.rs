use serde::{Deserialize, Serialize};

use crate::facts::claim::Claim;
use crate::facts::confidence::Confidence;
use crate::facts::evidence::EvidenceRef;
use crate::symbol_graph::SymbolGraphRecord;

/// Where a claim came from. Drives default confidence bands and downstream
/// merge priority. Highest authority sources (PDB, DWARF) override lower
/// ones (heuristic, naming) when the same slot has conflicting claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSource {
    Pdb,
    Dwarf,
    ObjectSymbol,
    Rtti,
    ExceptionHandling,
    CtorDtorPattern,
    FieldAccessInference,
    SwitchReconstruction,
    JumpTableHeuristic,
    Naming,
    LlmHeuristic,
}

impl ClaimSource {
    /// Returns the `(low, high)` inclusive confidence band that a fresh claim
    /// from this source should fall in. Per-pass code is free to pick any
    /// value in `[low, high]`; the `Claim::new` constructor picks the midpoint.
    ///
    /// `Naming` and `LlmHeuristic` are **never authoritative** — their `high`
    /// stays below the `Medium` band threshold (0.60) so a naming-derived
    /// claim cannot override an RTTI/EH/debug-info claim during merge.
    pub fn default_confidence_band(self) -> (f32, f32) {
        match self {
            ClaimSource::Pdb | ClaimSource::Dwarf => (0.98, 1.00),
            ClaimSource::ObjectSymbol => (0.85, 0.95),
            ClaimSource::Rtti => (0.85, 0.97),
            ClaimSource::ExceptionHandling => (0.75, 0.95),
            ClaimSource::CtorDtorPattern => (0.65, 0.90),
            ClaimSource::FieldAccessInference => (0.45, 0.85),
            ClaimSource::SwitchReconstruction => (0.65, 0.95),
            ClaimSource::JumpTableHeuristic => (0.40, 0.70),
            ClaimSource::Naming | ClaimSource::LlmHeuristic => (0.20, 0.55),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ClaimSource::Pdb => "pdb",
            ClaimSource::Dwarf => "dwarf",
            ClaimSource::ObjectSymbol => "object_symbol",
            ClaimSource::Rtti => "rtti",
            ClaimSource::ExceptionHandling => "exception_handling",
            ClaimSource::CtorDtorPattern => "ctor_dtor_pattern",
            ClaimSource::FieldAccessInference => "field_access_inference",
            ClaimSource::SwitchReconstruction => "switch_reconstruction",
            ClaimSource::JumpTableHeuristic => "jump_table_heuristic",
            ClaimSource::Naming => "naming",
            ClaimSource::LlmHeuristic => "llm_heuristic",
        }
    }
}

/// Map a legacy `SymbolGraphRecord.provider` string to a typed `ClaimSource`.
/// Unknown providers degrade to `Naming` (never-authoritative) rather than
/// erroring out — preserves forward compatibility with new providers added
/// to `symbol_graph.rs` before they're enumerated here.
pub fn coerce_provider(provider: &str) -> ClaimSource {
    match provider.to_ascii_lowercase().as_str() {
        "pdb" => ClaimSource::Pdb,
        "dwarf" => ClaimSource::Dwarf,
        "object" | "object_symbol" => ClaimSource::ObjectSymbol,
        "rtti" => ClaimSource::Rtti,
        "eh" | "exception_handling" => ClaimSource::ExceptionHandling,
        _ => ClaimSource::Naming,
    }
}

impl From<&SymbolGraphRecord> for Claim<()> {
    fn from(rec: &SymbolGraphRecord) -> Self {
        let evidence = rec
            .evidence
            .iter()
            .filter_map(|s| {
                s.strip_prefix("rva_or_va:")
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                    .map(|va| EvidenceRef::RawAddr { va })
            })
            .collect();
        Claim {
            value: (),
            source: coerce_provider(&rec.provider),
            confidence: Confidence::from_str(&rec.confidence),
            evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pdb_band_is_high_and_tight() {
        let (lo, hi) = ClaimSource::Pdb.default_confidence_band();
        assert!(lo >= 0.98 && hi <= 1.00, "got ({lo}, {hi})");
    }

    #[test]
    fn naming_band_never_authoritative() {
        // Naming/LLM must stay below the Medium band threshold of 0.60
        // so they cannot win a merge against a real provider.
        let (_, hi) = ClaimSource::Naming.default_confidence_band();
        assert!(
            hi < 0.60,
            "naming should never reach Medium band, got hi={hi}"
        );
        let (_, hi2) = ClaimSource::LlmHeuristic.default_confidence_band();
        assert!(
            hi2 < 0.60,
            "llm heuristic should never reach Medium band, got hi={hi2}"
        );
    }

    #[test]
    fn all_bands_within_unit_interval() {
        let sources = [
            ClaimSource::Pdb,
            ClaimSource::Dwarf,
            ClaimSource::ObjectSymbol,
            ClaimSource::Rtti,
            ClaimSource::ExceptionHandling,
            ClaimSource::CtorDtorPattern,
            ClaimSource::FieldAccessInference,
            ClaimSource::SwitchReconstruction,
            ClaimSource::JumpTableHeuristic,
            ClaimSource::Naming,
            ClaimSource::LlmHeuristic,
        ];
        for src in sources {
            let (lo, hi) = src.default_confidence_band();
            assert!(lo >= 0.0 && hi <= 1.0, "{src:?}: ({lo}, {hi})");
            assert!(lo <= hi, "{src:?}: lo>hi");
        }
    }

    #[test]
    fn coerce_provider_handles_known_strings() {
        assert_eq!(coerce_provider("pdb"), ClaimSource::Pdb);
        assert_eq!(coerce_provider("DWARF"), ClaimSource::Dwarf);
        assert_eq!(coerce_provider("object"), ClaimSource::ObjectSymbol);
        assert_eq!(coerce_provider("rtti"), ClaimSource::Rtti);
        assert_eq!(
            coerce_provider("exception_handling"),
            ClaimSource::ExceptionHandling
        );
    }

    #[test]
    fn coerce_unknown_provider_degrades_to_naming() {
        assert_eq!(coerce_provider("brand_new_provider"), ClaimSource::Naming);
        assert_eq!(coerce_provider(""), ClaimSource::Naming);
    }
}
