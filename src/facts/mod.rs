//! Facts framework: structured `Claim<T>` + `Evidence` + `Confidence` shared by
//! all fact-emitting passes (switches, eh, cpp_classes).
//!
//! `dead_code` is allowed across this module until step 2 (`src/switches.rs`)
//! lands and starts consuming these types. Without this, the foundational
//! `pub use` re-exports would be flagged because the parent `mod facts;` is
//! crate-private, so the items are not reachable externally.
#![allow(dead_code)]
//!
//! Every recovered fact carries a `ClaimSource` (PDB / RTTI / EH / heuristic / …),
//! a numeric `Confidence`, and a list of `EvidenceRef`s that point back at the
//! bytes that justify the claim. Downstream LLM consumers can therefore filter,
//! sort, and explain results without re-deriving provenance from the raw artifact.
//!
//! Wire compatibility: a bridge in [`provider`] lifts existing
//! `SymbolGraphRecord` rows (which use a `String` confidence like `"high"` and
//! `"rva_or_va:<HEX>"` evidence strings) into the typed framework on demand.
//! The `symbol_graph/1` schema is untouched.

pub const FACTS_SCHEMA: &str = "facts/1";
pub const EVIDENCE_SCHEMA: &str = "evidence/1";

pub mod claim;
pub mod confidence;
pub mod evidence;
pub mod provider;

pub use claim::Claim;
pub use confidence::{Confidence, ConfidenceBand};
pub use evidence::{Evidence, EvidenceRef};
pub use provider::{coerce_provider, ClaimSource};
