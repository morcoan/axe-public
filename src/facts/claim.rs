use serde::{Deserialize, Serialize};

use crate::facts::confidence::Confidence;
use crate::facts::evidence::EvidenceRef;
use crate::facts::provider::ClaimSource;

/// A typed claim about a recovered fact, with source attribution,
/// confidence, and evidence references.
///
/// `T` is the claimed value (a string for a class name, an integer for
/// a field size, `()` for a "this thing exists" marker).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Claim<T> {
    pub value: T,
    pub source: ClaimSource,
    pub confidence: Confidence,
    pub evidence: Vec<EvidenceRef>,
}

impl<T> Claim<T> {
    /// Construct a claim with the source's default-band midpoint as confidence
    /// and an empty evidence vec. Callers should typically `.with_evidence(...)`
    /// before storing.
    pub fn new(value: T, source: ClaimSource) -> Self {
        let (lo, hi) = source.default_confidence_band();
        let mid = (lo + hi) * 0.5;
        Self {
            value,
            source,
            confidence: Confidence::from_score(mid),
            evidence: Vec::new(),
        }
    }

    /// Override the default-band score. Caller is responsible for staying
    /// within the source's band — see `ClaimSource::default_confidence_band`.
    pub fn with_score(mut self, score: f32) -> Self {
        self.confidence = Confidence::from_score(score);
        self
    }

    /// Replace the confidence wholesale (band + score).
    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Append evidence refs.
    pub fn with_evidence(mut self, ev: impl IntoIterator<Item = EvidenceRef>) -> Self {
        self.evidence.extend(ev);
        self
    }

    pub fn push_evidence(&mut self, ev: EvidenceRef) {
        self.evidence.push(ev);
    }

    /// Map the value while preserving source / confidence / evidence.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Claim<U> {
        Claim {
            value: f(self.value),
            source: self.source,
            confidence: self.confidence,
            evidence: self.evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::confidence::ConfidenceBand;

    #[test]
    fn new_uses_source_band_midpoint() {
        let c = Claim::new("Foo".to_string(), ClaimSource::Pdb);
        // PDB band is (0.98, 1.00), midpoint 0.99.
        assert!((c.confidence.as_f32() - 0.99).abs() < 1e-6);
        assert_eq!(c.confidence.band, ConfidenceBand::High);
        assert!(c.evidence.is_empty());
    }

    #[test]
    fn with_score_overrides_default() {
        let c = Claim::new((), ClaimSource::Rtti).with_score(0.88);
        assert!((c.confidence.as_f32() - 0.88).abs() < 1e-6);
    }

    #[test]
    fn with_evidence_appends() {
        let c = Claim::new((), ClaimSource::ExceptionHandling).with_evidence(vec![
            EvidenceRef::Instruction { va: 0x100 },
            EvidenceRef::Section {
                name: ".pdata".into(),
                va: 0x200,
            },
        ]);
        assert_eq!(c.evidence.len(), 2);
    }

    #[test]
    fn map_preserves_metadata() {
        let c = Claim::new(42u32, ClaimSource::Dwarf).with_score(0.99);
        let mapped = c.clone().map(|n| n.to_string());
        assert_eq!(mapped.value, "42");
        assert_eq!(mapped.source, c.source);
        assert_eq!(mapped.confidence, c.confidence);
    }
}
