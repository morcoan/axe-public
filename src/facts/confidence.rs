use serde::{Deserialize, Serialize};

/// Coarse confidence bucket. Wire-compatible with the legacy
/// `SymbolGraphRecord.confidence: String` field ("high"/"medium"/"low").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceBand {
    High,
    Medium,
    Low,
    Unknown,
}

impl ConfidenceBand {
    /// Numeric midpoint used when only a band is known.
    pub fn midpoint(self) -> f32 {
        match self {
            ConfidenceBand::High => 0.92,
            ConfidenceBand::Medium => 0.70,
            ConfidenceBand::Low => 0.45,
            ConfidenceBand::Unknown => 0.30,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ConfidenceBand::High => "high",
            ConfidenceBand::Medium => "medium",
            ConfidenceBand::Low => "low",
            ConfidenceBand::Unknown => "unknown",
        }
    }

    /// Bucket a numeric score into a band using fixed thresholds.
    /// Thresholds are deliberately wide so heuristic-tuning churn does
    /// not reshuffle existing facts.
    pub fn from_score(score: f32) -> Self {
        if score >= 0.85 {
            ConfidenceBand::High
        } else if score >= 0.60 {
            ConfidenceBand::Medium
        } else if score >= 0.35 {
            ConfidenceBand::Low
        } else {
            ConfidenceBand::Unknown
        }
    }
}

/// A confidence value: both a coarse band and a precise score.
///
/// Wire shape: `{"band": "high", "score": 0.92}`. Always carries both views so
/// downstream consumers can filter or sort without branching on shape.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Confidence {
    pub band: ConfidenceBand,
    pub score: f32,
}

impl Confidence {
    /// Build from a numeric score; band is derived from thresholds.
    pub fn from_score(score: f32) -> Self {
        let clamped = score.clamp(0.0, 1.0);
        Self {
            band: ConfidenceBand::from_score(clamped),
            score: clamped,
        }
    }

    /// Build from a coarse band; score is the band midpoint.
    pub fn from_band(band: ConfidenceBand) -> Self {
        Self {
            band,
            score: band.midpoint(),
        }
    }

    /// Parse from either a numeric string ("0.83") or a band string
    /// ("high"/"medium"/"low"/"unknown"). Unknown input maps to the
    /// `Unknown` band rather than failing.
    pub fn from_str(s: &str) -> Self {
        if let Ok(score) = s.parse::<f32>() {
            return Self::from_score(score);
        }
        let band = match s.to_ascii_lowercase().as_str() {
            "high" => ConfidenceBand::High,
            "medium" | "med" => ConfidenceBand::Medium,
            "low" => ConfidenceBand::Low,
            _ => ConfidenceBand::Unknown,
        };
        Self::from_band(band)
    }

    pub fn as_f32(&self) -> f32 {
        self.score
    }

    /// Returns the legacy band string ("high"/"medium"/"low"/"unknown")
    /// for wire compatibility with `SymbolGraphRecord.confidence`.
    pub fn to_legacy_band(&self) -> &'static str {
        self.band.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_from_score_thresholds() {
        assert_eq!(ConfidenceBand::from_score(0.95), ConfidenceBand::High);
        assert_eq!(ConfidenceBand::from_score(0.85), ConfidenceBand::High);
        assert_eq!(ConfidenceBand::from_score(0.70), ConfidenceBand::Medium);
        assert_eq!(ConfidenceBand::from_score(0.60), ConfidenceBand::Medium);
        assert_eq!(ConfidenceBand::from_score(0.40), ConfidenceBand::Low);
        assert_eq!(ConfidenceBand::from_score(0.10), ConfidenceBand::Unknown);
    }

    #[test]
    fn confidence_from_score_clamps_and_buckets() {
        let c = Confidence::from_score(0.83);
        assert_eq!(c.band, ConfidenceBand::Medium);
        assert!((c.as_f32() - 0.83).abs() < 1e-6);

        let clamped_high = Confidence::from_score(1.5);
        assert_eq!(clamped_high.score, 1.0);

        let clamped_low = Confidence::from_score(-0.2);
        assert_eq!(clamped_low.score, 0.0);
    }

    #[test]
    fn confidence_from_band_uses_midpoint() {
        let c = Confidence::from_band(ConfidenceBand::High);
        assert!((c.score - 0.92).abs() < 1e-6);
        assert_eq!(c.band, ConfidenceBand::High);
    }

    #[test]
    fn confidence_from_str_handles_numeric_and_band() {
        assert_eq!(Confidence::from_str("high").band, ConfidenceBand::High);
        assert_eq!(Confidence::from_str("medium").band, ConfidenceBand::Medium);
        assert_eq!(Confidence::from_str("low").band, ConfidenceBand::Low);
        assert_eq!(Confidence::from_str("0.92").band, ConfidenceBand::High);
        assert_eq!(Confidence::from_str("0.50").band, ConfidenceBand::Low);
        assert_eq!(Confidence::from_str("bogus").band, ConfidenceBand::Unknown);
        assert_eq!(Confidence::from_str("HIGH").band, ConfidenceBand::High);
    }

    #[test]
    fn to_legacy_band_matches_existing_symbol_graph_strings() {
        // src/symbol_graph.rs writes literal "high"/"medium"/"low"; these
        // must remain byte-identical for downstream parsers.
        for s in ["high", "medium", "low"] {
            let c = Confidence::from_str(s);
            assert_eq!(c.to_legacy_band(), s);
        }
    }

    #[test]
    fn confidence_serializes_with_both_band_and_score() {
        let c = Confidence::from_score(0.91);
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains(r#""band":"high""#), "got: {json}");
        assert!(json.contains(r#""score":0.91"#), "got: {json}");
    }
}
