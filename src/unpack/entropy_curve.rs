//! Streaming per-region Shannon entropy time-series.
//!
//! Aurora samples region entropy at intervals during the
//! unpacking run. The "entropy drops sharply" signal is the
//! strongest of the 4 OEP signals: packed bytes look random
//! (entropy ≈ 8.0); decoded x86 code looks structured
//! (entropy ≈ 5.5–6.5). A drop from ≥7.2 to ≤6.5 in the same
//! region is the canonical "the packer just unpacked" signal.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::atomic_write::write_atomic;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntropySample {
    pub ts_ms: u64,
    pub region_id: u32,
    pub entropy: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntropyDropEvent {
    pub region_id: u32,
    pub before: f64,
    pub after: f64,
    pub at_ts_ms: u64,
}

pub struct EntropyCurve {
    samples: Vec<EntropySample>,
}

impl EntropyCurve {
    pub fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    pub fn sample(&mut self, ts_ms: u64, region_id: u32, bytes: &[u8]) {
        self.samples.push(EntropySample {
            ts_ms,
            region_id,
            entropy: shannon_entropy(bytes),
        });
    }

    pub fn samples(&self) -> &[EntropySample] {
        &self.samples
    }

    /// Detect entropy drops: for each region, find consecutive
    /// samples where the second is at least `delta` lower AND
    /// the first was above `high_threshold`. Drop semantics
    /// match the unpacking-stub-finished signal.
    pub fn detect_drops(&self, delta: f64, high_threshold: f64) -> Vec<EntropyDropEvent> {
        let mut out = Vec::new();
        let mut by_region: std::collections::BTreeMap<u32, Vec<&EntropySample>> =
            std::collections::BTreeMap::new();
        for s in &self.samples {
            by_region.entry(s.region_id).or_default().push(s);
        }
        for (region_id, mut samples) in by_region {
            samples.sort_by_key(|s| s.ts_ms);
            for w in samples.windows(2) {
                if w[0].entropy >= high_threshold && (w[0].entropy - w[1].entropy) >= delta {
                    out.push(EntropyDropEvent {
                        region_id,
                        before: w[0].entropy,
                        after: w[1].entropy,
                        at_ts_ms: w[1].ts_ms,
                    });
                }
            }
        }
        out
    }

    pub fn emit_jsonl(&self, path: &Path) -> std::io::Result<u64> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut buf: Vec<u8> = Vec::with_capacity(self.samples.len() * 80);
        for s in &self.samples {
            let line = serde_json::to_string(s)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            buf.extend_from_slice(line.as_bytes());
            buf.push(b'\n');
        }
        write_atomic(path, &buf)?;
        Ok(buf.len() as u64)
    }
}

impl Default for EntropyCurve {
    fn default() -> Self {
        Self::new()
    }
}

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut h = 0.0_f64;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        h -= p * p.log2();
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_bytes_entropy_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn zero_bytes_entropy_zero() {
        assert_eq!(shannon_entropy(&[0u8; 4096]), 0.0);
    }

    #[test]
    fn uniform_bytes_entropy_near_eight() {
        let bytes: Vec<u8> = (0..=255u8).cycle().take(256 * 32).collect();
        let h = shannon_entropy(&bytes);
        assert!((h - 8.0).abs() < 0.01);
    }

    #[test]
    fn sample_records_ts_and_region_id() {
        let mut curve = EntropyCurve::new();
        curve.sample(100, 0, &[0u8; 16]);
        curve.sample(200, 0, &[0u8; 16]);
        assert_eq!(curve.samples().len(), 2);
        assert_eq!(curve.samples()[0].region_id, 0);
        assert_eq!(curve.samples()[0].ts_ms, 100);
    }

    #[test]
    fn detect_drops_finds_high_to_low_transition() {
        let mut curve = EntropyCurve::new();
        // High-entropy random-looking bytes
        curve.samples.push(EntropySample {
            ts_ms: 100,
            region_id: 0,
            entropy: 7.8,
        });
        // After unpacking — structured code
        curve.samples.push(EntropySample {
            ts_ms: 200,
            region_id: 0,
            entropy: 5.9,
        });
        let drops = curve.detect_drops(1.0, 7.2);
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].region_id, 0);
        assert!((drops[0].before - 7.8).abs() < 0.001);
        assert!((drops[0].after - 5.9).abs() < 0.001);
    }

    #[test]
    fn detect_drops_ignores_small_changes() {
        let mut curve = EntropyCurve::new();
        curve.samples.push(EntropySample {
            ts_ms: 100,
            region_id: 0,
            entropy: 7.8,
        });
        curve.samples.push(EntropySample {
            ts_ms: 200,
            region_id: 0,
            entropy: 7.5,
        });
        assert!(curve.detect_drops(1.0, 7.2).is_empty());
    }

    #[test]
    fn detect_drops_isolates_per_region() {
        let mut curve = EntropyCurve::new();
        curve.samples.push(EntropySample {
            ts_ms: 100,
            region_id: 0,
            entropy: 7.8,
        });
        curve.samples.push(EntropySample {
            ts_ms: 100,
            region_id: 1,
            entropy: 5.9,
        });
        curve.samples.push(EntropySample {
            ts_ms: 200,
            region_id: 0,
            entropy: 5.9,
        });
        let drops = curve.detect_drops(1.0, 7.2);
        assert_eq!(drops.len(), 1);
        assert_eq!(drops[0].region_id, 0);
    }

    #[test]
    fn emit_jsonl_round_trips() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut curve = EntropyCurve::new();
        curve.sample(0, 0, &[0u8; 16]);
        curve.sample(100, 0, &[0xFFu8; 16]);
        let path = tmp.path().join("entropy_curve.jsonl");
        curve.emit_jsonl(&path).expect("emit");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2);
        for line in text.lines() {
            let _: EntropySample = serde_json::from_str(line).unwrap();
        }
    }
}
