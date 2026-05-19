use serde::{Deserialize, Serialize};

/// A pointer to the bytes or record that justify a claim.
///
/// Tagged enum on the wire (`{"kind": "instruction", "va": "0x..."}`).
/// VAs serialize as `0x`-prefixed lowercase 16-char hex strings to avoid
/// u64 precision loss in JSON numbers and to match the legacy
/// `"rva_or_va:<HEX>"` evidence format used by `symbol_graph.jsonl`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceRef {
    /// A single instruction at the given VA.
    Instruction {
        #[serde(with = "hex_va")]
        va: u64,
    },
    /// A half-open VA range (basic block, function chunk, table region).
    Range {
        #[serde(with = "hex_va")]
        start_va: u64,
        #[serde(with = "hex_va")]
        end_va: u64,
    },
    /// A section (`.rdata`, `.pdata`, `.eh_frame`, …) with an anchor VA.
    Section {
        name: String,
        #[serde(with = "hex_va")]
        va: u64,
    },
    /// A debug-info record (PDB symbol index, DWARF DIE offset).
    DebugRecord { provider: String, key: String },
    /// A cross-reference to an existing artifact row. `entity_kind`
    /// names the referenced row's kind (e.g. `"function_symbol"`,
    /// `"type_def"`); it is intentionally NOT named `kind` to avoid
    /// colliding with the serde internal-tag discriminator.
    Artifact { entity_kind: String, id: String },
    /// Raw VA escape hatch, byte-identical to the legacy `rva_or_va:<HEX>`
    /// format. Use for round-trip with existing `symbol_graph.jsonl` readers.
    RawAddr {
        #[serde(with = "hex_va")]
        va: u64,
    },
    /// Reference to an event in `out/dynamic_trace/events.ndjson`.
    ///
    /// Typed-only in v1: `to_legacy_string()` returns `None` for this
    /// variant. The legacy `rva_or_va:<HEX>` consumers parse only VAs,
    /// and inventing a `trace_event:evt_NNNN` second dialect would
    /// create silent misparses across `symbol_graph.jsonl` readers
    /// that don't yet know about runtime events. Parser support is
    /// deferred to v1.1, once a dynamic-trace consumer actually
    /// requires legacy-string interop.
    TraceEvent { event_id: String },
}

impl EvidenceRef {
    /// Render as `"rva_or_va:<16-uppercase-hex>"` when the variant carries a VA.
    /// Returns `None` for variants without a single anchor VA
    /// (`DebugRecord`, `Artifact`).
    ///
    /// This preserves wire compatibility with consumers of
    /// `symbol_graph.jsonl::evidence` such as
    /// `llm_artifacts::parse_symbol_graph_evidence`.
    pub fn to_legacy_string(&self) -> Option<String> {
        let va = match self {
            EvidenceRef::Instruction { va }
            | EvidenceRef::RawAddr { va }
            | EvidenceRef::Section { va, .. } => *va,
            EvidenceRef::Range { start_va, .. } => *start_va,
            EvidenceRef::DebugRecord { .. }
            | EvidenceRef::Artifact { .. }
            | EvidenceRef::TraceEvent { .. } => return None,
        };
        Some(format!("rva_or_va:{va:016X}"))
    }
}

mod hex_va {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(va: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{va:016x}"))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        let trimmed = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(&s);
        u64::from_str_radix(trimmed, 16).map_err(serde::de::Error::custom)
    }
}

/// Convenience newtype around a vec of evidence refs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence(pub Vec<EvidenceRef>);

impl Evidence {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push(&mut self, r: EvidenceRef) {
        self.0.push(r);
    }

    pub fn extend(&mut self, it: impl IntoIterator<Item = EvidenceRef>) {
        self.0.extend(it);
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Render every VA-bearing evidence ref as the legacy
    /// `"rva_or_va:<HEX>"` strings, dropping non-VA variants. Use when
    /// emitting compat rows alongside the typed evidence vec.
    pub fn to_legacy_strings(&self) -> Vec<String> {
        self.0
            .iter()
            .filter_map(EvidenceRef::to_legacy_string)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_to_legacy_string() {
        let r = EvidenceRef::Instruction { va: 0x140012340 };
        assert_eq!(
            r.to_legacy_string().as_deref(),
            Some("rva_or_va:0000000140012340"),
        );
    }

    #[test]
    fn raw_addr_matches_existing_symbol_graph_format() {
        // src/symbol_graph.rs:1032 emits exactly this format.
        let r = EvidenceRef::RawAddr { va: 0x140020000 };
        assert_eq!(
            r.to_legacy_string().as_deref(),
            Some("rva_or_va:0000000140020000"),
        );
    }

    #[test]
    fn range_uses_start_va_for_legacy_string() {
        let r = EvidenceRef::Range {
            start_va: 0x1000,
            end_va: 0x1100,
        };
        assert_eq!(
            r.to_legacy_string().as_deref(),
            Some("rva_or_va:0000000000001000"),
        );
    }

    #[test]
    fn debug_record_and_artifact_have_no_legacy_string() {
        let d = EvidenceRef::DebugRecord {
            provider: "pdb".into(),
            key: "sym/12".into(),
        };
        let a = EvidenceRef::Artifact {
            entity_kind: "function_symbol".into(),
            id: "foo".into(),
        };
        assert!(d.to_legacy_string().is_none());
        assert!(a.to_legacy_string().is_none());
    }

    #[test]
    fn trace_event_has_no_legacy_string() {
        let t = EvidenceRef::TraceEvent {
            event_id: "evt_0000018342".into(),
        };
        assert!(
            t.to_legacy_string().is_none(),
            "TraceEvent is typed-only in v1; emitting a legacy string would create a second dialect"
        );
    }

    #[test]
    fn trace_event_roundtrips_through_json() {
        let t = EvidenceRef::TraceEvent {
            event_id: "evt_0000018342".into(),
        };
        let s = serde_json::to_string(&t).unwrap();
        assert!(s.contains(r#""kind":"trace_event""#), "got: {s}");
        assert!(s.contains(r#""event_id":"evt_0000018342""#), "got: {s}");
        let back: EvidenceRef = serde_json::from_str(&s).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn evidence_to_legacy_strings_skips_trace_event_variants() {
        let mut e = Evidence::new();
        e.push(EvidenceRef::Instruction { va: 0x100 });
        e.push(EvidenceRef::TraceEvent {
            event_id: "evt_0000000007".into(),
        });
        e.push(EvidenceRef::RawAddr { va: 0x200 });
        let legacy = e.to_legacy_strings();
        // TraceEvent dropped silently; only the two VA variants make it through.
        assert_eq!(legacy.len(), 2);
        assert!(legacy[0].ends_with("0000000000000100"));
        assert!(legacy[1].ends_with("0000000000000200"));
    }

    #[test]
    fn evidence_serializes_with_kind_discriminator() {
        let r = EvidenceRef::Instruction { va: 0x12340 };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""kind":"instruction""#), "got: {s}");
        assert!(s.contains(r#""va":"0x0000000000012340""#), "got: {s}");
    }

    #[test]
    fn evidence_roundtrips_through_json() {
        let r = EvidenceRef::Range {
            start_va: 0x1000,
            end_va: 0x1100,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: EvidenceRef = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn evidence_to_legacy_strings_skips_non_va_variants() {
        let mut e = Evidence::new();
        e.push(EvidenceRef::Instruction { va: 0x100 });
        e.push(EvidenceRef::DebugRecord {
            provider: "pdb".into(),
            key: "x".into(),
        });
        e.push(EvidenceRef::RawAddr { va: 0x200 });
        let legacy = e.to_legacy_strings();
        assert_eq!(legacy.len(), 2);
        assert!(legacy[0].ends_with("0000000000000100"));
        assert!(legacy[1].ends_with("0000000000000200"));
    }
}
