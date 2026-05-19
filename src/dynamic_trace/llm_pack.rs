//! LLM-facing artifact emitters.
//!
//! Three emit functions land here, one per step in the plan:
//! - Step 11: [`emit_entity_graph`] + [`emit_behavior_facts`].
//! - Step 12: [`emit_behavior_fact_union`] — common envelope around
//!   static `BehaviorDossierRecord` AND dynamic
//!   `DynamicBehaviorFactRecord` so the LLM sees one fact stream
//!   instead of joining across files (Codex finding 6 complete fix).
//! - Step 13: [`emit_evidence_pack`] — top-N events + summary +
//!   uncertainties, with **negative claims suppressed when
//!   `events_dropped > 0`** (Codex finding 3 complete fix).
//!
//! All emit functions use [`crate::atomic_write::AtomicWriter`] for
//! one-shot artifacts (entity_graph, evidence_pack) and
//! [`crate::atomic_write::AtomicWriter`] streaming + finalize for
//! JSONL artifacts (behavior_facts, behavior_fact_union). A failed
//! emit leaves the prior file untouched.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;

use serde::Serialize;

use crate::atomic_write::AtomicWriter;
use crate::dynamic_trace::behavior_facts::LossMeta;
use crate::dynamic_trace::event::{EntityRef, EventType, TraceEvent};
use crate::dynamic_trace::store::TraceStore;
use crate::facts::confidence::Confidence;
use crate::facts::evidence::EvidenceRef;
use crate::pe::DynamicBehaviorFactRecord;

pub const GRAPH_SCHEMA: &str = "dynamic_trace.entity_graph.v1";
pub const UNION_SCHEMA: &str = "dynamic_trace.fact_union.v1";
pub const PACK_SCHEMA: &str = "dynamic_trace.evidence_pack.v1";

// ---------------------------------------------------------------------
// Step 11: entity_graph.json + behavior_facts.jsonl
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct EntityGraph<'a> {
    schema: &'a str,
    run_id: &'a str,
    nodes: Vec<EntityNode>,
    edges: Vec<EntityEdge>,
}

#[derive(Serialize, Clone, Debug)]
struct EntityNode {
    id: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
struct EntityEdge {
    from: String,
    to: String,
    edge_type: String,
    first_ts_ns: u64,
    last_ts_ns: u64,
    count: u64,
    event_refs: Vec<String>,
}

/// Emit `entity_graph.json` derived from the event stream. Each
/// distinct subject/object becomes a node; each event becomes an
/// (upserted) edge. Cap event_refs per edge at 32 in the wire output
/// so the JSON stays small even on busy targets.
pub fn emit_entity_graph(path: &Path, run_id: &str, events: &[TraceEvent]) -> io::Result<u64> {
    let mut nodes: BTreeMap<String, EntityNode> = BTreeMap::new();
    let mut edges: BTreeMap<(String, String, String), EntityEdge> = BTreeMap::new();

    let insert_node = |nodes: &mut BTreeMap<String, EntityNode>, e: &EntityRef| {
        nodes.entry(e.id.clone()).or_insert_with(|| EntityNode {
            id: e.id.clone(),
            kind: format!("{:?}", e.kind).to_lowercase(),
            name: e.name.clone(),
        });
    };

    for ev in events {
        insert_node(&mut nodes, &ev.subject);
        let Some(obj) = &ev.object else { continue };
        insert_node(&mut nodes, obj);

        let key = (ev.subject.id.clone(), obj.id.clone(), ev.operation.clone());
        let entry = edges.entry(key).or_insert(EntityEdge {
            from: ev.subject.id.clone(),
            to: obj.id.clone(),
            edge_type: ev.operation.clone(),
            first_ts_ns: ev.ts_ns,
            last_ts_ns: ev.ts_ns,
            count: 0,
            event_refs: Vec::new(),
        });
        entry.last_ts_ns = entry.last_ts_ns.max(ev.ts_ns);
        entry.first_ts_ns = entry.first_ts_ns.min(ev.ts_ns);
        entry.count += 1;
        if entry.event_refs.len() < 32 {
            entry.event_refs.push(ev.event_id.clone());
        }
    }

    let graph = EntityGraph {
        schema: GRAPH_SCHEMA,
        run_id,
        nodes: nodes.into_values().collect(),
        edges: edges.into_values().collect(),
    };
    let bytes = serde_json::to_vec_pretty(&graph).map_err(io::Error::other)?;
    let len = bytes.len() as u64;
    let mut w = AtomicWriter::create(path)?;
    w.write_all(&bytes)?;
    w.finalize()?;
    Ok(len)
}

/// Emit `behavior_facts.jsonl` — one JSONL record per dynamic fact.
pub fn emit_behavior_facts(path: &Path, facts: &[DynamicBehaviorFactRecord]) -> io::Result<u64> {
    let mut w = AtomicWriter::create(path)?;
    let mut bytes_written = 0u64;
    for fact in facts {
        let line = serde_json::to_vec(fact).map_err(io::Error::other)?;
        w.write_all(&line)?;
        w.write_all(b"\n")?;
        bytes_written += line.len() as u64 + 1;
    }
    w.finalize()?;
    Ok(bytes_written)
}

// ---------------------------------------------------------------------
// Step 12: behavior_fact_union.jsonl
// ---------------------------------------------------------------------

#[derive(Serialize, Debug, Clone)]
struct UnionEnvelope {
    schema: String,
    source: String,
    fact_id: String,
    run_id: String,
    category: String,
    claim: String,
    confidence: Confidence,
    evidence: Vec<EvidenceRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uncertainty: Option<String>,
}

/// Lightweight projection of `BehaviorDossierRecord` for the union
/// artifact. Callers convert their static dossiers to this shape;
/// keeping the union emitter agnostic of the static record's heavy
/// field set means we don't pull the full `BehaviorDossierRecord`
/// into the union code path.
#[derive(Clone, Debug)]
pub struct StaticFactView {
    pub fact_id: String,
    pub category: String,
    pub claim: String,
    pub confidence_score: f32,
    pub evidence: Vec<EvidenceRef>,
    pub uncertainty: Option<String>,
}

pub fn emit_behavior_fact_union(
    path: &Path,
    run_id: &str,
    static_facts: &[StaticFactView],
    dynamic_facts: &[DynamicBehaviorFactRecord],
) -> io::Result<u64> {
    let mut w = AtomicWriter::create(path)?;
    let mut bytes_written = 0u64;

    for sf in static_facts {
        let env = UnionEnvelope {
            schema: UNION_SCHEMA.to_string(),
            source: "static".into(),
            fact_id: sf.fact_id.clone(),
            run_id: run_id.to_string(),
            category: sf.category.clone(),
            claim: sf.claim.clone(),
            confidence: Confidence::from_score(sf.confidence_score),
            evidence: sf.evidence.clone(),
            uncertainty: sf.uncertainty.clone(),
        };
        let line = serde_json::to_vec(&env).map_err(io::Error::other)?;
        w.write_all(&line)?;
        w.write_all(b"\n")?;
        bytes_written += line.len() as u64 + 1;
    }

    for df in dynamic_facts {
        let env = UnionEnvelope {
            schema: UNION_SCHEMA.to_string(),
            source: "dynamic".into(),
            fact_id: df.fact_id.clone(),
            run_id: df.run_id.clone(),
            category: df.category.clone(),
            claim: df.claim.clone(),
            confidence: df.confidence.clone(),
            evidence: df.evidence.clone(),
            uncertainty: df.uncertainty.clone(),
        };
        let line = serde_json::to_vec(&env).map_err(io::Error::other)?;
        w.write_all(&line)?;
        w.write_all(b"\n")?;
        bytes_written += line.len() as u64 + 1;
    }

    w.finalize()?;
    Ok(bytes_written)
}

// ---------------------------------------------------------------------
// Step 13: evidence_pack.json with loss-aware semantics
// ---------------------------------------------------------------------

#[derive(Serialize, Debug, Clone)]
struct EvidencePack {
    schema: String,
    run_id: String,
    target: TargetInfo,
    duration_ms: u64,
    events_total: u64,
    events_dropped: u64,
    summary: Vec<String>,
    top_events: Vec<String>,
    top_facts: Vec<String>,
    uncertainties: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
struct TargetInfo {
    image: Option<String>,
    pid: Option<u32>,
    hash: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct PackInputs<'a> {
    pub run_id: &'a str,
    pub duration_ms: u64,
    pub target_image: Option<&'a str>,
    pub target_pid: Option<u32>,
    pub target_hash: Option<&'a str>,
    pub symbolication_miss_rate: f32,
}

pub fn emit_evidence_pack(
    path: &Path,
    inputs: &PackInputs<'_>,
    events: &[TraceEvent],
    facts: &[DynamicBehaviorFactRecord],
    loss: &LossMeta,
) -> io::Result<u64> {
    let events_total = events.len() as u64;
    let summary = build_summary(events, facts, loss);
    let top_events = rank_top_events(events, facts, 10);
    let top_facts = top_n_facts(facts, 10);
    let uncertainties = build_uncertainties(facts, loss, inputs.symbolication_miss_rate);

    let pack = EvidencePack {
        schema: PACK_SCHEMA.to_string(),
        run_id: inputs.run_id.to_string(),
        target: TargetInfo {
            image: inputs.target_image.map(String::from),
            pid: inputs.target_pid,
            hash: inputs.target_hash.map(String::from),
        },
        duration_ms: inputs.duration_ms,
        events_total,
        events_dropped: loss.events_dropped,
        summary,
        top_events,
        top_facts,
        uncertainties,
    };
    let bytes = serde_json::to_vec_pretty(&pack).map_err(io::Error::other)?;
    let len = bytes.len() as u64;
    let mut w = AtomicWriter::create(path)?;
    w.write_all(&bytes)?;
    w.finalize()?;
    Ok(len)
}

fn build_summary(
    events: &[TraceEvent],
    facts: &[DynamicBehaviorFactRecord],
    loss: &LossMeta,
) -> Vec<String> {
    let mut sentences = Vec::new();

    // Process activity.
    let process_starts = events
        .iter()
        .filter(|e| matches!(e.event_type, EventType::ProcessStart))
        .count();
    if process_starts > 0 {
        sentences.push(format!(
            "Process tree spawned {process_starts} child process(es)."
        ));
    }

    // File activity.
    let writes = events
        .iter()
        .filter(|e| matches!(e.event_type, EventType::FileWrite))
        .count();
    let reads = events
        .iter()
        .filter(|e| matches!(e.event_type, EventType::FileRead | EventType::FileOpen))
        .count();
    if writes > 0 || reads > 0 {
        sentences.push(format!(
            "File I/O: {writes} write(s), {reads} read/open(s)."
        ));
    }

    // Network activity — Codex finding 3 fix: SUPPRESS negative claim
    // when events were dropped. "no outbound activity observed" is
    // unsafe to assert in the presence of loss.
    let net_sends = events
        .iter()
        .filter(|e| {
            matches!(
                e.event_type,
                EventType::NetworkSend | EventType::NetworkConnect
            )
        })
        .count();
    if net_sends > 0 {
        sentences.push(format!("Network: {net_sends} outbound send/connect(s)."));
    } else if loss.events_dropped == 0 {
        sentences.push("Network: no outbound activity observed.".into());
    } else {
        sentences.push(format!(
            "Network: assessment insufficient ({} events dropped during capture).",
            loss.events_dropped
        ));
    }

    // Image-load activity (DLL counts).
    let image_loads = events
        .iter()
        .filter(|e| matches!(e.event_type, EventType::ImageLoad))
        .count();
    if image_loads > 0 {
        sentences.push(format!("Loaded {image_loads} module(s)."));
    }

    // Top-confidence behavior.
    if let Some(top) = facts
        .iter()
        .max_by(|a, b| a.confidence.score.partial_cmp(&b.confidence.score).unwrap())
    {
        sentences.push(format!(
            "Highest-confidence behavior: {} (band {:?}, score {:.2}).",
            top.category, top.confidence.band, top.confidence.score
        ));
    }

    sentences
}

fn rank_top_events(
    events: &[TraceEvent],
    facts: &[DynamicBehaviorFactRecord],
    n: usize,
) -> Vec<String> {
    // Build a quick "this event_id is referenced by a behavior fact"
    // index.
    let mut fact_refs: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for f in facts {
        for e in &f.evidence {
            if let EvidenceRef::TraceEvent { event_id } = e {
                *fact_refs.entry(event_id.clone()).or_insert(0) += 1;
            }
        }
    }

    let mut seen_types: std::collections::HashSet<EventType> = std::collections::HashSet::new();
    let mut scored: Vec<(f32, &TraceEvent)> = events
        .iter()
        .map(|ev| {
            let fact_bonus = (*fact_refs.get(&ev.event_id).unwrap_or(&0) as f32) * 3.0;
            let first_of_kind = if seen_types.insert(ev.event_type) {
                2.0
            } else {
                0.0
            };
            let rarity = match ev.event_type {
                EventType::ProcessStart | EventType::ImageLoad => 0.5,
                EventType::FileWrite | EventType::FileRead => 0.3,
                _ => 1.0,
            };
            (fact_bonus + first_of_kind + rarity, ev)
        })
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    scored
        .into_iter()
        .take(n)
        .map(|(_, e)| e.event_id.clone())
        .collect()
}

fn top_n_facts(facts: &[DynamicBehaviorFactRecord], n: usize) -> Vec<String> {
    let mut sorted: Vec<&DynamicBehaviorFactRecord> = facts.iter().collect();
    sorted.sort_by(|a, b| b.confidence.score.partial_cmp(&a.confidence.score).unwrap());
    sorted
        .into_iter()
        .take(n)
        .map(|f| f.fact_id.clone())
        .collect()
}

fn build_uncertainties(
    facts: &[DynamicBehaviorFactRecord],
    loss: &LossMeta,
    symbolication_miss_rate: f32,
) -> Vec<String> {
    let mut out = Vec::new();
    if loss.events_dropped > 0 {
        out.push(format!(
            "Captured stream dropped {} event(s); negative claims should not be trusted.",
            loss.events_dropped
        ));
    }
    if symbolication_miss_rate > 0.10 {
        out.push(format!(
            "Symbol resolution coverage {:.0}% (>10% miss rate). Module:offset attribution incomplete.",
            (1.0 - symbolication_miss_rate) * 100.0
        ));
    }
    // Stack-walk caveat is universal in v1.
    out.push("Stack-frame attribution unavailable in v1 (module + offset only).".into());

    // Low-confidence facts → uncertainty surface.
    let low_conf: Vec<&DynamicBehaviorFactRecord> =
        facts.iter().filter(|f| f.confidence.score < 0.65).collect();
    if !low_conf.is_empty() {
        out.push(format!(
            "{} dynamic fact(s) emitted with confidence < 0.65.",
            low_conf.len()
        ));
    }
    out
}

// Helper used by the smoke test to verify that ALL three writers
// finalize cleanly given a small synthetic input set.
pub fn emit_all(
    out_dir: &Path,
    inputs: &PackInputs<'_>,
    events: &[TraceEvent],
    static_facts: &[StaticFactView],
    dynamic_facts: &[DynamicBehaviorFactRecord],
    loss: &LossMeta,
    store: Option<&TraceStore>,
) -> io::Result<EmittedSizes> {
    let _ = store; // reserved for v1.1 cross-reference output
    Ok(EmittedSizes {
        entity_graph: emit_entity_graph(&out_dir.join("entity_graph.json"), inputs.run_id, events)?,
        behavior_facts: emit_behavior_facts(&out_dir.join("behavior_facts.jsonl"), dynamic_facts)?,
        behavior_fact_union: emit_behavior_fact_union(
            &out_dir.join("behavior_fact_union.jsonl"),
            inputs.run_id,
            static_facts,
            dynamic_facts,
        )?,
        evidence_pack: emit_evidence_pack(
            &out_dir.join("evidence_pack.json"),
            inputs,
            events,
            dynamic_facts,
            loss,
        )?,
    })
}

#[derive(Clone, Debug, Default)]
pub struct EmittedSizes {
    pub entity_graph: u64,
    pub behavior_facts: u64,
    pub behavior_fact_union: u64,
    pub evidence_pack: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic_trace::event::{EntityRef, EventResult, EventSource, EventType, HostOs};
    use tempfile::TempDir;

    fn mk_ev(et: EventType, n: u64, object_id: Option<&str>) -> TraceEvent {
        let mut ev = TraceEvent::new(
            &TraceEvent::format_event_id(n),
            "blake3:r",
            100 * n,
            HostOs::Windows,
            EventSource::Etw,
            4210,
            0,
            et,
            "op",
            EntityRef::process(4210, "t", Some("cmd.exe")),
        );
        if let Some(id) = object_id {
            let obj = if id.starts_with("file:") {
                EntityRef::file(&id[5..])
            } else if id.starts_with("sock:") {
                EntityRef::socket("0:0", &id[5..])
            } else {
                EntityRef::module(id)
            };
            ev.object = Some(obj);
        }
        ev.result = Some(EventResult::success());
        ev
    }

    fn fact(
        id: &str,
        category: &str,
        score: f32,
        evidence_ids: &[&str],
    ) -> DynamicBehaviorFactRecord {
        DynamicBehaviorFactRecord {
            schema: "dynamic_trace.behavior_fact.v1".into(),
            fact_id: id.into(),
            run_id: "r".into(),
            category: category.into(),
            claim: format!("test {category}"),
            confidence: Confidence::from_score(score),
            evidence: evidence_ids
                .iter()
                .map(|s| EvidenceRef::TraceEvent {
                    event_id: (*s).into(),
                })
                .collect(),
            uncertainty: None,
        }
    }

    #[test]
    fn entity_graph_round_trips_with_nodes_and_edges() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("entity_graph.json");
        let events = vec![
            mk_ev(EventType::FileWrite, 1, Some("file:C:\\tmp\\x")),
            mk_ev(EventType::FileWrite, 2, Some("file:C:\\tmp\\x")),
            mk_ev(EventType::FileRead, 3, Some("file:C:\\tmp\\y")),
        ];
        emit_entity_graph(&path, "run", &events).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let nodes = json["nodes"].as_array().unwrap();
        let edges = json["edges"].as_array().unwrap();
        assert_eq!(nodes.len(), 3); // proc:4210 + 2 file nodes
        assert_eq!(edges.len(), 2); // 2 op-grouped edges
        assert_eq!(json["schema"], "dynamic_trace.entity_graph.v1");
    }

    #[test]
    fn behavior_facts_jsonl_writes_one_record_per_line() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("behavior_facts.jsonl");
        let facts = vec![
            fact("fact_0001", "persistence", 0.78, &["evt_0000000001"]),
            fact("fact_0002", "discovery", 0.82, &["evt_0000000002"]),
        ];
        emit_behavior_facts(&path, &facts).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
        for line in content.lines() {
            let _: DynamicBehaviorFactRecord = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn behavior_fact_union_combines_static_and_dynamic_sources() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("behavior_fact_union.jsonl");
        let static_facts = vec![StaticFactView {
            fact_id: "bd_0001".into(),
            category: "code_injection".into(),
            claim: "Binary imports CreateRemoteThread".into(),
            confidence_score: 0.78,
            evidence: vec![EvidenceRef::Instruction { va: 0x140012a40 }],
            uncertainty: None,
        }];
        let dynamic_facts = vec![fact("fact_0001", "persistence", 0.85, &["evt_0000000001"])];
        emit_behavior_fact_union(&path, "run", &static_facts, &dynamic_facts).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let static_env: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let dynamic_env: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(static_env["source"], "static");
        assert_eq!(dynamic_env["source"], "dynamic");
        assert_eq!(static_env["fact_id"], "bd_0001");
        assert_eq!(dynamic_env["fact_id"], "fact_0001");
    }

    #[test]
    fn evidence_pack_summary_includes_negative_network_claim_when_no_loss() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("evidence_pack.json");
        let events = vec![mk_ev(EventType::FileWrite, 1, Some("file:C:\\tmp\\x"))];
        let inputs = PackInputs {
            run_id: "r",
            duration_ms: 100,
            target_image: Some("cmd.exe"),
            target_pid: Some(4210),
            target_hash: Some("blake3:abc"),
            symbolication_miss_rate: 0.0,
        };
        emit_evidence_pack(&path, &inputs, &events, &[], &LossMeta::default()).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let summary: Vec<String> = serde_json::from_value(json["summary"].clone()).unwrap();
        assert!(summary
            .iter()
            .any(|s| s == "Network: no outbound activity observed."));
    }

    #[test]
    fn evidence_pack_summary_suppresses_negative_network_claim_when_lossy() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("evidence_pack.json");
        let events = vec![mk_ev(EventType::FileWrite, 1, Some("file:C:\\tmp\\x"))];
        let inputs = PackInputs {
            run_id: "r",
            duration_ms: 100,
            target_image: Some("cmd.exe"),
            target_pid: Some(4210),
            target_hash: Some("blake3:abc"),
            symbolication_miss_rate: 0.0,
        };
        let loss = LossMeta { events_dropped: 42 };
        emit_evidence_pack(&path, &inputs, &events, &[], &loss).unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let summary: Vec<String> = serde_json::from_value(json["summary"].clone()).unwrap();
        // Negative claim REPLACED with insufficient-evidence assessment.
        assert!(
            summary
                .iter()
                .any(|s| s.contains("assessment insufficient")),
            "expected suppression of negative claim, got: {summary:?}"
        );
        assert!(
            !summary
                .iter()
                .any(|s| s == "Network: no outbound activity observed."),
            "negative claim must be suppressed under loss"
        );
        // Uncertainty mentions the drop.
        let uncertainties: Vec<String> =
            serde_json::from_value(json["uncertainties"].clone()).unwrap();
        assert!(uncertainties.iter().any(|s| s.contains("dropped 42")));
    }

    #[test]
    fn top_events_ranking_prioritizes_fact_referenced_events() {
        let events: Vec<TraceEvent> = (1..=10)
            .map(|i| mk_ev(EventType::FileWrite, i, Some(&format!("file:/x{i}"))))
            .collect();
        let facts = vec![fact(
            "fact_0001",
            "exfil_staging",
            0.85,
            &["evt_0000000007", "evt_0000000003"],
        )];
        let top = rank_top_events(&events, &facts, 5);
        assert!(top.contains(&"evt_0000000003".to_string()));
        assert!(top.contains(&"evt_0000000007".to_string()));
        // The fact-referenced events should come first.
        assert_eq!(top[0], "evt_0000000003");
        assert_eq!(top[1], "evt_0000000007");
    }

    #[test]
    fn emit_all_writes_all_four_artifacts_on_disk() {
        let tmp = TempDir::new().unwrap();
        let events = vec![mk_ev(EventType::FileWrite, 1, Some("file:C:\\tmp\\x"))];
        let facts = vec![fact("fact_0001", "persistence", 0.78, &["evt_0000000001"])];
        let static_facts: Vec<StaticFactView> = Vec::new();
        let inputs = PackInputs {
            run_id: "r",
            duration_ms: 100,
            ..Default::default()
        };
        let sizes = emit_all(
            tmp.path(),
            &inputs,
            &events,
            &static_facts,
            &facts,
            &LossMeta::default(),
            None,
        )
        .unwrap();
        assert!(tmp.path().join("entity_graph.json").exists());
        assert!(tmp.path().join("behavior_facts.jsonl").exists());
        assert!(tmp.path().join("behavior_fact_union.jsonl").exists());
        assert!(tmp.path().join("evidence_pack.json").exists());
        assert!(sizes.entity_graph > 0);
        assert!(sizes.behavior_facts > 0);
        assert!(sizes.evidence_pack > 0);
    }
}
