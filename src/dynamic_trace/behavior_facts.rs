//! Capability detectors — strict coverage-matrix v1 set
//! (Codex finding 2 fix).
//!
//! Each detector is a pure function `Fn(&[TraceEvent]) -> Vec<Fact>`.
//! The detector set is intentionally narrow: every detector below has
//! a clear evidence chain in the v1 kernel-provider bundle. Detectors
//! that require the `Microsoft-Windows-Kernel-Object` provider (e.g.
//! `code_injection` via `WriteProcessMemory` + `CreateRemoteThread`,
//! LSASS direct access, generic process-enumeration) are EXPLICITLY
//! NOT IMPLEMENTED in v1 — they're listed in the
//! [`V1_1_PLANNED_DETECTORS`] doc block so a future commit can light
//! them up by adding the Object provider to the bundle.
//!
//! Codex finding 3 partial fix: every emitted fact carries an
//! `uncertainty: Some("captured_stream_had_N_dropped_events")`
//! annotation when [`LossMeta::events_dropped > 0`]. The session
//! orchestrator (Step 17) is the canonical source of that count.

#![allow(dead_code)]

use std::collections::HashSet;

use crate::dynamic_trace::event::{EventType, TraceEvent};
use crate::facts::confidence::Confidence;
use crate::facts::evidence::EvidenceRef;
use crate::pe::DynamicBehaviorFactRecord;

pub const FACT_SCHEMA: &str = "dynamic_trace.behavior_fact.v1";

/// v1.1 detectors that need the Object provider — listed for the
/// roadmap doc only.
pub const V1_1_PLANNED_DETECTORS: &[&str] = &[
    "code_injection (needs WriteProcessMemory/CreateRemoteThread → Object provider)",
    "lsass_credential_access (needs OpenProcess(LSASS) → Object provider)",
    "process_enumeration (needs many OpenProcess calls → Object provider)",
];

#[derive(Clone, Debug, Default)]
pub struct LossMeta {
    pub events_dropped: u64,
}

/// Run every v1 detector against the event slice. The returned facts
/// are ordered by detector ID for stable output.
pub fn extract_facts(
    run_id: &str,
    events: &[TraceEvent],
    loss: &LossMeta,
) -> Vec<DynamicBehaviorFactRecord> {
    let mut out = Vec::new();
    let mut next_id = 1u64;

    out.extend(detect_persistence(run_id, events, &mut next_id, loss));
    out.extend(detect_defense_evasion(run_id, events, &mut next_id, loss));
    out.extend(detect_exfil_staging(run_id, events, &mut next_id, loss));
    out.extend(detect_discovery(run_id, events, &mut next_id, loss));
    out.extend(detect_service_creation(run_id, events, &mut next_id, loss));
    out.extend(detect_browser_credential_access(
        run_id,
        events,
        &mut next_id,
        loss,
    ));

    out
}

fn next_fact_id(counter: &mut u64) -> String {
    let n = *counter;
    *counter += 1;
    format!("fact_{n:04}")
}

fn build_fact(
    run_id: &str,
    fact_id: String,
    category: &str,
    claim: String,
    confidence: f32,
    evidence: Vec<EvidenceRef>,
    loss: &LossMeta,
) -> DynamicBehaviorFactRecord {
    let uncertainty = if loss.events_dropped > 0 {
        Some(format!(
            "captured_stream_had_{}_dropped_events; negative claims (e.g. no_network_activity) should not be trusted",
            loss.events_dropped
        ))
    } else {
        None
    };
    DynamicBehaviorFactRecord {
        schema: FACT_SCHEMA.to_string(),
        fact_id,
        run_id: run_id.to_string(),
        category: category.to_string(),
        claim,
        confidence: Confidence::from_score(confidence),
        evidence,
        uncertainty,
    }
}

// ---------------------------------------------------------------------
// Detectors
// ---------------------------------------------------------------------

fn detect_persistence(
    run_id: &str,
    events: &[TraceEvent],
    next_id: &mut u64,
    loss: &LossMeta,
) -> Vec<DynamicBehaviorFactRecord> {
    let mut hits = Vec::new();
    for ev in events {
        match ev.event_type {
            EventType::RegistryWrite => {
                if let Some(obj) = &ev.object {
                    let lower = obj.id.to_lowercase();
                    if lower.contains("\\software\\microsoft\\windows\\currentversion\\run") {
                        hits.push(EvidenceRef::TraceEvent {
                            event_id: ev.event_id.clone(),
                        });
                    }
                }
            }
            EventType::FileWrite => {
                if let Some(obj) = &ev.object {
                    if obj.id.to_lowercase().contains("\\system32\\tasks\\") {
                        hits.push(EvidenceRef::TraceEvent {
                            event_id: ev.event_id.clone(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    if hits.is_empty() {
        return Vec::new();
    }
    let confidence = score_from_hits(0.72, hits.len());
    vec![build_fact(
        run_id,
        next_fact_id(next_id),
        "persistence",
        format!(
            "Process wrote to {} persistence mechanism(s) (Run key or scheduled-task file).",
            hits.len()
        ),
        confidence,
        hits,
        loss,
    )]
}

fn detect_defense_evasion(
    run_id: &str,
    events: &[TraceEvent],
    next_id: &mut u64,
    loss: &LossMeta,
) -> Vec<DynamicBehaviorFactRecord> {
    let hits: Vec<EvidenceRef> = events
        .iter()
        .filter(|ev| matches!(ev.event_type, EventType::RegistryWrite))
        .filter(|ev| {
            ev.object
                .as_ref()
                .map(|o| {
                    let lower = o.id.to_lowercase();
                    lower.contains("\\windows defender")
                        || lower.contains("\\policies\\microsoft\\windows defender")
                })
                .unwrap_or(false)
        })
        .map(|ev| EvidenceRef::TraceEvent {
            event_id: ev.event_id.clone(),
        })
        .collect();
    if hits.is_empty() {
        return Vec::new();
    }
    let confidence = score_from_hits(0.82, hits.len());
    vec![build_fact(
        run_id,
        next_fact_id(next_id),
        "defense_evasion",
        format!(
            "Process modified {} Windows Defender registry key(s).",
            hits.len()
        ),
        confidence,
        hits,
        loss,
    )]
}

fn detect_exfil_staging(
    run_id: &str,
    events: &[TraceEvent],
    next_id: &mut u64,
    loss: &LossMeta,
) -> Vec<DynamicBehaviorFactRecord> {
    // Heuristic: any temp-dir write followed within the same session
    // by ANY outbound network send. v1 doesn't try to correlate
    // payload size — that requires sustained event-level join.
    let temp_writes: Vec<&TraceEvent> = events
        .iter()
        .filter(|ev| matches!(ev.event_type, EventType::FileWrite))
        .filter(|ev| {
            ev.object
                .as_ref()
                .map(|o| {
                    let lower = o.id.to_lowercase();
                    lower.contains("\\temp\\")
                        || lower.contains("\\appdata\\local\\temp\\")
                        || lower.contains("/tmp/")
                })
                .unwrap_or(false)
        })
        .collect();
    let network_sends: Vec<&TraceEvent> = events
        .iter()
        .filter(|ev| {
            matches!(
                ev.event_type,
                EventType::NetworkSend | EventType::NetworkConnect
            )
        })
        .collect();
    if temp_writes.is_empty() || network_sends.is_empty() {
        return Vec::new();
    }
    let mut hits: Vec<EvidenceRef> = Vec::new();
    for ev in temp_writes.iter().chain(network_sends.iter()).take(8) {
        hits.push(EvidenceRef::TraceEvent {
            event_id: ev.event_id.clone(),
        });
    }
    let confidence = score_from_hits(0.55, hits.len());
    vec![build_fact(
        run_id,
        next_fact_id(next_id),
        "exfil_staging",
        format!(
            "Process wrote {} file(s) to temp + made {} outbound network send/connect(s).",
            temp_writes.len(),
            network_sends.len()
        ),
        confidence,
        hits,
        loss,
    )]
}

const DISCOVERY_TOOL_NAMES: &[&str] = &[
    "whoami.exe",
    "net.exe",
    "net1.exe",
    "systeminfo.exe",
    "tasklist.exe",
    "ipconfig.exe",
    "nltest.exe",
    "ping.exe",
    "arp.exe",
    "route.exe",
];

fn detect_discovery(
    run_id: &str,
    events: &[TraceEvent],
    next_id: &mut u64,
    loss: &LossMeta,
) -> Vec<DynamicBehaviorFactRecord> {
    let hits: Vec<EvidenceRef> = events
        .iter()
        .filter(|ev| matches!(ev.event_type, EventType::ProcessStart))
        .filter(|ev| {
            let image = ev
                .args
                .get("image")
                .and_then(|v| v.as_str())
                .or_else(|| ev.process_image.as_deref())
                .unwrap_or("");
            let basename = image
                .rsplit_once(['\\', '/'])
                .map(|(_, n)| n)
                .unwrap_or(image)
                .to_lowercase();
            DISCOVERY_TOOL_NAMES.iter().any(|t| basename == *t)
        })
        .map(|ev| EvidenceRef::TraceEvent {
            event_id: ev.event_id.clone(),
        })
        .collect();
    if hits.is_empty() {
        return Vec::new();
    }
    let confidence = score_from_hits(0.78, hits.len());
    vec![build_fact(
        run_id,
        next_fact_id(next_id),
        "discovery",
        format!("Process spawned {} system-discovery tool(s).", hits.len()),
        confidence,
        hits,
        loss,
    )]
}

fn detect_service_creation(
    run_id: &str,
    events: &[TraceEvent],
    next_id: &mut u64,
    loss: &LossMeta,
) -> Vec<DynamicBehaviorFactRecord> {
    let mut seen_services: HashSet<String> = HashSet::new();
    let mut hits: Vec<EvidenceRef> = Vec::new();
    for ev in events {
        if !matches!(ev.event_type, EventType::RegistryWrite) {
            continue;
        }
        let Some(obj) = &ev.object else { continue };
        let lower = obj.id.to_lowercase();
        if !lower.contains("\\system\\currentcontrolset\\services\\") {
            continue;
        }
        if !lower.contains("\\imagepath") {
            continue;
        }
        // Service path follows pattern HKLM\SYSTEM\CCS\Services\<name>\ImagePath
        let svc_name = extract_service_name(&lower);
        if seen_services.insert(svc_name) {
            hits.push(EvidenceRef::TraceEvent {
                event_id: ev.event_id.clone(),
            });
        }
    }
    if hits.is_empty() {
        return Vec::new();
    }
    let confidence = score_from_hits(0.86, hits.len());
    vec![build_fact(
        run_id,
        next_fact_id(next_id),
        "service_creation",
        format!("Process created or modified {} service(s).", hits.len()),
        confidence,
        hits,
        loss,
    )]
}

fn extract_service_name(lower: &str) -> String {
    if let Some(tail) = lower.split("\\services\\").nth(1) {
        if let Some(name) = tail.split('\\').next() {
            return name.to_string();
        }
    }
    "<unknown>".to_string()
}

const BROWSER_DB_PATTERNS: &[&str] = &[
    "\\chrome\\user data\\",
    "\\chromium\\user data\\",
    "\\edge\\user data\\",
    "\\mozilla\\firefox\\profiles\\",
    "login data",
    "cookies",
    "web data",
    "places.sqlite",
    "key4.db",
    "logins.json",
];

fn detect_browser_credential_access(
    run_id: &str,
    events: &[TraceEvent],
    next_id: &mut u64,
    loss: &LossMeta,
) -> Vec<DynamicBehaviorFactRecord> {
    let hits: Vec<EvidenceRef> = events
        .iter()
        .filter(|ev| matches!(ev.event_type, EventType::FileRead | EventType::FileOpen))
        .filter(|ev| {
            ev.object
                .as_ref()
                .map(|o| {
                    let lower = o.id.to_lowercase();
                    BROWSER_DB_PATTERNS.iter().any(|p| lower.contains(p))
                })
                .unwrap_or(false)
        })
        .map(|ev| EvidenceRef::TraceEvent {
            event_id: ev.event_id.clone(),
        })
        .collect();
    if hits.is_empty() {
        return Vec::new();
    }
    let confidence = score_from_hits(0.88, hits.len());
    vec![build_fact(
        run_id,
        next_fact_id(next_id),
        "browser_credential_access",
        format!(
            "Process read {} browser credential / profile file(s).",
            hits.len()
        ),
        confidence,
        hits,
        loss,
    )]
}

// ---------------------------------------------------------------------
// Confidence math — mirrors src/behavior.rs:259-264 shape.
// ---------------------------------------------------------------------

/// `base + bonus(min(hits, 4) * 0.04)`, capped at 0.96 (matches the
/// static-side `BehaviorDossierRecord` cap in `src/behavior.rs`).
fn score_from_hits(base: f32, hits: usize) -> f32 {
    let bonus = (hits.min(4) as f32) * 0.04;
    (base + bonus).min(0.96)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic_trace::event::{
        EntityRef, EventResult, EventSource, EventType, HostOs, TraceEvent,
    };

    fn make(et: EventType, object_id: &str, event_id_n: u64) -> TraceEvent {
        let mut ev = TraceEvent::new(
            &TraceEvent::format_event_id(event_id_n),
            "blake3:r",
            100 * event_id_n,
            HostOs::Windows,
            EventSource::Etw,
            4210,
            0,
            et,
            "op",
            EntityRef::process(4210, "t", None),
        );
        let obj = if object_id.starts_with("file:") {
            EntityRef::file(&object_id[5..])
        } else if object_id.starts_with("reg:") {
            EntityRef::registry(&object_id[4..])
        } else if object_id.starts_with("sock:") {
            EntityRef::socket("0.0.0.0:0", &object_id[5..])
        } else if object_id.starts_with("dns:") {
            EntityRef::dns(&object_id[4..])
        } else {
            EntityRef::module(object_id)
        };
        ev.object = Some(obj);
        ev.result = Some(EventResult::success());
        ev
    }

    fn empty_loss() -> LossMeta {
        LossMeta::default()
    }

    #[test]
    fn persistence_detects_run_key_write() {
        let events = vec![make(
            EventType::RegistryWrite,
            "reg:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MyApp",
            1,
        )];
        let facts = extract_facts("run", &events, &empty_loss());
        let p: Vec<_> = facts
            .iter()
            .filter(|f| f.category == "persistence")
            .collect();
        assert_eq!(p.len(), 1);
        assert!(p[0].claim.contains("persistence"));
        assert_eq!(p[0].evidence.len(), 1);
    }

    #[test]
    fn persistence_detects_scheduled_task_file_write() {
        let events = vec![make(
            EventType::FileWrite,
            "file:C:\\Windows\\System32\\Tasks\\MyTask",
            1,
        )];
        let facts = extract_facts("run", &events, &empty_loss());
        assert!(facts.iter().any(|f| f.category == "persistence"));
    }

    #[test]
    fn defense_evasion_detects_defender_registry_tamper() {
        let events = vec![make(
            EventType::RegistryWrite,
            "reg:HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware",
            1,
        )];
        let facts = extract_facts("run", &events, &empty_loss());
        assert!(facts.iter().any(|f| f.category == "defense_evasion"));
    }

    #[test]
    fn exfil_staging_requires_both_temp_write_and_network_send() {
        // Only temp write → no fact
        let events1 = vec![make(EventType::FileWrite, "file:C:\\temp\\x", 1)];
        let facts1 = extract_facts("run", &events1, &empty_loss());
        assert!(!facts1.iter().any(|f| f.category == "exfil_staging"));

        // Only network → no fact
        let events2 = vec![make(EventType::NetworkSend, "sock:1.2.3.4:80", 1)];
        let facts2 = extract_facts("run", &events2, &empty_loss());
        assert!(!facts2.iter().any(|f| f.category == "exfil_staging"));

        // Both → fact
        let events3 = vec![
            make(EventType::FileWrite, "file:C:\\temp\\x", 1),
            make(EventType::NetworkSend, "sock:1.2.3.4:80", 2),
        ];
        let facts3 = extract_facts("run", &events3, &empty_loss());
        assert!(facts3.iter().any(|f| f.category == "exfil_staging"));
    }

    #[test]
    fn discovery_detects_whoami_spawn() {
        let mut ev = make(EventType::ProcessStart, "mod:whoami.exe", 1);
        ev.args.insert(
            "image".into(),
            serde_json::Value::from("C:\\Windows\\System32\\whoami.exe"),
        );
        let facts = extract_facts("run", &[ev], &empty_loss());
        assert!(facts.iter().any(|f| f.category == "discovery"));
    }

    #[test]
    fn service_creation_detects_image_path_write() {
        let events = vec![make(
            EventType::RegistryWrite,
            "reg:HKLM\\SYSTEM\\CurrentControlSet\\Services\\Evil\\ImagePath",
            1,
        )];
        let facts = extract_facts("run", &events, &empty_loss());
        assert!(facts.iter().any(|f| f.category == "service_creation"));
    }

    #[test]
    fn browser_credential_access_detects_login_data_read() {
        let events = vec![make(
            EventType::FileRead,
            "file:C:\\Users\\analyst\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            1,
        )];
        let facts = extract_facts("run", &events, &empty_loss());
        assert!(facts
            .iter()
            .any(|f| f.category == "browser_credential_access"));
    }

    #[test]
    fn lossy_run_stamps_uncertainty_on_every_emitted_fact() {
        let events = vec![make(
            EventType::RegistryWrite,
            "reg:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\X",
            1,
        )];
        let loss = LossMeta { events_dropped: 42 };
        let facts = extract_facts("run", &events, &loss);
        assert!(!facts.is_empty());
        for f in &facts {
            assert!(
                f.uncertainty
                    .as_deref()
                    .map(|s| s.contains("42_dropped"))
                    .unwrap_or(false),
                "fact {} missing uncertainty stamp: {:?}",
                f.fact_id,
                f.uncertainty
            );
        }
    }

    #[test]
    fn confidence_score_caps_at_0_96() {
        for hits in 1..=20 {
            let s = score_from_hits(0.88, hits);
            assert!(s <= 0.96, "score {s} exceeded cap with hits={hits}");
        }
    }

    #[test]
    fn empty_event_stream_produces_no_facts() {
        let facts = extract_facts("run", &[], &empty_loss());
        assert!(facts.is_empty());
    }

    #[test]
    fn v1_excluded_detectors_are_documented() {
        // Codex finding 2: these detectors are explicitly cut from v1.
        // The plan calls them out for the v1.1 follow-up.
        assert!(V1_1_PLANNED_DETECTORS
            .iter()
            .any(|s| s.contains("code_injection")));
        assert!(V1_1_PLANNED_DETECTORS
            .iter()
            .any(|s| s.contains("lsass_credential_access")));
        assert!(V1_1_PLANNED_DETECTORS
            .iter()
            .any(|s| s.contains("process_enumeration")));
    }

    #[test]
    fn fact_id_format_is_zero_padded_four_digit() {
        let events = vec![
            make(
                EventType::RegistryWrite,
                "reg:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\A",
                1,
            ),
            make(
                EventType::RegistryWrite,
                "reg:HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\X",
                2,
            ),
        ];
        let facts = extract_facts("run", &events, &empty_loss());
        for f in facts {
            assert!(f.fact_id.starts_with("fact_"));
            assert_eq!(f.fact_id.len(), 5 + 4);
        }
    }
}
