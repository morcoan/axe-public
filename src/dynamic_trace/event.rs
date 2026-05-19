//! Canonical event schema — OS-agnostic.
//!
//! Both the Windows ETW collector (Step 8) and any future Linux Aya
//! collector (v2) translate raw events into [`TraceEvent`]. Downstream
//! consumers (store, behavior facts, LLM pack, evidence pack) only see
//! the canonical form.
//!
//! The schema is structurally OS-neutral on purpose. Field names like
//! `process_image` and `pid` map cleanly to both Windows (PROCESS_ID,
//! ImageFileName) and Linux (pid_t, /proc/<pid>/exe). The `HostOs` and
//! `EventSource` tags let consumers branch on origin without inspecting
//! field shapes.

#![allow(dead_code)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::facts::evidence::EvidenceRef;

pub const EVENT_SCHEMA: &str = "dynamic_trace.event.v1";

/// One canonical event in the dynamic-trace stream. Serializes
/// 1-event-per-line as JSONL in `events.ndjson`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceEvent {
    /// Always `"dynamic_trace.event.v1"`.
    pub schema: String,
    /// Monotonic in-run identifier, formatted `evt_<10-digit-zero-padded>`.
    pub event_id: String,
    /// Per-session BLAKE3 of target hash + start time.
    pub run_id: String,
    /// Capture timestamp, nanoseconds since UNIX epoch.
    pub ts_ns: u64,
    pub host_os: HostOs,
    pub source: EventSource,
    pub pid: u32,
    pub tid: u32,
    pub process_image: Option<String>,
    pub process_hash: Option<String>,
    pub event_type: EventType,
    /// Human-readable verb, e.g. `"open"`, `"write"`, `"connect"`.
    /// Usually mirrors the action part of [`EventType`] but may add
    /// detail (e.g. `"open_create"` vs `"open_existing"`).
    pub operation: String,
    pub subject: EntityRef,
    /// `None` for events with no object (e.g. process_start).
    pub object: Option<EntityRef>,
    /// Free-form per-event-type payload. Always serializes as a JSON
    /// object. Empty if nothing to add.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub args: BTreeMap<String, serde_json::Value>,
    pub result: Option<EventResult>,
    /// Reference to an in-store stack record. v1 leaves this `None`
    /// (stack-walking deferred to v1.1).
    pub stack_id: Option<String>,
    /// Cross-reference to static-analysis records when the event's
    /// `(process_image, process_hash)` matches a binary axe has
    /// analyzed in the same run. Populated by `symbolicate::decorate`
    /// in Step 9 (Codex finding 6 fix). Empty by default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub static_refs: Vec<EvidenceRef>,
    /// Free-form tags for grouping in the evidence pack. Example:
    /// `["file_write", "user_temp", "module:cmd.exe+0x1a82"]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl TraceEvent {
    /// Build a fresh event with the canonical schema string and empty
    /// optional collections. Callers fill the rest.
    pub fn new(
        event_id: &str,
        run_id: &str,
        ts_ns: u64,
        host_os: HostOs,
        source: EventSource,
        pid: u32,
        tid: u32,
        event_type: EventType,
        operation: &str,
        subject: EntityRef,
    ) -> Self {
        Self {
            schema: EVENT_SCHEMA.to_string(),
            event_id: event_id.to_string(),
            run_id: run_id.to_string(),
            ts_ns,
            host_os,
            source,
            pid,
            tid,
            process_image: None,
            process_hash: None,
            event_type,
            operation: operation.to_string(),
            subject,
            object: None,
            args: BTreeMap::new(),
            result: None,
            stack_id: None,
            static_refs: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Format an event_id from a monotonic counter.
    pub fn format_event_id(counter: u64) -> String {
        format!("evt_{counter:010}")
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostOs {
    Windows,
    Linux,
    Macos,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    /// Windows ETW (kernel SystemTraceProvider in v1).
    Etw,
    /// Linux eBPF via Aya (v2 plan).
    Aya,
    /// Offline JSONL replay path (test-only, also the OS-agnostic
    /// smoke-test entry point).
    Jsonl,
}

/// Six event-family categories with dotted-string wire form. Maps 1:1
/// onto the v1 provider bundle. v1.1 extensions (handle events,
/// thread events, memory events) add new variants here.
///
/// Wire form is the dotted string from [`Self::as_dotted`]
/// (e.g. `"file.write"`), matching the LLM-consumer schema fixed in
/// the plan. Per-variant `serde(rename = "...")` is verbose but keeps
/// the wire form readable AND auditable next to the enum definition.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EventType {
    // Process provider
    #[serde(rename = "process.start")]
    ProcessStart,
    #[serde(rename = "process.exit")]
    ProcessExit,
    #[serde(rename = "thread.start")]
    ThreadStart,
    #[serde(rename = "thread.exit")]
    ThreadExit,
    // Image-load provider
    #[serde(rename = "image.load")]
    ImageLoad,
    #[serde(rename = "image.unload")]
    ImageUnload,
    // File provider
    #[serde(rename = "file.open")]
    FileOpen,
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "file.delete")]
    FileDelete,
    #[serde(rename = "file.rename")]
    FileRename,
    // Registry provider
    #[serde(rename = "registry.read")]
    RegistryRead,
    #[serde(rename = "registry.write")]
    RegistryWrite,
    #[serde(rename = "registry.delete")]
    RegistryDelete,
    // Network provider
    #[serde(rename = "network.connect")]
    NetworkConnect,
    #[serde(rename = "network.accept")]
    NetworkAccept,
    #[serde(rename = "network.send")]
    NetworkSend,
    #[serde(rename = "network.recv")]
    NetworkRecv,
    #[serde(rename = "network.disconnect")]
    NetworkDisconnect,
    // DNS provider
    #[serde(rename = "dns.query")]
    DnsQuery,
    #[serde(rename = "dns.response")]
    DnsResponse,
}

impl EventType {
    /// Return the dotted-string form expected on the wire. Used when
    /// serializing to legacy-compatible TraceEventRecord and when
    /// matching detectors that key on string event types.
    pub fn as_dotted(&self) -> &'static str {
        match self {
            Self::ProcessStart => "process.start",
            Self::ProcessExit => "process.exit",
            Self::ThreadStart => "thread.start",
            Self::ThreadExit => "thread.exit",
            Self::ImageLoad => "image.load",
            Self::ImageUnload => "image.unload",
            Self::FileOpen => "file.open",
            Self::FileRead => "file.read",
            Self::FileWrite => "file.write",
            Self::FileDelete => "file.delete",
            Self::FileRename => "file.rename",
            Self::RegistryRead => "registry.read",
            Self::RegistryWrite => "registry.write",
            Self::RegistryDelete => "registry.delete",
            Self::NetworkConnect => "network.connect",
            Self::NetworkAccept => "network.accept",
            Self::NetworkSend => "network.send",
            Self::NetworkRecv => "network.recv",
            Self::NetworkDisconnect => "network.disconnect",
            Self::DnsQuery => "dns.query",
            Self::DnsResponse => "dns.response",
        }
    }
}

/// Reference to an entity (process, file, registry key, socket, …)
/// that an event subject or object points at. Stable IDs survive PID
/// reuse (process IDs tuple in process_start_time_100ns).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntityRef {
    pub kind: EntityKind,
    pub id: String,
    pub name: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Process,
    Thread,
    Module,
    File,
    Registry,
    Socket,
    Dns,
}

impl EntityRef {
    /// Build a process entity ID as `proc:<pid>@<start_time_iso>`.
    /// Survives PID reuse during long runs.
    pub fn process(pid: u32, start_time_iso: &str, image: Option<&str>) -> Self {
        Self {
            kind: EntityKind::Process,
            id: format!("proc:{pid}@{start_time_iso}"),
            name: image.map(|s| s.to_string()),
        }
    }

    pub fn file(path: &str) -> Self {
        Self {
            kind: EntityKind::File,
            id: format!("file:{path}"),
            name: Some(file_name_only(path).to_string()),
        }
    }

    pub fn registry(key: &str) -> Self {
        Self {
            kind: EntityKind::Registry,
            id: format!("reg:{key}"),
            name: None,
        }
    }

    pub fn socket(local: &str, remote: &str) -> Self {
        Self {
            kind: EntityKind::Socket,
            id: format!("sock:{local}->{remote}"),
            name: None,
        }
    }

    pub fn dns(qname: &str) -> Self {
        Self {
            kind: EntityKind::Dns,
            id: format!("dns:{qname}"),
            name: Some(qname.to_string()),
        }
    }

    pub fn module(image: &str) -> Self {
        Self {
            kind: EntityKind::Module,
            id: format!("mod:{image}"),
            name: Some(file_name_only(image).to_string()),
        }
    }
}

fn file_name_only(path: &str) -> &str {
    path.rsplit_once(['\\', '/'])
        .map(|(_, n)| n)
        .unwrap_or(path)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventResult {
    pub status: EventStatus,
    /// Underlying status code in OS-native form (NTSTATUS on Windows,
    /// errno on Linux). Hex string for Windows, decimal for Linux.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ntstatus: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errno: Option<i32>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventStatus {
    Success,
    Failure,
    Pending,
}

impl EventResult {
    pub fn success() -> Self {
        Self {
            status: EventStatus::Success,
            ntstatus: Some("0x00000000".into()),
            errno: None,
        }
    }
}

// ---------------------------------------------------------------------
// Bridge to the existing static-analysis correlator
// (src/trace_ingest.rs).
//
// Lets `axe --trace-dir <out_dir>/dynamic_trace/` work for free: the
// existing static correlator consumes TraceEventRecord, and every
// canonical TraceEvent maps to one via this impl.
// ---------------------------------------------------------------------

impl From<TraceEvent> for crate::portable::TraceEventRecord {
    fn from(e: TraceEvent) -> Self {
        let mut registers = BTreeMap::new();
        // Surface the args as register-like key/value pairs so the
        // existing renderer can show them. Values are stringified.
        for (k, v) in &e.args {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            registers.insert(k.clone(), s);
        }
        let api = match &e.object {
            Some(o) => Some(format!("{}::{}", e.event_type.as_dotted(), o.id)),
            None => Some(e.event_type.as_dotted().to_string()),
        };
        crate::portable::TraceEventRecord {
            event_id: e.event_id,
            source_path: e
                .process_image
                .clone()
                .unwrap_or_else(|| "<dynamic_trace>".into()),
            event_type: e.event_type.as_dotted().to_string(),
            timestamp: Some(format_ts_ns(e.ts_ns)),
            // No VA on dynamic events in v1 (no stack-walk → no return-address attribution).
            va: None,
            api,
            registers,
            evidence: Vec::new(),
        }
    }
}

fn format_ts_ns(ns: u64) -> String {
    // ISO-8601-ish; renderer doesn't validate timezone, just stores
    // the string. Keep precision lossless.
    format!("{}.{:09}", ns / 1_000_000_000, ns % 1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_event() -> TraceEvent {
        let mut ev = TraceEvent::new(
            "evt_0000018342",
            "blake3:7a1f",
            184400219301,
            HostOs::Windows,
            EventSource::Etw,
            4210,
            4214,
            EventType::FileWrite,
            "write",
            EntityRef::process(4210, "2026-05-17T11:23:04.5121234Z", Some("cmd.exe")),
        );
        ev.process_image = Some("C:\\Windows\\System32\\cmd.exe".into());
        ev.process_hash = Some("blake3:9c2e".into());
        ev.object = Some(EntityRef::file(
            "C:\\Users\\analyst\\AppData\\Local\\Temp\\probe.txt",
        ));
        ev.args.insert("bytes".into(), serde_json::Value::from(3));
        ev.args.insert("offset".into(), serde_json::Value::from(0));
        ev.result = Some(EventResult::success());
        ev.tags.push("file_write".into());
        ev.tags.push("user_temp".into());
        ev
    }

    #[test]
    fn event_roundtrips_through_json_byte_identical() {
        let ev = fixture_event();
        let s = serde_json::to_string(&ev).unwrap();
        let back: TraceEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(back, ev);
    }

    #[test]
    fn event_serializes_with_schema_field_and_dotted_type() {
        let ev = fixture_event();
        let s = serde_json::to_string(&ev).unwrap();
        assert!(s.contains(r#""schema":"dynamic_trace.event.v1""#));
        // Wire form uses the dotted string from EventType::as_dotted(),
        // not snake_case. Matches the LLM-consumer schema in the plan.
        assert!(
            s.contains(r#""event_type":"file.write""#),
            "expected dotted event_type; got: {s}"
        );
    }

    #[test]
    fn dotted_form_for_each_event_type_is_unique_and_stable() {
        use std::collections::HashSet;
        let dotted: HashSet<&str> = [
            EventType::ProcessStart,
            EventType::ProcessExit,
            EventType::ThreadStart,
            EventType::ThreadExit,
            EventType::ImageLoad,
            EventType::ImageUnload,
            EventType::FileOpen,
            EventType::FileRead,
            EventType::FileWrite,
            EventType::FileDelete,
            EventType::FileRename,
            EventType::RegistryRead,
            EventType::RegistryWrite,
            EventType::RegistryDelete,
            EventType::NetworkConnect,
            EventType::NetworkAccept,
            EventType::NetworkSend,
            EventType::NetworkRecv,
            EventType::NetworkDisconnect,
            EventType::DnsQuery,
            EventType::DnsResponse,
        ]
        .iter()
        .map(|e| e.as_dotted())
        .collect();
        assert_eq!(dotted.len(), 21);
        assert!(dotted.contains("file.write"));
        assert!(dotted.contains("dns.query"));
    }

    #[test]
    fn entity_ref_process_id_includes_start_time_for_pid_reuse_resilience() {
        let p = EntityRef::process(4210, "2026-05-17T11:23:04.5121234Z", Some("cmd.exe"));
        assert!(p.id.starts_with("proc:4210@"));
        assert!(p.id.contains("2026-05-17"));
        assert_eq!(p.kind, EntityKind::Process);
    }

    #[test]
    fn entity_ref_file_strips_path_for_display_name() {
        let f = EntityRef::file("C:\\Users\\analyst\\AppData\\Local\\Temp\\probe.txt");
        assert_eq!(f.name.as_deref(), Some("probe.txt"));
        assert_eq!(
            f.id,
            "file:C:\\Users\\analyst\\AppData\\Local\\Temp\\probe.txt"
        );
    }

    #[test]
    fn bridge_to_trace_event_record_preserves_event_id_and_type() {
        let ev = fixture_event();
        let event_id = ev.event_id.clone();
        let r: crate::portable::TraceEventRecord = ev.into();
        assert_eq!(r.event_id, event_id);
        assert_eq!(r.event_type, "file.write");
        assert_eq!(r.source_path, "C:\\Windows\\System32\\cmd.exe");
        // args were mirrored as register-like kv pairs.
        assert!(r.registers.contains_key("bytes"));
        assert!(r.registers.contains_key("offset"));
        // API combined event_type + object id.
        assert!(r.api.as_deref().unwrap().contains("probe.txt"));
    }

    #[test]
    fn static_refs_default_empty_and_serialize_only_when_populated() {
        let ev = fixture_event();
        assert!(ev.static_refs.is_empty());
        let s = serde_json::to_string(&ev).unwrap();
        assert!(!s.contains("static_refs"));

        let mut ev2 = ev;
        ev2.static_refs.push(EvidenceRef::Artifact {
            entity_kind: "function".into(),
            id: "func:0x140012a40".into(),
        });
        let s = serde_json::to_string(&ev2).unwrap();
        assert!(s.contains(r#""static_refs":[{"kind":"artifact""#));
    }

    #[test]
    fn format_event_id_zero_pads_to_ten_digits() {
        assert_eq!(TraceEvent::format_event_id(7), "evt_0000000007");
        assert_eq!(TraceEvent::format_event_id(18342), "evt_0000018342");
    }
}
