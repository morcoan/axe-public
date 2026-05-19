//! Raw → canonical event translator.
//!
//! Two entry points, one canonical output type:
//! - [`normalize_etw`] (Windows-only, gated on `dynamic-trace-etw`)
//!   takes a ferrisetw [`EventRecord`] + the active provider plan and
//!   produces an [`Option<TraceEvent>`]. None means "drop this raw
//!   event" (PID filter rejected, unknown event class, etc.).
//! - [`normalize_jsonl`] (always available) takes a JSON value and
//!   produces an [`Option<TraceEvent>`]. Used by the OS-agnostic
//!   smoke test in Step 18 to exercise the full pipeline (schema →
//!   store → facts → LLM pack) without ETW.
//!
//! Provider field decoding (`process_id`, `image_name`, file path,
//! registry key, network endpoints, etc.) uses ferrisetw's `Parser`
//! API. v1 covers the six kernel provider classes; v1.1 extends to
//! the Object provider for handle events.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::dynamic_trace::collector::ProviderPlan;
use crate::dynamic_trace::event::{
    EntityRef, EventResult, EventSource, EventType, HostOs, TraceEvent,
};
use crate::dynamic_trace::ProviderKind;

/// Monotonic per-session event-id counter shared by all collector
/// callbacks. Wraps in [`Arc<AtomicU64>`] so the ferrisetw
/// callback thread + the JSONL replay path use the same counter
/// when running in the same process.
#[derive(Clone, Debug, Default)]
pub struct EventIdCounter(pub Arc<AtomicU64>);

impl EventIdCounter {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }

    pub fn next(&self) -> String {
        let n = self.0.fetch_add(1, Ordering::Relaxed) + 1;
        TraceEvent::format_event_id(n)
    }
}

/// Normalization context shared across callback invocations.
#[derive(Clone, Debug)]
pub struct NormalizeContext {
    pub run_id: String,
    pub host_os: HostOs,
    pub source: EventSource,
    pub counter: EventIdCounter,
    pub plan: ProviderPlan,
}

// ---------------------------------------------------------------------
// JSONL adapter — OS-agnostic, used by Step 18's smoke test.
// ---------------------------------------------------------------------

/// Parse a JSONL value into a canonical [`TraceEvent`]. Accepts both
/// (a) already-canonical events (passes through after schema check)
/// and (b) the small JSONL fixture format used by tests.
///
/// Fixture format (one record per line):
/// ```json
/// {"ts_ns": 100, "pid": 4210, "tid": 4214, "event_type": "file.write",
///  "operation": "write",
///  "subject": {"kind": "process", "id": "proc:4210@t", "name": "cmd.exe"},
///  "object":  {"kind": "file",    "id": "file:/tmp/x",  "name": "x"},
///  "args": {"bytes": 3}}
/// ```
pub fn normalize_jsonl(value: &serde_json::Value, ctx: &NormalizeContext) -> Option<TraceEvent> {
    // Already-canonical path: schema field present + matches.
    if value
        .get("schema")
        .and_then(|s| s.as_str())
        .map(|s| s.starts_with("dynamic_trace.event."))
        .unwrap_or(false)
    {
        return serde_json::from_value(value.clone()).ok();
    }

    // Fixture-format path: synthesize a canonical event.
    let event_type_str = value.get("event_type")?.as_str()?;
    let event_type = dotted_to_event_type(event_type_str)?;
    let operation = value
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or(event_type.as_dotted())
        .to_string();
    let pid = value.get("pid")?.as_u64()? as u32;
    let tid = value.get("tid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let ts_ns = value.get("ts_ns")?.as_u64()?;
    let subject = parse_entity(value.get("subject")?)?;
    let object = value.get("object").and_then(parse_entity);

    let mut ev = TraceEvent::new(
        &ctx.counter.next(),
        &ctx.run_id,
        ts_ns,
        ctx.host_os,
        ctx.source,
        pid,
        tid,
        event_type,
        &operation,
        subject,
    );
    ev.object = object;
    if let Some(serde_json::Value::Object(args)) = value.get("args") {
        for (k, v) in args {
            ev.args.insert(k.clone(), v.clone());
        }
    }
    if let Some(img) = value.get("process_image").and_then(|v| v.as_str()) {
        ev.process_image = Some(img.to_string());
    }
    if let Some(h) = value.get("process_hash").and_then(|v| v.as_str()) {
        ev.process_hash = Some(h.to_string());
    }
    ev.result = Some(EventResult::success());
    Some(ev)
}

fn dotted_to_event_type(s: &str) -> Option<EventType> {
    let mapping = [
        ("process.start", EventType::ProcessStart),
        ("process.exit", EventType::ProcessExit),
        ("thread.start", EventType::ThreadStart),
        ("thread.exit", EventType::ThreadExit),
        ("image.load", EventType::ImageLoad),
        ("image.unload", EventType::ImageUnload),
        ("file.open", EventType::FileOpen),
        ("file.read", EventType::FileRead),
        ("file.write", EventType::FileWrite),
        ("file.delete", EventType::FileDelete),
        ("file.rename", EventType::FileRename),
        ("registry.read", EventType::RegistryRead),
        ("registry.write", EventType::RegistryWrite),
        ("registry.delete", EventType::RegistryDelete),
        ("network.connect", EventType::NetworkConnect),
        ("network.accept", EventType::NetworkAccept),
        ("network.send", EventType::NetworkSend),
        ("network.recv", EventType::NetworkRecv),
        ("network.disconnect", EventType::NetworkDisconnect),
        ("dns.query", EventType::DnsQuery),
        ("dns.response", EventType::DnsResponse),
    ];
    mapping
        .iter()
        .find_map(|(k, v)| if *k == s { Some(*v) } else { None })
}

fn parse_entity(value: &serde_json::Value) -> Option<EntityRef> {
    serde_json::from_value::<EntityRef>(value.clone()).ok()
}

// ---------------------------------------------------------------------
// ETW adapter — Windows-only, gated on `dynamic-trace-etw`.
// ---------------------------------------------------------------------

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
pub fn normalize_etw(
    record: &ferrisetw::EventRecord,
    locator: &ferrisetw::schema_locator::SchemaLocator,
    ctx: &NormalizeContext,
    provider_kind: ProviderKind,
) -> Option<TraceEvent> {
    // Schema lookup gives provider name + property layout. Without it
    // we'd be reading raw bytes blind, which v1 refuses.
    let schema = locator.event_schema(record).ok()?;
    let parser = ferrisetw::parser::Parser::create(record, &schema);

    // PID filter — drop events from non-target processes early.
    let pid = record.process_id();
    if let Some(target_pid) = ctx.plan.target_pid_filter {
        if pid != target_pid {
            return None;
        }
    }
    let tid = record.thread_id();
    let ts_ns = etw_ts_to_ns(record);

    // Per-provider field extraction. v1 reads the most common fields
    // for each event class; v1.1 expands to ntstatus/result codes.
    let (event_type, operation, subject, object, args) = match provider_kind {
        ProviderKind::File => parse_file_event(record, &parser, pid)?,
        ProviderKind::Registry => parse_registry_event(record, &parser, pid)?,
        ProviderKind::Network => parse_network_event(record, &parser, pid)?,
        ProviderKind::Dns => parse_dns_event(record, &parser, pid)?,
        ProviderKind::Process => parse_process_event(record, &parser, pid)?,
        ProviderKind::ImageLoad => parse_image_load_event(record, &parser, pid)?,
    };

    let mut ev = TraceEvent::new(
        &ctx.counter.next(),
        &ctx.run_id,
        ts_ns,
        ctx.host_os,
        ctx.source,
        pid,
        tid,
        event_type,
        &operation,
        subject,
    );
    ev.object = object;
    ev.args = args;
    ev.result = Some(EventResult::success());
    Some(ev)
}

/// Stub for non-Windows / no-etw builds — always returns None so the
/// collector's session-orchestration code can still be referenced
/// without the feature being on.
#[cfg(not(all(windows, feature = "dynamic-trace-etw")))]
pub fn normalize_etw_stub() -> Option<TraceEvent> {
    None
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn etw_ts_to_ns(record: &ferrisetw::EventRecord) -> u64 {
    // ETW raw timestamp is 100ns ticks since 1601-01-01 (FILETIME).
    // Convert to ns-since-UNIX-epoch via the well-known FILETIME→UNIX
    // tick offset. v1 doesn't need sub-100ns resolution; we just
    // multiply by 100 at the end.
    const FILETIME_TO_UNIX_TICKS: i64 = 116_444_736_000_000_000;
    let ticks = record.raw_timestamp() - FILETIME_TO_UNIX_TICKS;
    if ticks < 0 {
        0
    } else {
        (ticks as u64).saturating_mul(100)
    }
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn parse_file_event(
    record: &ferrisetw::EventRecord,
    parser: &ferrisetw::parser::Parser,
    pid: u32,
) -> Option<(
    EventType,
    String,
    EntityRef,
    Option<EntityRef>,
    std::collections::BTreeMap<String, serde_json::Value>,
)> {
    let opcode = record.opcode();
    let event_type = match opcode {
        // Common FileIo opcodes (KrabsEtw-style):
        // 0 = NameInfo, 32 = Create, 35 = Close, 36 = Read, 37 = Write,
        // 38 = SetInfo, 39 = QueryInfo, 64 = FileCreate, 65 = FileDelete,
        // 71 = Rename
        32 | 64 => EventType::FileOpen,
        36 => EventType::FileRead,
        37 => EventType::FileWrite,
        65 => EventType::FileDelete,
        71 => EventType::FileRename,
        _ => return None,
    };
    let path: String = parser
        .try_parse("OpenPath")
        .or_else(|_| parser.try_parse::<String>("FileName"))
        .or_else(|_| parser.try_parse::<String>("FilePath"))
        .unwrap_or_default();
    if path.is_empty() {
        return None;
    }
    let mut args = std::collections::BTreeMap::new();
    if let Ok(bytes) = parser.try_parse::<u32>("IoSize") {
        args.insert("bytes".into(), serde_json::Value::from(bytes));
    }
    let subject = EntityRef::process(pid, "", None);
    let object = Some(EntityRef::file(&path));
    Some((
        event_type,
        event_type.as_dotted().to_string(),
        subject,
        object,
        args,
    ))
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn parse_registry_event(
    record: &ferrisetw::EventRecord,
    parser: &ferrisetw::parser::Parser,
    pid: u32,
) -> Option<(
    EventType,
    String,
    EntityRef,
    Option<EntityRef>,
    std::collections::BTreeMap<String, serde_json::Value>,
)> {
    let opcode = record.opcode();
    let event_type = match opcode {
        // Registry opcodes: 10 = Create, 11 = Open, 12 = Delete,
        // 14 = SetValue, 15 = DeleteValue, 16 = QueryValue
        10 | 11 => EventType::RegistryRead,
        14 => EventType::RegistryWrite,
        12 | 15 => EventType::RegistryDelete,
        16 => EventType::RegistryRead,
        _ => return None,
    };
    let key: String = parser
        .try_parse::<String>("KeyName")
        .or_else(|_| parser.try_parse::<String>("ValueName"))
        .unwrap_or_default();
    if key.is_empty() {
        return None;
    }
    let mut args = std::collections::BTreeMap::new();
    if let Ok(value_name) = parser.try_parse::<String>("ValueName") {
        if !value_name.is_empty() {
            args.insert("value_name".into(), serde_json::Value::from(value_name));
        }
    }
    let subject = EntityRef::process(pid, "", None);
    let object = Some(EntityRef::registry(&key));
    Some((
        event_type,
        event_type.as_dotted().to_string(),
        subject,
        object,
        args,
    ))
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn parse_network_event(
    record: &ferrisetw::EventRecord,
    parser: &ferrisetw::parser::Parser,
    pid: u32,
) -> Option<(
    EventType,
    String,
    EntityRef,
    Option<EntityRef>,
    std::collections::BTreeMap<String, serde_json::Value>,
)> {
    let opcode = record.opcode();
    let event_type = match opcode {
        // TcpIp opcodes: 10 = Send, 11 = Recv, 12 = Connect, 13 = Disconnect,
        // 14 = Retransmit, 15 = Accept, 16 = Reconnect
        12 => EventType::NetworkConnect,
        15 => EventType::NetworkAccept,
        10 => EventType::NetworkSend,
        11 => EventType::NetworkRecv,
        13 => EventType::NetworkDisconnect,
        _ => return None,
    };
    let daddr: String = parser.try_parse::<String>("daddr").unwrap_or_default();
    let dport: u16 = parser.try_parse::<u16>("dport").unwrap_or(0);
    let saddr: String = parser.try_parse::<String>("saddr").unwrap_or_default();
    let sport: u16 = parser.try_parse::<u16>("sport").unwrap_or(0);
    let local = format!("{saddr}:{sport}");
    let remote = format!("{daddr}:{dport}");
    let mut args = std::collections::BTreeMap::new();
    if let Ok(size) = parser.try_parse::<u32>("size") {
        args.insert("bytes".into(), serde_json::Value::from(size));
    }
    let subject = EntityRef::process(pid, "", None);
    let object = Some(EntityRef::socket(&local, &remote));
    Some((
        event_type,
        event_type.as_dotted().to_string(),
        subject,
        object,
        args,
    ))
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn parse_dns_event(
    _record: &ferrisetw::EventRecord,
    parser: &ferrisetw::parser::Parser,
    pid: u32,
) -> Option<(
    EventType,
    String,
    EntityRef,
    Option<EntityRef>,
    std::collections::BTreeMap<String, serde_json::Value>,
)> {
    let qname: String = parser
        .try_parse::<String>("QueryName")
        .or_else(|_| parser.try_parse::<String>("DnsServer"))
        .unwrap_or_default();
    if qname.is_empty() {
        return None;
    }
    let event_type = EventType::DnsQuery;
    let args = std::collections::BTreeMap::new();
    let subject = EntityRef::process(pid, "", None);
    let object = Some(EntityRef::dns(&qname));
    Some((
        event_type,
        event_type.as_dotted().to_string(),
        subject,
        object,
        args,
    ))
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn parse_process_event(
    record: &ferrisetw::EventRecord,
    parser: &ferrisetw::parser::Parser,
    pid: u32,
) -> Option<(
    EventType,
    String,
    EntityRef,
    Option<EntityRef>,
    std::collections::BTreeMap<String, serde_json::Value>,
)> {
    let opcode = record.opcode();
    let event_type = match opcode {
        // Process opcodes: 1 = Start, 2 = End, 3 = DCStart, 4 = DCEnd
        1 | 3 => EventType::ProcessStart,
        2 | 4 => EventType::ProcessExit,
        _ => return None,
    };
    let image: String = parser
        .try_parse::<String>("ImageFileName")
        .or_else(|_| parser.try_parse::<String>("ImageName"))
        .unwrap_or_default();
    let mut args = std::collections::BTreeMap::new();
    if !image.is_empty() {
        args.insert("image".into(), serde_json::Value::from(image.clone()));
    }
    if let Ok(cmd) = parser.try_parse::<String>("CommandLine") {
        args.insert("command_line".into(), serde_json::Value::from(cmd));
    }
    let image_opt = if image.is_empty() {
        None
    } else {
        Some(image.as_str())
    };
    let subject = EntityRef::process(pid, "", image_opt);
    Some((
        event_type,
        event_type.as_dotted().to_string(),
        subject,
        None,
        args,
    ))
}

#[cfg(all(windows, feature = "dynamic-trace-etw"))]
fn parse_image_load_event(
    record: &ferrisetw::EventRecord,
    parser: &ferrisetw::parser::Parser,
    pid: u32,
) -> Option<(
    EventType,
    String,
    EntityRef,
    Option<EntityRef>,
    std::collections::BTreeMap<String, serde_json::Value>,
)> {
    let opcode = record.opcode();
    let event_type = match opcode {
        // ImageLoad opcodes: 2 = Unload, 3 = DCStart, 4 = DCEnd, 10 = Load
        10 | 3 => EventType::ImageLoad,
        2 | 4 => EventType::ImageUnload,
        _ => return None,
    };
    let image: String = parser
        .try_parse::<String>("FileName")
        .or_else(|_| parser.try_parse::<String>("ImageFileName"))
        .unwrap_or_default();
    if image.is_empty() {
        return None;
    }
    let mut args = std::collections::BTreeMap::new();
    if let Ok(base) = parser.try_parse::<u64>("ImageBase") {
        args.insert("image_base".into(), serde_json::Value::from(base));
    }
    if let Ok(size) = parser.try_parse::<u64>("ImageSize") {
        args.insert("image_size".into(), serde_json::Value::from(size));
    }
    let subject = EntityRef::process(pid, "", None);
    let object = Some(EntityRef::module(&image));
    Some((
        event_type,
        event_type.as_dotted().to_string(),
        subject,
        object,
        args,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> NormalizeContext {
        NormalizeContext {
            run_id: "blake3:test".into(),
            host_os: HostOs::Windows,
            source: EventSource::Jsonl,
            counter: EventIdCounter::new(),
            plan: ProviderPlan::for_target(ProviderKind::v1_default_bundle(), None),
        }
    }

    #[test]
    fn fixture_jsonl_round_trips_through_normalize() {
        let v = json!({
            "ts_ns": 184400219301u64,
            "pid": 4210,
            "tid": 4214,
            "event_type": "file.write",
            "operation": "write",
            "subject": {"kind": "process", "id": "proc:4210@t", "name": "cmd.exe"},
            "object":  {"kind": "file",    "id": "file:/tmp/x",  "name": "x"},
            "args": {"bytes": 3, "offset": 0},
            "process_image": "C:\\Windows\\System32\\cmd.exe"
        });
        let ev = normalize_jsonl(&v, &ctx()).unwrap();
        assert_eq!(ev.event_type, EventType::FileWrite);
        assert_eq!(ev.pid, 4210);
        assert_eq!(ev.ts_ns, 184400219301);
        assert_eq!(
            ev.process_image.as_deref(),
            Some("C:\\Windows\\System32\\cmd.exe")
        );
        assert_eq!(ev.args.get("bytes").unwrap().as_u64(), Some(3));
    }

    #[test]
    fn already_canonical_jsonl_passes_through() {
        let canonical = json!({
            "schema": "dynamic_trace.event.v1",
            "event_id": "evt_0000000099",
            "run_id": "blake3:test",
            "ts_ns": 100,
            "host_os": "windows",
            "source": "etw",
            "pid": 1,
            "tid": 2,
            "event_type": "file.read",
            "operation": "read",
            "subject": {"kind": "process", "id": "proc:1@t", "name": "x"}
        });
        let ev = normalize_jsonl(&canonical, &ctx()).unwrap();
        assert_eq!(ev.event_id, "evt_0000000099");
        assert_eq!(ev.event_type, EventType::FileRead);
    }

    #[test]
    fn unknown_event_type_returns_none() {
        let v = json!({
            "ts_ns": 0,
            "pid": 0,
            "event_type": "nope.invalid",
            "subject": {"kind": "process", "id": "proc:0@t"}
        });
        assert!(normalize_jsonl(&v, &ctx()).is_none());
    }

    #[test]
    fn missing_required_field_returns_none() {
        let v = json!({
            "ts_ns": 100,
            "event_type": "file.write",
            "subject": {"kind": "process", "id": "p"}
            // no pid
        });
        assert!(normalize_jsonl(&v, &ctx()).is_none());
    }

    #[test]
    fn event_id_counter_is_monotonic_across_normalize_calls() {
        let ctx = ctx();
        let v = json!({
            "ts_ns": 100, "pid": 1, "event_type": "file.write",
            "subject": {"kind": "process", "id": "p"}
        });
        let a = normalize_jsonl(&v, &ctx).unwrap();
        let b = normalize_jsonl(&v, &ctx).unwrap();
        let c = normalize_jsonl(&v, &ctx).unwrap();
        assert_eq!(a.event_id, "evt_0000000001");
        assert_eq!(b.event_id, "evt_0000000002");
        assert_eq!(c.event_id, "evt_0000000003");
    }

    #[test]
    fn dotted_event_type_mapping_is_total_for_v1_set() {
        // Sample one per family.
        assert!(dotted_to_event_type("file.write").is_some());
        assert!(dotted_to_event_type("registry.read").is_some());
        assert!(dotted_to_event_type("network.connect").is_some());
        assert!(dotted_to_event_type("dns.query").is_some());
        assert!(dotted_to_event_type("process.start").is_some());
        assert!(dotted_to_event_type("image.load").is_some());
    }
}
