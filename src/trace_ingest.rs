use crate::portable::{
    function_for, parse_int, PortableInput, TraceCorrelationRecord, TraceEventRecord,
};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

pub fn ingest_traces(
    input: &PortableInput<'_>,
) -> (Vec<TraceEventRecord>, Vec<TraceCorrelationRecord>) {
    let Some(trace_dir) = input.trace_dir else {
        return (Vec::new(), Vec::new());
    };
    if input.profile != "native-max" {
        return (Vec::new(), Vec::new());
    }
    let mut events = Vec::new();
    for path in jsonl_files(trace_dir).into_iter().take(256) {
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        for line in text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .take(4096)
        {
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let index = events.len();
            events.push(event_from_value(index, &path, &value));
        }
    }
    let correlations = events
        .iter()
        .enumerate()
        .map(|(index, event)| {
            let function = event.va.and_then(|va| function_for(input.functions, va));
            let import = event.api.as_ref().and_then(|api| {
                input
                    .imports
                    .iter()
                    .find(|row| {
                        row.symbol.eq_ignore_ascii_case(api) || row.name.eq_ignore_ascii_case(api)
                    })
                    .map(|row| row.symbol.clone())
                    .or_else(|| Some(api.clone()))
            });
            TraceCorrelationRecord {
                correlation_id: format!("tracecorr:{index:04X}"),
                event_id: event.event_id.clone(),
                function,
                import,
                confidence: if function.is_some() {
                    "high"
                } else if event.api.is_some() {
                    "medium"
                } else {
                    "low"
                }
                .to_string(),
                evidence: event.evidence.clone(),
            }
        })
        .collect();
    (events, correlations)
}

fn jsonl_files(root: &Path) -> Vec<PathBuf> {
    let mut rows = Vec::new();
    if root.is_file() {
        rows.push(root.to_path_buf());
        return rows;
    }
    let Ok(entries) = fs::read_dir(root) else {
        return rows;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
        {
            rows.push(path);
        }
    }
    rows.sort();
    rows
}

fn event_from_value(index: usize, path: &Path, value: &Value) -> TraceEventRecord {
    let event_type = value
        .get("event_type")
        .or_else(|| value.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("event")
        .to_string();
    let timestamp = value
        .get("timestamp")
        .and_then(Value::as_str)
        .map(str::to_string);
    let va = value
        .get("va")
        .or_else(|| value.get("ip"))
        .and_then(value_u64);
    let api = value
        .get("api")
        .or_else(|| value.get("symbol"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let registers = value
        .get("registers")
        .and_then(Value::as_object)
        .map(|object| {
            object
                .iter()
                .map(|(key, value)| {
                    (
                        key.to_ascii_lowercase(),
                        value
                            .as_str()
                            .map(str::to_string)
                            .unwrap_or_else(|| value.to_string()),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    TraceEventRecord {
        event_id: format!("trace:{index:04X}"),
        source_path: path.to_string_lossy().to_string(),
        event_type,
        timestamp,
        va,
        api,
        registers,
        evidence: va.map(|value| vec![value]).unwrap_or_default(),
    }
}

fn value_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_int))
}
