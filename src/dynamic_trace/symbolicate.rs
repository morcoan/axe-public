//! Light symbolication + static-ref join (Codex finding 6 fix).
//!
//! v1 deliberately does NOT do per-frame `SymFromAddr` symbolication
//! (deferred to v1.1 — ferrisetw doesn't expose stack walking, and
//! the dbghelp path is its own complexity). What v1 DOES do:
//!
//! 1. **Module-base tracking**: listen for `image.load`/`image.unload`
//!    events and maintain a per-PID list of loaded modules sorted by
//!    base address. For any event that carries a code address, decorate
//!    its `tags` with `module:offset_hex`.
//!
//! 2. **Static-ref join** (Codex finding 6): if `process_image_hash`
//!    matches a binary axe has analyzed in the same run, populate
//!    `TraceEvent::static_refs` with `EvidenceRef::Artifact` entries
//!    pointing at the matching `FunctionRecord` / `ImportRecord`. The
//!    LLM consumer can then trace from a dynamic event back to the
//!    static analysis row that explains "why this binary did X."
//!
//! Both passes are pure functions over an in-memory state — no I/O,
//! no native API calls. That makes the OS-agnostic smoke test in
//! Step 18 exercise this layer too.

#![allow(dead_code)]

use std::collections::HashMap;

use crate::dynamic_trace::event::{EventType, TraceEvent};
use crate::facts::evidence::EvidenceRef;

/// One loaded module in a PID's address space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedModule {
    pub name: String,
    pub base: u64,
    pub size: u64,
}

impl LoadedModule {
    pub fn contains(&self, va: u64) -> bool {
        va >= self.base && va < self.base.saturating_add(self.size)
    }
    pub fn offset_of(&self, va: u64) -> u64 {
        va.saturating_sub(self.base)
    }
}

/// Per-session running state. Lives on the consumer thread (NOT the
/// ETW callback) because update + read happen in the same place.
#[derive(Clone, Debug, Default)]
pub struct SymbolicateState {
    /// PID → loaded modules, sorted by base.
    by_pid: HashMap<u32, Vec<LoadedModule>>,
    /// (process_image_basename_lowercase, image_hash) → ref to a
    /// static binary axe has analyzed.
    static_index: HashMap<(String, String), StaticRef>,
}

/// Lightweight pointer to one of axe's static-analysis artifacts. The
/// concrete `EvidenceRef` is produced by [`SymbolicateState::ref_for`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticRef {
    pub entity_kind: String,
    pub id: String,
}

impl SymbolicateState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a known static binary for join. Calling code (e.g.
    /// the session orchestrator) populates this from the same run's
    /// PE-analysis results before the collector starts.
    pub fn register_static_binary(
        &mut self,
        basename_lowercase: &str,
        image_hash: &str,
        static_ref: StaticRef,
    ) {
        self.static_index.insert(
            (basename_lowercase.to_string(), image_hash.to_string()),
            static_ref,
        );
    }

    /// Apply an image.load / image.unload event to the per-PID module list.
    pub fn apply_image_event(&mut self, event: &TraceEvent) {
        match event.event_type {
            EventType::ImageLoad => {
                if let Some(module) = module_from_event(event) {
                    let list = self.by_pid.entry(event.pid).or_default();
                    list.push(module);
                    list.sort_by_key(|m| m.base);
                }
            }
            EventType::ImageUnload => {
                if let Some(module) = module_from_event(event) {
                    if let Some(list) = self.by_pid.get_mut(&event.pid) {
                        list.retain(|m| m.base != module.base);
                    }
                }
            }
            _ => {}
        }
    }

    /// Resolve a code VA in a PID's address space to `module:offset`.
    pub fn resolve_va(&self, pid: u32, va: u64) -> Option<String> {
        let mods = self.by_pid.get(&pid)?;
        mods.iter()
            .find(|m| m.contains(va))
            .map(|m| format!("{}:{:#x}", m.name, m.offset_of(va)))
    }

    /// Look up the static-binary join for an event. Returns the
    /// matching [`EvidenceRef`] when `(process_image, process_hash)`
    /// resolves; `None` otherwise.
    pub fn ref_for(&self, event: &TraceEvent) -> Option<EvidenceRef> {
        let image = event.process_image.as_ref()?;
        let hash = event.process_hash.as_ref()?;
        let basename = image
            .rsplit_once(['\\', '/'])
            .map(|(_, n)| n)
            .unwrap_or(image);
        let key = (basename.to_lowercase(), hash.clone());
        self.static_index
            .get(&key)
            .map(|sref| EvidenceRef::Artifact {
                entity_kind: sref.entity_kind.clone(),
                id: sref.id.clone(),
            })
    }

    /// One-shot decorate: feed the event through both module-offset
    /// tagging (if a `code_va` arg is present) AND static-ref join.
    /// Returns the (possibly modified) event.
    pub fn decorate(&self, mut event: TraceEvent) -> TraceEvent {
        if let Some(serde_json::Value::Number(n)) = event.args.get("code_va") {
            if let Some(va) = n.as_u64() {
                if let Some(tag) = self.resolve_va(event.pid, va) {
                    event.tags.push(format!("module:{tag}"));
                }
            }
        }
        if let Some(static_ref) = self.ref_for(&event) {
            event.static_refs.push(static_ref);
        }
        event
    }
}

fn module_from_event(event: &TraceEvent) -> Option<LoadedModule> {
    let obj = event.object.as_ref()?;
    let name = obj.name.clone().unwrap_or_else(|| obj.id.clone());
    let base = event
        .args
        .get("image_base")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let size = event
        .args
        .get("image_size")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if base == 0 && size == 0 {
        // We need at least a base address to track this module.
        return None;
    }
    Some(LoadedModule { name, base, size })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic_trace::event::{EntityRef, EventSource, EventType, HostOs, TraceEvent};

    fn mk_event(pid: u32, et: EventType, image_base: u64, image_size: u64) -> TraceEvent {
        let mut ev = TraceEvent::new(
            "evt_0000000001",
            "r",
            100,
            HostOs::Windows,
            EventSource::Etw,
            pid,
            0,
            et,
            "op",
            EntityRef::process(pid, "t", None),
        );
        ev.object = Some(EntityRef::module("ntdll.dll"));
        ev.args
            .insert("image_base".into(), serde_json::Value::from(image_base));
        ev.args
            .insert("image_size".into(), serde_json::Value::from(image_size));
        ev
    }

    #[test]
    fn image_load_then_resolve_returns_module_and_offset() {
        let mut state = SymbolicateState::new();
        state.apply_image_event(&mk_event(4210, EventType::ImageLoad, 0x10000, 0x1000));
        let resolved = state.resolve_va(4210, 0x10123).unwrap();
        assert_eq!(resolved, "ntdll.dll:0x123");
    }

    #[test]
    fn image_unload_removes_module_so_resolve_misses() {
        let mut state = SymbolicateState::new();
        state.apply_image_event(&mk_event(4210, EventType::ImageLoad, 0x10000, 0x1000));
        state.apply_image_event(&mk_event(4210, EventType::ImageUnload, 0x10000, 0x1000));
        assert!(state.resolve_va(4210, 0x10123).is_none());
    }

    #[test]
    fn resolve_va_misses_when_no_modules_loaded() {
        let state = SymbolicateState::new();
        assert!(state.resolve_va(4210, 0x1000).is_none());
    }

    #[test]
    fn resolve_va_misses_when_va_outside_any_module() {
        let mut state = SymbolicateState::new();
        state.apply_image_event(&mk_event(4210, EventType::ImageLoad, 0x10000, 0x1000));
        assert!(state.resolve_va(4210, 0x20000).is_none());
    }

    #[test]
    fn ref_for_populates_static_artifact_when_hash_and_basename_match() {
        let mut state = SymbolicateState::new();
        state.register_static_binary(
            "cmd.exe",
            "blake3:9c2e",
            StaticRef {
                entity_kind: "binary".into(),
                id: "bin:cmd_exe".into(),
            },
        );
        let mut ev = mk_event(1, EventType::FileWrite, 0, 0);
        ev.process_image = Some("C:\\Windows\\System32\\cmd.exe".into());
        ev.process_hash = Some("blake3:9c2e".into());
        let r = state.ref_for(&ev).unwrap();
        match r {
            EvidenceRef::Artifact { entity_kind, id } => {
                assert_eq!(entity_kind, "binary");
                assert_eq!(id, "bin:cmd_exe");
            }
            other => panic!("expected Artifact, got {other:?}"),
        }
    }

    #[test]
    fn ref_for_returns_none_when_no_image_metadata() {
        let state = SymbolicateState::new();
        let ev = mk_event(1, EventType::FileWrite, 0, 0);
        assert!(state.ref_for(&ev).is_none());
    }

    #[test]
    fn decorate_adds_module_tag_and_static_ref_when_both_available() {
        let mut state = SymbolicateState::new();
        state.apply_image_event(&mk_event(4210, EventType::ImageLoad, 0x10000, 0x1000));
        state.register_static_binary(
            "cmd.exe",
            "blake3:9c2e",
            StaticRef {
                entity_kind: "binary".into(),
                id: "bin:cmd_exe".into(),
            },
        );
        let mut ev = mk_event(4210, EventType::FileWrite, 0, 0);
        ev.process_image = Some("C:\\Windows\\System32\\cmd.exe".into());
        ev.process_hash = Some("blake3:9c2e".into());
        ev.args
            .insert("code_va".into(), serde_json::Value::from(0x10123u64));
        let decorated = state.decorate(ev);
        assert!(decorated.tags.iter().any(|t| t == "module:ntdll.dll:0x123"));
        assert_eq!(decorated.static_refs.len(), 1);
    }
}
