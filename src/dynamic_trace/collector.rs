//! `TraceCollector` trait — Codex finding 5 fix.
//!
//! The trait sits between the orchestrator (`session.rs`) and any
//! OS-specific collector implementation. Defining it BEFORE writing
//! the first impl means:
//! - The downstream pipeline (normalize, store, behavior facts, LLM
//!   pack) consumes [`TraceEvent`]s from a [`Sender`] without caring
//!   how they were captured.
//! - If `ferrisetw =1.2.0` proves insufficient for any single
//!   provider (e.g. event field decoding bugs, threading issues,
//!   missing kernel-flag support), a raw-`windows`-crate
//!   [`TraceCollector`] impl is a localized swap, not a rewrite.
//! - The v2 Linux Aya collector is a third impl of the same trait.
//!
//! Step 7 ships the trait + types only — no impls. Step 8 lands
//! `FerrisEtwCollector`. Step 7 also lands
//! `tests/dynamic_trace_provider_probe.rs`, a `#[ignore]` automated
//! spike that drives ferrisetw DIRECTLY (not via the trait) and
//! asserts ≥1 distinct event per requested provider class — that
//! gate the architectural commitment to ferrisetw before Step 8 is
//! written.

#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crossbeam_channel::Sender;

use crate::dynamic_trace::event::TraceEvent;
use crate::dynamic_trace::ProviderKind;

#[derive(Clone, Debug)]
pub struct ProviderPlan {
    pub providers: Vec<ProviderKind>,
    /// If `Some(pid)`, the collector should drop events that don't
    /// match this PID before sending them on the channel. Lets v1
    /// avoid drowning the consumer in unrelated kernel chatter.
    pub target_pid_filter: Option<u32>,
}

impl ProviderPlan {
    pub fn for_target(providers: Vec<ProviderKind>, target_pid: Option<u32>) -> Self {
        Self {
            providers,
            target_pid_filter: target_pid,
        }
    }
}

/// Per-collector report returned from [`TraceCollector::stop`].
#[derive(Clone, Debug, Default)]
pub struct CollectorReport {
    pub events_emitted: u64,
    pub events_dropped: u64,
    pub per_provider_counts: std::collections::BTreeMap<ProviderKind, u64>,
    /// Backend-specific diagnostics, free-form.
    pub diagnostics: Vec<String>,
}

impl CollectorReport {
    pub fn record_emit(&mut self, kind: ProviderKind) {
        self.events_emitted += 1;
        *self.per_provider_counts.entry(kind).or_default() += 1;
    }

    pub fn record_drop(&mut self) {
        self.events_dropped += 1;
    }
}

/// Shared drop counter for the bounded-channel back-pressure case.
/// The collector's ETW callback thread increments this atomically
/// when `Sender::try_send` returns `Full`. The orchestrator reads it
/// at stop time to populate [`CollectorReport`].
#[derive(Clone, Debug, Default)]
pub struct DropCounter(pub Arc<AtomicU64>);

impl DropCounter {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }
    pub fn increment(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CollectorError {
    #[error("collector is unsupported on this OS")]
    UnsupportedOs,
    #[error("session start failed: {0}")]
    SessionStart(String),
    #[error("session stop failed: {0}")]
    SessionStop(String),
    #[error("provider {0:?} cannot be enabled in this collector")]
    UnsupportedProvider(ProviderKind),
    #[error("name collision: a session named {0} is already running")]
    SessionAlreadyExists(String),
}

/// The collector boundary. v1 has one impl
/// ([`crate::dynamic_trace::etw::FerrisEtwCollector`] on Windows);
/// v1.1 contingency: `RawWindowsEtwCollector`. v2: `AyaCollector`
/// (Linux).
pub trait TraceCollector {
    /// Begin capture. Returns when the session is live and ready to
    /// emit events on `tx`. The collector keeps a clone of `tx` and
    /// of the [`DropCounter`] until [`Self::stop`] is called.
    fn start(
        &mut self,
        plan: ProviderPlan,
        tx: Sender<TraceEvent>,
        drops: DropCounter,
    ) -> Result<(), CollectorError>;

    /// End capture. Consumes the collector and returns a final
    /// report. After this call, no more events will arrive on `tx`.
    fn stop(self: Box<Self>) -> Result<CollectorReport, CollectorError>;

    /// Backend name for diagnostics + manifest.
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_plan_constructs_with_target_pid() {
        let plan = ProviderPlan::for_target(ProviderKind::v1_default_bundle(), Some(4210));
        assert_eq!(plan.providers.len(), 6);
        assert_eq!(plan.target_pid_filter, Some(4210));
    }

    #[test]
    fn drop_counter_is_thread_safe_and_observable() {
        let dc = DropCounter::new();
        let dc_clone = dc.clone();
        let h = std::thread::spawn(move || {
            for _ in 0..100 {
                dc_clone.increment();
            }
        });
        for _ in 0..100 {
            dc.increment();
        }
        h.join().unwrap();
        assert_eq!(dc.snapshot(), 200);
    }

    #[test]
    fn collector_report_records_per_provider_counts() {
        let mut r = CollectorReport::default();
        r.record_emit(ProviderKind::File);
        r.record_emit(ProviderKind::File);
        r.record_emit(ProviderKind::Network);
        r.record_drop();
        assert_eq!(r.events_emitted, 3);
        assert_eq!(r.events_dropped, 1);
        assert_eq!(r.per_provider_counts[&ProviderKind::File], 2);
        assert_eq!(r.per_provider_counts[&ProviderKind::Network], 1);
        assert!(!r.per_provider_counts.contains_key(&ProviderKind::Registry));
    }
}
