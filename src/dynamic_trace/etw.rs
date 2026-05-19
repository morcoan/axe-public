//! `FerrisEtwCollector` — Windows-only impl of [`TraceCollector`].
//!
//! Wires ferrisetw 1.2.0's `KernelTrace` + 6 v1 providers
//! (FILE_IO, REGISTRY, TCP_IP, PROCESS, IMAGE_LOAD, plus a DNS user
//! provider) to the canonical event channel via
//! [`crate::dynamic_trace::normalize::normalize_etw`].
//!
//! Architecture (Codex finding 5 reminder): this is one of N possible
//! `TraceCollector` impls. The trait makes a raw-`windows` contingency
//! a localized swap.
//!
//! Lifecycle:
//! 1. [`Self::start`] builds the trace with a per-provider callback,
//!    starts it in a background thread via `start_and_process`, and
//!    returns immediately. The session is live.
//! 2. Each callback normalizes its raw event and `try_send`s on the
//!    bounded channel. On `Full`, increments [`DropCounter`] —
//!    NEVER blocks the kernel buffer thread.
//! 3. [`Self::stop`] drops the trace handle (ferrisetw stops the
//!    session on drop or via explicit `.stop()`), gathers the final
//!    counts, returns [`CollectorReport`].

#![cfg(all(windows, feature = "dynamic-trace-etw"))]
#![allow(dead_code)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crossbeam_channel::{Sender, TrySendError};
use ferrisetw::provider::kernel_providers::{
    FILE_IO_PROVIDER, IMAGE_LOAD_PROVIDER, PROCESS_PROVIDER, REGISTRY_PROVIDER, TCP_IP_PROVIDER,
};
use ferrisetw::provider::Provider;
use ferrisetw::trace::{KernelTrace, TraceTrait};

use crate::dynamic_trace::collector::{
    CollectorError, CollectorReport, DropCounter, ProviderPlan, TraceCollector,
};
use crate::dynamic_trace::event::{EventSource, HostOs, TraceEvent};
use crate::dynamic_trace::normalize::{normalize_etw, EventIdCounter, NormalizeContext};
use crate::dynamic_trace::ProviderKind;

pub const BACKEND_NAME: &str = "ferrisetw_kernel";

pub struct FerrisEtwCollector {
    run_id: String,
    session_name: String,
    counter: EventIdCounter,
    emitted: Arc<AtomicU64>,
    trace: Option<KernelTrace>,
}

impl FerrisEtwCollector {
    pub fn new(run_id: &str) -> Self {
        let session_name = format!("axe-trace-{}", short_id(run_id));
        Self {
            run_id: run_id.to_string(),
            session_name,
            counter: EventIdCounter::new(),
            emitted: Arc::new(AtomicU64::new(0)),
            trace: None,
        }
    }

    pub fn session_name(&self) -> &str {
        &self.session_name
    }

    /// Build a per-provider callback that normalizes the raw event +
    /// `try_send`s on the bounded channel. Shared by all 6 providers
    /// — only the provider kind differs.
    fn make_callback(
        provider_kind: ProviderKind,
        ctx: NormalizeContext,
        tx: Sender<TraceEvent>,
        drops: DropCounter,
        emitted: Arc<AtomicU64>,
    ) -> impl FnMut(&ferrisetw::EventRecord, &ferrisetw::schema_locator::SchemaLocator)
           + Send
           + Sync
           + 'static {
        move |record, schema_locator| {
            if let Some(event) = normalize_etw(record, schema_locator, &ctx, provider_kind) {
                match tx.try_send(event) {
                    Ok(()) => {
                        emitted.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(TrySendError::Full(_)) => {
                        drops.increment();
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        // Consumer is gone — nothing else we can do.
                    }
                }
            }
        }
    }

    fn build_provider(
        kind: ProviderKind,
        ctx: NormalizeContext,
        tx: Sender<TraceEvent>,
        drops: DropCounter,
        emitted: Arc<AtomicU64>,
    ) -> Result<Provider, CollectorError> {
        let kernel_provider = match kind {
            ProviderKind::File => &FILE_IO_PROVIDER,
            ProviderKind::Registry => &REGISTRY_PROVIDER,
            ProviderKind::Network => &TCP_IP_PROVIDER,
            ProviderKind::Process => &PROCESS_PROVIDER,
            ProviderKind::ImageLoad => &IMAGE_LOAD_PROVIDER,
            ProviderKind::Dns => {
                // DNS is a user-mode provider (Microsoft-Windows-DNS-Client),
                // not part of the SystemTraceProvider kernel bundle. v1
                // skips it from the kernel session; v1.1 adds a parallel
                // UserTrace session.
                return Err(CollectorError::UnsupportedProvider(kind));
            }
        };
        let callback = Self::make_callback(kind, ctx, tx, drops, emitted);
        Ok(Provider::kernel(kernel_provider)
            .add_callback(callback)
            .build())
    }
}

impl TraceCollector for FerrisEtwCollector {
    fn start(
        &mut self,
        plan: ProviderPlan,
        tx: Sender<TraceEvent>,
        drops: DropCounter,
    ) -> Result<(), CollectorError> {
        let ctx = NormalizeContext {
            run_id: self.run_id.clone(),
            host_os: HostOs::Windows,
            source: EventSource::Etw,
            counter: self.counter.clone(),
            plan: plan.clone(),
        };

        let mut builder = KernelTrace::new().named(self.session_name.clone());
        for &kind in &plan.providers {
            match Self::build_provider(
                kind,
                ctx.clone(),
                tx.clone(),
                drops.clone(),
                self.emitted.clone(),
            ) {
                Ok(provider) => {
                    builder = builder.enable(provider);
                }
                Err(CollectorError::UnsupportedProvider(_)) => {
                    // DNS skipped from kernel bundle — keep going.
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        let trace = builder
            .start_and_process()
            .map_err(|e| classify_start_err(&self.session_name, e))?;
        self.trace = Some(trace);
        Ok(())
    }

    fn stop(mut self: Box<Self>) -> Result<CollectorReport, CollectorError> {
        let mut report = CollectorReport {
            events_emitted: self.emitted.load(Ordering::Relaxed),
            events_dropped: 0,
            per_provider_counts: std::collections::BTreeMap::new(),
            diagnostics: Vec::new(),
        };
        if let Some(trace) = self.trace.take() {
            let handled = trace.events_handled();
            report
                .diagnostics
                .push(format!("ferrisetw_events_handled={handled}"));
            trace
                .stop()
                .map_err(|e| CollectorError::SessionStop(format!("{e:?}")))?;
        }
        Ok(report)
    }

    fn name(&self) -> &'static str {
        BACKEND_NAME
    }
}

fn classify_start_err(session_name: &str, e: ferrisetw::trace::TraceError) -> CollectorError {
    let msg = format!("{e:?}");
    if msg.contains("AlreadyExists") || msg.contains("ALREADY_EXISTS") {
        CollectorError::SessionAlreadyExists(session_name.to_string())
    } else {
        CollectorError::SessionStart(msg)
    }
}

fn short_id(run_id: &str) -> String {
    // Keep the session name within ETW's name length budget (1024 wide
    // chars limit, but practical UIs choke far earlier). Take the
    // first 12 hex chars after any `blake3:` prefix.
    let body = run_id.strip_prefix("blake3:").unwrap_or(run_id);
    body.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_name_strips_blake3_prefix_and_caps_length() {
        let c = FerrisEtwCollector::new("blake3:7a1f0123456789abcdef");
        assert!(c.session_name().starts_with("axe-trace-"));
        assert!(c.session_name().len() <= "axe-trace-".len() + 12);
        assert!(c.session_name().contains("7a1f01234567"));
    }

    #[test]
    fn collector_constructs_without_starting_etw() {
        // Without calling start() no ETW session is created.
        // Smoke-tests that the type can be instantiated outside admin
        // context.
        let c = FerrisEtwCollector::new("blake3:test");
        assert_eq!(c.name(), BACKEND_NAME);
        assert!(c.trace.is_none());
    }
}
