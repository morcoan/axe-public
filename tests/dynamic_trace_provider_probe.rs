//! Per-provider ETW validation spike — Codex finding 5 fix.
//!
//! Codex flagged that committing to `ferrisetw =1.2.0` as the sole
//! v1 ETW backend without per-provider validation was building on
//! sand: if ferrisetw silently misses events for, say, the registry
//! provider, downstream Steps 8-17 are wasted work.
//!
//! This spike subscribes to EACH provider in the v1 bundle in a
//! separate short session, drives a deterministic stimulus, and
//! asserts at least one event was captured. If ANY provider class
//! fails its spike, the architectural decision to use ferrisetw is
//! revisited BEFORE the trait-impl in Step 8 is written.
//!
//! Invocation (must run as Administrator):
//!     cargo test --features dynamic-trace-etw \
//!         -- --ignored dynamic_trace_provider_probe --test-threads=1
//!
//! The `--test-threads=1` is required because ETW sessions hold a
//! global slot — two parallel spike tests would collide.
//!
//! v1 status: this file establishes the test scaffold. Each per-
//! provider stimulus body is marked TODO until the actual ferrisetw
//! API surface for v1.2.0 is verified against installed headers. The
//! intent is documented in code so the implementer can fill in each
//! body without re-deriving the design.

#![cfg(all(windows, feature = "dynamic-trace-etw"))]

use std::time::Duration;

/// Duration of each provider's spike session. Long enough to see
/// activity, short enough that running all six takes < 30 seconds.
const SPIKE_SESSION_DURATION: Duration = Duration::from_secs(2);

/// Helper to require Administrator before doing anything. We don't
/// want test runners that aren't elevated to produce confusing
/// pass/fail signals.
fn require_elevated() {
    use axe_core::dynamic_trace::privilege::is_elevated;
    assert!(
        is_elevated(),
        "dynamic_trace_provider_probe MUST run elevated. \
         Run `cargo test --features dynamic-trace-etw -- --ignored --test-threads=1` \
         from an Administrator shell."
    );
}

#[test]
#[ignore = "requires Administrator + ferrisetw API verification"]
fn provider_probe_file() {
    require_elevated();
    // TODO(step-7-spike): subscribe to the FileIo kernel provider via
    // ferrisetw::trace::KernelTraceBuilder with EVENT_TRACE_FLAG_FILE_IO
    // + EVENT_TRACE_FLAG_FILE_IO_INIT. Stimulus: write a small file to
    // %TEMP% via std::fs::write. Assert: ≥1 FileIo event observed in
    // the callback.
    let _ = SPIKE_SESSION_DURATION;
}

#[test]
#[ignore = "requires Administrator + ferrisetw API verification"]
fn provider_probe_registry() {
    require_elevated();
    // TODO(step-7-spike): subscribe to Registry kernel provider via
    // EVENT_TRACE_FLAG_REGISTRY. Stimulus: write a value to
    // HKCU\Software\axe-trace-spike-test then delete it. Assert:
    // ≥1 RegistryWrite event observed.
}

#[test]
#[ignore = "requires Administrator + ferrisetw API verification"]
fn provider_probe_network() {
    require_elevated();
    // TODO(step-7-spike): subscribe to TcpIp kernel provider via
    // EVENT_TRACE_FLAG_NETWORK_TCPIP. Stimulus: open a TCP socket to
    // 127.0.0.1:65535 (will refuse — that's fine; we just need the
    // connect attempt to fire). Assert: ≥1 TcpConnect event observed.
}

#[test]
#[ignore = "requires Administrator + ferrisetw API verification"]
fn provider_probe_dns() {
    require_elevated();
    // TODO(step-7-spike): subscribe to Microsoft-Windows-DNS-Client
    // provider (separate from kernel SystemTraceProvider). Stimulus:
    // resolve "localhost" via std::net::ToSocketAddrs. Assert: ≥1
    // DnsQuery event observed.
}

#[test]
#[ignore = "requires Administrator + ferrisetw API verification"]
fn provider_probe_process() {
    require_elevated();
    // TODO(step-7-spike): subscribe to Process kernel provider via
    // EVENT_TRACE_FLAG_PROCESS. Stimulus: spawn `cmd.exe /c exit 0`
    // and wait. Assert: ≥1 ProcessStart event for that PID.
}

#[test]
#[ignore = "requires Administrator + ferrisetw API verification"]
fn provider_probe_image_load() {
    require_elevated();
    // TODO(step-7-spike): subscribe to ImageLoad kernel provider via
    // EVENT_TRACE_FLAG_IMAGE_LOAD. Stimulus: spawn `cmd.exe /c exit 0`
    // and wait. Assert: ≥1 ImageLoad event for ntdll.dll under that PID.
}

#[test]
#[ignore = "requires Administrator + verifies session-name collision handling"]
fn private_session_name_collision_is_handled() {
    require_elevated();
    // TODO(step-7-spike): start a private session named
    // "axe-trace-spike-collision-test". Try to start a SECOND
    // session with the SAME name. Assert: second start returns
    // ERROR_ALREADY_EXISTS, then ControlTrace(STOP) on the first
    // session cleans up, then the second start succeeds. Documents
    // and validates the orphan-reclaim path Step 8 will exercise.
}
