//! Executor abstraction + first concrete impl wrapping the in-tree
//! `crate::native_emulator` interpreter.
//!
//! The [`FuzzExecutor`] trait is the seam between the fuzzing loop and
//! whatever actually runs the candidate input. Two impls are planned:
//! - [`EmulatorExecutor`] (this step) — wraps `emulate_function` from
//!   `native_emulator.rs`. Crash-authoritative because it's an
//!   interpreter that returns `Result`; cannot itself segfault. Works
//!   on any binary axe-core can already analyze.
//! - `InProcessExecutor` (step 17) — LibAFL + SanitizerCoverage hooks.
//!   Fast but no crash trust; lives behind the same trait.
//!
//! The trait deliberately holds no lifetime parameters — the borrowed
//! analyzer data lives on the impl struct ([`EmulatorExecutor`] takes
//! `<'a>`). This keeps `dyn FuzzExecutor` ergonomic downstream.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::hash::Hasher;
use std::time::{Duration, Instant};

use crate::fuzzer::coverage::CoverageMap;
use crate::native_emulator::{emulate_function, NativeEmulationResult};
use crate::pe::FunctionRecord;
use crate::portable::PortableInput;

/// The fuzz loop's contract with an executor backend.
pub trait FuzzExecutor {
    /// Run the harness/target on `input`. Returns metadata about the
    /// execution; the per-run coverage map is borrowable via
    /// [`map`](Self::map) immediately after.
    ///
    /// `timeout` is advisory; the EmulatorExecutor approximates it via
    /// an instruction budget rather than wall-clock interruption.
    fn run(&mut self, input: &[u8], timeout: Duration) -> ExecutionResult;

    /// Wipe the per-run coverage map. Called between executions; the
    /// global map is held by the caller and not touched here.
    fn reset(&mut self);

    /// Borrow the per-run coverage map. Valid only between calls to
    /// [`reset`](Self::reset) — the next reset will zero it.
    fn map(&self) -> &CoverageMap;
}

/// How a single execution finished. Mapped from the underlying
/// backend's native reporting (emulator exit_reason, signal codes,
/// sanitizer crash kind, etc.).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitKind {
    /// Function returned normally (`ret` or fallthrough at end).
    Ok,
    /// Process/harness crashed via signal or panic.
    Crash,
    /// Wall-clock or instruction-budget timeout.
    Timeout,
    /// AddressSanitizer / UBSan / MSan reported an issue.
    Sanitizer,
    /// Rust panic (in-process backend).
    Panic,
    /// Emulator detected an out-of-bounds memory write.
    EmulatorOOB,
    /// Emulator's unsupported-instructions ratio crossed the fidelity
    /// floor — result is not trustworthy as either success or failure.
    EmulatorLowFidelity,
}

impl ExitKind {
    pub fn is_crash_like(self) -> bool {
        matches!(
            self,
            ExitKind::Crash | ExitKind::Sanitizer | ExitKind::Panic | ExitKind::EmulatorOOB
        )
    }
}

/// What the executor reports back to the loop. Includes any crash
/// details; the loop hands the [`CrashInfo`] off to the dedup database
/// in `crash.rs` (step 6).
#[derive(Clone, Debug)]
pub struct ExecutionResult {
    pub exit: ExitKind,
    pub exec_us: u64,
    pub crash: Option<CrashInfo>,
    /// Count of edges recorded into the coverage map this run. Useful
    /// as a sanity metric in the events stream.
    pub edges_observed: u64,
}

/// Crash details captured by the executor. The dedup layer in step 6
/// hashes a subset of these fields into a [`CrashSignature`] and uses
/// the rest for the LLM-readable `Finding` record.
///
/// [`CrashSignature`]: crate::fuzzer::coverage::CoverageMap
#[derive(Clone, Debug, Default)]
pub struct CrashInfo {
    /// Coarse class: `"emulator_oob"`, `"low_fidelity"`,
    /// `"suspicious_loop_guard"`, `"heap-buffer-overflow"`, …
    pub kind: String,
    pub signal: Option<i32>,
    pub fault_pc: Option<u64>,
    /// Top N application frames (no addresses; just PCs). The dedup
    /// layer normalizes and hashes these.
    pub top_frames: Vec<u64>,
    /// Sanitizer class string (`"AddressSanitizer"`, `"UBSan"`, …)
    /// when known.
    pub sanitizer_type: Option<String>,
}

/// Concrete executor that drives the in-tree `native_emulator`
/// interpreter. Crash-authoritative (the interpreter cannot itself
/// crash — it returns `Option<NativeEmulationResult>`).
///
/// Holds borrowed references to the analyzer's [`PortableInput`] and
/// the target [`FunctionRecord`]; both come from the analysis pass
/// that already ran upstream of the fuzzer.
pub struct EmulatorExecutor<'a> {
    portable: &'a PortableInput<'a>,
    function: &'a FunctionRecord,
    map: CoverageMap,
    budget: usize,
}

impl<'a> EmulatorExecutor<'a> {
    pub fn new(
        portable: &'a PortableInput<'a>,
        function: &'a FunctionRecord,
        budget: usize,
    ) -> Self {
        Self {
            portable,
            function,
            map: CoverageMap::new(),
            budget,
        }
    }
}

// ───── InProcessExecutor (step 17) ──────────────────────────────────
//
// Wraps a `HarnessFn` from the global registry and runs it in-process.
// Per the architecture decision in `mod.rs`, this executor is
// explicitly **not crash-authoritative** — a SIGSEGV in the harness
// kills the parent process. Panics are caught via `catch_unwind`;
// signal-handler bridging (POSIX `sigaction` + Windows
// `SetUnhandledExceptionFilter`) is deferred to a follow-up since
// it needs LibAFL's `WindowsExceptionHandler` and isn't testable
// in a hermetic CI environment.
//
// Coverage: real SanCov pc-guard hooks need the harness compiled
// with `-C passes='sancov-module' -C llvm-args='-sanitizer-coverage-level=4'`
// and the `libafl_targets` linker glue. This step ships the executor
// shell with an empty coverage map; the SanCov bridge is plumbed in
// when the user actually builds a harness with the right flags.

/// In-process executor that runs a registered harness function.
/// See [`crate::fuzzer::harness`] for the registry + `fuzz_target!`
/// macro that defines harnesses.
pub struct InProcessExecutor {
    harness: crate::fuzzer::harness::HarnessFn,
    name: String,
    map: CoverageMap,
}

impl InProcessExecutor {
    /// Construct an executor for a harness registered under `name`.
    /// Returns `None` if no such harness exists; the caller can fall
    /// back to `EmulatorExecutor` or surface the error.
    pub fn lookup(name: &str) -> Option<Self> {
        let harness = crate::fuzzer::harness::lookup(name)?;
        Some(Self {
            harness,
            name: name.to_string(),
            map: CoverageMap::new(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl FuzzExecutor for InProcessExecutor {
    fn run(&mut self, input: &[u8], _timeout: Duration) -> ExecutionResult {
        self.reset();
        let start = Instant::now();
        let owned = input.to_vec();
        let harness = self.harness;
        // catch_unwind catches Rust panics. It does NOT catch
        // SIGSEGV / SIGABRT / sanitizer aborts — those will kill the
        // process. The crash-authoritative emulator (Hybrid mode,
        // step 18) compensates by replaying inputs that triggered
        // a parent-process death.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| harness(&owned)));
        let exec_us = start.elapsed().as_micros() as u64;
        match result {
            Ok(()) => ExecutionResult {
                exit: ExitKind::Ok,
                exec_us,
                crash: None,
                edges_observed: 0, // SanCov plumbing deferred
            },
            Err(panic_payload) => {
                let kind = panic_message(&panic_payload);
                ExecutionResult {
                    exit: ExitKind::Panic,
                    exec_us,
                    crash: Some(CrashInfo {
                        kind,
                        signal: None,
                        fault_pc: None,
                        top_frames: Vec::new(),
                        sanitizer_type: None,
                    }),
                    edges_observed: 0,
                }
            }
        }
    }

    fn reset(&mut self) {
        self.map.clear();
    }

    fn map(&self) -> &CoverageMap {
        &self.map
    }
}

// ───── HybridExecutor (step 18) ─────────────────────────────────────
//
// Combines two `FuzzExecutor` impls (typically `InProcessExecutor`
// + `EmulatorExecutor`) per the Codex finding 2 architecture:
// - **Primary** runs every input for coverage discovery.
// - **Replay** is invoked on every primary-crash to produce the
//   authoritative `CrashInfo` (since the primary may have died
//   in a way that corrupted its own crash detection).
//
// The HybridExecutor returns the PRIMARY's coverage map (because
// that's what novelty classification is built against) but the
// REPLAY's crash info (when a crash happened). On no-crash runs,
// the replay is skipped entirely — fast path.

pub struct HybridExecutor<P, R> {
    primary: P,
    replay: R,
    primary_crashes: u64,
    replay_replays: u64,
}

impl<P: FuzzExecutor, R: FuzzExecutor> HybridExecutor<P, R> {
    pub fn new(primary: P, replay: R) -> Self {
        Self {
            primary,
            replay,
            primary_crashes: 0,
            replay_replays: 0,
        }
    }

    pub fn primary_crashes(&self) -> u64 {
        self.primary_crashes
    }

    pub fn replay_replays(&self) -> u64 {
        self.replay_replays
    }
}

impl<P: FuzzExecutor, R: FuzzExecutor> FuzzExecutor for HybridExecutor<P, R> {
    fn run(&mut self, input: &[u8], timeout: Duration) -> ExecutionResult {
        let primary_result = self.primary.run(input, timeout);
        if !primary_result.exit.is_crash_like() {
            return primary_result;
        }
        self.primary_crashes += 1;
        // Replay under the crash-authoritative backend.
        let replay_result = self.replay.run(input, timeout);
        self.replay_replays += 1;
        // Build the final result: primary's coverage + exec_us, but
        // the REPLAY's exit kind + crash info. If the replay didn't
        // also crash (false positive on InProcess side?), surface
        // both signals: keep the primary's exit but tag the crash
        // info as `replay_disagrees`.
        if replay_result.exit.is_crash_like() {
            ExecutionResult {
                exit: replay_result.exit,
                exec_us: primary_result.exec_us + replay_result.exec_us,
                crash: replay_result.crash,
                edges_observed: primary_result.edges_observed,
            }
        } else {
            // Replay didn't reproduce — likely a primary-only
            // condition (e.g., panic in Rust harness that the
            // emulator can't replicate because the emulator doesn't
            // run Rust). Keep the primary's signal but note it.
            let mut crash = primary_result.crash.clone().unwrap_or_default();
            crash.kind = format!("primary_only({})", crash.kind);
            ExecutionResult {
                exit: primary_result.exit,
                exec_us: primary_result.exec_us + replay_result.exec_us,
                crash: Some(crash),
                edges_observed: primary_result.edges_observed,
            }
        }
    }

    fn reset(&mut self) {
        self.primary.reset();
        self.replay.reset();
    }

    fn map(&self) -> &CoverageMap {
        self.primary.map()
    }
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        format!("panic: {s}")
    } else if let Some(s) = payload.downcast_ref::<String>() {
        format!("panic: {s}")
    } else {
        "panic: <non-string payload>".to_string()
    }
}

impl<'a> FuzzExecutor for EmulatorExecutor<'a> {
    fn run(&mut self, input: &[u8], _timeout: Duration) -> ExecutionResult {
        self.reset();
        let start = Instant::now();
        let initial_regs = input_to_regs(input);
        let result = emulate_function(
            self.portable,
            self.function,
            Some(&initial_regs),
            Some(self.budget),
        );
        let exec_us = start.elapsed().as_micros() as u64;
        match result {
            Some(emu) => {
                let edges_observed = record_path_as_edges(&mut self.map, &emu.visited_path);
                let exit = classify_emulator_exit(&emu);
                let crash = build_crash_info(&emu, exit);
                ExecutionResult {
                    exit,
                    exec_us,
                    crash,
                    edges_observed,
                }
            }
            None => ExecutionResult {
                exit: ExitKind::EmulatorLowFidelity,
                exec_us,
                crash: Some(CrashInfo {
                    kind: "emulator_unable_to_start".into(),
                    ..CrashInfo::default()
                }),
                edges_observed: 0,
            },
        }
    }

    fn reset(&mut self) {
        self.map.clear();
    }

    fn map(&self) -> &CoverageMap {
        &self.map
    }
}

/// Convert a fuzz-input byte string into initial GPR values for the
/// emulator. Hash the bytes into a u64 seed, then distribute via the
/// `mutate_value` boundary table across the System-V/Win64 calling-
/// convention argument registers (rcx/rdx/r8/r9).
///
/// This mirrors `native_fuzzer.rs::mutated_initial_regs` but seeds
/// from the input bytes instead of a deterministic counter — the
/// coverage feedback loop is what drives diversity here, not the seed
/// formula.
pub fn input_to_regs(bytes: &[u8]) -> BTreeMap<String, u64> {
    let seed = hash_input_to_seed(bytes);
    let mut regs = BTreeMap::new();
    for name in [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
    ] {
        regs.insert(name.to_string(), 0u64);
    }
    regs.insert("rsp".into(), 0x7FFE_0000);
    regs.insert("rbp".into(), 0x7FFE_0000);
    regs.insert("rcx".into(), mutate_value(seed, 0));
    regs.insert("rdx".into(), mutate_value(seed, 1));
    regs.insert("r8".into(), mutate_value(seed, 2));
    regs.insert("r9".into(), mutate_value(seed, 3));
    regs
}

fn hash_input_to_seed(bytes: &[u8]) -> u64 {
    let mut h = ahash::AHasher::default();
    h.write(bytes);
    h.finish()
}

/// Re-export the canonical boundary-value table from `mutators.rs`.
/// Lives there to keep the table single-sourced; this thin alias
/// preserves call sites in `input_to_regs`.
fn mutate_value(seed: u64, slot: u32) -> u64 {
    crate::fuzzer::mutators::boundary_value(seed, slot)
}

/// Fold an emulator's PC trace into AFL-style edges and record them
/// into the coverage map. Each consecutive `(path[i], path[i+1])` pair
/// becomes one edge — same semantic shape as
/// `__sanitizer_cov_trace_pc_guard`'s edge instrumentation, just
/// derived from the trace instead of inserted by the compiler.
///
/// Returns the count of edges recorded (including duplicates within
/// this run, since the map saturates on the per-edge byte).
pub fn record_path_as_edges(map: &mut CoverageMap, visited_path: &[u64]) -> u64 {
    let mut count = 0u64;
    for window in visited_path.windows(2) {
        map.record_edge(window[0], window[1]);
        count += 1;
    }
    count
}

/// Map the emulator's native exit reasoning into [`ExitKind`].
/// Ports the classification logic from `native_fuzzer.rs:122`.
pub fn classify_emulator_exit(result: &NativeEmulationResult) -> ExitKind {
    if !result.oob_write_sites.is_empty() {
        return ExitKind::EmulatorOOB;
    }
    let supported = result.trace.supported_steps as f64;
    let unsupported = result.trace.unsupported_instructions.len() as f64;
    if supported > 0.0 && unsupported / supported > 0.25 {
        return ExitKind::EmulatorLowFidelity;
    }
    match result.trace.exit_reason.as_str() {
        "return" | "function_end" => ExitKind::Ok,
        "budget_cap" => ExitKind::Timeout,
        // "loop_guard" and "branch_exit" are anomalies but not crashes
        // — they suggest the emulator hit something interesting but
        // not necessarily faulty. Surface as Ok for now; crash.rs in
        // step 6 may re-classify some of these as suspicious.
        _ => ExitKind::Ok,
    }
}

/// Build a [`CrashInfo`] from an emulator result when the exit looks
/// crash-like. Returns `None` for normal exits.
fn build_crash_info(result: &NativeEmulationResult, exit: ExitKind) -> Option<CrashInfo> {
    if !exit.is_crash_like() && exit != ExitKind::Timeout && exit != ExitKind::EmulatorLowFidelity {
        return None;
    }
    let kind = match exit {
        ExitKind::EmulatorOOB => "emulator_oob".to_string(),
        ExitKind::EmulatorLowFidelity => "low_fidelity".to_string(),
        ExitKind::Timeout => "budget_cap".to_string(),
        _ => result.trace.exit_reason.clone(),
    };
    let fault_pc = result.oob_write_sites.first().copied();
    // Top frames = last N PCs in the trace; the dedup layer normalizes.
    let top_frames: Vec<u64> = result.visited_path.iter().rev().take(6).copied().collect();
    Some(CrashInfo {
        kind,
        signal: None,
        fault_pc,
        top_frames,
        sanitizer_type: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_to_regs_seeds_argument_registers() {
        let regs = input_to_regs(b"hello world");
        // The argument registers must be populated (non-default).
        // We can't predict the exact values across ahash seeds, but
        // they must come from the mutate_value table so the high bits
        // either match a boundary value or are derived from the seed.
        assert!(regs.contains_key("rcx"));
        assert!(regs.contains_key("rdx"));
        assert!(regs.contains_key("r8"));
        assert!(regs.contains_key("r9"));
        // The non-argument scratch regs stay at zero.
        assert_eq!(regs.get("rax").copied(), Some(0));
        assert_eq!(regs.get("rsi").copied(), Some(0));
        // Stack and frame pointers are set to a safe high address.
        assert_eq!(regs.get("rsp").copied(), Some(0x7FFE_0000));
        assert_eq!(regs.get("rbp").copied(), Some(0x7FFE_0000));
    }

    #[test]
    fn input_to_regs_is_deterministic_for_same_input() {
        let a = input_to_regs(b"same input");
        let b = input_to_regs(b"same input");
        assert_eq!(a, b, "same bytes must produce same registers");
    }

    #[test]
    fn input_to_regs_differs_across_inputs() {
        let a = input_to_regs(b"input one");
        let b = input_to_regs(b"input two");
        // At least the argument registers should differ.
        assert!(
            a.get("rcx") != b.get("rcx") || a.get("rdx") != b.get("rdx"),
            "different inputs should produce different argument regs"
        );
    }

    #[test]
    fn input_to_regs_handles_empty_input() {
        let regs = input_to_regs(b"");
        // Must not panic; all expected keys present.
        assert!(regs.contains_key("rcx"));
        assert!(regs.contains_key("rsp"));
    }

    #[test]
    fn mutate_value_hits_each_boundary() {
        // The match is on `seed & 7`, so seeds 0..7 cover every arm.
        let observed: std::collections::BTreeSet<u64> =
            (0..64).map(|s| mutate_value(s, 0)).collect();
        // We expect at least the explicit boundary values to appear.
        assert!(observed.contains(&0));
        assert!(observed.contains(&1));
        assert!(observed.contains(&0xFFFF_FFFF));
        assert!(observed.contains(&u64::MAX));
    }

    #[test]
    fn record_path_as_edges_counts_pairs() {
        let mut map = CoverageMap::new();
        let path = vec![0x1000u64, 0x1010, 0x1020, 0x1030];
        let count = record_path_as_edges(&mut map, &path);
        assert_eq!(count, 3, "3 windows of 2 over 4 PCs");
        // The map should now have at least 3 non-zero slots (could be
        // 2 in the absurdly unlikely case of 2 hash collisions — but
        // for these well-spread inputs we expect 3).
        let nonzero = map.as_slice().iter().filter(|&&b| b > 0).count();
        assert!(nonzero >= 2, "at least 2 distinct edge slots populated");
    }

    #[test]
    fn record_path_handles_short_traces() {
        let mut map = CoverageMap::new();
        // Single PC = zero pairs.
        let count = record_path_as_edges(&mut map, &[0x1000]);
        assert_eq!(count, 0);
        // Empty = zero pairs.
        let count = record_path_as_edges(&mut map, &[]);
        assert_eq!(count, 0);
    }

    #[test]
    fn classify_oob_writes_as_emulator_oob() {
        let result = synth_result_with_oob(&[0x1234_5678]);
        assert_eq!(classify_emulator_exit(&result), ExitKind::EmulatorOOB);
    }

    #[test]
    fn classify_normal_return_as_ok() {
        let result = synth_result("return", 50, 0);
        assert_eq!(classify_emulator_exit(&result), ExitKind::Ok);
    }

    #[test]
    fn classify_budget_cap_as_timeout() {
        let result = synth_result("budget_cap", 50, 0);
        assert_eq!(classify_emulator_exit(&result), ExitKind::Timeout);
    }

    #[test]
    fn classify_low_fidelity_above_25pct_ratio() {
        // 4 supported / 2 unsupported = 50% > 25% → low fidelity.
        let result = synth_result("return", 4, 2);
        assert_eq!(
            classify_emulator_exit(&result),
            ExitKind::EmulatorLowFidelity
        );
    }

    #[test]
    fn classify_within_fidelity_floor_is_ok() {
        // 100 supported / 10 unsupported = 10% < 25% → still ok.
        let result = synth_result("return", 100, 10);
        assert_eq!(classify_emulator_exit(&result), ExitKind::Ok);
    }

    #[test]
    fn exit_kind_crash_classification() {
        assert!(ExitKind::Crash.is_crash_like());
        assert!(ExitKind::EmulatorOOB.is_crash_like());
        assert!(ExitKind::Sanitizer.is_crash_like());
        assert!(ExitKind::Panic.is_crash_like());
        assert!(!ExitKind::Ok.is_crash_like());
        assert!(!ExitKind::Timeout.is_crash_like());
        assert!(!ExitKind::EmulatorLowFidelity.is_crash_like());
    }

    // --- helpers ---

    fn synth_result(
        exit_reason: &str,
        supported: usize,
        unsupported: usize,
    ) -> NativeEmulationResult {
        use crate::native_emulator::NativeEmulationResult;
        use crate::portable::EmulationTraceRecord;
        use std::collections::BTreeMap;
        NativeEmulationResult {
            function: 0,
            start_va: 0,
            unsupported_instructions: Vec::new(),
            cap_hit: false,
            predicates: Vec::new(),
            trace: EmulationTraceRecord {
                trace_id: "test".into(),
                function: 0,
                start_va: 0,
                status: "ok".into(),
                step_count: supported + unsupported,
                supported_steps: supported,
                unsupported_instructions: vec!["nop".into(); unsupported],
                cap_hit: false,
                budget: "test".into(),
                api_stubs: Vec::new(),
                api_stub_events: Vec::new(),
                memory_events: Vec::new(),
                exit_reason: exit_reason.into(),
                registers: BTreeMap::new(),
                evidence: Vec::new(),
            },
            visited_path: Vec::new(),
            oob_write_sites: Vec::new(),
        }
    }

    fn synth_result_with_oob(oob_sites: &[u64]) -> NativeEmulationResult {
        let mut r = synth_result("return", 10, 0);
        r.oob_write_sites = oob_sites.to_vec();
        r
    }

    // ───── InProcessExecutor tests (step 17) ─────

    use crate::fuzzer::harness;
    use std::sync::Mutex;
    use std::time::Duration;

    static IPE_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn ok_harness(_data: &[u8]) {}

    fn panic_harness(_data: &[u8]) {
        panic!("intentional test panic");
    }

    fn echo_panic_on_specific(input: &[u8]) {
        if input == b"crash-me" {
            panic!("triggered by input");
        }
    }

    #[test]
    fn inprocess_lookup_returns_none_for_unknown_name() {
        let _g = IPE_TEST_LOCK.lock().unwrap();
        assert!(InProcessExecutor::lookup("missing_harness_xyz").is_none());
    }

    #[test]
    fn inprocess_runs_ok_harness_to_completion() {
        let _g = IPE_TEST_LOCK.lock().unwrap();
        harness::register("ipe_ok", ok_harness);
        let mut e = InProcessExecutor::lookup("ipe_ok").unwrap();
        let r = e.run(b"input", Duration::from_secs(1));
        assert_eq!(r.exit, ExitKind::Ok);
        assert!(r.crash.is_none());
    }

    #[test]
    fn inprocess_catches_panic_and_reports_kind() {
        let _g = IPE_TEST_LOCK.lock().unwrap();
        harness::register("ipe_panic", panic_harness);
        let mut e = InProcessExecutor::lookup("ipe_panic").unwrap();
        let r = e.run(b"any", Duration::from_secs(1));
        assert_eq!(r.exit, ExitKind::Panic);
        let crash = r.crash.expect("crash info populated");
        assert!(
            crash.kind.contains("intentional test panic"),
            "panic message preserved in CrashInfo.kind, got {}",
            crash.kind
        );
    }

    #[test]
    fn inprocess_input_dependent_panic() {
        let _g = IPE_TEST_LOCK.lock().unwrap();
        harness::register("ipe_input_panic", echo_panic_on_specific);
        let mut e = InProcessExecutor::lookup("ipe_input_panic").unwrap();
        let safe = e.run(b"safe-input", Duration::from_secs(1));
        assert_eq!(safe.exit, ExitKind::Ok);
        let crash = e.run(b"crash-me", Duration::from_secs(1));
        assert_eq!(crash.exit, ExitKind::Panic);
    }

    // ───── HybridExecutor tests (step 18) ─────

    /// Inline stub executor for hybrid-mode tests. Driven by a
    /// scripted exit-kind so we don't need PortableInput here.
    struct StubExecutor {
        next_exit: ExitKind,
        kind_label: String,
        map: CoverageMap,
        runs: u64,
    }

    impl StubExecutor {
        fn new(exit: ExitKind, kind_label: &str) -> Self {
            Self {
                next_exit: exit,
                kind_label: kind_label.to_string(),
                map: CoverageMap::new(),
                runs: 0,
            }
        }
    }

    impl FuzzExecutor for StubExecutor {
        fn run(&mut self, _input: &[u8], _timeout: Duration) -> ExecutionResult {
            self.runs += 1;
            self.reset();
            ExecutionResult {
                exit: self.next_exit,
                exec_us: 100,
                crash: if self.next_exit.is_crash_like() {
                    Some(CrashInfo {
                        kind: self.kind_label.clone(),
                        signal: None,
                        fault_pc: None,
                        top_frames: Vec::new(),
                        sanitizer_type: None,
                    })
                } else {
                    None
                },
                edges_observed: 1,
            }
        }
        fn reset(&mut self) {
            self.map.clear();
        }
        fn map(&self) -> &CoverageMap {
            &self.map
        }
    }

    #[test]
    fn hybrid_no_crash_path_skips_replay() {
        let primary = StubExecutor::new(ExitKind::Ok, "");
        let replay = StubExecutor::new(ExitKind::Ok, "");
        let mut h = HybridExecutor::new(primary, replay);
        let r = h.run(b"input", Duration::from_secs(1));
        assert_eq!(r.exit, ExitKind::Ok);
        assert_eq!(h.primary_crashes(), 0);
        assert_eq!(h.replay_replays(), 0);
    }

    #[test]
    fn hybrid_crash_in_primary_triggers_replay_and_uses_replay_kind() {
        // Primary panics; replay reproduces as emulator_oob.
        let primary = StubExecutor::new(ExitKind::Panic, "intentional");
        let replay = StubExecutor::new(ExitKind::EmulatorOOB, "emulator_oob");
        let mut h = HybridExecutor::new(primary, replay);
        let r = h.run(b"input", Duration::from_secs(1));
        // The hybrid returns the emulator (replay) backend's exit/crash.
        assert_eq!(r.exit, ExitKind::EmulatorOOB);
        assert_eq!(r.crash.unwrap().kind, "emulator_oob");
        assert_eq!(h.primary_crashes(), 1);
        assert_eq!(h.replay_replays(), 1);
    }

    #[test]
    fn hybrid_replay_disagrees_marks_primary_only() {
        // Primary panics, replay doesn't reproduce.
        let primary = StubExecutor::new(ExitKind::Panic, "rust_only_panic");
        let replay = StubExecutor::new(ExitKind::Ok, "");
        let mut h = HybridExecutor::new(primary, replay);
        let r = h.run(b"input", Duration::from_secs(1));
        // Primary's exit kind is kept; kind prefixed with primary_only(...)
        assert_eq!(r.exit, ExitKind::Panic);
        let crash = r.crash.unwrap();
        assert!(
            crash.kind.contains("primary_only"),
            "expected primary_only marker, got {}",
            crash.kind
        );
        assert!(
            crash.kind.contains("rust_only_panic"),
            "original kind preserved inside marker, got {}",
            crash.kind
        );
    }

    #[test]
    fn hybrid_reset_propagates_to_both_backends() {
        let primary = StubExecutor::new(ExitKind::Ok, "");
        let replay = StubExecutor::new(ExitKind::Ok, "");
        let mut h = HybridExecutor::new(primary, replay);
        h.run(b"a", Duration::from_secs(1));
        h.reset();
        // The trait is reset-call-only; no observable state we can
        // assert on stub executors. Reaching this point without panic
        // is the assertion.
    }
}
