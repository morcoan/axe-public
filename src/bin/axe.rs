use anyhow::{anyhow, Context, Result};
use axe_core::folder_scan::{scan_folder, ScanOptions};
use axe_core::AnalysisOptions;
use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "axe",
    version,
    about = "Headless reverse-engineering engine for LLM-feeding workflows",
    long_about = "axe analyzes PE/ELF/Mach-O binaries (x86/x64) and emits structured JSONL + Markdown dossier cards. Headless, single static binary, no Python."
)]
struct Args {
    /// Path to a binary file or a folder of binaries to analyze
    #[arg(value_name = "PATH")]
    path: PathBuf,

    /// Explicit analysis preset. `real-5`/`real-8`/`real-9` enable high-signal deterministic artifact profiles.
    #[arg(long, value_parser = ["real-5", "real-8", "real-9"])]
    preset: Option<String>,

    /// Output root directory (each run gets a fresh subdirectory)
    #[arg(long, value_name = "DIR", default_value = "out")]
    out_root: PathBuf,

    /// Number of parallel workers; "auto" uses CPU count
    #[arg(long, value_name = "N|auto", default_value = "auto")]
    workers: String,

    // ---------- folder gating ----------
    /// Skip archive extraction during folder scans
    #[arg(long)]
    no_extract_archives: bool,

    /// Max recursion depth for folder walks
    #[arg(long, default_value_t = 6)]
    max_depth: usize,

    /// Max files to enqueue during a folder scan
    #[arg(long, default_value_t = 4096)]
    max_files: usize,

    /// Max total bytes to enqueue during a folder scan
    #[arg(long, default_value_t = 4 * 1024 * 1024 * 1024_u64)]
    max_bytes: u64,

    /// Max corpus chunks emitted per folder run
    #[arg(long, default_value_t = 0)]
    max_corpus_chunks: usize,

    /// Per-file byte limit; files over this size are skipped in folder mode
    #[arg(long, default_value_t = 256 * 1024 * 1024_u64)]
    single_file_byte_limit: u64,

    /// Folder-mode PE handling
    #[arg(long, value_parser = ["full", "triage", "skip"], default_value = "full")]
    folder_pe_mode: String,

    /// Progress every N samples
    #[arg(long, default_value_t = 8)]
    progress_every: usize,

    /// Progress seconds heartbeat
    #[arg(long, default_value_t = 2)]
    progress_seconds: usize,

    /// Archive recursion depth (0 disables)
    #[arg(long, default_value_t = 2)]
    archive_depth: usize,

    // ---------- analysis depth ----------
    /// Analysis mode
    #[arg(long, value_parser = ["fast", "full"], default_value = "full")]
    mode: String,

    /// Semantic level (off | basic | true10)
    #[arg(long, default_value = "basic")]
    semantic_level: String,

    /// Semantic budget
    #[arg(long, value_parser = ["low", "normal", "high"], default_value = "normal")]
    semantic_budget: String,

    /// Semantic focus
    #[arg(long, default_value = "malware")]
    semantic_focus: String,

    /// Wrapper-collapse search depth
    #[arg(long, default_value_t = 4)]
    wrapper_collapse_depth: usize,

    /// Pseudo-IR depth
    #[arg(long, value_parser = ["basic", "expanded"], default_value = "basic")]
    pseudo_ir: String,

    /// Second-pass policy
    #[arg(long, value_parser = ["off", "auto", "all"], default_value = "auto")]
    second_pass: String,

    // ---------- native capabilities ----------
    /// Capability profile
    #[arg(long, value_parser = ["portable-max", "native-max"], default_value = "native-max")]
    capability_profile: String,

    /// Portable tools directory
    #[arg(long, default_value = "tools")]
    portable_tools_dir: String,

    /// Emulation budget
    #[arg(long, value_parser = ["normal", "high", "max"], default_value = "normal")]
    emulation_budget: String,

    /// Fuzz mode
    #[arg(long, value_parser = ["off", "dry-run", "execute"], default_value = "execute")]
    fuzz_mode: String,

    /// Fuzz iterations per candidate
    #[arg(long, default_value_t = 16)]
    fuzz_iterations: usize,

    /// Offline trace dir for trace ingest
    #[arg(long, value_name = "DIR")]
    trace_dir: Option<PathBuf>,

    // ---------- dynamic-trace (Windows ETW v1) ----------
    /// Dynamic-trace mode (Windows ETW). `on` runs a session; `off` skips it.
    #[arg(long, value_parser = ["off", "on"], default_value = "off")]
    dynamic_trace: String,

    /// Wall-clock cap for the dynamic-trace session, seconds.
    #[arg(long, value_name = "SECS", default_value_t = 30)]
    dynamic_trace_duration: u64,

    /// PID or exe path to capture (exe path → spawn CREATE_SUSPENDED).
    #[arg(long, value_name = "PID|EXE")]
    dynamic_trace_target: Option<String>,

    /// Output directory for dynamic-trace artifacts (default: <out-root>/dynamic_trace).
    #[arg(long, value_name = "DIR")]
    dynamic_trace_out: Option<PathBuf>,

    /// Comma-separated provider bundle. v1 default is the full kernel set.
    #[arg(
        long,
        value_name = "CSV",
        default_value = "file,registry,network,dns,process,image_load"
    )]
    dynamic_trace_providers: String,

    /// What to do when events get dropped under back-pressure
    /// (Codex finding 3). `partial` (default) downgrades outcome to
    /// Partial; `fail` aborts as Failed; `warn` keeps Complete with
    /// uncertainty stamp.
    #[arg(long, value_parser = ["warn", "partial", "fail"], default_value = "partial")]
    dynamic_trace_loss_policy: String,

    // ---------- vuln-discovery (v1.0 static-only) ----------
    /// Vuln-discovery pipeline mode. v1.0 ships static-only; v1.1
    /// (dynamic confirmation, harness synthesis, lifetime templates)
    /// is gated by docs/vuln-calibration.md.
    #[arg(long, value_parser = ["off", "on"], default_value = "off")]
    vuln_discovery: String,

    /// Comma-separated template ids, or "all" for the full v1.0 set
    /// (12 templates).
    #[arg(long, value_name = "CSV|all", default_value = "all")]
    vuln_templates: String,

    /// Drop findings with confidence.score below this threshold from
    /// the manifest. v1.0 default 0.45.
    #[arg(long, value_name = "0.0-1.0", default_value_t = 0.45)]
    vuln_confidence_threshold: f32,

    /// Output directory for vuln artifacts (default: <out-root>/vuln).
    #[arg(long, value_name = "DIR")]
    vuln_out: Option<PathBuf>,

    // ---------- vuln-discovery v1.1 ----------
    /// v1.1 dynamic-confirmation source selector. `off` keeps the
    /// v1.0 static-only behavior; `fuzz`/`trace`/`concolic` enable
    /// the named source; `both` enables fuzz+trace; `all` enables
    /// every available source. Per Codex finding 1, sources without
    /// their gating Cargo feature compiled in are silently skipped.
    #[arg(
        long,
        value_parser = ["off", "fuzz", "trace", "both", "concolic", "all"],
        default_value = "off",
    )]
    vuln_dynamic_confirmation: String,

    /// v1.1: opt in to the alias-limited lifetime templates
    /// (`uaf_candidate`, `double_free_candidate`). Findings emit to
    /// `vuln/lifetime_candidates.jsonl`, NOT `findings.jsonl`, and
    /// are excluded from `evidence_bundle.json::top_findings` per
    /// Codex finding 3.
    #[arg(long)]
    vuln_include_lifetime: bool,

    /// v1.1: synthesized-harness tier selector. `skeleton` (default)
    /// emits only Markdown skeletons (binary-only PE entries always
    /// get this tier per Codex finding 2). `both` ALSO emits a
    /// .runnable.rs template for source-available chains; the
    /// runnable file is written ONLY after verify_runnable() PASSES.
    #[arg(
        long,
        value_parser = ["skeleton", "both"],
        default_value = "skeleton",
    )]
    vuln_harness_tier: String,

    // ---------- unpack (Aurora generic unpacker) ----------
    /// Aurora unpacker mode. `on` spawns the target under
    /// Aurora's debugger + memory tracer + anti-anti-VM hooks
    /// and emits a snapshot (`out/unpack/`) that
    /// `PEImage::from_snapshot()` re-consumes. See
    /// `docs/unpack-capabilities.md` for honest capability
    /// bounds.
    #[arg(long, value_parser = ["off", "on"], default_value = "off")]
    unpack: String,

    /// Which tracer drives the unpacking. `debug` (Windows
    /// debug API) works in any virt layer; `whp` requires
    /// Hyper-V (mutually exclusive with VMware/VBox);
    /// `driver` requires test-signing mode; `auto` picks the
    /// best available.
    #[arg(long, value_parser = ["debug", "whp", "driver", "auto"], default_value = "debug")]
    unpack_tracer: String,

    /// Wall-clock budget for the Aurora session in seconds.
    #[arg(long, default_value_t = 60u64)]
    unpack_timeout_secs: u64,

    /// Instruction-count budget (~1000 instr per debug event).
    #[arg(long, default_value_t = 100_000_000u64)]
    unpack_instr_budget: u64,

    /// Output directory for unpack artifacts (default: <out-root>/unpack).
    #[arg(long, value_name = "DIR")]
    unpack_out: Option<PathBuf>,

    /// Disable user-mode anti-anti-VM + anti-debug hooks
    /// (useful for fixtures that want to observe what the
    /// target does without suppression).
    #[arg(long, default_value_t = false)]
    unpack_hooks_disable: bool,

    /// Opt-in: enable the devirt pass (legacy
    /// VMProtect/Themida handler-stepping). Requires
    /// `unpack-emulation` feature. Produces `best_effort` tier
    /// findings only.
    #[arg(long, default_value_t = false)]
    unpack_include_devirt: bool,

    /// Opt-in: allow the Themida 3.x partial-recovery devirt path.
    /// Defaults OFF — modern Themida 3.x defeats the generic
    /// dispatcher-walking technique, so its output is hard-capped at
    /// `best_effort` confidence (Phase B5 0.40 score cap, enforced in
    /// `devirt/trace.rs::TraceWriter::finalize`). Without this flag set,
    /// detection of Themida 3.x markers (≥3 of 4) emits an informational
    /// note in the snapshot and skips the trace; with it, a partial
    /// trace is written.
    #[arg(long, default_value_t = false)]
    devirt_allow_best_effort_3x: bool,

    /// C decompilation mode
    #[arg(long, value_parser = ["off", "selected", "all"], default_value = "selected")]
    decompile_c: String,

    /// Deterministic LLM artifact graph mode
    #[arg(long, value_parser = ["off", "selected", "all"], default_value = "all")]
    llm_artifacts: String,

    /// Compact review-pack generation mode
    #[arg(long, value_parser = ["off", "ranked", "all"], default_value = "ranked")]
    review_packs: String,

    /// Rust-like source view mode
    #[arg(long, value_parser = ["off", "selected", "all"], default_value = "selected")]
    decompile_source: String,

    /// Rust-only debug symbol mode
    #[arg(long, value_parser = ["off", "basic", "full"], default_value = "basic")]
    symbols: String,

    /// Symbol packet generation mode
    #[arg(long, value_parser = ["off", "ranked", "all"], default_value = "ranked")]
    symbol_packets: String,

    /// Query an existing output folder's SymbolGraph without rerunning analysis
    #[arg(long, value_parser = ["address", "name", "source", "type"])]
    symbol_query: Option<String>,

    /// Query value for --symbol-query
    #[arg(long)]
    symbol_query_value: Option<String>,

    /// Local directory to search for PDB, DWARF, dSYM, or split-debug files; repeatable
    #[arg(long = "symbol-path", value_name = "DIR")]
    symbol_paths: Vec<PathBuf>,

    /// Optional local parsed-index cache directory
    #[arg(long, value_name = "DIR")]
    symbol_cache: Option<PathBuf>,

    // ---------- limits ----------
    /// Max strings extracted
    #[arg(long, default_value_t = 8192)]
    max_strings: usize,

    /// Max functions discovered
    #[arg(long, default_value_t = 4096)]
    max_functions: usize,

    /// Max xrefs collected
    #[arg(long, default_value_t = 65536)]
    max_xrefs: usize,

    /// Max bytes of corpus text aggregated per folder run
    #[arg(long, default_value_t = 4 * 1024 * 1024_u64)]
    max_text_bytes: u64,

    // ---------- profiling ----------
    /// Emit a per-stage timing breakdown to analysis.json
    #[arg(long)]
    profile_analysis: bool,

    /// Precomputed SHA-256 of the input (skips internal hashing)
    #[arg(long)]
    precomputed_sha256: Option<String>,

    // ---------- diff mode ----------
    /// Run cross-binary diff instead of analyze: <PATH> is the left run output dir, --diff <RIGHT> is the right
    #[arg(long, value_name = "RIGHT_OUT_DIR")]
    diff: Option<PathBuf>,

    /// Write diff report to this Markdown file (default: <left>/diff_<timestamp>.md)
    #[arg(long, value_name = "FILE")]
    diff_output: Option<PathBuf>,

    /// Print the full analysis JSON to stdout (default: just the run-dir path).
    /// JSON files are always written to disk; this flag controls stdout noise.
    #[arg(long)]
    print_analysis: bool,
}

impl Args {
    fn into_scan_options(&self) -> ScanOptions {
        ScanOptions {
            analysis: self.into_options(),
            workers: resolve_workers(&self.workers),
            max_depth: self.max_depth,
            max_files: self.max_files,
            max_bytes: self.max_bytes,
            single_file_byte_limit: self.single_file_byte_limit,
            no_extract_archives: self.no_extract_archives,
            archive_depth: self.archive_depth,
            folder_pe_mode: self.folder_pe_mode.clone(),
            progress_every: self.progress_every,
            progress_seconds: self.progress_seconds,
        }
    }

    fn into_options(&self) -> AnalysisOptions {
        let mut options = AnalysisOptions {
            preset: self.preset.clone(),
            max_strings: self.max_strings,
            max_functions: self.max_functions,
            max_xrefs: self.max_xrefs,
            deep: self.mode == "full",
            precomputed_sha256: self.precomputed_sha256.clone(),
            native_inner_workers: None,
            profile_analysis: self.profile_analysis,
            semantic_level: self.semantic_level.clone(),
            second_pass: self.second_pass.clone(),
            semantic_budget: self.semantic_budget.clone(),
            semantic_focus: self.semantic_focus.clone(),
            wrapper_collapse_depth: self.wrapper_collapse_depth,
            pseudo_ir: self.pseudo_ir.clone(),
            capability_profile: self.capability_profile.clone(),
            portable_tools_dir: self.portable_tools_dir.clone(),
            emulation_budget: self.emulation_budget.clone(),
            fuzz_mode: self.fuzz_mode.clone(),
            fuzz_iterations: self.fuzz_iterations,
            trace_dir: self
                .trace_dir
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            decompile_c: self.decompile_c.clone(),
            llm_artifacts: self.llm_artifacts.clone(),
            review_packs: self.review_packs.clone(),
            decompile_source: self.decompile_source.clone(),
            symbols: self.symbols.clone(),
            symbol_packets: self.symbol_packets.clone(),
            symbol_paths: self
                .symbol_paths
                .iter()
                .map(|path| path.to_string_lossy().to_string())
                .collect(),
            symbol_cache: self
                .symbol_cache
                .as_ref()
                .map(|path| path.to_string_lossy().to_string()),
            progress_path: None,
            dynamic_trace_mode: self.dynamic_trace.clone(),
            dynamic_trace_duration_secs: self.dynamic_trace_duration,
            dynamic_trace_target: self.dynamic_trace_target.clone(),
            dynamic_trace_out: self
                .dynamic_trace_out
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            dynamic_trace_providers: self.dynamic_trace_providers.clone(),
            dynamic_trace_loss_policy: self.dynamic_trace_loss_policy.clone(),
            vuln_discovery_mode: self.vuln_discovery.clone(),
            vuln_templates: self.vuln_templates.clone(),
            vuln_confidence_threshold: self.vuln_confidence_threshold,
            vuln_out: self
                .vuln_out
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            vuln_dynamic_confirmation: self.vuln_dynamic_confirmation.clone(),
            vuln_dynamic_evidence: Vec::new(),
            vuln_include_lifetime: self.vuln_include_lifetime,
            vuln_harness_tier: self.vuln_harness_tier.clone(),
            unpack_mode: self.unpack.clone(),
            unpack_tracer: self.unpack_tracer.clone(),
            unpack_timeout_secs: self.unpack_timeout_secs,
            unpack_instr_budget: self.unpack_instr_budget,
            unpack_out: self
                .unpack_out
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            unpack_hooks_disable: self.unpack_hooks_disable,
            unpack_include_devirt: self.unpack_include_devirt,
        };
        if self.preset.as_deref() == Some("real-5") {
            options.apply_real_5_profile();
        } else if self.preset.as_deref() == Some("real-8") {
            options.apply_real_8_profile();
        } else if self.preset.as_deref() == Some("real-9") {
            options.apply_real_9_profile();
        }
        options
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args = Args::parse();

    if let Some(query_kind) = args.symbol_query.as_deref() {
        let value = args
            .symbol_query_value
            .as_deref()
            .ok_or_else(|| anyhow!("--symbol-query-value is required with --symbol-query"))?;
        let out_dir = args
            .path
            .to_str()
            .ok_or_else(|| anyhow!("output path is not valid UTF-8"))?;
        let packet = axe_core::query_symbol_packet(out_dir, query_kind, value)
            .map_err(|err| anyhow!(err.to_string()))
            .with_context(|| format!("symbol query failed for {}", args.path.display()))?;
        println!("{packet}");
        return Ok(());
    }

    if let Some(right) = args.diff.clone() {
        let left = args.path.clone();
        let md_path = args.diff_output.clone().unwrap_or_else(|| {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            left.join(format!("diff_{:x}.md", stamp))
        });
        let report = axe_core::diff::run_diff(&left, &right, Some(&md_path))
            .map_err(|err| anyhow!("diff failed: {err}"))?;
        let report_json = serde_json::to_string_pretty(&report)
            .map_err(|err| anyhow!("serialize diff: {err}"))?;
        println!("{}", report_json);
        eprintln!("axe: diff written to {}", md_path.display());
        return Ok(());
    }

    let metadata = std::fs::metadata(&args.path)
        .with_context(|| format!("cannot stat input path {}", args.path.display()))?;

    let out_root = make_run_dir(&args.out_root)?;
    let path_str = args
        .path
        .to_str()
        .ok_or_else(|| anyhow!("input path is not valid UTF-8"))?;
    let out_str = out_root
        .to_str()
        .ok_or_else(|| anyhow!("output path is not valid UTF-8"))?;

    let interrupt = Arc::new(AtomicBool::new(false));
    install_ctrlc_handler(Arc::clone(&interrupt));

    if metadata.is_dir() {
        let result = scan_folder(
            &args.path,
            &out_root,
            args.into_scan_options(),
            Some(interrupt),
        )
        .map_err(|err| anyhow!(err.to_string()))
        .with_context(|| format!("folder scan failed for {}", args.path.display()))?;
        println!("{}", out_root.display());
        eprintln!(
            "axe: scan complete. {} samples scheduled, {} unique, {} archives, {:.1}s elapsed{}",
            result.sample_count,
            result.unique_sha_count,
            result.archive_count,
            result.elapsed_seconds,
            if result.interrupted {
                " (INTERRUPTED — partial case_index.json written)"
            } else {
                ""
            }
        );
        Ok(())
    } else {
        let result = axe_core::analyze_path(path_str, out_str, args.into_options())
            .map_err(|err| anyhow!(err.to_string()))
            .with_context(|| format!("analysis failed for {}", args.path.display()))?;
        if args.print_analysis {
            println!("{}", result);
        } else {
            println!("{}", out_root.display());
        }
        Ok(())
    }
}

fn install_ctrlc_handler(flag: Arc<AtomicBool>) {
    let _ = ctrlc::set_handler(move || {
        if flag.swap(true, Ordering::SeqCst) {
            // already interrupted once; second Ctrl-C exits hard
            std::process::exit(130);
        }
        eprintln!("axe: SIGINT received — finishing in-flight samples and writing partial case_index.json...");
    });
}

fn resolve_workers(workers: &str) -> Option<usize> {
    match workers {
        "auto" | "" => None,
        other => other.parse::<usize>().ok(),
    }
}

fn make_run_dir(root: &std::path::Path) -> Result<PathBuf> {
    std::fs::create_dir_all(root)
        .with_context(|| format!("cannot create out-root {}", root.display()))?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let pid = std::process::id();
    let run_dir = root.join(format!("run_{stamp:x}_{pid:x}"));
    std::fs::create_dir_all(&run_dir)
        .with_context(|| format!("cannot create run dir {}", run_dir.display()))?;
    Ok(run_dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn advertised_v1_1_and_unpack_flags_reach_analysis_options() {
        let args = Args::parse_from([
            "axe",
            "sample.exe",
            "--vuln-discovery",
            "on",
            "--vuln-dynamic-confirmation",
            "all",
            "--vuln-include-lifetime",
            "--vuln-harness-tier",
            "both",
            "--unpack",
            "on",
            "--unpack-tracer",
            "auto",
            "--unpack-timeout-secs",
            "7",
            "--unpack-instr-budget",
            "42",
            "--unpack-out",
            "custom_unpack",
            "--unpack-hooks-disable",
            "--unpack-include-devirt",
        ]);

        let opts = args.into_options();

        assert_eq!(opts.vuln_discovery_mode, "on");
        assert_eq!(opts.vuln_dynamic_confirmation, "all");
        assert!(opts.vuln_include_lifetime);
        assert_eq!(opts.vuln_harness_tier, "both");
        assert_eq!(opts.unpack_mode, "on");
        assert_eq!(opts.unpack_tracer, "auto");
        assert_eq!(opts.unpack_timeout_secs, 7);
        assert_eq!(opts.unpack_instr_budget, 42);
        assert_eq!(opts.unpack_out.as_deref(), Some("custom_unpack"));
        assert!(opts.unpack_hooks_disable);
        assert!(opts.unpack_include_devirt);
    }

    #[test]
    fn real_5_preset_sets_high_signal_defaults() {
        let args = Args::parse_from(["axe", "sample.exe", "--preset", "real-5"]);

        let opts = args.into_options();

        assert_eq!(opts.preset.as_deref(), Some("real-5"));
        assert_eq!(opts.vuln_discovery_mode, "on");
        assert_eq!(opts.vuln_dynamic_confirmation, "all");
        assert!(opts.vuln_include_lifetime);
        assert_eq!(opts.vuln_harness_tier, "both");
        assert_eq!(opts.pseudo_ir, "expanded");
        assert_eq!(opts.semantic_budget, "high");
        assert_eq!(opts.llm_artifacts, "all");
        assert_eq!(opts.review_packs, "all");
        assert_eq!(opts.symbols, "full");
        assert_eq!(opts.symbol_packets, "all");
        assert_eq!(opts.decompile_c, "selected");
    }

    #[test]
    fn real_8_preset_sets_high_signal_defaults() {
        let args = Args::parse_from(["axe", "sample.exe", "--preset", "real-8"]);

        let opts = args.into_options();

        assert_eq!(opts.preset.as_deref(), Some("real-8"));
        assert_eq!(opts.vuln_discovery_mode, "on");
        assert_eq!(opts.vuln_dynamic_confirmation, "all");
        assert!(opts.vuln_include_lifetime);
        assert_eq!(opts.vuln_harness_tier, "both");
        assert_eq!(opts.pseudo_ir, "expanded");
        assert_eq!(opts.semantic_budget, "high");
        assert_eq!(opts.llm_artifacts, "all");
        assert_eq!(opts.review_packs, "all");
        assert_eq!(opts.symbols, "full");
        assert_eq!(opts.symbol_packets, "all");
        assert_eq!(opts.decompile_c, "selected");
    }
}
