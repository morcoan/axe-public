use crate::archive_extract;
use crate::image::detect_format;
use crate::AnalysisOptions;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

const PE_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".drv", ".efi", ".mui",
];
const AGGREGATE_JSONL: &[&str] = &[
    "graph/nodes.jsonl",
    "graph/edges.jsonl",
    "debug_modules.jsonl",
    "debug_identities.jsonl",
    "symbols.jsonl",
    "source_files.jsonl",
    "line_entries.jsonl",
    "inline_scopes.jsonl",
    "debug_types.jsonl",
    "symbol_uncertainty.jsonl",
    "symbol_graph.jsonl",
    "emulation_traces.jsonl",
    "symbolic_paths.jsonl",
    "unpacked_artifacts.jsonl",
    "firmware_modules.jsonl",
    "kernel_artifacts.jsonl",
    "vuln_candidates.jsonl",
    "fuzz_runs.jsonl",
    "decompiled_c.jsonl",
    "trace_events.jsonl",
    "trace_correlations.jsonl",
    "vuln/findings.jsonl",
    "vuln/dynamic_evidence.jsonl",
    "vuln/dynamic_attempts.jsonl",
    "vuln/patch_suggestions.jsonl",
    "vuln/test_suggestions.jsonl",
    "vuln/lifetime_candidates.jsonl",
];
const AGGREGATE_JSON: &[(&str, &str)] = &[
    ("symbol_indexes.json", "symbol_indexes.jsonl"),
    (
        "symbol_packets/manifest.json",
        "symbol_packet_manifests.jsonl",
    ),
    ("vuln/chain_graph.json", "vuln_chain_graphs.jsonl"),
    ("vuln/evidence_bundle.json", "vuln_evidence_bundles.jsonl"),
    ("vuln/run_status.json", "vuln_run_statuses.jsonl"),
    (
        "vuln/vuln_packets/manifest.json",
        "vuln_packet_manifests.jsonl",
    ),
];

#[derive(Clone)]
pub struct ScanOptions {
    pub analysis: AnalysisOptions,
    pub workers: Option<usize>,
    pub max_depth: usize,
    pub max_files: usize,
    pub max_bytes: u64,
    pub single_file_byte_limit: u64,
    pub no_extract_archives: bool,
    pub archive_depth: usize,
    pub folder_pe_mode: String,
    pub progress_every: usize,
    pub progress_seconds: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanResult {
    pub root: String,
    pub sample_count: usize,
    pub unique_sha_count: usize,
    pub archive_count: usize,
    pub skipped: Vec<SkippedEntry>,
    pub samples: Vec<SampleEntry>,
    pub elapsed_seconds: f64,
    pub interrupted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SampleEntry {
    pub sha256: String,
    pub sample_dir: String,
    pub paths: Vec<String>,
    pub format: String,
    pub size_bytes: u64,
    pub extracted_from: Option<String>,
    pub analysis_seconds: f64,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SkippedEntry {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Classification {
    Pe,
    Elf,
    MachO,
    Archive,
    Other,
}

#[derive(Clone, Debug)]
struct QueueItem {
    path: PathBuf,
    size: u64,
    extracted_from: Option<String>,
    archive_depth_remaining: usize,
}

#[derive(Clone, Debug, Serialize)]
struct CrossFolderApiPatternRecord {
    schema: &'static str,
    pattern_id: String,
    source_kind: String,
    sink_api: String,
    bug_classes: Vec<String>,
    shared_imports: Vec<String>,
    shared_exports: Vec<String>,
    protocol_strings: Vec<String>,
    reachable_apis: Vec<String>,
    affected_binary_count: usize,
    finding_count: usize,
    dynamic_confirmed_findings: usize,
    sample_sha256s: Vec<String>,
    proof_packets: Vec<ProofPacketRef>,
}

#[derive(Default)]
struct PatternAccumulator {
    source_kind: String,
    sink_api: String,
    bug_classes: BTreeSet<String>,
    shared_imports: BTreeSet<String>,
    shared_exports: BTreeSet<String>,
    protocol_strings: BTreeSet<String>,
    reachable_apis: BTreeSet<String>,
    sample_sha256s: BTreeSet<String>,
    finding_count: usize,
    dynamic_confirmed_findings: usize,
    proof_packets: BTreeSet<ProofPacketRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
struct ProofPacketRef {
    sample_sha256: String,
    finding_id: String,
    packet_path: String,
}

#[derive(Default)]
struct SampleAttackSurfaceFacts {
    imports: BTreeSet<String>,
    exports: BTreeSet<String>,
    protocol_strings: BTreeSet<String>,
}

impl Eq for QueueItem {}
impl PartialEq for QueueItem {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size
    }
}
impl PartialOrd for QueueItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for QueueItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Largest first → use Ord directly (BinaryHeap is max-heap).
        self.size.cmp(&other.size)
    }
}

pub fn scan_folder(
    root: &Path,
    out_root: &Path,
    options: ScanOptions,
    interrupt: Option<Arc<AtomicBool>>,
) -> Result<ScanResult, Box<dyn Error>> {
    let started = Instant::now();
    fs::create_dir_all(out_root)?;
    let samples_root = out_root.join("samples");
    fs::create_dir_all(&samples_root)?;
    let extracted_root = out_root.join("extracted");

    let interrupt = interrupt.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));

    let mut queue: BinaryHeap<QueueItem> = BinaryHeap::new();
    let mut enqueued_paths: BTreeSet<PathBuf> = BTreeSet::new();
    let mut total_bytes_enqueued: u64 = 0;
    let mut skipped: Vec<SkippedEntry> = Vec::new();

    walk_into_queue(
        root,
        options.max_depth,
        options.max_files,
        options.max_bytes,
        options.single_file_byte_limit,
        options.archive_depth,
        &mut queue,
        &mut enqueued_paths,
        &mut total_bytes_enqueued,
        &mut skipped,
    );

    let dedup: BTreeMap<String, SampleEntry> = BTreeMap::new();
    let dedup_lock = std::sync::Mutex::new(dedup);
    let archive_count = AtomicUsize::new(0);
    let scheduled = AtomicUsize::new(0);
    let mut interrupted_flag = false;

    while let Some(item) = queue.pop() {
        if interrupt.load(Ordering::SeqCst) {
            interrupted_flag = true;
            break;
        }
        scheduled.fetch_add(1, Ordering::Relaxed);

        let bytes = match fs::read(&item.path) {
            Ok(b) => b,
            Err(err) => {
                skipped.push(SkippedEntry {
                    path: item.path.to_string_lossy().to_string(),
                    reason: format!("read_failed: {err}"),
                });
                continue;
            }
        };

        let classification = classify(&item.path, &bytes);
        if classification == Classification::Archive {
            archive_count.fetch_add(1, Ordering::Relaxed);
            if options.no_extract_archives || item.archive_depth_remaining == 0 {
                skipped.push(SkippedEntry {
                    path: item.path.to_string_lossy().to_string(),
                    reason: "archive_extraction_disabled_or_depth_exhausted".to_string(),
                });
                continue;
            }
            handle_archive(
                &item.path,
                &extracted_root,
                item.archive_depth_remaining,
                &options,
                &mut queue,
                &mut enqueued_paths,
                &mut total_bytes_enqueued,
                &mut skipped,
            );
            continue;
        }

        if !matches!(
            classification,
            Classification::Pe | Classification::Elf | Classification::MachO
        ) {
            skipped.push(SkippedEntry {
                path: item.path.to_string_lossy().to_string(),
                reason: "not_a_supported_binary".to_string(),
            });
            continue;
        }

        let sha256 = sha256_hex(&bytes);
        {
            let mut dedup = dedup_lock.lock().unwrap();
            if let Some(existing) = dedup.get_mut(&sha256) {
                existing.paths.push(item.path.to_string_lossy().to_string());
                continue;
            }
        }

        let sample_dir = samples_root.join(&sha256[..16]);
        if let Err(err) = fs::create_dir_all(&sample_dir) {
            skipped.push(SkippedEntry {
                path: item.path.to_string_lossy().to_string(),
                reason: format!("create_sample_dir_failed: {err}"),
            });
            continue;
        }

        let path_str = item.path.to_string_lossy().to_string();
        let sample_dir_str = sample_dir.to_string_lossy().to_string();
        let mut options_for_sample = options.analysis.clone();
        options_for_sample.precomputed_sha256 = Some(sha256.clone());

        let analyze_started = Instant::now();
        let analysis_result = crate::analyze_path(&path_str, &sample_dir_str, options_for_sample);
        let analysis_seconds = analyze_started.elapsed().as_secs_f64();

        let (error, format_name) = match analysis_result {
            Ok(_) => (None, format_label(classification)),
            Err(err) => (Some(err.to_string()), format_label(classification)),
        };

        let entry = SampleEntry {
            sha256: sha256.clone(),
            sample_dir: sample_dir_str,
            paths: vec![path_str],
            format: format_name,
            size_bytes: item.size,
            extracted_from: item.extracted_from.clone(),
            analysis_seconds,
            error,
        };
        dedup_lock.lock().unwrap().insert(sha256, entry);

        if options.progress_every > 0
            && scheduled.load(Ordering::Relaxed) % options.progress_every == 0
        {
            eprintln!(
                "axe: scanned {} samples ({} unique so far, {:.1}s elapsed)",
                scheduled.load(Ordering::Relaxed),
                dedup_lock.lock().unwrap().len(),
                started.elapsed().as_secs_f64()
            );
        }
    }

    let dedup = dedup_lock.into_inner().unwrap();
    let samples: Vec<SampleEntry> = dedup.into_values().collect();
    let unique_sha_count = samples.len();
    let archive_count_final = archive_count.load(Ordering::Relaxed);

    aggregate_jsonl_at_root(&samples, out_root);
    aggregate_json_at_root(&samples, out_root);
    aggregate_folder_attack_surface(&samples, out_root)?;

    let elapsed_seconds = started.elapsed().as_secs_f64();
    let result = ScanResult {
        root: root.to_string_lossy().to_string(),
        sample_count: scheduled.load(Ordering::Relaxed),
        unique_sha_count,
        archive_count: archive_count_final,
        skipped,
        samples,
        elapsed_seconds,
        interrupted: interrupted_flag,
    };

    let case_index_path = out_root.join("case_index.json");
    fs::write(&case_index_path, serde_json::to_string_pretty(&result)?)?;

    Ok(result)
}

fn walk_into_queue(
    root: &Path,
    max_depth: usize,
    max_files: usize,
    max_bytes: u64,
    single_file_byte_limit: u64,
    archive_depth: usize,
    queue: &mut BinaryHeap<QueueItem>,
    enqueued: &mut BTreeSet<PathBuf>,
    total_bytes: &mut u64,
    skipped: &mut Vec<SkippedEntry>,
) {
    for entry in walkdir::WalkDir::new(root)
        .max_depth(max_depth)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if queue.len() >= max_files {
            skipped.push(SkippedEntry {
                path: entry.path().to_string_lossy().to_string(),
                reason: "max_files_reached".to_string(),
            });
            break;
        }
        let path = entry.path().to_path_buf();
        let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
        if size > single_file_byte_limit {
            skipped.push(SkippedEntry {
                path: path.to_string_lossy().to_string(),
                reason: format!("over_single_file_byte_limit: {size}"),
            });
            continue;
        }
        if *total_bytes + size > max_bytes {
            skipped.push(SkippedEntry {
                path: path.to_string_lossy().to_string(),
                reason: "max_bytes_reached".to_string(),
            });
            break;
        }
        if !enqueued.insert(path.clone()) {
            continue;
        }
        *total_bytes += size;
        queue.push(QueueItem {
            path,
            size,
            extracted_from: None,
            archive_depth_remaining: archive_depth,
        });
    }
}

fn handle_archive(
    src: &Path,
    extracted_root: &Path,
    archive_depth_remaining: usize,
    options: &ScanOptions,
    queue: &mut BinaryHeap<QueueItem>,
    enqueued: &mut BTreeSet<PathBuf>,
    total_bytes: &mut u64,
    skipped: &mut Vec<SkippedEntry>,
) {
    let bytes = match fs::read(src) {
        Ok(b) => b,
        Err(err) => {
            skipped.push(SkippedEntry {
                path: src.to_string_lossy().to_string(),
                reason: format!("archive_read_failed: {err}"),
            });
            return;
        }
    };
    let archive_sha = sha256_hex(&bytes);
    let dest = extracted_root.join(&archive_sha[..16]);
    if let Err(err) = fs::create_dir_all(&dest) {
        skipped.push(SkippedEntry {
            path: src.to_string_lossy().to_string(),
            reason: format!("create_extract_dest_failed: {err}"),
        });
        return;
    }
    let result = archive_extract::extract_archive(src, &dest);
    if result.skipped {
        skipped.push(SkippedEntry {
            path: src.to_string_lossy().to_string(),
            reason: result
                .reason
                .unwrap_or_else(|| "archive_skipped".to_string()),
        });
        return;
    }
    for file in result.files {
        if queue.len() >= options.max_files {
            break;
        }
        let size = fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
        if size > options.single_file_byte_limit {
            skipped.push(SkippedEntry {
                path: file.to_string_lossy().to_string(),
                reason: format!("over_single_file_byte_limit: {size}"),
            });
            continue;
        }
        if *total_bytes + size > options.max_bytes {
            break;
        }
        if !enqueued.insert(file.clone()) {
            continue;
        }
        *total_bytes += size;
        queue.push(QueueItem {
            path: file,
            size,
            extracted_from: Some(archive_sha.clone()),
            archive_depth_remaining: archive_depth_remaining.saturating_sub(1),
        });
    }
}

fn classify(path: &Path, bytes: &[u8]) -> Classification {
    if let Some(fmt) = detect_format(bytes) {
        return match fmt {
            crate::image::Format::Pe => Classification::Pe,
            crate::image::Format::Elf => Classification::Elf,
            crate::image::Format::MachO => Classification::MachO,
        };
    }
    if archive_extract::detect_archive_format(path).is_some() {
        return Classification::Archive;
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .map(|s| format!(".{s}"));
    if let Some(ext) = ext {
        if PE_EXTENSIONS.iter().any(|p| *p == ext.as_str()) {
            return Classification::Pe;
        }
    }
    Classification::Other
}

fn format_label(c: Classification) -> String {
    match c {
        Classification::Pe => "pe".into(),
        Classification::Elf => "elf".into(),
        Classification::MachO => "macho".into(),
        Classification::Archive => "archive".into(),
        Classification::Other => "other".into(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn aggregate_jsonl_at_root(samples: &[SampleEntry], out_root: &Path) {
    for name in AGGREGATE_JSONL {
        let dest_path = out_root.join(name);
        if let Some(parent) = dest_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut out_file = match fs::File::create(&dest_path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        use std::io::Write;
        for sample in samples {
            let sample_jsonl = Path::new(&sample.sample_dir).join(name);
            if let Ok(contents) = fs::read(&sample_jsonl) {
                let _ = out_file.write_all(&contents);
            }
        }
    }
}

fn aggregate_json_at_root(samples: &[SampleEntry], out_root: &Path) {
    for (source_name, dest_name) in AGGREGATE_JSON {
        let dest_path = out_root.join(dest_name);
        if let Some(parent) = dest_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut out_file = match fs::File::create(&dest_path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        use std::io::Write;
        for sample in samples {
            let sample_json = Path::new(&sample.sample_dir).join(source_name);
            if let Ok(contents) = fs::read(&sample_json) {
                let _ = out_file.write_all(&contents);
                let _ = out_file.write_all(b"\n");
            }
        }
    }
}

fn aggregate_folder_attack_surface(
    samples: &[SampleEntry],
    out_root: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut patterns: BTreeMap<String, PatternAccumulator> = BTreeMap::new();
    for sample in samples {
        let proof_packet_refs = sample_proof_packet_refs(sample);
        let sample_facts = sample_attack_surface_facts(sample);
        let path = Path::new(&sample.sample_dir)
            .join("vuln")
            .join("findings.jsonl");
        let Ok(contents) = fs::read_to_string(&path) else {
            continue;
        };
        for line in contents.lines().filter(|line| !line.trim().is_empty()) {
            let Ok(row) = serde_json::from_str::<Value>(line) else {
                continue;
            };
            let source_kind = row
                .pointer("/source/kind")
                .and_then(Value::as_str)
                .unwrap_or("unknown_source");
            let sink_api = row
                .pointer("/sink/api")
                .and_then(Value::as_str)
                .unwrap_or("unknown_sink");
            let bug_class = row
                .get("bug_class")
                .and_then(Value::as_str)
                .unwrap_or("unknown_bug_class");
            let finding_id = row.get("finding_id").and_then(Value::as_str);
            let key = format!(
                "{}->{}",
                source_kind.to_ascii_lowercase(),
                sink_api.to_ascii_lowercase()
            );
            let acc = patterns.entry(key).or_insert_with(|| PatternAccumulator {
                source_kind: source_kind.to_string(),
                sink_api: sink_api.to_string(),
                ..Default::default()
            });
            acc.finding_count += 1;
            acc.bug_classes.insert(bug_class.to_string());
            acc.shared_imports
                .extend(sample_facts.imports.iter().take(32).cloned());
            acc.shared_exports
                .extend(sample_facts.exports.iter().take(32).cloned());
            acc.protocol_strings
                .extend(sample_facts.protocol_strings.iter().take(32).cloned());
            acc.reachable_apis.insert(sink_api.to_string());
            acc.sample_sha256s.insert(sample.sha256.clone());
            if dynamic_status_counts(&row) {
                acc.dynamic_confirmed_findings += 1;
            }
            if let Some(proof_ref) = finding_id.and_then(|id| proof_packet_refs.get(id).cloned()) {
                acc.proof_packets.insert(proof_ref);
            }
        }
    }

    let mut rows: Vec<CrossFolderApiPatternRecord> = patterns
        .into_iter()
        .map(|(pattern_id, acc)| CrossFolderApiPatternRecord {
            schema: "axe_cross_folder_api_pattern/1",
            pattern_id,
            source_kind: acc.source_kind,
            sink_api: acc.sink_api,
            bug_classes: acc.bug_classes.into_iter().collect(),
            shared_imports: acc.shared_imports.into_iter().take(32).collect(),
            shared_exports: acc.shared_exports.into_iter().take(32).collect(),
            protocol_strings: acc.protocol_strings.into_iter().take(32).collect(),
            reachable_apis: acc.reachable_apis.into_iter().take(32).collect(),
            affected_binary_count: acc.sample_sha256s.len(),
            finding_count: acc.finding_count,
            dynamic_confirmed_findings: acc.dynamic_confirmed_findings,
            sample_sha256s: acc.sample_sha256s.into_iter().collect(),
            proof_packets: acc.proof_packets.into_iter().collect(),
        })
        .collect();
    rows.sort_by(|left, right| {
        right
            .affected_binary_count
            .cmp(&left.affected_binary_count)
            .then_with(|| {
                right
                    .dynamic_confirmed_findings
                    .cmp(&left.dynamic_confirmed_findings)
            })
            .then_with(|| right.finding_count.cmp(&left.finding_count))
            .then_with(|| left.pattern_id.cmp(&right.pattern_id))
    });

    let patterns_path = out_root.join("cross_folder_api_patterns.jsonl");
    if let Some(parent) = patterns_path.parent() {
        fs::create_dir_all(parent)?;
    }
    {
        use std::io::Write;
        let mut writer = fs::File::create(&patterns_path)?;
        for row in &rows {
            serde_json::to_writer(&mut writer, row)?;
            writer.write_all(b"\n")?;
        }
    }

    let summary = json!({
        "schema": "axe_folder_attack_surface/1",
        "pattern_count": rows.len(),
        "repeated_pattern_count": rows
            .iter()
            .filter(|row| row.affected_binary_count > 1)
            .count(),
        "finding_count": rows.iter().map(|row| row.finding_count).sum::<usize>(),
        "dynamic_confirmed_findings": rows
            .iter()
            .map(|row| row.dynamic_confirmed_findings)
            .sum::<usize>(),
        "import_cluster_count": rows
            .iter()
            .filter(|row| !row.shared_imports.is_empty())
            .count(),
        "protocol_cluster_count": rows
            .iter()
            .filter(|row| !row.protocol_strings.is_empty())
            .count(),
        "top_patterns": rows.iter().take(20).collect::<Vec<_>>(),
    });
    fs::write(
        out_root.join("folder_attack_surface.json"),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    Ok(())
}

fn sample_attack_surface_facts(sample: &SampleEntry) -> SampleAttackSurfaceFacts {
    let sample_dir = Path::new(&sample.sample_dir);
    SampleAttackSurfaceFacts {
        imports: read_import_facts(&sample_dir.join("imports.jsonl")),
        exports: read_export_facts(&sample_dir.join("exports.jsonl")),
        protocol_strings: read_protocol_strings(&sample_dir.join("strings.jsonl")),
    }
}

fn read_import_facts(path: &Path) -> BTreeSet<String> {
    read_jsonl_values(path)
        .into_iter()
        .filter_map(|row| {
            let dll = row.get("dll").and_then(Value::as_str)?;
            let name = row
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| row.get("symbol").and_then(Value::as_str))?;
            Some(format!("{dll}!{name}"))
        })
        .collect()
}

fn read_export_facts(path: &Path) -> BTreeSet<String> {
    read_jsonl_values(path)
        .into_iter()
        .filter_map(|row| row.get("name").and_then(Value::as_str).map(str::to_string))
        .collect()
}

fn read_protocol_strings(path: &Path) -> BTreeSet<String> {
    read_jsonl_values(path)
        .into_iter()
        .filter_map(|row| {
            let text = row.get("text").and_then(Value::as_str)?;
            let classified_protocol = row
                .get("classifiers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|value| {
                    value
                        .as_str()
                        .is_some_and(|classifier| classifier.eq_ignore_ascii_case("protocol"))
                });
            (classified_protocol || looks_like_protocol_string(text)).then(|| text.to_string())
        })
        .collect()
}

fn looks_like_protocol_string(text: &str) -> bool {
    let upper = text.to_ascii_uppercase();
    [
        "HTTP/", "GET ", "POST ", "USER ", "PASS ", "AUTH", "TOKEN", "CMD=",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

fn read_jsonl_values(path: &Path) -> Vec<Value> {
    let Ok(contents) = fs::read_to_string(path) else {
        return Vec::new();
    };
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

fn dynamic_status_counts(row: &Value) -> bool {
    matches!(
        row.pointer("/dynamic_evidence/status")
            .and_then(Value::as_str)
            .or_else(|| {
                row.pointer("/dynamic_confirmation/status")
                    .and_then(Value::as_str)
            }),
        Some("confirmed_trigger" | "reached_only")
    )
}

fn sample_proof_packet_refs(sample: &SampleEntry) -> BTreeMap<String, ProofPacketRef> {
    let path = Path::new(&sample.sample_dir)
        .join("vuln")
        .join("vuln_packets")
        .join("manifest.json");
    let Ok(contents) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let Ok(manifest) = serde_json::from_str::<Value>(&contents) else {
        return BTreeMap::new();
    };
    manifest
        .get("packets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|packet| {
            let finding_id = packet.get("finding_id").and_then(Value::as_str)?;
            let rel_path = packet.get("path").and_then(Value::as_str)?;
            Some((
                finding_id.to_string(),
                ProofPacketRef {
                    sample_sha256: sample.sha256.clone(),
                    finding_id: finding_id.to_string(),
                    packet_path: format!("vuln/{}", rel_path.replace('\\', "/")),
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_minimal_pe(path: &Path) {
        // Minimal MZ stub — enough for magic detection. Full PE not required for
        // queueing/classification tests; analysis itself will fail gracefully.
        fs::write(path, b"MZ\x90\x00").unwrap();
    }

    fn write_minimal_elf(path: &Path) {
        fs::write(path, b"\x7fELF\x02\x01").unwrap();
    }

    #[test]
    fn classify_recognises_pe_by_magic() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("noext");
        write_minimal_pe(&p);
        assert_eq!(Classification::Pe, classify(&p, b"MZ\x90\x00"));
    }

    #[test]
    fn classify_recognises_pe_by_extension_when_magic_missing() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("looks_like.exe");
        fs::write(&p, b"not_actually_pe").unwrap();
        assert_eq!(Classification::Pe, classify(&p, b"not_actually_pe"));
    }

    #[test]
    fn classify_recognises_elf() {
        let tmp = TempDir::new().unwrap();
        let p = tmp.path().join("noext");
        write_minimal_elf(&p);
        assert_eq!(Classification::Elf, classify(&p, b"\x7fELF\x02"));
    }

    #[test]
    fn size_priority_queue_pops_largest_first() {
        let mut heap: BinaryHeap<QueueItem> = BinaryHeap::new();
        heap.push(QueueItem {
            path: PathBuf::from("small"),
            size: 100,
            extracted_from: None,
            archive_depth_remaining: 0,
        });
        heap.push(QueueItem {
            path: PathBuf::from("huge"),
            size: 10_000,
            extracted_from: None,
            archive_depth_remaining: 0,
        });
        heap.push(QueueItem {
            path: PathBuf::from("medium"),
            size: 1000,
            extracted_from: None,
            archive_depth_remaining: 0,
        });
        assert_eq!("huge", heap.pop().unwrap().path.to_string_lossy());
        assert_eq!("medium", heap.pop().unwrap().path.to_string_lossy());
        assert_eq!("small", heap.pop().unwrap().path.to_string_lossy());
    }

    #[test]
    fn walk_respects_max_files() {
        let tmp = TempDir::new().unwrap();
        for i in 0..10 {
            let p = tmp.path().join(format!("file_{i}.bin"));
            fs::write(&p, b"x").unwrap();
        }
        let mut queue = BinaryHeap::new();
        let mut enqueued = BTreeSet::new();
        let mut total_bytes = 0u64;
        let mut skipped = Vec::new();
        walk_into_queue(
            tmp.path(),
            5,
            3,
            u64::MAX,
            u64::MAX,
            0,
            &mut queue,
            &mut enqueued,
            &mut total_bytes,
            &mut skipped,
        );
        assert_eq!(3, queue.len());
        assert!(skipped.iter().any(|s| s.reason == "max_files_reached"));
    }

    #[test]
    fn walk_respects_max_bytes() {
        let tmp = TempDir::new().unwrap();
        for i in 0..5 {
            let p = tmp.path().join(format!("file_{i}.bin"));
            let mut f = fs::File::create(&p).unwrap();
            f.write_all(&vec![0u8; 100]).unwrap();
        }
        let mut queue = BinaryHeap::new();
        let mut enqueued = BTreeSet::new();
        let mut total_bytes = 0u64;
        let mut skipped = Vec::new();
        walk_into_queue(
            tmp.path(),
            5,
            100,
            250, // 2 files (200 bytes) fits, 3rd would push to 300
            u64::MAX,
            0,
            &mut queue,
            &mut enqueued,
            &mut total_bytes,
            &mut skipped,
        );
        assert_eq!(2, queue.len());
        assert!(skipped.iter().any(|s| s.reason == "max_bytes_reached"));
    }

    #[test]
    fn walk_respects_single_file_byte_limit() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join("small.bin"), b"x").unwrap();
        fs::write(tmp.path().join("big.bin"), vec![0u8; 1000]).unwrap();
        let mut queue = BinaryHeap::new();
        let mut enqueued = BTreeSet::new();
        let mut total_bytes = 0u64;
        let mut skipped = Vec::new();
        walk_into_queue(
            tmp.path(),
            5,
            100,
            u64::MAX,
            100,
            0,
            &mut queue,
            &mut enqueued,
            &mut total_bytes,
            &mut skipped,
        );
        assert_eq!(1, queue.len());
        assert!(skipped
            .iter()
            .any(|s| s.reason.starts_with("over_single_file_byte_limit")));
    }

    #[test]
    fn aggregation_creates_nested_graph_outputs() {
        let tmp = TempDir::new().unwrap();
        let sample = tmp.path().join("sample");
        fs::create_dir_all(sample.join("graph")).unwrap();
        fs::write(
            sample.join("graph").join("nodes.jsonl"),
            "{\"id\":\"n1\"}\n",
        )
        .unwrap();
        fs::write(
            sample.join("graph").join("edges.jsonl"),
            "{\"id\":\"e1\"}\n",
        )
        .unwrap();
        fs::write(sample.join("symbols.jsonl"), "{\"symbol_id\":\"s1\"}\n").unwrap();
        fs::write(sample.join("symbol_graph.jsonl"), "{\"graph_id\":\"g1\"}\n").unwrap();
        fs::write(
            sample.join("symbol_indexes.json"),
            "{\"schema\":\"symbol_indexes/1\"}",
        )
        .unwrap();
        fs::create_dir_all(sample.join("symbol_packets")).unwrap();
        fs::write(
            sample.join("symbol_packets").join("manifest.json"),
            "{\"schema\":\"symbol_packet_manifest/1\"}",
        )
        .unwrap();
        fs::write(
            sample.join("debug_identities.jsonl"),
            "{\"identity_id\":\"d1\"}\n",
        )
        .unwrap();
        fs::create_dir_all(sample.join("vuln").join("vuln_packets")).unwrap();
        fs::write(
            sample.join("vuln").join("findings.jsonl"),
            "{\"finding_id\":\"vf1\"}\n",
        )
        .unwrap();
        fs::write(
            sample.join("vuln").join("dynamic_evidence.jsonl"),
            "{\"chain_id\":\"c1\",\"status\":\"confirmed_trigger\"}\n",
        )
        .unwrap();
        fs::write(
            sample.join("vuln").join("dynamic_attempts.jsonl"),
            "{\"chain_id\":\"c1\",\"source\":\"trace\"}\n",
        )
        .unwrap();
        fs::write(
            sample.join("vuln").join("chain_graph.json"),
            "{\"schema\":\"vuln_discovery.chain_graph.v1\"}",
        )
        .unwrap();
        fs::write(
            sample.join("vuln").join("evidence_bundle.json"),
            "{\"schema\":\"vuln_discovery.evidence_bundle.v1_1\"}",
        )
        .unwrap();
        fs::write(
            sample.join("vuln").join("run_status.json"),
            "{\"schema\":\"vuln_discovery.run_status.v1\"}",
        )
        .unwrap();
        fs::write(
            sample
                .join("vuln")
                .join("vuln_packets")
                .join("manifest.json"),
            "{\"schema\":\"vuln_discovery.proof_packet_manifest.v1\"}",
        )
        .unwrap();

        let out_root = tmp.path().join("out");
        fs::create_dir_all(&out_root).unwrap();
        aggregate_jsonl_at_root(
            &[SampleEntry {
                sha256: "00".repeat(32),
                sample_dir: sample.to_string_lossy().to_string(),
                paths: vec!["fixture".to_string()],
                format: "elf".to_string(),
                size_bytes: 1,
                extracted_from: None,
                analysis_seconds: 0.0,
                error: None,
            }],
            &out_root,
        );

        assert!(out_root.join("graph").join("nodes.jsonl").is_file());
        assert!(out_root.join("graph").join("edges.jsonl").is_file());
        assert!(out_root.join("symbols.jsonl").is_file());
        assert!(out_root.join("symbol_graph.jsonl").is_file());
        assert!(out_root.join("vuln").join("findings.jsonl").is_file());
        assert!(out_root
            .join("vuln")
            .join("dynamic_evidence.jsonl")
            .is_file());
        assert!(out_root
            .join("vuln")
            .join("dynamic_attempts.jsonl")
            .is_file());
        aggregate_json_at_root(
            &[SampleEntry {
                sha256: "00".repeat(32),
                sample_dir: sample.to_string_lossy().to_string(),
                paths: vec!["fixture".to_string()],
                format: "elf".to_string(),
                size_bytes: 1,
                extracted_from: None,
                analysis_seconds: 0.0,
                error: None,
            }],
            &out_root,
        );
        assert!(out_root.join("symbol_indexes.jsonl").is_file());
        assert!(out_root.join("symbol_packet_manifests.jsonl").is_file());
        assert!(out_root.join("vuln_chain_graphs.jsonl").is_file());
        assert!(out_root.join("vuln_evidence_bundles.jsonl").is_file());
        assert!(out_root.join("vuln_run_statuses.jsonl").is_file());
        assert!(out_root.join("vuln_packet_manifests.jsonl").is_file());
        assert!(out_root.join("debug_identities.jsonl").is_file());
    }

    #[test]
    fn folder_attack_surface_groups_repeated_source_sink_patterns() {
        let tmp = TempDir::new().unwrap();
        let sample_a = tmp.path().join("sample-a");
        let sample_b = tmp.path().join("sample-b");
        fs::create_dir_all(sample_a.join("vuln")).unwrap();
        fs::create_dir_all(sample_b.join("vuln")).unwrap();
        fs::create_dir_all(sample_a.join("vuln").join("vuln_packets")).unwrap();
        fs::write(
            sample_a.join("vuln").join("findings.jsonl"),
            r#"{"finding_id":"F-1","bug_class":"unchecked_copy_length","source":{"kind":"network_recv"},"sink":{"api":"memcpy"},"dynamic_evidence":{"status":"confirmed_trigger"}}"#,
        )
        .unwrap();
        fs::write(
            sample_a.join("imports.jsonl"),
            r#"{"dll":"ws2_32.dll","name":"recv","symbol":"recv","va":4096,"rva":4096,"hint":null,"categories":["network"]}"#,
        )
        .unwrap();
        fs::write(
            sample_a.join("exports.jsonl"),
            r#"{"name":"HandlePacket","ordinal":1,"va":8192,"rva":8192}"#,
        )
        .unwrap();
        fs::write(
            sample_a.join("strings.jsonl"),
            r#"{"va":12288,"rva":12288,"file_offset":64,"encoding":"ascii","size":8,"text":"USER %s","classifiers":["protocol"],"section":".rdata"}"#,
        )
        .unwrap();
        fs::write(
            sample_a
                .join("vuln")
                .join("vuln_packets")
                .join("manifest.json"),
            r#"{"schema":"vuln_discovery.proof_packet_manifest.v1","packets":[{"packet_id":"P-F-1","finding_id":"F-1","chain_id":"C-1","path":"vuln_packets/F-1_C-1.json"}]}"#,
        )
        .unwrap();
        fs::write(
            sample_b.join("vuln").join("findings.jsonl"),
            r#"{"finding_id":"F-2","bug_class":"unchecked_copy_length","source":{"kind":"network_recv"},"sink":{"api":"memcpy"}}"#,
        )
        .unwrap();
        fs::write(
            sample_b.join("imports.jsonl"),
            r#"{"dll":"ws2_32.dll","name":"recv","symbol":"recv","va":4096,"rva":4096,"hint":null,"categories":["network"]}"#,
        )
        .unwrap();
        fs::write(
            sample_b.join("exports.jsonl"),
            r#"{"name":"ProcessFrame","ordinal":1,"va":8192,"rva":8192}"#,
        )
        .unwrap();
        fs::write(
            sample_b.join("strings.jsonl"),
            r#"{"va":12288,"rva":12288,"file_offset":64,"encoding":"ascii","size":8,"text":"USER %s","classifiers":["protocol"],"section":".rdata"}"#,
        )
        .unwrap();
        let samples = vec![
            SampleEntry {
                sha256: "11".repeat(32),
                sample_dir: sample_a.to_string_lossy().to_string(),
                paths: vec!["a.exe".to_string()],
                format: "pe".to_string(),
                size_bytes: 1,
                extracted_from: None,
                analysis_seconds: 0.0,
                error: None,
            },
            SampleEntry {
                sha256: "22".repeat(32),
                sample_dir: sample_b.to_string_lossy().to_string(),
                paths: vec!["b.exe".to_string()],
                format: "pe".to_string(),
                size_bytes: 1,
                extracted_from: None,
                analysis_seconds: 0.0,
                error: None,
            },
        ];
        let out_root = tmp.path().join("out");
        fs::create_dir_all(&out_root).unwrap();

        aggregate_folder_attack_surface(&samples, &out_root).unwrap();

        let patterns =
            fs::read_to_string(out_root.join("cross_folder_api_patterns.jsonl")).unwrap();
        let row: serde_json::Value =
            serde_json::from_str(patterns.lines().next().unwrap()).unwrap();
        assert_eq!(row["source_kind"], "network_recv");
        assert_eq!(row["sink_api"], "memcpy");
        assert_eq!(row["affected_binary_count"], 2);
        assert_eq!(row["finding_count"], 2);
        assert_eq!(row["dynamic_confirmed_findings"], 1);
        assert_eq!(row["shared_imports"][0], "ws2_32.dll!recv");
        assert_eq!(row["protocol_strings"][0], "USER %s");
        assert_eq!(row["reachable_apis"][0], "memcpy");
        assert_eq!(row["proof_packets"][0]["finding_id"], "F-1");
        assert_eq!(
            row["proof_packets"][0]["packet_path"],
            "vuln/vuln_packets/F-1_C-1.json"
        );
        assert!(out_root.join("folder_attack_surface.json").is_file());
    }
}
