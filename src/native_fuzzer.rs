use crate::native_emulator::{emulate_function, NativeEmulationResult};
use crate::pe::FunctionRecord;
use crate::portable::{FuzzRunRecord, PortableInput, VulnCandidateRecord};
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

pub fn run_fuzz(
    input: &PortableInput<'_>,
    candidates: &[VulnCandidateRecord],
    baseline: Option<&NativeEmulationResult>,
) -> Vec<FuzzRunRecord> {
    if input.profile != "native-max" || input.fuzz_mode == "off" || candidates.is_empty() {
        return Vec::new();
    }
    let iterations = input.fuzz_iterations.max(1).min(1024);
    let dry_run = input.fuzz_mode != "execute";

    let mut runs = Vec::new();
    let mut baseline_cache: BTreeMap<u64, Option<NativeEmulationResult>> = BTreeMap::new();

    for candidate in candidates
        .iter()
        .filter(|row| row.site_va.is_some() && !row.evidence.is_empty())
        .take(32)
    {
        let site_va = candidate.site_va.unwrap_or_default();
        let target = match find_function(input.functions, site_va) {
            Some(f) => f,
            None => continue,
        };

        let baseline_for_fn = baseline_cache.entry(target.start).or_insert_with(|| {
            if dry_run {
                None
            } else {
                emulate_function(input, target, Some(&zero_initial_regs()), Some(192))
            }
        });
        let baseline_exit = baseline_for_fn
            .as_ref()
            .map(|r| r.trace.exit_reason.clone())
            .or_else(|| baseline.map(|r| r.trace.exit_reason.clone()));

        for iteration in 0..iterations {
            let seed = deterministic_seed(&candidate.candidate_id, iteration);

            let (status, exit_reason) = if dry_run {
                (
                    "dry_run_planned".to_string(),
                    "fuzz_mode_dry_run".to_string(),
                )
            } else {
                let initial = mutated_initial_regs(seed);
                match emulate_function(input, target, Some(&initial), Some(192)) {
                    Some(result) => {
                        let classification = classify_exit(&result, baseline_exit.as_deref());
                        ("executed".to_string(), classification)
                    }
                    None => ("executed".to_string(), "no_emulation_trace".to_string()),
                }
            };

            runs.push(FuzzRunRecord {
                run_id: format!("fuzz:{}:{iteration:04X}", candidate.fuzz_harness_ref),
                harness_id: candidate.fuzz_harness_ref.clone(),
                candidate_id: candidate.candidate_id.clone(),
                status,
                iteration,
                seed,
                exercised_va: Some(site_va),
                exit_reason,
                evidence: candidate.evidence.clone(),
            });
        }
    }
    runs
}

fn find_function(functions: &[FunctionRecord], va: u64) -> Option<&FunctionRecord> {
    functions.iter().find(|f| f.start <= va && va < f.end)
}

fn zero_initial_regs() -> BTreeMap<String, u64> {
    let mut regs = BTreeMap::new();
    for name in [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
    ] {
        regs.insert(name.to_string(), 0);
    }
    regs.insert("rsp".into(), 0x7FFE_0000);
    regs.insert("rbp".into(), 0x7FFE_0000);
    regs
}

fn mutated_initial_regs(seed: u64) -> BTreeMap<String, u64> {
    let mut regs = zero_initial_regs();
    regs.insert("rcx".into(), mutate_value(seed, 0));
    regs.insert("rdx".into(), mutate_value(seed, 1));
    regs.insert("r8".into(), mutate_value(seed, 2));
    regs.insert("r9".into(), mutate_value(seed, 3));
    regs
}

fn mutate_value(seed: u64, slot: u32) -> u64 {
    let shifted = seed.rotate_left((slot.wrapping_mul(11)) & 63);
    match shifted & 7 {
        0 => 0,
        1 => 1,
        2 => 0x0000_0000_FFFF_FFFF,
        3 => u64::MAX,
        4 => 0x0000_0000_7FFF_FFFF,
        5 => 0x0000_0000_0010_0000,
        6 => 0x0000_0000_0000_0100,
        _ => shifted,
    }
}

fn classify_exit(result: &NativeEmulationResult, baseline_exit: Option<&str>) -> String {
    if !result.oob_write_sites.is_empty() {
        return format!(
            "suspicious_memory_write_oob@0x{:016X}",
            result.oob_write_sites[0]
        );
    }
    let supported = result.trace.supported_steps as f64;
    let unsupported = result.trace.unsupported_instructions.len() as f64;
    if supported > 0.0 && unsupported / supported > 0.25 {
        return "low_fidelity".to_string();
    }
    let raw = result.trace.exit_reason.as_str();
    let normal = matches!(raw, "return" | "function_end");
    let base = match raw {
        "return" => "normal_return",
        "function_end" => "normal_fallthrough",
        "loop_guard" => "suspicious_loop_guard",
        "branch_exit" => "suspicious_branch_exit",
        "budget_cap" => "suspicious_budget_cap",
        other => other,
    };
    if normal {
        base.to_string()
    } else if baseline_exit.is_some() && baseline_exit != Some(raw) {
        format!("divergent_{base}")
    } else {
        base.to_string()
    }
}

fn deterministic_seed(candidate_id: &str, iteration: usize) -> u64 {
    let mut hasher = DefaultHasher::new();
    candidate_id.hash(&mut hasher);
    iteration.hash(&mut hasher);
    hasher.finish()
}
