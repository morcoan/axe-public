use crate::image::BinaryImage;
use crate::pe::{ExceptionRecord, ExportRecord, FunctionRecord, InstructionRecord};
use rustc_hash::FxHashMap;
use std::collections::{BTreeMap, BTreeSet};

pub fn discover_functions(
    image: &dyn BinaryImage,
    instructions: &[InstructionRecord],
    exceptions: &[ExceptionRecord],
    exports: &[ExportRecord],
    direct_code_targets: &BTreeSet<u64>,
    max_functions: usize,
) -> Vec<FunctionRecord> {
    // FxHashMap for O(1) VA lookups in the hot path; instructions are already sorted by VA
    // when produced by disasm, so we collect a parallel sorted addresses Vec for iteration.
    let ins_by_va: FxHashMap<u64, &InstructionRecord> =
        instructions.iter().map(|row| (row.address, row)).collect();
    let mut addresses: Vec<u64> = ins_by_va.keys().copied().collect();
    addresses.sort();
    let mut seeds = BTreeMap::new();
    if image.entry_va() != 0 {
        seeds.insert(image.entry_va(), "entry".to_string());
    }
    for exc in exceptions {
        seeds
            .entry(exc.begin)
            .or_insert_with(|| "pdata".to_string());
    }
    for export in exports {
        if image
            .section_for_va(export.va)
            .map(|s| s.executable)
            .unwrap_or(false)
        {
            seeds
                .entry(export.va)
                .or_insert_with(|| "export".to_string());
        }
    }
    for target in direct_code_targets {
        seeds.entry(*target).or_insert_with(|| "call".to_string());
    }
    for section in image.sections() {
        if section.executable {
            seeds
                .entry(section.va)
                .or_insert_with(|| "section".to_string());
        }
    }

    let exc_end: BTreeMap<u64, u64> = exceptions.iter().map(|row| (row.begin, row.end)).collect();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut functions = Vec::new();
    for (start, source) in seeds {
        if functions.len() >= max_functions {
            break;
        }
        if !ins_by_va.contains_key(&start) {
            continue;
        }
        if ranges
            .iter()
            .any(|(begin, end)| *begin <= start && start < *end)
        {
            continue;
        }
        let Some(section) = image.section_for_va(start) else {
            continue;
        };
        if !section.executable {
            continue;
        }
        let end = guess_function_end(image, &addresses, &ins_by_va, &exc_end, start);
        if end <= start {
            continue;
        }
        ranges.push((start, end));
        functions.push(FunctionRecord {
            start,
            end,
            size: end - start,
            source,
            calls: Vec::new(),
            calls_imports: Vec::new(),
            strings: Vec::new(),
            xrefs: 0,
        });
    }
    functions.sort_by_key(|row| row.start);
    functions
}

fn guess_function_end(
    image: &dyn BinaryImage,
    addresses: &[u64],
    ins_by_va: &FxHashMap<u64, &InstructionRecord>,
    exc_end: &BTreeMap<u64, u64>,
    start: u64,
) -> u64 {
    if let Some(end) = exc_end.get(&start) {
        return *end;
    }
    let Some(section) = image.section_for_va(start) else {
        return start;
    };
    let max_end = (section.va + section.data_size as u64).min(start + 0x4000);
    let start_index = addresses.partition_point(|addr| *addr < start);
    for address in &addresses[start_index..] {
        if *address >= max_end {
            break;
        }
        if let Some(ins) = ins_by_va.get(address) {
            if ins.is_ret {
                return ins.address + ins.size as u64;
            }
        }
    }
    max_end
}
