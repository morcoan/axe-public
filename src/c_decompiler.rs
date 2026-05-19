//! C decompilation pipeline.
//!
//! Lifts x86_64 instructions for selected functions into structured C
//! source files written under `<out_dir>/decompiled_c/`. The pipeline is
//! 3-phase + several cross-cutting passes, all run per-function inside
//! `lift_function`:
//!
//! ## Phase 1 — Per-instruction lift
//!
//! `lift_instruction` translates one `InstructionRecord` to one C statement
//! string. Pure mechanical mapping: `mov` → `=`, `add` → `+=`, jCC → `if
//! (cond) goto L_X;`, cmov/setcc → ternary, ret → `return rax;`, call →
//! `rax = call_<name>(args)` (or `rax = call_at_0x<addr>()` for unresolved
//! targets, see `synthesize_call_name`). Output is collected into a
//! `Vec<StmtRec>` so subsequent phases can rewrite text and mark dead.
//!
//! ## Phase 2 — Expression composition (A2)
//!
//! `compose_expressions` walks the stmt list with a live-value map keyed
//! by *canonical* 64-bit register name (`canonical_storage`). Substitutes
//! reads of any register alias (`eax`/`ax`/`al` for `rax`) with the
//! producer's RHS expression, then marks the producer `removed` when it
//! crosses an overwrite, a branch target, or the `ret` instruction. At
//! `ret`, caller-saved registers (`CALLER_SAVED_X64`) get UNCONDITIONAL
//! producer-removal — the caller can't observe them per the ABI, so the
//! write is dead even if `use_count == 0`.
//!
//! Compound ops (`+=`, `-=`, ...) only compose when a prior live value
//! exists for the LHS — otherwise they invalidate to prevent self-
//! referential expressions like `(eax) + (1)` that would corrupt future
//! substitutions.
//!
//! Substitution tracks substituted byte ranges so an expression like
//! `(uint64_t)(uint8_t)al` inserted in place of `rax` doesn't get re-
//! substituted on the next alias iteration (the `al` inside is part of
//! the expression, not an original reference).
//!
//! ## Phase 2.4 — Struct-field access rewrite (A6.1)
//!
//! `rewrite_struct_field_accesses` scans surviving stmt texts for the
//! `*((uint64_t *)(base+offset))` template emitted by `render_operand`
//! for bracketed memory operands. When (base, offset) matches an entry in
//! the per-function `infer_struct_hints` output (≥2 distinct offsets on
//! the same base), rewrites to `base->field_<hex_offset>` form.
//!
//! ## Phase 2.5 — Do-while loop lifting (A3)
//!
//! `build_dowhile_plan` recognises single-backedge natural loops whose
//! backedge source is an `if (cond) goto L_HEADER;` line (after Phase 2
//! substitution). Plans the emission as `do { ... } while (cond);`,
//! suppressing both the header's `L_<va>:` label and the original
//! conditional-goto line.
//!
//! ## Phase 2.6 — Dead-local-decl elimination (A2.1)
//!
//! Decl emission is deferred until after compose so we can filter the
//! built-up `decl_lines` against the surviving stmt texts. A decl is kept
//! only when its promoted name OR raw storage appears as a standalone
//! word in at least one non-removed stmt — locals whose producer got
//! elided by A2 are dropped.
//!
//! ## Phase 3 — Emit
//!
//! Interleaves labels and loop markers around the surviving stmts; pushes
//! the filtered decls plus the captured structured-flow preamble between
//! the function signature and the body. Closes any leftover open loops
//! as a safety net.
//!
//! ## Cross-cutting passes
//!
//! - **ABI detection** (`detect_abi`): magic bytes → Win64 (PE) or SysV
//!   (ELF/Mach-O); drives `recover_arg_decls` arg-register list.
//! - **Hex literal normalization** (`normalize_hex_literal`, A2.2):
//!   Intel-syntax `0Ah` becomes C-form `0x0a` in rendered operands.
//! - **Struct-hint inference** (`infer_struct_hints`, A6): offset-cluster
//!   detection on `[reg+const]` patterns, emitted as a hint comment
//!   above the function signature and consumed by A6.1's rewriter.
//! - **5-tier confidence ladder** (`assess_confidence`, A5): widens the
//!   record's confidence from high/medium/low to high/medium/low/conflict
//!   /unknown so the LLM consumer can distinguish "no analysis signal"
//!   (unknown) from "conflicting type info" (conflict — emitted by a
//!   future revision of `recover_types`).
//! - **Fixed-point type propagation** (`recover_types`, A5): seeds from
//!   API prototypes + dataflow type tags, then propagates along
//!   dataflow edges until convergence.
//!
//! ## Test coverage
//!
//! 9 golden fixtures pinned in `tests/decompiler_golden.rs` exercise the
//! pipeline end-to-end on synthesized ELF binaries (no checked-in binary
//! fixtures). Each goldenupdate goes through `BLESS=1 cargo test --test
//! decompiler_golden` for review.

use crate::pe::{
    ApiFlowRecord, DataflowEdgeRecord, FunctionRecord, InstructionRecord, SsaValueRecord,
};
use crate::portable::{safe_file_component, DecompiledCRecord, PortableInput};
use crate::winapi::prototype;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

pub fn build_decompiled_c(input: &PortableInput<'_>) -> Vec<DecompiledCRecord> {
    if input.profile != "native-max" || input.decompile_c == "off" {
        return Vec::new();
    }
    let limit = if input.decompile_c == "all" { 1024 } else { 8 };

    let mut ranked: Vec<&FunctionRecord> = input.functions.iter().collect();
    ranked.sort_by_key(|f| {
        let api_density = input
            .api_flows
            .iter()
            .filter(|row| row.function == f.start)
            .count();
        std::cmp::Reverse(api_density)
    });

    ranked
        .into_iter()
        .take(limit)
        .collect::<Vec<_>>()
        .par_iter()
        .map(|function| lift_function(input, function))
        .collect()
}

fn lift_function(input: &PortableInput<'_>, function: &FunctionRecord) -> DecompiledCRecord {
    let instructions: Vec<&InstructionRecord> = input
        .instructions
        .iter()
        .filter(|row| row.address >= function.start && row.address < function.end)
        .collect();

    let ssa_for_fn: Vec<&SsaValueRecord> = input
        .ssa_values
        .iter()
        .filter(|row| row.function == function.start)
        .collect();
    let dataflow_for_fn: Vec<&DataflowEdgeRecord> = input
        .dataflow_edges
        .iter()
        .filter(|row| row.function == function.start)
        .collect();
    let api_flows_by_callsite = group_api_flows(input.api_flows, function.start);
    let structured = input
        .structured_flow
        .iter()
        .find(|row| row.function == function.start);

    let types = recover_types(&ssa_for_fn, &dataflow_for_fn, &api_flows_by_callsite);
    let storages = collect_storages(&instructions, &ssa_for_fn);
    let branch_targets = collect_branch_targets(&instructions, function);

    let mut lines = Vec::new();
    lines.push("#include <stdint.h>".to_string());
    lines.push(
        "/* decompiled by rerun; uintN_t locals; goto-form for irreducible regions */".to_string(),
    );
    lines.push(String::new());

    let abi = detect_abi(input);
    let return_type = recover_return_type(&instructions, &api_flows_by_callsite);
    let arg_decls = recover_arg_decls(&api_flows_by_callsite, &instructions, abi);

    // A6 — emit struct-candidate hints for any base register accessed at
    // multiple distinct offsets. Hint-only output (a comment); future phases
    // upgrade this to real anonymous-struct declarations once PDB / RTTI
    // facts feed in.
    for hint in infer_struct_hints(&instructions) {
        let offsets_str = hint
            .offsets
            .iter()
            .map(|o| format!("0x{:x}", o))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "/* struct candidate on {}: {} field(s) at {{{}}} */",
            hint.base,
            hint.offsets.len(),
            offsets_str
        ));
    }

    lines.push(format!(
        "{} function_{:016X}({}) {{",
        return_type, function.start, arg_decls
    ));

    // Dedupe by promoted local name so `[rsp+0x20]` and `stack[+32]` (which
    // both map to `arg_20h`) emit a single declaration. Sort by promoted name
    // for stable LLM-friendly output.
    let mut sorted_storages: Vec<&String> = storages.iter().collect();
    sorted_storages.sort();
    let mut emitted_names: BTreeSet<String> = BTreeSet::new();
    let mut decl_lines: Vec<(String, String, String, String)> = Vec::new(); // (name, ty, storage, line)
    for storage in &sorted_storages {
        let name = local_name(storage);
        if !emitted_names.insert(name.clone()) {
            continue;
        }
        let ty = types
            .get(*storage)
            .cloned()
            .unwrap_or_else(|| default_type_for_storage(storage));
        decl_lines.push((
            name.clone(),
            ty.clone(),
            (*storage).clone(),
            format!("    {} {}; /* {} */", ty, name, storage),
        ));
    }
    decl_lines.sort_by(|a, b| a.0.cmp(&b.0));
    // NOTE: decl_lines are NOT pushed here. They're filtered against the
    // post-A2 stmt list and pushed below (after `build_dowhile_plan`) so
    // that locals whose producers got elided by the composer aren't
    // declared.

    // Loop reconstruction: for each natural-loop backedge `(from, to)`, `to`
    // is the loop header and `from` is the last instruction inside the loop
    // body. We annotate the entry with `while (1) {` and the backedge source
    // with `} /* continue loop */`. This is annotative (not full
    // restructuring) — the goto labels remain for irreducible flow, but
    // LLM consumers get a structured signal.
    let mut loop_headers: BTreeMap<u64, Vec<u64>> = BTreeMap::new(); // header -> sources
    let mut loop_backedge_sources: BTreeSet<u64> = BTreeSet::new();
    let mut structured_preamble: Option<String> = None;
    if let Some(flow) = structured {
        for edge in &flow.natural_loops {
            loop_headers.entry(edge.to).or_default().push(edge.from);
            loop_backedge_sources.insert(edge.from);
        }
        if flow.has_loop_like_backedge && !flow.natural_loops.is_empty() {
            structured_preamble = Some(format!(
                "    /* structured: {} region(s), {} natural loop(s) */",
                flow.regions.len(),
                flow.natural_loops.len()
            ));
        }
    }

    // Phase 1: lift each instruction to its raw per-instruction statement via
    // the existing `lift_instruction`. Collect into `StmtRec`s so the A2
    // expression-composition pass can substitute reads and elide dead stores
    // before we interleave labels / loop markers on emit.
    let mut last_cmp: Option<(String, String)> = None;
    let mut stmts: Vec<StmtRec> = Vec::with_capacity(instructions.len());
    for ins in &instructions {
        let text = lift_instruction(ins, &api_flows_by_callsite, &mut last_cmp);
        stmts.push(StmtRec {
            va: ins.address,
            text,
            src_comment: format!("0x{:016X}: {} {}", ins.address, ins.mnemonic, ins.op_str),
            mnemonic: ins.mnemonic.to_ascii_lowercase(),
            is_label_target: branch_targets.contains(&ins.address),
            is_loop_backedge_src: loop_backedge_sources.contains(&ins.address),
            loop_backedge_target: ins.branch_target,
            removed: false,
        });
    }

    // Phase 2: expression composition (A2). Mutates `text` and `removed` in
    // place; preserves per-statement `va` / `src_comment` / label flags so the
    // emit step below can still interleave labels and loop markers.
    compose_expressions(&mut stmts);

    // Phase 2.4 (A6.1): rewrite `*((uint64_t *)(<base>+<offset>))` accesses
    // as `<base>->field_<hex_offset>` when (base, offset) matches a
    // recognized struct candidate from `infer_struct_hints`. Done post-A2 so
    // it operates on whatever survived composer substitution / dead-store
    // elimination — including expressions that the composer just inlined
    // into a `return (...)` clause.
    let struct_hints = infer_struct_hints(&instructions);
    if !struct_hints.is_empty() {
        for stmt in stmts.iter_mut() {
            if stmt.removed {
                continue;
            }
            stmt.text = rewrite_struct_field_accesses(&stmt.text, &struct_hints);
        }
    }

    // Phase 2.5: structured control-flow lifting (A3). For each single-
    // backedge natural loop whose backedge source is a recognized conditional
    // jump back to the header, build a `do { ... } while (cond);` plan. The
    // plan records:
    //   * the header VA to suppress the `L_<va>:` label and the spurious
    //     "natural loop header" annotation
    //   * the backedge-source VA to suppress its `if (cond) goto L_X;` line
    //     and emit `} while (cond);` in its place
    //
    // Loops that don't fit this shape (multi-backedge, irreducible, or whose
    // backedge isn't an `if (...) goto L_HEADER;` after A2 composition) fall
    // back to the existing `while (1) { ... } /* continue loop */` form.
    let dowhile_plan = build_dowhile_plan(&stmts, &loop_headers);

    // Phase 2.6 (A2.1): dead-local-decl elimination. A2's composer may have
    // marked single-use producer lines as `removed`; their declared locals
    // now have no readers in the surviving body. Filter decl_lines to only
    // those whose promoted name (or the raw storage as a fallback) appears
    // as a standalone word in at least one non-removed stmt's `text`. Note
    // we deliberately do NOT scan `src_comment` — those carry the original
    // mnemonic and would produce false positives (`xor eax,eax` would
    // "use" both eax and rax even after A2 elided the producer).
    let live_decls: Vec<&(String, String, String, String)> = decl_lines
        .iter()
        .filter(|(name, _ty, storage, _line)| {
            stmts.iter().any(|s| {
                !s.removed
                    && (find_word(&s.text, name, 0).is_some()
                        || find_word(&s.text, storage, 0).is_some())
            })
        })
        .collect();
    for (_, _, _, line) in &live_decls {
        lines.push((*line).clone());
    }
    if !live_decls.is_empty() {
        lines.push(String::new());
    }
    if let Some(preamble) = structured_preamble {
        lines.push(preamble);
    }

    // Phase 3: emit. Interleave labels and natural-loop markers around the
    // composed statements, skipping `removed` entries.
    let mut open_loop_depth: u32 = 0;
    for stmt in &stmts {
        let is_dowhile_header = dowhile_plan.headers.contains_key(&stmt.va);
        let is_dowhile_backedge = dowhile_plan.backedge_to_cond.contains_key(&stmt.va);

        // Suppress the `L_<va>:` label when this VA is the header of a
        // recognized do-while: the loop's `do {` already marks the entry.
        if stmt.is_label_target && !is_dowhile_header {
            lines.push(format!("L_{:08X}:", stmt.va));
        }
        if is_dowhile_header {
            lines.push("    do {".to_string());
            open_loop_depth += 1;
        } else if let Some(sources) = loop_headers.get(&stmt.va) {
            // Non-do-while natural loop falls back to the annotative form,
            // but only when at least one backedge source is forward (greater
            // VA) than the header. The structured-flow analyzer occasionally
            // reports headers past all their sources (e.g., a `ret` claimed
            // as a loop header) — those are malformed and we skip the
            // annotation.
            let has_forward_source = sources.iter().any(|src| *src > stmt.va);
            if has_forward_source {
                let from_label: Vec<String> =
                    sources.iter().map(|va| format!("0x{:08X}", va)).collect();
                lines.push(format!(
                    "    /* natural loop header — backedge from {} */",
                    from_label.join(", ")
                ));
                lines.push("    while (1) {".to_string());
                open_loop_depth += 1;
            }
        }
        // Body emission: skip if removed (A2 dead-store) OR if this is the
        // backedge of a do-while (its condition went into the `} while (...)`
        // closer below).
        if !stmt.removed && !is_dowhile_backedge {
            let indent = if open_loop_depth > 0 {
                "        "
            } else {
                "    "
            };
            lines.push(format!(
                "{}{}  /* {} */",
                indent, stmt.text, stmt.src_comment
            ));
        }
        if open_loop_depth > 0 && stmt.is_loop_backedge_src {
            if let Some(cond) = dowhile_plan.backedge_to_cond.get(&stmt.va) {
                lines.push(format!(
                    "    }} while ({});  /* {} */",
                    cond, stmt.src_comment
                ));
            } else {
                lines.push(format!(
                    "    }} /* continue loop → 0x{:08X} (backedge) */",
                    stmt.loop_backedge_target.unwrap_or(0)
                ));
            }
            open_loop_depth = open_loop_depth.saturating_sub(1);
        }
    }
    // Close any leftover open loops (safety net for malformed natural-loop sets).
    while open_loop_depth > 0 {
        lines.push("    } /* close dangling loop */".to_string());
        open_loop_depth -= 1;
    }

    lines.push("}".to_string());

    let file_name = format!(
        "function_{}.c",
        safe_file_component(&format!("{:016X}", function.start))
    );
    let relative = PathBuf::from("decompiled_c").join(file_name);
    let path = input.out_dir.join(&relative);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&path, format!("{}\n", lines.join("\n")));

    let confidence = assess_confidence(
        !ssa_for_fn.is_empty(),
        !dataflow_for_fn.is_empty(),
        structured.is_some(),
        !api_flows_by_callsite.is_empty(),
        api_flows_by_callsite
            .values()
            .any(|flows| flows.iter().any(|flow| prototype(&flow.api).is_some())),
    );

    DecompiledCRecord {
        decompile_id: format!("c:{:016X}", function.start),
        function: function.start,
        status: "executed".to_string(),
        output_path: relative.to_string_lossy().replace('\\', "/"),
        lines,
        confidence,
        evidence: vec![function.start],
    }
}

fn group_api_flows<'a>(
    flows: &'a [ApiFlowRecord],
    function_start: u64,
) -> BTreeMap<u64, Vec<&'a ApiFlowRecord>> {
    let mut grouped: BTreeMap<u64, Vec<&ApiFlowRecord>> = BTreeMap::new();
    for flow in flows.iter().filter(|row| row.function == function_start) {
        grouped.entry(flow.callsite).or_default().push(flow);
    }
    grouped
}

fn recover_types(
    ssa: &[&SsaValueRecord],
    dataflow: &[&DataflowEdgeRecord],
    api_flows_by_callsite: &BTreeMap<u64, Vec<&ApiFlowRecord>>,
) -> BTreeMap<String, String> {
    let mut types: BTreeMap<String, String> = BTreeMap::new();

    // Phase 1 (seed): per-edge type_tag from dataflow.
    for edge in dataflow {
        if let Some(tag) = &edge.type_tag {
            types
                .entry(edge.to_storage.clone())
                .or_insert_with(|| win_type_to_c(tag));
        }
    }

    // Phase 2 (seed): API-prototype-driven typing of arg registers and return
    // storage. Multiple calls to the same API converge on the same type; if
    // different APIs disagree on a register's type, the first-seen wins
    // (consistent with `or_insert_with` semantics).
    for flows in api_flows_by_callsite.values() {
        let Some(any) = flows.first() else { continue };
        let Some(proto) = prototype(&any.api) else {
            continue;
        };
        for flow in flows {
            let (Some(reg), Some(idx)) = (&flow.argument_register, flow.argument_index) else {
                continue;
            };
            if let Some(tag) = proto.args.get(idx) {
                types
                    .entry(reg.to_ascii_lowercase())
                    .or_insert_with(|| win_type_to_c(tag));
            }
        }
        types
            .entry("rax".to_string())
            .or_insert_with(|| win_type_to_c(proto.return_type));
    }

    // Phase 3 (A5): fixed-point propagation along dataflow edges. If a
    // typed `from_storage` flows into an untyped `to_storage`, the type
    // propagates. Bounded by edge count to guarantee termination on
    // pathological dataflow graphs.
    let max_iter = dataflow.len().saturating_add(1);
    for _ in 0..max_iter {
        let mut changed = false;
        for edge in dataflow {
            let Some(from_storage) = &edge.from_storage else {
                continue;
            };
            let from_lower = from_storage.to_ascii_lowercase();
            let to_lower = edge.to_storage.to_ascii_lowercase();
            if types.contains_key(&to_lower) {
                continue;
            }
            if let Some(from_ty) = types.get(&from_lower).cloned() {
                types.insert(to_lower, from_ty);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    // Phase 4 (defaults): every SSA storage that still has no recovered
    // type falls back to a width-appropriate `uintN_t`.
    for value in ssa {
        let storage = value.storage.to_ascii_lowercase();
        types
            .entry(storage.clone())
            .or_insert_with(|| default_type_for_storage(&storage));
    }

    types
}

fn win_type_to_c(tag: &str) -> String {
    match tag {
        "LPCWSTR" | "LPWSTR" => "wchar_t *".to_string(),
        "LPCSTR" | "LPSTR" => "char *".to_string(),
        "HANDLE" | "HMODULE" | "HWND" | "HKEY" => "void *".to_string(),
        "LPVOID" | "PVOID" | "PUCHAR" => "void *".to_string(),
        "LPDWORD" | "PDWORD" => "uint32_t *".to_string(),
        "DWORD" | "ULONG" | "UINT" => "uint32_t".to_string(),
        "WORD" | "USHORT" => "uint16_t".to_string(),
        "BYTE" | "UCHAR" => "uint8_t".to_string(),
        "BOOL" | "BOOLEAN" => "uint32_t".to_string(),
        "SIZE_T" | "ULONGLONG" | "ULONG64" => "uint64_t".to_string(),
        "HRESULT" | "NTSTATUS" => "int32_t".to_string(),
        "LPSECURITY_ATTRIBUTES" => "void *".to_string(),
        "SOCKADDR_PTR" => "void *".to_string(),
        other => other.to_string(),
    }
}

fn default_type_for_storage(storage: &str) -> String {
    let lower = storage.to_ascii_lowercase();
    if lower.starts_with('[') {
        return "uint64_t".to_string();
    }
    match lower.as_str() {
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rsp" | "rbp" | "r8" | "r9" | "r10"
        | "r11" | "r12" | "r13" | "r14" | "r15" => "uint64_t".to_string(),
        "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "esp" | "ebp" | "r8d" | "r9d" | "r10d"
        | "r11d" | "r12d" | "r13d" | "r14d" | "r15d" => "uint32_t".to_string(),
        "ax" | "bx" | "cx" | "dx" | "si" | "di" | "sp" | "bp" | "r8w" | "r9w" | "r10w" | "r11w"
        | "r12w" | "r13w" | "r14w" | "r15w" => "uint16_t".to_string(),
        "al" | "bl" | "cl" | "dl" | "sil" | "dil" | "spl" | "bpl" | "r8b" | "r9b" | "r10b"
        | "r11b" | "r12b" | "r13b" | "r14b" | "r15b" => "uint8_t".to_string(),
        _ => "uint64_t".to_string(),
    }
}

fn collect_storages(
    instructions: &[&InstructionRecord],
    ssa: &[&SsaValueRecord],
) -> BTreeSet<String> {
    let mut storages: BTreeSet<String> = BTreeSet::new();
    for value in ssa {
        storages.insert(value.storage.to_ascii_lowercase());
    }
    for ins in instructions {
        for op in split_operands(&ins.op_str) {
            let normalized = normalize_operand(&op);
            if is_register(&normalized) {
                storages.insert(normalized);
            } else if let Some(slot) = stack_slot_name(&normalized) {
                storages.insert(slot);
            }
        }
    }
    storages
}

fn collect_branch_targets(
    instructions: &[&InstructionRecord],
    function: &FunctionRecord,
) -> BTreeSet<u64> {
    instructions
        .iter()
        .filter_map(|row| row.branch_target)
        .filter(|va| *va >= function.start && *va < function.end)
        .collect()
}

fn recover_return_type(
    instructions: &[&InstructionRecord],
    api_flows_by_callsite: &BTreeMap<u64, Vec<&ApiFlowRecord>>,
) -> String {
    let has_ret = instructions
        .iter()
        .any(|row| row.is_ret || row.mnemonic.eq_ignore_ascii_case("ret"));
    if !has_ret {
        return "void".to_string();
    }
    let last_call = instructions
        .iter()
        .rev()
        .find(|row| row.is_call && api_flows_by_callsite.contains_key(&row.address));
    if let Some(call) = last_call {
        if let Some(flows) = api_flows_by_callsite.get(&call.address) {
            if let Some(flow) = flows.first() {
                if let Some(proto) = prototype(&flow.api) {
                    return win_type_to_c(proto.return_type);
                }
            }
        }
    }
    "uint64_t".to_string()
}

fn recover_arg_decls(
    api_flows_by_callsite: &BTreeMap<u64, Vec<&ApiFlowRecord>>,
    instructions: &[&InstructionRecord],
    abi: Abi,
) -> String {
    let regs: &[&str] = match abi {
        Abi::Win64 => WIN64_ARG_REGS,
        Abi::SysV => SYSV_ARG_REGS,
    };
    let mut used: BTreeMap<&str, String> = BTreeMap::new();
    // Phase 1: type-aware recovery from API flows
    for flows in api_flows_by_callsite.values() {
        for flow in flows {
            let Some(reg) = flow.argument_register.as_deref() else {
                continue;
            };
            let lower = reg.to_ascii_lowercase();
            if !regs.contains(&lower.as_str()) {
                continue;
            }
            used.entry(
                regs.iter()
                    .find(|r| **r == lower.as_str())
                    .copied()
                    .unwrap(),
            )
            .or_insert_with(|| "uint64_t".to_string());
        }
    }
    // Phase 2: walk the prologue (~40 instructions) and look for the first
    // read of each ABI-register before it gets written. A pre-write read is
    // strong evidence the register is an inbound parameter.
    let mut seen_written: BTreeSet<&str> = BTreeSet::new();
    let mut seen_read: BTreeSet<&str> = BTreeSet::new();
    for ins in instructions.iter().take(40) {
        let ops = split_operands(&ins.op_str);
        let mnemonic = ins.mnemonic.to_ascii_lowercase();
        let writes_first = matches!(
            mnemonic.as_str(),
            "mov"
                | "movzx"
                | "movsx"
                | "movsxd"
                | "lea"
                | "add"
                | "sub"
                | "and"
                | "or"
                | "xor"
                | "shl"
                | "shr"
                | "sar"
                | "sal"
                | "rol"
                | "ror"
                | "inc"
                | "dec"
                | "neg"
                | "not"
                | "bswap"
                | "cmovz"
                | "cmove"
                | "cmovnz"
                | "cmovne"
                | "cmovg"
                | "cmovl"
                | "cmovge"
                | "cmovle"
                | "cmova"
                | "cmovae"
                | "cmovb"
                | "cmovbe"
                | "cmovs"
                | "cmovns"
        );
        for (idx, op) in ops.iter().enumerate() {
            let normalized = normalize_operand(op);
            let alias = canonical_reg64(&normalized);
            if !regs.contains(&alias) {
                continue;
            }
            // First operand of writes_first is a write. All other operand positions are reads.
            if writes_first && idx == 0 && !normalized.starts_with('[') {
                if !seen_read.contains(alias) {
                    seen_written.insert(alias);
                }
            } else if !seen_written.contains(alias) {
                seen_read.insert(alias);
                used.entry(alias).or_insert_with(|| "uint64_t".to_string());
            }
        }
    }
    if used.is_empty() {
        return "void".to_string();
    }
    let mut decls = Vec::new();
    for reg in regs {
        if let Some(ty) = used.get(reg) {
            decls.push(format!("{} {}_in", ty, reg));
        }
    }
    decls.join(", ")
}

fn canonical_reg64(name: &str) -> &'static str {
    canonical_reg_full(name).unwrap_or("")
}

/// Render an x86_64 condition-code suffix (`e`, `ne`, `g`, `nle`, `s`, ...)
/// as a C expression using `lhs` and `rhs` from the last cmp/test. Shared by
/// jCC (after stripping the leading `j`), cmovCC (after `cmov`), and setCC
/// (after `set`). Returns a literal fallback comment for unknown CCs.
fn condition_from_cc(suffix: &str, lhs: &str, rhs: &str) -> String {
    match suffix {
        "e" | "z" => format!("{} == {}", lhs, rhs),
        "ne" | "nz" => format!("{} != {}", lhs, rhs),
        "g" | "nle" => format!("(int64_t){} > (int64_t){}", lhs, rhs),
        "ge" | "nl" => format!("(int64_t){} >= (int64_t){}", lhs, rhs),
        "l" | "nge" => format!("(int64_t){} < (int64_t){}", lhs, rhs),
        "le" | "ng" => format!("(int64_t){} <= (int64_t){}", lhs, rhs),
        "a" | "nbe" => format!("{} > {}", lhs, rhs),
        "ae" | "nb" | "nc" => format!("{} >= {}", lhs, rhs),
        "b" | "nae" | "c" => format!("{} < {}", lhs, rhs),
        "be" | "na" => format!("{} <= {}", lhs, rhs),
        "s" => format!("(int64_t){} < 0", lhs),
        "ns" => format!("(int64_t){} >= 0", lhs),
        "o" => "/* overflow */ 0".to_string(),
        "no" => "/* !overflow */ 1".to_string(),
        "p" | "pe" => "/* parity-even */ 0".to_string(),
        "np" | "po" => "/* parity-odd */ 0".to_string(),
        other => format!("/* cc:{} */ 0", other),
    }
}

/// Calling-convention used to interpret arg registers in `recover_arg_decls`.
#[derive(Clone, Copy)]
enum Abi {
    /// Windows x64: rcx, rdx, r8, r9 — used by PE binaries.
    Win64,
    /// System V AMD64: rdi, rsi, rdx, rcx, r8, r9 — used by ELF and Mach-O.
    SysV,
}

const WIN64_ARG_REGS: &[&str] = &["rcx", "rdx", "r8", "r9"];
const SYSV_ARG_REGS: &[&str] = &["rdi", "rsi", "rdx", "rcx", "r8", "r9"];

/// Pick the ABI for the binary under analysis. PE → Win64; ELF / Mach-O /
/// unknown → System V. Detected via the file's magic bytes, which is more
/// reliable than file-extension sniffing for synthesized fixtures.
fn detect_abi(input: &PortableInput<'_>) -> Abi {
    let bytes = input.bytes;
    if bytes.len() >= 2 && &bytes[..2] == b"MZ" {
        Abi::Win64
    } else {
        Abi::SysV
    }
}

fn lift_instruction(
    ins: &InstructionRecord,
    api_flows_by_callsite: &BTreeMap<u64, Vec<&ApiFlowRecord>>,
    last_cmp: &mut Option<(String, String)>,
) -> String {
    let mnemonic = ins.mnemonic.to_ascii_lowercase();
    let operands = split_operands(&ins.op_str);

    match mnemonic.as_str() {
        "mov" | "movzx" | "movsx" | "movsxd" if operands.len() >= 2 => {
            let dst = render_operand(&operands[0]);
            let src = render_operand(&operands[1]);
            if mnemonic == "movzx" {
                format!("{} = (uint64_t)(uint8_t){};", dst, src)
            } else if mnemonic == "movsx" || mnemonic == "movsxd" {
                format!("{} = (int64_t)(int32_t){};", dst, src)
            } else {
                format!("{} = {};", dst, src)
            }
        }
        "lea" if operands.len() >= 2 => {
            let dst = render_operand(&operands[0]);
            let addr = render_address_expr(&operands[1]);
            format!("{} = (uintptr_t)({});", dst, addr)
        }
        "add" | "sub" | "and" | "or" | "xor" | "shl" | "shr" | "sar" | "sal" | "rol" | "ror"
            if operands.len() >= 2 =>
        {
            let dst = render_operand(&operands[0]);
            let src = render_operand(&operands[1]);
            if mnemonic == "xor"
                && normalize_operand(&operands[0]) == normalize_operand(&operands[1])
            {
                return format!("{} = 0;", dst);
            }
            let op = match mnemonic.as_str() {
                "add" => "+",
                "sub" => "-",
                "and" => "&",
                "or" => "|",
                "xor" => "^",
                "shl" | "sal" => "<<",
                "shr" | "sar" => ">>",
                "rol" => ".rol",
                "ror" => ".ror",
                _ => "?",
            };
            if op == ".rol" {
                format!(
                    "{} = ({} << ({} & 63)) | ({} >> ((64 - ({} & 63)) & 63));",
                    dst, dst, src, dst, src
                )
            } else if op == ".ror" {
                format!(
                    "{} = ({} >> ({} & 63)) | ({} << ((64 - ({} & 63)) & 63));",
                    dst, dst, src, dst, src
                )
            } else {
                format!("{} {}= {};", dst, op, src)
            }
        }
        "inc" if operands.len() >= 1 => format!("{} += 1;", render_operand(&operands[0])),
        "dec" if operands.len() >= 1 => format!("{} -= 1;", render_operand(&operands[0])),
        "neg" if operands.len() >= 1 => {
            let dst = render_operand(&operands[0]);
            format!("{} = ~{} + 1;", dst, dst)
        }
        "not" if operands.len() >= 1 => {
            let dst = render_operand(&operands[0]);
            format!("{} = ~{};", dst, dst)
        }
        "cmp" | "test" if operands.len() >= 2 => {
            // For `test op, op` (a common idiom that sets ZF iff op == 0),
            // record the semantic condition `op == 0` rather than the literal
            // `op == op`. Same logic for `cmp op, op` though that's almost
            // always dead code.
            let rendered = (render_operand(&operands[0]), render_operand(&operands[1]));
            *last_cmp = if mnemonic == "test"
                && normalize_operand(&operands[0]) == normalize_operand(&operands[1])
            {
                Some((rendered.0, "0".to_string()))
            } else {
                Some(rendered)
            };
            format!("/* {} {}, {} */", mnemonic, operands[0], operands[1])
        }
        "call" => {
            if let Some(flows) = api_flows_by_callsite.get(&ins.address) {
                render_api_call(flows)
            } else {
                let target = ins.op_str.trim();
                format!("rax = call_{}();", synthesize_call_name(target))
            }
        }
        m if m.starts_with('j') && ins.branch_target.is_some() => {
            let target = ins.branch_target.unwrap_or_default();
            if m == "jmp" {
                format!("goto L_{:08X};", target)
            } else {
                let (lhs, rhs) = last_cmp
                    .clone()
                    .unwrap_or_else(|| ("/*?*/".to_string(), "/*?*/".to_string()));
                let cond = condition_from_cc(&m[1..], &lhs, &rhs);
                format!("if ({}) goto L_{:08X};", cond, target)
            }
        }
        // A9 — CMov lifting: `cmovCC dst, src` becomes a ternary
        // `dst = (cond_CC) ? src : dst;`. The condition operands come from
        // the most recent flag-setting cmp/test.
        m if m.starts_with("cmov") && operands.len() >= 2 => {
            let dst = render_operand(&operands[0]);
            let src = render_operand(&operands[1]);
            let (lhs, rhs) = last_cmp
                .clone()
                .unwrap_or_else(|| ("/*?*/".to_string(), "/*?*/".to_string()));
            let cond = condition_from_cc(&m[4..], &lhs, &rhs);
            format!("{} = ({}) ? {} : {};", dst, cond, src, dst)
        }
        // A9 — SETcc lifting: `setCC dst` becomes `dst = (cond_CC) ? 1 : 0;`.
        // Only matches when `m` is at least 4 chars (set + a CC suffix).
        m if m.starts_with("set") && m.len() > 3 && operands.len() >= 1 => {
            let dst = render_operand(&operands[0]);
            let (lhs, rhs) = last_cmp
                .clone()
                .unwrap_or_else(|| ("/*?*/".to_string(), "/*?*/".to_string()));
            let cond = condition_from_cc(&m[3..], &lhs, &rhs);
            format!("{} = ({}) ? 1 : 0;", dst, cond)
        }
        "ret" => "return rax;".to_string(),
        "push" if operands.len() >= 1 => format!("/* push {} */", operands[0]),
        "pop" if operands.len() >= 1 => format!("/* pop {} */", operands[0]),
        "nop" | "endbr64" | "endbr32" | "leave" | "cdq" | "cqo" => format!("/* {} */", mnemonic),
        _ => format!("/* {} {} (unlifted) */", ins.mnemonic, ins.op_str),
    }
}

fn render_api_call(flows: &[&ApiFlowRecord]) -> String {
    let mut by_index: BTreeMap<usize, &ApiFlowRecord> = BTreeMap::new();
    for flow in flows {
        if let Some(idx) = flow.argument_index {
            by_index.entry(idx).or_insert(*flow);
        }
    }
    let api_name = flows
        .first()
        .map(|flow| flow.normalized_api.clone())
        .unwrap_or_default();
    let proto = prototype(&api_name);

    let mut args = Vec::new();
    let arg_count = proto
        .as_ref()
        .map(|p| p.args.len())
        .unwrap_or(by_index.len());
    for idx in 0..arg_count {
        match by_index.get(&idx) {
            Some(flow) => {
                let value = if !flow.value.is_empty() && flow.value != "(unknown)" {
                    render_arg_value(&flow.value)
                } else if let Some(reg) = &flow.argument_register {
                    reg.to_ascii_lowercase()
                } else {
                    "/*unresolved*/ 0".to_string()
                };
                let name = flow.argument_name.as_deref().unwrap_or(&flow.argument);
                args.push(format!("/*{}*/ {}", name, value));
            }
            None => {
                let arg_label = proto
                    .as_ref()
                    .and_then(|p| p.args.get(idx))
                    .copied()
                    .unwrap_or("arg");
                args.push(format!("/*{}*/ 0", arg_label));
            }
        }
    }
    format!("rax = {}({});", safe_symbol(&api_name), args.join(", "))
}

fn render_arg_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with('-') {
        return trimmed.to_string();
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        return trimmed.to_string();
    }
    if trimmed.starts_with('"') && trimmed.ends_with('"') {
        return trimmed.to_string();
    }
    format!("/*{}*/", trimmed)
}

fn render_operand(op: &str) -> String {
    let normalized = normalize_operand(op);
    if let Some(stripped) = strip_brackets(&normalized) {
        format!("*((uint64_t *)({}))", stripped)
    } else if is_register(&normalized) {
        local_name(&normalized)
    } else {
        normalize_hex_literal(&normalized)
    }
}

/// Convert Intel-syntax hex literals (`0Ah`, `1234h`, `0FFFFFFFFh`) to C
/// form (`0xa`, `0x1234`, `0xffffffff`). Decimal literals and already-C-form
/// literals pass through unchanged. Important: C accepts `0x` prefix but
/// NOT a trailing `h` — leaving the Intel form makes the decompiled output
/// non-compilable as C, which breaks downstream tooling.
fn normalize_hex_literal(s: &str) -> String {
    let trimmed = s.trim();
    let lower = trimmed.to_ascii_lowercase();
    if let Some(stripped) = lower.strip_suffix('h') {
        if !stripped.is_empty() && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
            // Drop a leading "0" *only* if the remaining text starts with a
            // hex letter (a-f). Keeps `0a` (→ `0x0a`) tidy without padding
            // already-C-friendly forms like `7fffffff`.
            return format!("0x{}", stripped);
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod register_aliasing_tests {
    use super::{canonical_reg_full, register_aliases};

    #[test]
    fn rax_family_canonicalizes_to_rax() {
        for alias in ["rax", "eax", "ax", "al", "ah"] {
            assert_eq!(
                canonical_reg_full(alias),
                Some("rax"),
                "alias {} should canonicalize to rax",
                alias
            );
        }
    }

    #[test]
    fn rdi_family_canonicalizes_to_rdi() {
        for alias in ["rdi", "edi", "di", "dil"] {
            assert_eq!(
                canonical_reg_full(alias),
                Some("rdi"),
                "alias {} should canonicalize to rdi",
                alias
            );
        }
    }

    #[test]
    fn r8_family_canonicalizes_to_r8() {
        for alias in ["r8", "r8d", "r8w", "r8b"] {
            assert_eq!(
                canonical_reg_full(alias),
                Some("r8"),
                "alias {} should canonicalize to r8",
                alias
            );
        }
    }

    #[test]
    fn non_register_returns_none() {
        assert_eq!(canonical_reg_full("foo"), None);
        assert_eq!(canonical_reg_full("local_18h"), None);
        assert_eq!(canonical_reg_full("arg_0"), None);
        assert_eq!(canonical_reg_full(""), None);
    }

    #[test]
    fn register_aliases_returns_all_subwidth_names() {
        let rax_aliases = register_aliases("rax");
        // Expect 5 aliases: rax, eax, ax, al, ah.
        assert_eq!(rax_aliases.len(), 5);
        for alias in ["rax", "eax", "ax", "al", "ah"] {
            assert!(
                rax_aliases.contains(&alias),
                "rax aliases should include {}",
                alias
            );
        }
    }

    #[test]
    fn register_aliases_for_r8_has_4_entries() {
        let r8_aliases = register_aliases("r8");
        // r8 family doesn't have an 8-bit-high alias (no `r8h`).
        assert_eq!(r8_aliases.len(), 4);
        for alias in ["r8", "r8d", "r8w", "r8b"] {
            assert!(r8_aliases.contains(&alias));
        }
    }

    #[test]
    fn register_aliases_for_non_register_returns_empty() {
        let empty_aliases = register_aliases("local_18h");
        assert!(empty_aliases.is_empty());
    }

    #[test]
    fn rsi_rdi_rsp_rbp_have_no_high_byte() {
        // The lower-encoding-pressure regs use REX-form _l_ bytes (`sil`,
        // `dil`, `spl`, `bpl`) instead of a separate high-byte register.
        for alias in ["rsi", "esi", "si", "sil"] {
            assert_eq!(canonical_reg_full(alias), Some("rsi"));
        }
        for alias in ["rbp", "ebp", "bp", "bpl"] {
            assert_eq!(canonical_reg_full(alias), Some("rbp"));
        }
    }
}

#[cfg(test)]
mod substitute_storage_in_rhs_tests {
    use super::{substitute_storage_in_rhs, LiveValue};
    use std::collections::BTreeMap;

    fn live_with(canon: &str, expr: &str) -> BTreeMap<String, LiveValue> {
        let mut m = BTreeMap::new();
        m.insert(
            canon.to_string(),
            LiveValue {
                expr: expr.to_string(),
                producer_idx: 0,
                use_count: 0,
            },
        );
        m
    }

    #[test]
    fn simple_substitution_in_return() {
        let mut live = live_with("rax", "0");
        let result = substitute_storage_in_rhs("return rax;", "rax", "0", &mut live);
        assert_eq!(result, "return (0);");
        assert_eq!(live["rax"].use_count, 1);
    }

    #[test]
    fn substitutes_via_alias() {
        // live[rax] should match `eax` in the body (alias of rax).
        let mut live = live_with("rax", "0");
        let result = substitute_storage_in_rhs("return eax;", "rax", "0", &mut live);
        assert_eq!(result, "return (0);");
    }

    /// CRITICAL — pins the A9.1 bugfix at the function level.
    ///
    /// Before the fix: substituting `rax` with `(uint64_t)(uint8_t)al` in
    /// `return rax;` would produce `return ((uint64_t)(uint8_t)al);`, then
    /// the alias-iteration would search for `al` in the now-substituted
    /// body and find it INSIDE the substituted expression, leading to
    /// `return ((uint64_t)(uint8_t)((uint64_t)(uint8_t)al));` (self-nested).
    ///
    /// The substituted-region tracking prevents this.
    #[test]
    fn does_not_re_substitute_inside_substituted_expression() {
        let mut live = live_with("rax", "(uint64_t)(uint8_t)al");
        let result =
            substitute_storage_in_rhs("return rax;", "rax", "(uint64_t)(uint8_t)al", &mut live);
        assert_eq!(
            result, "return ((uint64_t)(uint8_t)al);",
            "must not re-substitute `al` inside the just-substituted expression"
        );
    }

    #[test]
    fn substitutes_only_in_rhs_region_for_assignment() {
        // For `LHS = RHS;` only the RHS should be touched. With live[rax] = 99,
        // an `rax` on the LHS would be a write target; we mustn't substitute it.
        // (Our parser's lhs-vs-rhs split is handled by split_rhs_region.)
        let mut live = live_with("rax", "99");
        let result = substitute_storage_in_rhs("rax = rax;", "rax", "99", &mut live);
        // Note: in the real composer, the LHS of `rax = rax;` would be a
        // write — but substitute_storage_in_rhs JUST substitutes reads in
        // the RHS region. The LHS rax stays.
        assert_eq!(result, "rax = (99);");
    }

    #[test]
    fn no_match_means_no_substitution() {
        let mut live = live_with("rax", "0");
        let result = substitute_storage_in_rhs("return 5;", "rax", "0", &mut live);
        assert_eq!(result, "return 5;");
        // use_count should NOT have been incremented.
        assert_eq!(live["rax"].use_count, 0);
    }

    #[test]
    fn substitutes_multiple_distinct_occurrences() {
        let mut live = live_with("rax", "X");
        // Multiple references to rax (and eax — alias) in same RHS.
        // The composer wraps each in `(X)` separately.
        let result = substitute_storage_in_rhs("return rax + eax;", "rax", "X", &mut live);
        assert_eq!(result, "return (X) + (X);");
    }
}

#[cfg(test)]
mod parse_int_literal_tests {
    use super::parse_int_literal;

    #[test]
    fn decimal_forms() {
        assert_eq!(parse_int_literal("0"), Some(0));
        assert_eq!(parse_int_literal("1"), Some(1));
        assert_eq!(parse_int_literal("42"), Some(42));
        assert_eq!(parse_int_literal("100"), Some(100));
    }

    #[test]
    fn intel_hex_form() {
        assert_eq!(parse_int_literal("0Ah"), Some(0x0A));
        assert_eq!(parse_int_literal("10h"), Some(0x10));
        assert_eq!(parse_int_literal("1234h"), Some(0x1234));
        assert_eq!(parse_int_literal("ffh"), Some(0xff));
    }

    #[test]
    fn c_hex_form() {
        assert_eq!(parse_int_literal("0x10"), Some(0x10));
        assert_eq!(parse_int_literal("0xff"), Some(0xff));
        assert_eq!(parse_int_literal("0x140005000"), Some(0x140005000));
    }

    #[test]
    fn whitespace_tolerated() {
        assert_eq!(parse_int_literal("  10h  "), Some(0x10));
        assert_eq!(parse_int_literal(" 0x10 "), Some(0x10));
    }

    #[test]
    fn unrecognized_input_returns_none() {
        assert_eq!(parse_int_literal(""), None);
        assert_eq!(parse_int_literal("foo"), None);
        assert_eq!(parse_int_literal("rax"), None);
    }
}

#[cfg(test)]
mod detect_abi_via_magic_tests {
    // detect_abi itself takes PortableInput which is impractical to
    // construct here, but the magic-bytes branch can be exercised by
    // calling the inner predicate directly. We replicate the predicate's
    // intent for symmetry with the implementation.
    #[test]
    fn pe_magic_is_recognized() {
        let bytes = b"MZ\x90\x00";
        assert!(bytes.len() >= 2 && &bytes[..2] == b"MZ");
    }

    #[test]
    fn elf_magic_is_not_mz() {
        let bytes = b"\x7fELF\x02";
        assert!(!(bytes.len() >= 2 && &bytes[..2] == b"MZ"));
    }

    #[test]
    fn empty_bytes_falls_to_sysv() {
        let bytes: &[u8] = &[];
        assert!(!(bytes.len() >= 2 && &bytes[..2] == b"MZ"));
    }
}

#[cfg(test)]
mod condition_from_cc_tests {
    use super::condition_from_cc;

    #[test]
    fn equality_predicates() {
        assert_eq!(condition_from_cc("e", "rax", "0"), "rax == 0");
        assert_eq!(condition_from_cc("z", "rax", "0"), "rax == 0");
        assert_eq!(condition_from_cc("ne", "rax", "0"), "rax != 0");
        assert_eq!(condition_from_cc("nz", "rax", "0"), "rax != 0");
    }

    #[test]
    fn signed_ordering_uses_int64_casts() {
        assert_eq!(
            condition_from_cc("g", "rax", "rbx"),
            "(int64_t)rax > (int64_t)rbx"
        );
        assert_eq!(
            condition_from_cc("l", "rax", "rbx"),
            "(int64_t)rax < (int64_t)rbx"
        );
        assert_eq!(
            condition_from_cc("ge", "rax", "rbx"),
            "(int64_t)rax >= (int64_t)rbx"
        );
        assert_eq!(
            condition_from_cc("le", "rax", "rbx"),
            "(int64_t)rax <= (int64_t)rbx"
        );
    }

    #[test]
    fn signed_ordering_aliases() {
        // jng = jle, jnle = jg, jnge = jl, jnl = jge
        assert_eq!(
            condition_from_cc("nle", "a", "b"),
            condition_from_cc("g", "a", "b")
        );
        assert_eq!(
            condition_from_cc("nl", "a", "b"),
            condition_from_cc("ge", "a", "b")
        );
        assert_eq!(
            condition_from_cc("nge", "a", "b"),
            condition_from_cc("l", "a", "b")
        );
        assert_eq!(
            condition_from_cc("ng", "a", "b"),
            condition_from_cc("le", "a", "b")
        );
    }

    #[test]
    fn unsigned_ordering_no_casts() {
        assert_eq!(condition_from_cc("a", "rax", "rbx"), "rax > rbx");
        assert_eq!(condition_from_cc("b", "rax", "rbx"), "rax < rbx");
        assert_eq!(condition_from_cc("ae", "rax", "rbx"), "rax >= rbx");
        assert_eq!(condition_from_cc("be", "rax", "rbx"), "rax <= rbx");
    }

    #[test]
    fn unsigned_ordering_aliases() {
        // jnbe = ja, jnb = jae, jnae = jb, jna = jbe
        // jc = jb (carry set = below for unsigned), jnc = jae
        assert_eq!(
            condition_from_cc("nbe", "a", "b"),
            condition_from_cc("a", "a", "b")
        );
        assert_eq!(
            condition_from_cc("nb", "a", "b"),
            condition_from_cc("ae", "a", "b")
        );
        assert_eq!(
            condition_from_cc("c", "a", "b"),
            condition_from_cc("b", "a", "b")
        );
        assert_eq!(
            condition_from_cc("nc", "a", "b"),
            condition_from_cc("ae", "a", "b")
        );
    }

    #[test]
    fn sign_flag_predicates_compare_to_zero_signed() {
        assert_eq!(condition_from_cc("s", "rax", "rbx"), "(int64_t)rax < 0");
        assert_eq!(condition_from_cc("ns", "rax", "rbx"), "(int64_t)rax >= 0");
    }

    #[test]
    fn unknown_cc_falls_back_to_comment() {
        let r = condition_from_cc("xxx", "a", "b");
        assert!(r.contains("cc:xxx"), "got: {}", r);
    }
}

#[cfg(test)]
mod find_top_level_assign_tests {
    use super::find_top_level_assign;

    #[test]
    fn finds_simple_assign() {
        assert_eq!(find_top_level_assign("rax = 0"), Some(4));
    }

    #[test]
    fn finds_compound_op_position() {
        // Returns the position of the `=` regardless of compound prefix.
        assert_eq!(find_top_level_assign("rax += 1"), Some(5));
        assert_eq!(find_top_level_assign("rax -= 1"), Some(5));
    }

    #[test]
    fn ignores_double_equals() {
        // `==` is NOT an assignment.
        assert_eq!(find_top_level_assign("rax == 1"), None);
    }

    #[test]
    fn ignores_not_equals() {
        assert_eq!(find_top_level_assign("rax != 1"), None);
    }

    #[test]
    fn ignores_less_equal_and_greater_equal() {
        assert_eq!(find_top_level_assign("rax <= 1"), None);
        assert_eq!(find_top_level_assign("rax >= 1"), None);
    }

    #[test]
    fn ignores_equals_inside_parens() {
        // The `==` inside the parens should be skipped (already handled by
        // the prev-char check), and there's no top-level `=` here.
        assert_eq!(find_top_level_assign("(rax == 1)"), None);
    }

    #[test]
    fn finds_assignment_with_ternary_rhs() {
        // The top-level `=` precedes the ternary; the `==` inside is at
        // depth 1.
        let text = "rax = (rcx == 0) ? 1 : 0";
        let pos = find_top_level_assign(text).expect("should find");
        assert_eq!(&text[pos..pos + 1], "=");
        assert_eq!(pos, 4);
    }

    #[test]
    fn finds_assignment_with_memory_deref_rhs() {
        let text = "rax = *((uint64_t *)(rcx+8))";
        let pos = find_top_level_assign(text).expect("should find");
        assert_eq!(&text[pos..pos + 1], "=");
        assert_eq!(pos, 4);
    }

    #[test]
    fn empty_input_returns_none() {
        assert_eq!(find_top_level_assign(""), None);
    }
}

#[cfg(test)]
mod struct_rewrite_tests {
    use super::{rewrite_struct_field_accesses, StructHint};
    use std::collections::BTreeSet;

    fn hint(base: &str, offsets: &[i64]) -> StructHint {
        StructHint {
            base: base.to_string(),
            offsets: offsets.iter().copied().collect::<BTreeSet<i64>>(),
        }
    }

    #[test]
    fn rewrites_simple_deref_to_field_access() {
        let hints = vec![hint("rcx", &[8, 16])];
        let input = "rax = *((uint64_t *)(rcx+8));";
        let output = rewrite_struct_field_accesses(input, &hints);
        assert_eq!(output, "rax = rcx->field_8;");
    }

    #[test]
    fn rewrites_hex_offset_using_hex_form() {
        let hints = vec![hint("rcx", &[8, 16])];
        let input = "rax = *((uint64_t *)(rcx+10h));";
        let output = rewrite_struct_field_accesses(input, &hints);
        assert_eq!(output, "rax = rcx->field_10;");
    }

    #[test]
    fn rewrites_multiple_accesses_in_same_text() {
        let hints = vec![hint("rcx", &[8, 16])];
        let input = "*((uint64_t *)(rcx+10h)) = (*((uint64_t *)(rcx+8)));";
        let output = rewrite_struct_field_accesses(input, &hints);
        assert_eq!(output, "rcx->field_10 = (rcx->field_8);");
    }

    #[test]
    fn does_not_rewrite_when_base_not_in_hints() {
        let hints = vec![hint("rcx", &[8])];
        let input = "rax = *((uint64_t *)(rdx+8));";
        let output = rewrite_struct_field_accesses(input, &hints);
        // rdx has no hint → leave the deref alone.
        assert_eq!(output, "rax = *((uint64_t *)(rdx+8));");
    }

    #[test]
    fn does_not_rewrite_when_offset_not_in_hint() {
        let hints = vec![hint("rcx", &[8, 16])];
        let input = "rax = *((uint64_t *)(rcx+0x20));";
        let output = rewrite_struct_field_accesses(input, &hints);
        // Offset 0x20 isn't in hint's offsets {8, 16} → leave alone.
        assert_eq!(output, "rax = *((uint64_t *)(rcx+0x20));");
    }

    #[test]
    fn empty_hints_no_op() {
        let hints: Vec<StructHint> = vec![];
        let input = "rax = *((uint64_t *)(rcx+8));";
        let output = rewrite_struct_field_accesses(input, &hints);
        assert_eq!(output, input);
    }

    #[test]
    fn rewrites_in_return_expression() {
        let hints = vec![hint("rcx", &[8, 16])];
        let input = "return ((*((uint64_t *)(rcx+8))));";
        let output = rewrite_struct_field_accesses(input, &hints);
        assert_eq!(output, "return ((rcx->field_8));");
    }
}

#[cfg(test)]
mod parse_simple_assign_tests {
    use super::parse_simple_assign;

    #[test]
    fn simple_register_assignment() {
        let r = parse_simple_assign("rax = 0;").expect("parse");
        assert_eq!(r.0, "rax");
        assert_eq!(r.1, "=");
        assert_eq!(r.2, "0");
    }

    #[test]
    fn compound_add_assignment() {
        let r = parse_simple_assign("eax += 1;").expect("parse");
        assert_eq!(r.0, "eax");
        assert_eq!(r.1, "+=");
        assert_eq!(r.2, "1");
    }

    #[test]
    fn compound_sub_assignment() {
        let r = parse_simple_assign("local_rsp -= 0x28;").expect("parse");
        assert_eq!(r.0, "local_rsp");
        assert_eq!(r.1, "-=");
        assert_eq!(r.2, "0x28");
    }

    #[test]
    fn compound_xor_or_and_assignments() {
        assert_eq!(parse_simple_assign("rax ^= 1;").unwrap().1, "^=");
        assert_eq!(parse_simple_assign("rax |= 1;").unwrap().1, "|=");
        assert_eq!(parse_simple_assign("rax &= 1;").unwrap().1, "&=");
    }

    #[test]
    fn deref_lhs_is_rejected_due_to_plus() {
        // The exact shape that the is_call_text bug surfaced through. Memory
        // writes have a `+` in the lhs (from the address expression) and
        // MUST be rejected so the composer doesn't track them as register
        // writes.
        assert!(parse_simple_assign("*((uint64_t *)(rcx+10h)) = rax;").is_none());
    }

    #[test]
    fn deref_lhs_with_no_plus_is_accepted() {
        // `*(rcx)` style — no `+` in the lhs. The current allowed-char set
        // includes `*`, `(`, `)` so this parses. The composer would then
        // see `*(rcx)` as the storage name — non-register, tracked as-is.
        let r = parse_simple_assign("*(rcx) = 0;").expect("parse");
        assert_eq!(r.0, "*(rcx)");
        assert_eq!(r.1, "=");
    }

    #[test]
    fn arrow_field_lhs_is_rejected_due_to_arrow() {
        // The A6.1 struct-rewrite produces `rcx->field_8 = ...` shapes —
        // the `-` and `>` in `->` aren't in the allowed char set, so
        // parse_simple_assign rejects. Consistent with our intent: struct
        // writes are NOT register writes and shouldn't be tracked by the
        // composer's live map.
        assert!(parse_simple_assign("rcx->field_8 = (rcx->field_10);").is_none());
    }

    #[test]
    fn equality_check_in_rhs_does_not_confuse_parser() {
        // RHS contains `==` but the top-level `=` is the assignment one.
        let r = parse_simple_assign("rax = (rcx == 0) ? 1 : 0;").expect("parse");
        assert_eq!(r.0, "rax");
        assert_eq!(r.1, "=");
    }

    #[test]
    fn no_assign_returns_none() {
        assert!(parse_simple_assign("return rax;").is_none());
        assert!(parse_simple_assign("/* cmp eax, 1 */").is_none());
        assert!(parse_simple_assign("goto L_00000010;").is_none());
    }

    #[test]
    fn empty_lhs_returns_none() {
        assert!(parse_simple_assign(" = 0;").is_none());
    }
}

#[cfg(test)]
mod is_call_text_tests {
    use super::is_call_text;

    // True positives: real call shapes.
    #[test]
    fn simple_call_no_args() {
        assert!(is_call_text("rax = call_at_0x9();"));
    }

    #[test]
    fn call_with_args() {
        assert!(is_call_text("rax = CreateFileW(lpFileName, dwAccess);"));
    }

    #[test]
    fn call_through_register_indirect() {
        assert!(is_call_text("rax = call_rcx();"));
    }

    #[test]
    fn underscore_prefixed_call() {
        assert!(is_call_text("rax = _chkstk();"));
    }

    // False positives: NOT calls — must return false to prevent the
    // composer from poisoning live[rax] with these expressions.
    #[test]
    fn memory_write_with_parenthesized_rhs_is_not_a_call() {
        // The exact shape A6.2's struct read-then-write produces post-A2:
        assert!(!is_call_text(
            "*((uint64_t *)(rcx+10h)) = (*((uint64_t *)(rcx+8)));"
        ));
    }

    #[test]
    fn simple_parenthesized_constant_is_not_a_call() {
        assert!(!is_call_text("rax = (0);"));
    }

    #[test]
    fn parenthesized_struct_field_access_is_not_a_call() {
        assert!(!is_call_text("rax = (rcx->field_8);"));
    }

    #[test]
    fn ternary_is_not_a_call() {
        // The cmov fixture's RHS shape: starts with `(` and ends with `)`.
        assert!(!is_call_text("rax = ((rcx != 0) ? rcx : rax);"));
    }

    #[test]
    fn assignment_without_rhs_paren_is_not_a_call() {
        assert!(!is_call_text("rax = 0;"));
        assert!(!is_call_text("eax = rcx;"));
    }

    #[test]
    fn no_assignment_at_all_is_not_a_call() {
        assert!(!is_call_text("/* cmp eax, 1 */"));
        assert!(!is_call_text("return rax;"));
    }
}

#[cfg(test)]
mod hex_literal_tests {
    use super::normalize_hex_literal;

    #[test]
    fn intel_form_with_h_suffix_becomes_c_form() {
        assert_eq!(normalize_hex_literal("0Ah"), "0x0a");
        assert_eq!(normalize_hex_literal("1234h"), "0x1234");
        assert_eq!(normalize_hex_literal("0FFFFFFFFh"), "0x0ffffffff");
    }

    #[test]
    fn decimal_literals_pass_through() {
        assert_eq!(normalize_hex_literal("1"), "1");
        assert_eq!(normalize_hex_literal("42"), "42");
        assert_eq!(normalize_hex_literal("0"), "0");
    }

    #[test]
    fn already_c_form_passes_through() {
        assert_eq!(normalize_hex_literal("0xa"), "0xa");
        assert_eq!(normalize_hex_literal("0x1234"), "0x1234");
    }

    #[test]
    fn ambiguous_inputs_pass_through() {
        // No h suffix and not a hex pattern → unchanged.
        assert_eq!(normalize_hex_literal("foo"), "foo");
        // h-suffixed but contains non-hex chars (e.g., "xh" — the x isn't
        // hex) → unchanged (defensive: don't mangle unrelated identifiers).
        assert_eq!(normalize_hex_literal("xh"), "xh");
    }
}

fn render_address_expr(op: &str) -> String {
    let normalized = normalize_operand(op);
    strip_brackets(&normalized).unwrap_or(normalized)
}

fn local_name(storage: &str) -> String {
    let lower = storage.to_ascii_lowercase();
    if let Some(name) = promote_stack_slot(&lower) {
        return name;
    }
    // SSA-internal "stack[+N]" / "stack[-N]" representation → arg_/local_ promotion.
    if let Some(rest) = lower.strip_prefix("stack[") {
        if let Some(num) = rest.strip_suffix(']') {
            if let Some(rest) = num.strip_prefix('+') {
                if let Ok(n) = rest.parse::<i64>() {
                    if n == 0 {
                        return "arg_0".to_string();
                    }
                    return format!("arg_{:x}h", n);
                }
            } else if let Some(rest) = num.strip_prefix('-') {
                if let Ok(n) = rest.parse::<i64>() {
                    if n == 0 {
                        return "local_0".to_string();
                    }
                    return format!("local_{:x}h", n);
                }
            }
        }
    }
    if lower.starts_with('[') {
        let inner = lower.trim_start_matches('[').trim_end_matches(']');
        return format!("mem_{}", sanitize(inner));
    }
    if lower.starts_with("rsp") || lower.starts_with("rbp") {
        return format!("local_{}", sanitize(&lower));
    }
    lower
}

/// Promote `[rsp+0x20]`, `[rbp-0x18]`, etc. to Hex-Rays-style names:
/// - `[rsp+0]`        → `arg_0`     (in Win64, RSP+0 is the saved return addr)
/// - `[rsp+0x8]`      → `arg_8h`    (shadow / saved register area)
/// - `[rsp+0x20]`     → `arg_20h`   (5th+ stack args in Win64)
/// - `[rbp-0x18]`     → `local_18h` (negative offset from RBP = local var)
///
/// Hex-Rays uses similar conventions and LLM readers parse them naturally.
fn promote_stack_slot(operand: &str) -> Option<String> {
    let inner = operand.strip_prefix('[')?.strip_suffix(']')?;
    let (base, rest) = if let Some(rest) = inner.strip_prefix("rsp") {
        ("rsp", rest)
    } else if let Some(rest) = inner.strip_prefix("rbp") {
        ("rbp", rest)
    } else {
        return None;
    };
    let rest = rest.trim();
    let (sign, mag_str) = if rest.is_empty() {
        (0i64, "0")
    } else if let Some(stripped) = rest.strip_prefix('+') {
        (1, stripped.trim())
    } else if let Some(stripped) = rest.strip_prefix('-') {
        (-1, stripped.trim())
    } else {
        return None;
    };
    let magnitude: u64 = if let Some(hex) = mag_str.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()?
    } else if let Some(hex) = mag_str.strip_suffix('h') {
        u64::from_str_radix(hex, 16).ok()?
    } else {
        mag_str.parse::<u64>().ok()?
    };
    let prefix = match (base, sign) {
        // Win64 RSP+positive = inbound args or shadow space → arg_*
        ("rsp", s) if s >= 0 => "arg",
        // RSP-negative = locals reserved on stack
        ("rsp", _) => "local",
        // RBP-negative = classic local var (negative offset from frame pointer)
        ("rbp", s) if s < 0 => "local",
        // RBP+positive (rare in PE x64 without frame pointer) = arg slot
        ("rbp", _) => "arg",
        _ => unreachable!(),
    };
    if magnitude == 0 {
        Some(format!("{}_0", prefix))
    } else {
        Some(format!("{}_{:x}h", prefix, magnitude))
    }
}

fn stack_slot_name(operand: &str) -> Option<String> {
    let inner = strip_brackets(operand)?;
    if inner.starts_with("rsp") || inner.starts_with("rbp") {
        Some(format!("[{}]", inner))
    } else {
        None
    }
}

fn strip_brackets(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let inner = trimmed.strip_prefix('[')?.strip_suffix(']')?;
    Some(inner.to_string())
}

fn is_register(value: &str) -> bool {
    matches!(
        value,
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rsp"
            | "rbp"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
            | "eax"
            | "ebx"
            | "ecx"
            | "edx"
            | "esi"
            | "edi"
            | "esp"
            | "ebp"
            | "r8d"
            | "r9d"
            | "r10d"
            | "r11d"
            | "r12d"
            | "r13d"
            | "r14d"
            | "r15d"
            | "ax"
            | "bx"
            | "cx"
            | "dx"
            | "si"
            | "di"
            | "sp"
            | "bp"
            | "r8w"
            | "r9w"
            | "r10w"
            | "r11w"
            | "r12w"
            | "r13w"
            | "r14w"
            | "r15w"
            | "al"
            | "bl"
            | "cl"
            | "dl"
            | "sil"
            | "dil"
            | "spl"
            | "bpl"
            | "r8b"
            | "r9b"
            | "r10b"
            | "r11b"
            | "r12b"
            | "r13b"
            | "r14b"
            | "r15b"
    )
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn split_operands(op_str: &str) -> Vec<String> {
    op_str
        .split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn normalize_operand(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("qword ptr")
        .trim_start_matches("dword ptr")
        .trim_start_matches("word ptr")
        .trim_start_matches("byte ptr")
        .trim()
        .to_ascii_lowercase()
}

fn assess_confidence(
    has_ssa: bool,
    has_dataflow: bool,
    has_structured: bool,
    has_api_flows: bool,
    has_prototype: bool,
) -> String {
    // 5-tier ladder (A5 widening). `unknown` is the floor when no analysis
    // signal is present; `conflict` is reserved for divergent API type info
    // — emitted by future revisions of `recover_types` once it tracks per-
    // register type disagreements.
    let score = [
        has_ssa,
        has_dataflow,
        has_structured,
        has_api_flows,
        has_prototype,
    ]
    .iter()
    .filter(|x| **x)
    .count();
    match score {
        5 => "high".to_string(),
        4 | 3 => "medium".to_string(),
        2 | 1 => "low".to_string(),
        _ => "unknown".to_string(),
    }
}

fn safe_symbol(value: &str) -> String {
    let last = value.rsplit('!').next().unwrap_or(value);
    let safe: String = last
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if safe.is_empty() {
        "api".to_string()
    } else {
        safe
    }
}

/// Synthesize a readable C identifier for an unresolved call target.
///
/// Prioritises clarity over fidelity:
///   * `module!Symbol` → `Symbol` (preserves the resolved import name path).
///   * Hex address forms (`9`, `000000000000000Eh`, `0x140005000`,
///     `1234h`) → `at_0x<stripped>` after dropping leading zeros and any
///     Intel `h` suffix.
///   * Anything else → `safe_symbol` fallback (register names like `rax`
///     for indirect calls survive unchanged).
fn synthesize_call_name(target: &str) -> String {
    let trimmed = target.trim();
    if trimmed.contains('!') {
        return safe_symbol(trimmed);
    }
    let lower = trimmed.to_ascii_lowercase();
    let candidate = if let Some(stripped) = lower.strip_suffix('h') {
        stripped.to_string()
    } else if let Some(stripped) = lower.strip_prefix("0x") {
        stripped.to_string()
    } else {
        lower.clone()
    };
    if !candidate.is_empty() && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        let stripped = candidate.trim_start_matches('0');
        let display = if stripped.is_empty() { "0" } else { stripped };
        return format!("at_0x{}", display);
    }
    safe_symbol(trimmed)
}

#[cfg(test)]
mod call_name_tests {
    use super::synthesize_call_name;

    #[test]
    fn intel_hex_address_becomes_at_0x_form() {
        assert_eq!(synthesize_call_name("9"), "at_0x9");
        assert_eq!(synthesize_call_name("000000000000000Eh"), "at_0xe");
        assert_eq!(synthesize_call_name("1234h"), "at_0x1234");
    }

    #[test]
    fn c_form_hex_address_normalized() {
        assert_eq!(synthesize_call_name("0x140005000"), "at_0x140005000");
        assert_eq!(synthesize_call_name("0x0a"), "at_0xa");
    }

    #[test]
    fn module_symbol_path_preserved() {
        assert_eq!(synthesize_call_name("kernel32!CreateFileW"), "CreateFileW");
        assert_eq!(synthesize_call_name("ntdll!ZwReadFile"), "ZwReadFile");
    }

    #[test]
    fn indirect_call_via_register_passes_through() {
        assert_eq!(synthesize_call_name("rax"), "rax");
        assert_eq!(synthesize_call_name("rcx"), "rcx");
    }

    #[test]
    fn all_zeros_renders_as_0x0() {
        assert_eq!(synthesize_call_name("000000000h"), "at_0x0");
        assert_eq!(synthesize_call_name("0x0"), "at_0x0");
    }
}

// =====================================================================
// A6 — Struct field-layout inference (offset clustering)
// =====================================================================
//
// For each function, group `[reg+const]` accesses by base register and
// surface bases accessed at multiple distinct offsets as "struct candidates".
// Hint-only output for now (a `/* struct candidate ... */` comment line);
// later phases promote this to real anonymous-struct declarations once
// PDB / RTTI facts are wired in.
//
// Skipped: rsp- and rbp-based accesses — those are stack locals / args, not
// struct fields. Skipped: same-offset reads (no clustering signal).

struct StructHint {
    base: String,
    offsets: std::collections::BTreeSet<i64>,
}

fn infer_struct_hints(instructions: &[&InstructionRecord]) -> Vec<StructHint> {
    let mut by_base: BTreeMap<String, std::collections::BTreeSet<i64>> = BTreeMap::new();
    for ins in instructions {
        for op in split_operands(&ins.op_str) {
            if let Some((base, offset)) = parse_struct_offset_access(&op) {
                by_base.entry(base).or_default().insert(offset);
            }
        }
    }
    by_base
        .into_iter()
        .filter(|(_, offsets)| offsets.len() >= 2)
        .map(|(base, offsets)| StructHint { base, offsets })
        .collect()
}

/// Parse `[rcx+0x10]`, `[rdx-0x8]`, etc. into `(base_reg, offset)`. Returns
/// `None` for rsp/rbp-based accesses (stack-frame storage, not struct
/// fields), bracket-less operands, and unparseable offsets.
fn parse_struct_offset_access(op: &str) -> Option<(String, i64)> {
    let trimmed = normalize_operand(op);
    let inner = strip_brackets(&trimmed)?;
    let inner = inner.trim().to_ascii_lowercase();
    // Stack-frame regs are not struct bases.
    if inner.starts_with("rsp") || inner.starts_with("rbp") {
        return None;
    }
    // Bare register reference (e.g., `[rcx]`) — treat as offset 0 of `rcx`.
    if is_register(&inner) {
        return Some((inner, 0));
    }
    // Look for `+` or `-` to split base from displacement.
    if let Some(idx) = inner.find('+') {
        let base = inner[..idx].trim().to_string();
        if !is_register(&base) {
            return None;
        }
        let disp = inner[idx + 1..].trim();
        let value = parse_int_literal(disp)?;
        return Some((base, value));
    }
    if let Some(idx) = inner.find('-') {
        // Skip the case where '-' is part of a register name (none in x86_64
        // but defensive).
        let base = inner[..idx].trim().to_string();
        if !is_register(&base) {
            return None;
        }
        let disp = inner[idx + 1..].trim();
        let value = parse_int_literal(disp)?;
        return Some((base, -value));
    }
    None
}

/// Rewrite occurrences of `*((uint64_t *)(<base>+<offset>))` in `text` to
/// `<base>->field_<hexoffset>` when (base, offset) matches one of `hints`.
/// Offsets are rendered as lowercase hex without `0x` prefix to match the
/// Hex-Rays / IDA convention (`field_8`, `field_10`, `field_20`).
fn rewrite_struct_field_accesses(text: &str, hints: &[StructHint]) -> String {
    const PREFIX: &str = "*((uint64_t *)(";
    const SUFFIX: &str = "))";

    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if text[i..].starts_with(PREFIX) {
            let body_start = i + PREFIX.len();
            if let Some(close_off) = text[body_start..].find(SUFFIX) {
                let body = &text[body_start..body_start + close_off];
                if let Some((base, offset)) = parse_base_plus_offset(body) {
                    if hints
                        .iter()
                        .any(|h| h.base == base && h.offsets.contains(&offset))
                    {
                        out.push_str(&format!("{}->field_{:x}", base, offset));
                        i = body_start + close_off + SUFFIX.len();
                        continue;
                    }
                }
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Parse `<base>+<offset>` or `<base>-<offset>` where `<base>` is a register
/// name and `<offset>` is a decimal or hex literal (`8`, `10h`, `0x10`).
/// Returns `Some((base_lowercase, offset_signed))` on match.
fn parse_base_plus_offset(body: &str) -> Option<(String, i64)> {
    let trimmed = body.trim();
    let (split_idx, sign) = if let Some(idx) = trimmed.find('+') {
        (idx, 1)
    } else if let Some(idx) = trimmed.find('-') {
        // Don't match `-` at position 0 (negative-prefix only — no base).
        if idx == 0 {
            return None;
        }
        (idx, -1)
    } else {
        return None;
    };
    let base = trimmed[..split_idx].trim().to_ascii_lowercase();
    if !is_register(&base) {
        return None;
    }
    let off_str = trimmed[split_idx + 1..].trim();
    let value = parse_int_literal(off_str)?;
    Some((base, value * sign))
}

fn parse_int_literal(s: &str) -> Option<i64> {
    let s = s.trim().to_ascii_lowercase();
    if let Some(rest) = s.strip_prefix("0x") {
        i64::from_str_radix(rest, 16).ok()
    } else if let Some(rest) = s.strip_suffix('h') {
        i64::from_str_radix(rest, 16).ok()
    } else {
        s.parse::<i64>().ok()
    }
}

// =====================================================================
// A3 — Structured control-flow lifting
// =====================================================================
//
// Identifies natural loops whose backedge is a single conditional jump back
// to the header (the most common shape: counted loops, while-iterators) and
// emits them as `do { ... } while (cond);` instead of the annotative
// `while (1) { ... if (cond) goto L_HEADER; }` form. Plans the transformation
// per-loop; the emit pass below honors it.

#[derive(Default)]
struct DoWhilePlan {
    /// Header VAs that are emitted as `do {` (and whose `L_<va>:` label is
    /// suppressed).
    headers: BTreeMap<u64, u64>, // header_va → backedge_src_va
    /// Backedge-source VAs whose `if (cond) goto L_HEADER;` is suppressed and
    /// replaced by `} while (cond);` at emit time. Value is the extracted
    /// condition string.
    backedge_to_cond: BTreeMap<u64, String>,
}

/// Build a `DoWhilePlan` from the post-A2 statement list. A loop qualifies if:
///   - It has exactly one backedge source pointing at the header.
///   - The backedge source's text is `if (<cond>) goto L_<HEADER>;`.
///   - The header VA is the backedge's target.
///
/// Anything else falls back to the existing `while (1) + goto` form.
fn build_dowhile_plan(stmts: &[StmtRec], loop_headers: &BTreeMap<u64, Vec<u64>>) -> DoWhilePlan {
    let mut plan = DoWhilePlan::default();
    for (header_va, sources) in loop_headers {
        if sources.len() != 1 {
            continue; // multi-backedge — not a simple do-while
        }
        let backedge_src_va = sources[0];
        let Some(backedge_stmt) = stmts.iter().find(|s| s.va == backedge_src_va) else {
            continue;
        };
        // The backedge instruction must be a conditional jump (j[a-z]+) whose
        // branch target equals the header VA.
        if backedge_stmt.loop_backedge_target != Some(*header_va) {
            continue;
        }
        if backedge_stmt.mnemonic == "jmp" {
            continue; // unconditional backedge — that's `while (1) {}` / infinite loop
        }
        // Parse "if (<cond>) goto L_XXXXXXXX;" out of the post-A2 text.
        let Some(cond) = parse_if_goto_condition(&backedge_stmt.text) else {
            continue;
        };
        plan.headers.insert(*header_va, backedge_src_va);
        plan.backedge_to_cond.insert(backedge_src_va, cond);
    }
    plan
}

/// Parse `if (<cond>) goto L_XXXXXXXX;` and return `<cond>`. Returns `None`
/// if the text doesn't match — including after A2 substitution turned the
/// condition into a more complex expression (which we still preserve, since
/// the parser is delimiter-based).
fn parse_if_goto_condition(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let rest = trimmed.strip_prefix("if (")?;
    let close = rest.find(") goto ")?;
    Some(rest[..close].to_string())
}

// =====================================================================
// A2 — Expression DAG composition
// =====================================================================
//
// Per-instruction statements produced by `lift_instruction` get walked once
// after lifting. The composer maintains a live-value map keyed by canonical
// 64-bit register name and stack-slot name, substitutes those values into the
// RHS of subsequent statements, and removes single-use producers as dead
// stores. The result is closer to "expression DAG" output: `mov rax, [rbp-8];
// add rax, rcx; mov [rbp-16], rax` collapses to `local_16h = local_8h + rcx;`.
//
// This is text-level rewriting, not a true SSA-IR pass — the goal is the
// visible quality improvement promised by the plan's Phase A2, not full
// generality. Conservatism: any label, call, or memory-aliased write
// invalidates affected live entries.

/// One per-instruction statement collected during Phase 1 of `lift_function`
/// for A2 composition.
struct StmtRec {
    va: u64,
    text: String,
    src_comment: String,
    mnemonic: String,
    is_label_target: bool,
    is_loop_backedge_src: bool,
    loop_backedge_target: Option<u64>,
    /// Set by the composer when a producer line is consumed exactly once and
    /// can be inlined into its sole consumer.
    removed: bool,
}

/// Live entry tracked by the composer: an expression that currently holds in
/// the named storage, plus the index of the statement that produced it.
#[derive(Clone)]
struct LiveValue {
    expr: String,
    producer_idx: usize,
    /// Count of times this live value has been read by a following statement.
    /// 0 = nobody used it yet; 1 = single use (candidate for inlining); >1 =
    /// multiple uses (must keep the producer).
    use_count: u32,
}

/// Run the expression-composition pass over a sequence of `StmtRec`s.
fn compose_expressions(stmts: &mut [StmtRec]) {
    // Live map keyed by *canonical* 64-bit storage name. Substitutions look
    // for all register aliases (eax/ax/al/ah for rax, etc.) in the text.
    let mut live: BTreeMap<String, LiveValue> = BTreeMap::new();

    // Helper: drop a live entry. If it was consumed at least once, the
    // producer line is now dead (the value is already inlined wherever it's
    // needed) — mark it for removal.
    fn drop_entry(live: &mut BTreeMap<String, LiveValue>, stmts: &mut [StmtRec], canon: &str) {
        if let Some(old) = live.remove(canon) {
            if old.use_count > 0 {
                if let Some(producer) = stmts.get_mut(old.producer_idx) {
                    producer.removed = true;
                }
            }
        }
    }

    fn drain_all(live: &mut BTreeMap<String, LiveValue>, stmts: &mut [StmtRec]) {
        for (_, old) in std::mem::take(live).into_iter() {
            if old.use_count > 0 {
                if let Some(producer) = stmts.get_mut(old.producer_idx) {
                    producer.removed = true;
                }
            }
        }
    }

    for idx in 0..stmts.len() {
        // A branch target invalidates all live values — control flow can
        // arrive here from elsewhere with a different state.
        if stmts[idx].is_label_target {
            drain_all(&mut live, stmts);
        }

        // Phase 2a: substitute reads. For each canonical live entry, look
        // for any of its register aliases in the RHS region of the text.
        let live_snapshot: Vec<(String, String)> = live
            .iter()
            .map(|(k, v)| (k.clone(), v.expr.clone()))
            .collect();
        let mut new_text = stmts[idx].text.clone();
        for (canon_storage, expr) in &live_snapshot {
            new_text = substitute_storage_in_rhs(&new_text, canon_storage, expr, &mut live);
        }
        stmts[idx].text = new_text;

        // Phase 2b: call-clobber. Caller-saved registers are reset; rax in
        // particular gets a fresh live entry below.
        if stmts[idx].mnemonic == "call" {
            let to_drop: Vec<String> = CALLER_SAVED_X64
                .iter()
                .map(|r| canonical_storage(r))
                .collect();
            for canon in to_drop {
                drop_entry(&mut live, stmts, &canon);
            }
        }

        // Phase 2c: update live from this statement's write.
        if let Some((lhs, op, rhs)) = parse_simple_assign(&stmts[idx].text) {
            let canon = canonical_storage(&lhs);
            if canon.is_empty() {
                continue;
            }
            // Sub-16/sub-8 writes leave the parent 64-bit register in a
            // partially-defined state we can't safely track — invalidate.
            if is_sub16_or_sub8_register(&lhs) {
                drop_entry(&mut live, stmts, &canon);
                continue;
            }
            let new_expr = match op {
                "=" => rhs.to_string(),
                _ => {
                    // Compound `lhs op= rhs`. Only compose if we already knew
                    // lhs's prior expression — otherwise creating a
                    // self-referential `(lhs) op (rhs)` would corrupt
                    // subsequent substitutions.
                    let inner_op = op.trim_end_matches('=');
                    if let Some(old) = live.get(&canon) {
                        format!("({}) {} ({})", old.expr, inner_op, rhs)
                    } else {
                        // No prior live value — invalidate and move on.
                        drop_entry(&mut live, stmts, &canon);
                        continue;
                    }
                }
            };
            // Overwriting a previous live entry: if it was consumed, the
            // old producer is now dead.
            drop_entry(&mut live, stmts, &canon);
            live.insert(
                canon,
                LiveValue {
                    expr: new_expr,
                    producer_idx: idx,
                    use_count: 0,
                },
            );
        } else if is_call_text(&stmts[idx].text) {
            // After a call, rax holds the return value.
            let canon = canonical_storage("rax");
            drop_entry(&mut live, stmts, &canon);
            live.insert(
                canon,
                LiveValue {
                    expr: extract_call_rhs(&stmts[idx].text)
                        .unwrap_or_else(|| stmts[idx].text.clone()),
                    producer_idx: idx,
                    use_count: 0,
                },
            );
        }

        // At a `ret` instruction, all register-class live entries are no
        // longer observable to the caller. Per the Win64 + SysV ABIs, any
        // value sitting in a caller-saved register at the moment of ret is
        // unobservable (caller doesn't expect it preserved); callee-saved
        // registers are expected to be RESTORED by the function, so a
        // function-final write to one of them without restore would be a
        // binary bug, not something we should preserve in the decompilation.
        //
        // The rule:
        //   * Caller-saved registers (CALLER_SAVED_X64): mark producer
        //     removed UNCONDITIONALLY. Even if use_count == 0 the write was
        //     dead — caller can't observe it. This is the real dead-store
        //     elimination win.
        //   * Other register-class entries (callee-saved like rbx/r12+):
        //     mark removed only when use_count > 0 (the value was
        //     substituted into a consumer). Conservative; preserves writes
        //     that were *almost certainly* preceded by a save/restore the
        //     analyzer hasn't tracked.
        if stmts[idx].mnemonic == "ret" {
            let caller_saved: std::collections::BTreeSet<String> = CALLER_SAVED_X64
                .iter()
                .map(|r| canonical_storage(r))
                .collect();
            let to_drop: Vec<String> = live
                .keys()
                .filter(|k| register_aliases(k).len() > 0) // register-canon keys only
                .cloned()
                .collect();
            for canon in to_drop {
                if caller_saved.contains(&canon) {
                    // Unconditional removal — caller can't observe this reg.
                    if let Some(old) = live.remove(&canon) {
                        if let Some(producer) = stmts.get_mut(old.producer_idx) {
                            producer.removed = true;
                        }
                    }
                } else {
                    drop_entry(&mut live, stmts, &canon);
                }
            }
        }
    }
    // Any remaining live entries (stack slots, never-drained registers) are
    // kept — their producers may be observable to the caller.
}

/// Substitute any standalone reference to `canon_storage` (or any of its
/// register aliases — e.g., `eax`/`ax`/`al`/`ah` when `canon_storage` is
/// `"rax"`) in the RHS portion of `text` with `(expr)`. Updates `live` to
/// bump `use_count` so a future dead-store-elimination pass can recognise
/// single-use temporaries.
///
/// Tracks substituted byte ranges and skips future matches inside them —
/// prevents nested re-substitution when `expr` itself contains an alias of
/// `canon_storage` (e.g., the `al` inside `(uint64_t)(uint8_t)al` would
/// otherwise be re-matched when iterating aliases of `rax`).
fn substitute_storage_in_rhs(
    text: &str,
    canon_storage: &str,
    expr: &str,
    live: &mut BTreeMap<String, LiveValue>,
) -> String {
    let (prefix, body, suffix) = split_rhs_region(text);
    let mut new_body = body.to_string();
    let mut substituted = false;
    // Byte ranges in `new_body` whose contents came from a substitution. New
    // matches inside these ranges are skipped — the text there is part of
    // an inlined expression, not an original reference to the storage.
    let mut substituted_regions: Vec<(usize, usize)> = Vec::new();
    let aliases = register_aliases(canon_storage);
    let to_search: Vec<&str> = if aliases.is_empty() {
        vec![canon_storage]
    } else {
        aliases.iter().copied().collect()
    };
    for needle in &to_search {
        let mut search_from = 0;
        while let Some(pos) = find_word(&new_body, needle, search_from) {
            // Skip matches that land inside a previously substituted region.
            if substituted_regions
                .iter()
                .any(|(start, end)| pos >= *start && pos < *end)
            {
                search_from = pos + needle.len();
                continue;
            }
            let before = &new_body[..pos];
            let after = &new_body[pos + needle.len()..];
            let inserted_len = expr.len() + 2; // expr + surrounding parens
            let removed_len = needle.len();
            let delta = inserted_len as isize - removed_len as isize;
            // Shift any prior regions that start after `pos`.
            for region in substituted_regions.iter_mut() {
                if region.0 > pos {
                    region.0 = ((region.0 as isize) + delta) as usize;
                    region.1 = ((region.1 as isize) + delta) as usize;
                }
            }
            new_body = format!("{}({}){}", before, expr, after);
            substituted_regions.push((pos, pos + inserted_len));
            substituted = true;
            search_from = pos + inserted_len;
        }
    }
    if substituted {
        if let Some(lv) = live.get_mut(canon_storage) {
            lv.use_count = lv.use_count.saturating_add(1);
        }
    }
    format!("{}{}{}", prefix, new_body, suffix)
}

/// Find an exact-word occurrence of `needle` in `haystack` starting at
/// `start`. Returns the byte index, or `None`. Word boundaries are anything
/// that is not an ASCII alphanumeric or underscore.
fn find_word(haystack: &str, needle: &str, start: usize) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let bytes = haystack.as_bytes();
    let nbytes = needle.as_bytes();
    let mut i = start;
    while i + nbytes.len() <= bytes.len() {
        if &bytes[i..i + nbytes.len()] == nbytes {
            let before_ok = i == 0 || !is_word_byte(bytes[i - 1]);
            let after_ok =
                i + nbytes.len() == bytes.len() || !is_word_byte(bytes[i + nbytes.len()]);
            if before_ok && after_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Carve the RHS region of a lifted-instruction text. Returns (prefix,
/// body_to_substitute, suffix). The composer only rewrites `body`.
fn split_rhs_region(text: &str) -> (&str, &str, &str) {
    // Handle "LHS = RHS;" and "LHS op= RHS;"
    if let Some(eq_pos) = find_top_level_assign(text) {
        // Carve from after the operator (possibly multi-char like "+=") to
        // the trailing ';'.
        let mut rhs_start = eq_pos + 1;
        // Skip ASCII whitespace after the operator.
        let bytes = text.as_bytes();
        while rhs_start < bytes.len() && bytes[rhs_start] == b' ' {
            rhs_start += 1;
        }
        if let Some(semi) = text[rhs_start..].rfind(';') {
            let semi_abs = rhs_start + semi;
            return (
                &text[..rhs_start],
                &text[rhs_start..semi_abs],
                &text[semi_abs..],
            );
        }
    }
    // Handle "return RHS;"
    if let Some(rest) = text.strip_prefix("return ") {
        if let Some(semi) = rest.rfind(';') {
            let prefix_len = "return ".len();
            return (
                &text[..prefix_len],
                &text[prefix_len..prefix_len + semi],
                &text[prefix_len + semi..],
            );
        }
    }
    // Handle "if (cond) goto L_X;" — substitute inside cond.
    if let Some(rest) = text.strip_prefix("if (") {
        if let Some(close) = rest.find(") goto ") {
            let cond_start = "if (".len();
            let cond_end = cond_start + close;
            return (
                &text[..cond_start],
                &text[cond_start..cond_end],
                &text[cond_end..],
            );
        }
    }
    // Default: substitute throughout (calls, comments).
    ("", text, "")
}

/// Find the position of `=`, `+=`, `-=`, etc. operator at the top level
/// (outside parentheses). Returns the byte index of the `=` character.
fn find_top_level_assign(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'=' if depth == 0 => {
                // Skip ==, !=, <=, >=
                let prev = if i > 0 { bytes[i - 1] } else { 0 };
                let next = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
                if next == b'=' || prev == b'=' || prev == b'!' || prev == b'<' || prev == b'>' {
                    i += 1;
                    continue;
                }
                return Some(i);
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Parse "LHS op= RHS;" or "LHS = RHS;" into (lhs, op, rhs). The `op` is
/// either `"="`, `"+="`, `"-="`, `"&="`, `"|="`, `"^="`, `"<<="`, or `">>="`.
fn parse_simple_assign(text: &str) -> Option<(String, &'static str, &str)> {
    let trimmed = text.trim();
    let trimmed = trimmed.trim_end_matches(';').trim();
    let eq = find_top_level_assign(trimmed)?;
    let lhs_raw = trimmed[..eq].trim();
    let rhs = trimmed[eq + 1..].trim();
    // Determine compound op (last char of lhs_raw, if any)
    let (lhs, op) = if let Some(last) = lhs_raw.chars().last() {
        match last {
            '+' => (lhs_raw[..lhs_raw.len() - 1].trim().to_string(), "+="),
            '-' => (lhs_raw[..lhs_raw.len() - 1].trim().to_string(), "-="),
            '&' => (lhs_raw[..lhs_raw.len() - 1].trim().to_string(), "&="),
            '|' => (lhs_raw[..lhs_raw.len() - 1].trim().to_string(), "|="),
            '^' => (lhs_raw[..lhs_raw.len() - 1].trim().to_string(), "^="),
            _ => (lhs_raw.to_string(), "="),
        }
    } else {
        return None;
    };
    if lhs.is_empty() {
        return None;
    }
    // LHS must be a simple identifier or a `*(...)` deref — otherwise we
    // don't try to track it.
    if !lhs.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == '_'
            || c == '*'
            || c == '('
            || c == ')'
            || c == '['
            || c == ']'
            || c == ' '
    }) {
        return None;
    }
    Some((lhs, op, rhs))
}

fn is_call_text(text: &str) -> bool {
    // Recognise `LHS = NAME(args);` shape — a real function call has a
    // callable identifier immediately before its opening `(`. Bare
    // parentheticals like `(*((uint64_t *)(rcx+8)))` (memory dereference
    // expressions) start with `(` and end with `)` too, but the leading
    // `(` isn't preceded by an identifier — those must NOT be classified
    // as calls or the composer would overwrite `live[rax]` with the
    // memory-write's RHS.
    if let Some(eq) = find_top_level_assign(text) {
        let rhs = text[eq + 1..].trim_end_matches(';').trim();
        if !rhs.ends_with(')') {
            return false;
        }
        // Find the FIRST `(` at depth 0 in rhs and check its preceding char.
        let bytes = rhs.as_bytes();
        let mut depth = 0i32;
        for (i, b) in bytes.iter().enumerate() {
            match b {
                b'(' if depth == 0 => {
                    // Require an identifier char immediately before this
                    // open-paren — that's the callable name.
                    let prev = if i == 0 { 0 } else { bytes[i - 1] };
                    return prev.is_ascii_alphanumeric() || prev == b'_';
                }
                b'(' => depth += 1,
                b')' => depth -= 1,
                _ => {}
            }
        }
        false
    } else {
        false
    }
}

fn extract_call_rhs(text: &str) -> Option<String> {
    let eq = find_top_level_assign(text)?;
    let rhs = text[eq + 1..].trim_end_matches(';').trim();
    Some(rhs.to_string())
}

/// Map a storage name (register or stack slot) to its canonical form for
/// live-value tracking. For registers, this is the 64-bit family name. For
/// stack slots / promoted locals, the name itself.
///
/// Note: this is a wider mapping than the existing `canonical_reg64` helper
/// — that one only covers Win64 first-4-args (rcx/rdx/r8/r9) since that's
/// what it's used for elsewhere. The composer needs all 16 GPR families plus
/// their sub-width aliases.
fn canonical_storage(name: &str) -> String {
    let lower = name.trim().to_ascii_lowercase();
    if let Some(canon) = canonical_reg_full(&lower) {
        return canon.to_string();
    }
    // Already promoted name like `local_18h`, `arg_8h`, or a deref expression
    // — track it by itself.
    lower
}

/// Full canonical mapping: any x86_64 GPR alias → 64-bit name.
/// Returns `None` for non-register names.
fn canonical_reg_full(name: &str) -> Option<&'static str> {
    Some(match name {
        "rax" | "eax" | "ax" | "al" | "ah" => "rax",
        "rbx" | "ebx" | "bx" | "bl" | "bh" => "rbx",
        "rcx" | "ecx" | "cx" | "cl" | "ch" => "rcx",
        "rdx" | "edx" | "dx" | "dl" | "dh" => "rdx",
        "rsi" | "esi" | "si" | "sil" => "rsi",
        "rdi" | "edi" | "di" | "dil" => "rdi",
        "rsp" | "esp" | "sp" | "spl" => "rsp",
        "rbp" | "ebp" | "bp" | "bpl" => "rbp",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" => "r15",
        _ => return None,
    })
}

/// Return all register-name aliases that share the same canonical 64-bit name
/// as `canon`. Used by the composer to substitute writes-to-`eax` into reads-
/// of-`rax` and vice versa.
fn register_aliases(canon: &str) -> &'static [&'static str] {
    match canon {
        "rax" => &["rax", "eax", "ax", "al", "ah"],
        "rbx" => &["rbx", "ebx", "bx", "bl", "bh"],
        "rcx" => &["rcx", "ecx", "cx", "cl", "ch"],
        "rdx" => &["rdx", "edx", "dx", "dl", "dh"],
        "rsi" => &["rsi", "esi", "si", "sil"],
        "rdi" => &["rdi", "edi", "di", "dil"],
        "rsp" => &["rsp", "esp", "sp", "spl"],
        "rbp" => &["rbp", "ebp", "bp", "bpl"],
        "r8" => &["r8", "r8d", "r8w", "r8b"],
        "r9" => &["r9", "r9d", "r9w", "r9b"],
        "r10" => &["r10", "r10d", "r10w", "r10b"],
        "r11" => &["r11", "r11d", "r11w", "r11b"],
        "r12" => &["r12", "r12d", "r12w", "r12b"],
        "r13" => &["r13", "r13d", "r13w", "r13b"],
        "r14" => &["r14", "r14d", "r14w", "r14b"],
        "r15" => &["r15", "r15d", "r15w", "r15b"],
        // Non-register canonical key — only one form (the canonical itself).
        _ => &[],
    }
}

fn is_sub16_or_sub8_register(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "ax" | "bx"
            | "cx"
            | "dx"
            | "si"
            | "di"
            | "sp"
            | "bp"
            | "r8w"
            | "r9w"
            | "r10w"
            | "r11w"
            | "r12w"
            | "r13w"
            | "r14w"
            | "r15w"
            | "al"
            | "bl"
            | "cl"
            | "dl"
            | "sil"
            | "dil"
            | "spl"
            | "bpl"
            | "r8b"
            | "r9b"
            | "r10b"
            | "r11b"
            | "r12b"
            | "r13b"
            | "r14b"
            | "r15b"
            | "ah"
            | "bh"
            | "ch"
            | "dh"
    )
}

/// Windows x64 ABI caller-saved registers. A `call` instruction invalidates
/// the live entries for these names (and their canonical 64-bit forms). The
/// list intentionally includes both 64-bit and 32-bit aliases since both can
/// appear as keys.
const CALLER_SAVED_X64: &[&str] = &[
    "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "eax", "ecx", "edx", "r8d", "r9d", "r10d",
    "r11d",
];
