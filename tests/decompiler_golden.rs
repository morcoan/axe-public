//! Golden-file regression harness for the C decompiler — Phase A1 of the
//! Hex-Rays-parity uplift roadmap (`~/.claude/plans/zesty-shimmying-puddle.md`).
//!
//! The harness pins the current decompiler output against checked-in expected
//! files under `tests/fixtures/decompiler/`. Subsequent phases (A2-A11) update
//! the goldens as they intentionally change output shape, so unintentional
//! regressions in *other* fixtures are caught immediately.
//!
//! Fixtures are synthesized at test time via `object::write` (matching the
//! `tests/multi_format.rs` idiom) — no checked-in binary files.
//!
//! Set `BLESS=1` in the environment to regenerate the expected files instead
//! of asserting equality. Use this when an intentional decompiler change lands
//! and reviewer-acked output shifts are expected.
//!
//! Example: `BLESS=1 cargo test --test decompiler_golden`

use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

/// Options that mirror `tests/multi_format.rs::default_options()` but with
/// `decompile_c` flipped from `"off"` to `"selected"` so the C emitter
/// actually runs. `capability_profile` stays at `"native-max"` because
/// `c_decompiler::build_decompiled_c` gates on `input.profile == "native-max"`.
fn options_with_decompile_selected() -> axe_core::AnalysisOptions {
    axe_core::AnalysisOptions {
        preset: None,
        max_strings: 64,
        max_functions: 32,
        max_xrefs: 256,
        deep: true,
        precomputed_sha256: None,
        native_inner_workers: None,
        profile_analysis: false,
        semantic_level: "basic".to_string(),
        second_pass: "auto".to_string(),
        semantic_budget: "normal".to_string(),
        semantic_focus: "malware".to_string(),
        wrapper_collapse_depth: 4,
        pseudo_ir: "basic".to_string(),
        capability_profile: "native-max".to_string(),
        portable_tools_dir: "tools".to_string(),
        emulation_budget: "normal".to_string(),
        fuzz_mode: "off".to_string(),
        fuzz_iterations: 0,
        trace_dir: None,
        decompile_c: "selected".to_string(),
        llm_artifacts: "all".to_string(),
        review_packs: "ranked".to_string(),
        decompile_source: "selected".to_string(),
        symbols: "basic".to_string(),
        symbol_packets: "ranked".to_string(),
        symbol_paths: Vec::new(),
        symbol_cache: None,
        progress_path: None,
        dynamic_trace_mode: "off".to_string(),
        dynamic_trace_duration_secs: 0,
        dynamic_trace_target: None,
        dynamic_trace_out: None,
        dynamic_trace_providers: String::new(),
        dynamic_trace_loss_policy: "partial".to_string(),
        vuln_discovery_mode: "off".to_string(),
        vuln_templates: "all".to_string(),
        vuln_confidence_threshold: 0.45,
        vuln_out: None,
        vuln_dynamic_confirmation: "off".to_string(),
        vuln_dynamic_evidence: Vec::new(),
        vuln_include_lifetime: false,
        vuln_harness_tier: "skeleton".to_string(),
        unpack_mode: "off".to_string(),
        unpack_tracer: "debug".to_string(),
        unpack_timeout_secs: 60,
        unpack_instr_budget: 100_000_000,
        unpack_out: None,
        unpack_hooks_disable: false,
        unpack_include_devirt: false,
    }
}

/// Build a minimal x86_64 ELF with `code` placed at the start of `.text` and
/// a single function symbol named `symbol_name` pointing at it.
fn synth_elf(path: &Path, code: &[u8], symbol_name: &[u8]) {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text_id = obj.section_id(StandardSection::Text);
    let offset = obj.append_section_data(text_id, code, 16);
    obj.add_symbol(Symbol {
        name: symbol_name.to_vec(),
        value: offset,
        size: code.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text_id),
        flags: SymbolFlags::None,
    });
    let bytes = obj.write().expect("serialize synthesized ELF");
    fs::write(path, bytes).expect("write synthesized ELF to disk");
}

/// Assert that `actual` matches the contents of `expected_path`. When the
/// `BLESS` env-var is set, instead overwrite `expected_path` with `actual`.
/// Used to regenerate goldens when intentional decompiler changes land.
fn assert_golden(actual: &str, expected_path: &Path) {
    if env::var_os("BLESS").is_some() {
        if let Some(parent) = expected_path.parent() {
            fs::create_dir_all(parent).expect("create golden parent dir");
        }
        fs::write(expected_path, actual).expect("write golden");
        eprintln!(
            "BLESS: wrote {} ({} bytes)",
            expected_path.display(),
            actual.len()
        );
        return;
    }
    let expected = fs::read_to_string(expected_path).unwrap_or_else(|err| {
        panic!(
            "missing golden at {}: {}.\n\
             Run `BLESS=1 cargo test --test decompiler_golden` to create it.",
            expected_path.display(),
            err,
        );
    });
    if actual != expected {
        panic!(
            "golden mismatch at {}\n\
             === expected ({} bytes) ===\n{}\n\
             === actual ({} bytes) ===\n{}\n\
             === end ===\n\
             Run with BLESS=1 to update.",
            expected_path.display(),
            expected.len(),
            expected,
            actual.len(),
            actual,
        );
    }
}

/// Read every `*.c` file under `out_dir/decompiled_c/` and concatenate them
/// into a single golden-comparable string. Each file is prefixed by a
/// `// === <filename> ===\n` marker so multi-function fixtures can pin all
/// their outputs in a single diffable file.
fn read_decompiled_c_outputs(out_dir: &Path) -> String {
    let dir = out_dir.join("decompiled_c");
    if !dir.is_dir() {
        return String::new();
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read decompiled_c dir {:?}: {}", dir, e))
        .filter_map(|r| r.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("c"))
        .collect();
    entries.sort();
    let mut out = String::new();
    for entry in &entries {
        let name = entry
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string();
        let body = fs::read_to_string(entry)
            .unwrap_or_else(|e| panic!("read decompiled file {:?}: {}", entry, e));
        out.push_str(&format!("// === {} ===\n", name));
        out.push_str(&body);
        if !body.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from("tests")
        .join("fixtures")
        .join("decompiler")
        .join(format!("{}.c.expected", name))
}

/// Run the decompiler against an inline x86_64 byte sled and return the
/// concatenated `decompiled_c/*.c` output. Shared body for the per-fixture
/// tests below.
fn decompile_synth(symbol_name: &[u8], code: &[u8]) -> String {
    let tmp = TempDir::new().expect("tempdir");
    let fixture_path = tmp.path().join("fixture.elf");
    synth_elf(&fixture_path, code, symbol_name);

    let out_dir = tmp.path().join("out");
    axe_core::analyze_path(
        fixture_path.to_str().expect("utf-8 fixture path"),
        out_dir.to_str().expect("utf-8 out dir"),
        options_with_decompile_selected(),
    )
    .expect("analyze synthesized ELF");

    let actual = read_decompiled_c_outputs(&out_dir);
    if actual.is_empty() {
        panic!(
            "decompiler emitted no .c files in {:?} — check that profile == \
             'native-max' and decompile_c != 'off'",
            out_dir.join("decompiled_c")
        );
    }
    actual
}

// ---------------------------------------------------------------------------
// Fixture 1 — leaf function: `xor eax, eax; ret`
// ---------------------------------------------------------------------------
//
// The simplest meaningful decompiler input — a function that returns zero.
// Pins the baseline emit shape (preamble + function signature + single
// statement + closing brace) so any change touching the per-instruction lifter
// is surfaced immediately.
#[test]
fn leaf_xor_eax_ret() {
    // 31 C0  xor eax, eax  ;  C3  ret
    let code: &[u8] = &[0x31, 0xC0, 0xC3];
    let actual = decompile_synth(b"leaf_xor", code);
    assert_golden(&actual, &golden_path("leaf_xor"));
}

// ---------------------------------------------------------------------------
// Fixture 2 — simple natural loop: counter = 0; while (counter != 10) counter++;
// ---------------------------------------------------------------------------
//
// Exercises the natural-loop detector (`src/structured.rs::dominator_sets` +
// backedge classification) and the existing annotative `while (1) { ... } /*
// continue loop → 0xXX (backedge) */` decompiler emit at
// `src/c_decompiler.rs:108-168`. Phase A3 will re-bless this golden when
// condition hoisting lands and the output collapses to a structured
// `while (counter != 10) { ... }`.
#[test]
fn loop_inc_until_ten() {
    // 31 C0          xor eax, eax        ; counter = 0
    // FF C0          inc eax             ; loop_top: counter++
    // 83 F8 0A       cmp eax, 10
    // 75 F9          jne loop_top        ; jump -7 if not equal (back to inc)
    // C3             ret
    let code: &[u8] = &[
        0x31, 0xC0, // xor eax, eax
        0xFF, 0xC0, // inc eax
        0x83, 0xF8, 0x0A, // cmp eax, 10
        0x75, 0xF9, // jne -7
        0xC3, // ret
    ];
    let actual = decompile_synth(b"loop_inc_until_ten", code);
    assert_golden(&actual, &golden_path("loop_inc_until_ten"));
}

// ---------------------------------------------------------------------------
// Fixture 3 — call-dense function (api_heavy proxy)
// ---------------------------------------------------------------------------
//
// Three consecutive `call rel32` sites bracketed by a Win64-style prologue
// (`sub rsp, 0x28`) and epilogue (`add rsp, 0x28; ret`). The synthesized ELF
// has no import table so the calls land at unresolved relative addresses, but
// the decompiler's call-site enumeration still fires — pinning the shape that
// later phases A4 (signature recovery) and A5 (backward type propagation) will
// improve once real api_flows feed the type recovery.
#[test]
fn calls_dense_prologue_epilogue() {
    // 48 83 EC 28          sub rsp, 0x28
    // E8 00 00 00 00       call $+5
    // E8 00 00 00 00       call $+5
    // E8 00 00 00 00       call $+5
    // 48 83 C4 28          add rsp, 0x28
    // C3                   ret
    let code: &[u8] = &[
        0x48, 0x83, 0xEC, 0x28, // sub rsp, 0x28
        0xE8, 0x00, 0x00, 0x00, 0x00, // call +0
        0xE8, 0x00, 0x00, 0x00, 0x00, // call +0
        0xE8, 0x00, 0x00, 0x00, 0x00, // call +0
        0x48, 0x83, 0xC4, 0x28, // add rsp, 0x28
        0xC3, // ret
    ];
    let actual = decompile_synth(b"calls_dense", code);
    assert_golden(&actual, &golden_path("calls_dense"));
}

// ---------------------------------------------------------------------------
// Fixture 4 — decision-tree branch chain (if/else shape, not jump-table switch)
// ---------------------------------------------------------------------------
//
// A cmp/je decision tree: `if (eax==1) return 10; else if (eax==2) return 20;
// else return 30;`. Real jump-table switches need an indirect jmp through a
// memory table, which requires the table at a known address — out of scope
// for a single-section synthesized ELF. Phase A3 (structured C control flow)
// will fold these `je` sites into an `if/else if/else` chain when lifting
// from the structured-flow region tree.
#[test]
fn decision_tree_three_way() {
    // 83 F8 01          cmp eax, 1
    // 75 05             jne L1     (skip 5 bytes = mov+ret)
    // B8 0A 00 00 00    mov eax, 10
    // C3                ret
    // 83 F8 02          cmp eax, 2     ; L1
    // 75 05             jne L2     (skip 5 bytes)
    // B8 14 00 00 00    mov eax, 20
    // C3                ret
    // B8 1E 00 00 00    mov eax, 30    ; L2
    // C3                ret
    let code: &[u8] = &[
        0x83, 0xF8, 0x01, // cmp eax, 1
        0x75, 0x06, // jne +6
        0xB8, 0x0A, 0x00, 0x00, 0x00, // mov eax, 10
        0xC3, // ret
        0x83, 0xF8, 0x02, // cmp eax, 2
        0x75, 0x06, // jne +6
        0xB8, 0x14, 0x00, 0x00, 0x00, // mov eax, 20
        0xC3, // ret
        0xB8, 0x1E, 0x00, 0x00, 0x00, // mov eax, 30
        0xC3, // ret
    ];
    let actual = decompile_synth(b"decision_tree", code);
    assert_golden(&actual, &golden_path("decision_tree"));
}

// ---------------------------------------------------------------------------
// Fixture 5 — SysV ABI passthrough: `mov rax, rdi; ret`
// ---------------------------------------------------------------------------
//
// Exercises Phase A4's ABI detection: the synthesized ELF is x86_64, so the
// composer's `detect_abi` returns `SysV`, and `recover_arg_decls` looks for
// pre-write reads of `rdi`/`rsi`/... instead of the Win64 set. The fixture's
// `mov rax, rdi` reads rdi without writing it first → the signature gains a
// `uint64_t rdi_in` parameter.
//
// Phase A4's full deliverable (variadic detection, API-name-driven arg
// naming like `LPCWSTR lpFileName`) needs API-flow data the synthesized ELF
// can't carry — that pinning lives in a future PE fixture once we can ship
// one. For now this golden validates the ABI plumbing.
#[test]
fn arg_passthrough_sysv() {
    // 48 89 F8       mov rax, rdi      ; rax = first SysV arg
    // C3             ret
    let code: &[u8] = &[0x48, 0x89, 0xF8, 0xC3];
    let actual = decompile_synth(b"arg_passthrough_sysv", code);
    assert_golden(&actual, &golden_path("arg_passthrough_sysv"));
}

// ---------------------------------------------------------------------------
// Fixture 6 — struct-style access: two distinct offsets off rcx
// ---------------------------------------------------------------------------
//
// Exercises Phase A6's offset-cluster detection: two `mov` instructions that
// read different offsets off the same base register (`rcx`) trigger a struct-
// candidate hint comment. The fixture doesn't carry PDB / RTTI info so the
// hint stays at comment level (real anonymous-struct declarations come once
// PDB facts feed in — phase boundary documented in `infer_struct_hints`).
#[test]
fn struct_access_two_offsets() {
    // 48 8B 41 08    mov rax, [rcx+8]
    // 48 8B 51 10    mov rdx, [rcx+0x10]
    // C3             ret
    let code: &[u8] = &[
        0x48, 0x8B, 0x41, 0x08, // mov rax, [rcx+8]
        0x48, 0x8B, 0x51, 0x10, // mov rdx, [rcx+0x10]
        0xC3, // ret
    ];
    let actual = decompile_synth(b"struct_access_two_offsets", code);
    assert_golden(&actual, &golden_path("struct_access_two_offsets"));
}

// ---------------------------------------------------------------------------
// Fixture 7 — CMOV: `test rcx, rcx; cmovne rax, rcx; ret`
// ---------------------------------------------------------------------------
//
// Exercises Phase A9's cmov lifting. The `test rcx, rcx` sets ZF iff rcx==0
// (special-cased in the cmp/test lifter to record the condition as `rcx == 0`
// rather than the literal `rcx == rcx`); `cmovne rax, rcx` then becomes the
// ternary `rax = (rcx != 0) ? rcx : rax;`.
#[test]
fn cmov_passthrough_or_keep() {
    // 48 85 C9          test rcx, rcx
    // 48 0F 45 C1       cmovne rax, rcx
    // C3                ret
    let code: &[u8] = &[
        0x48, 0x85, 0xC9, // test rcx, rcx
        0x48, 0x0F, 0x45, 0xC1, // cmovne rax, rcx
        0xC3, // ret
    ];
    let actual = decompile_synth(b"cmov_passthrough_or_keep", code);
    assert_golden(&actual, &golden_path("cmov_passthrough_or_keep"));
}

// ---------------------------------------------------------------------------
// Fixture 8 — SETcc: `return rcx == 0;` idiom
// ---------------------------------------------------------------------------
//
// Exercises Phase A9's setcc lifting. The canonical compiled-C idiom for
// `return rcx == 0;` is `test rcx, rcx; sete al; movzx eax, al; ret`. This
// pins the lifter's ability to turn `sete al` into the boolean ternary,
// and demonstrates the sub-8 write → invalidate-canonical → re-establish-
// via-movzx behavior of the expression composer.
#[test]
fn setcc_is_zero_predicate() {
    // 48 85 C9          test rcx, rcx
    // 0F 94 C0          sete al           ; al = (rcx == 0) ? 1 : 0
    // 0F B6 C0          movzx eax, al     ; eax = (uint64_t)(uint8_t)al
    // C3                ret
    let code: &[u8] = &[
        0x48, 0x85, 0xC9, // test rcx, rcx
        0x0F, 0x94, 0xC0, // sete al
        0x0F, 0xB6, 0xC0, // movzx eax, al
        0xC3, // ret
    ];
    let actual = decompile_synth(b"setcc_is_zero", code);
    assert_golden(&actual, &golden_path("setcc_is_zero"));
}

// ---------------------------------------------------------------------------
// Fixture 9 — struct field read-then-write (passthrough pattern)
// ---------------------------------------------------------------------------
//
// Reads field_8 into rax, writes it to field_10, returns rax. Validates the
// full chain: A6 hint inference (2 offsets → struct candidate); A6.1 field-
// access rewrite on both the read and the write; A2 composer inlines the
// temp read into both the store RHS and the return; A2.1 drops the dead
// rax decl.
#[test]
fn struct_read_then_write_passthrough() {
    // 48 8B 41 08    mov rax, [rcx+8]
    // 48 89 41 10    mov [rcx+0x10], rax
    // C3             ret
    let code: &[u8] = &[
        0x48, 0x8B, 0x41, 0x08, // mov rax, [rcx+8]
        0x48, 0x89, 0x41, 0x10, // mov [rcx+0x10], rax
        0xC3, // ret
    ];
    let actual = decompile_synth(b"struct_read_then_write", code);
    assert_golden(&actual, &golden_path("struct_read_then_write"));
}

// ---------------------------------------------------------------------------
// Fixture 10 — multi-case decision-tree switch
// ---------------------------------------------------------------------------
//
// `switch (eax) { case 1: return 10; case 2: return 20; default: return 30; }`
// lowered as a cmp/je chain to in-function targets — exercises branch-
// target labels, multiple rets within one function, and the post-A2 emit
// ordering for this common decision-tree-as-switch shape. (Real jump-table
// switches need the table at a known address; this cmp/je form is the
// linear fallback the compiler emits for small case counts.)
#[test]
fn switch_three_case_cmp_je_chain() {
    // 83 F8 01          cmp eax, 1
    // 74 0B             je case_1 (PC=5, target=16)
    // 83 F8 02          cmp eax, 2
    // 74 0A             je case_2 (PC=10, target=20 — wait recompute)
    //                   actually with target at 0x16 and PC=12, disp=0x0a
    //                   so the je byte is `74 0A`, going to PC+0xa=22=0x16
    // B8 1E 00 00 00    mov eax, 30   ; default
    // C3                ret
    // B8 0A 00 00 00    mov eax, 10   ; case_1: at offset 16
    // C3                ret
    // B8 14 00 00 00    mov eax, 20   ; case_2: at offset 22
    // C3                ret
    // Layout:
    //   off 0  : cmp eax, 1                    (3 bytes)
    //   off 3  : je +11 → 16 (case_1)          (2 bytes; PC after je = 5)
    //   off 5  : cmp eax, 2                    (3 bytes)
    //   off 8  : je +12 → 22 (case_2)          (2 bytes; PC after je = 10)
    //   off 10 : mov eax, 30 (default)         (5 bytes)
    //   off 15 : ret                           (1 byte)
    //   off 16 : case_1: mov eax, 10           (5 bytes)
    //   off 21 : ret                           (1 byte)
    //   off 22 : case_2: mov eax, 20           (5 bytes)
    //   off 27 : ret                           (1 byte)
    let code: &[u8] = &[
        0x83, 0xF8, 0x01, // cmp eax, 1
        0x74, 0x0B, // je +11 → case_1 at offset 16
        0x83, 0xF8, 0x02, // cmp eax, 2
        0x74, 0x0C, // je +12 → case_2 at offset 22
        0xB8, 0x1E, 0x00, 0x00, 0x00, // mov eax, 30 (default)
        0xC3, // ret
        0xB8, 0x0A, 0x00, 0x00, 0x00, // case_1: mov eax, 10
        0xC3, // ret
        0xB8, 0x14, 0x00, 0x00, 0x00, // case_2: mov eax, 20
        0xC3, // ret
    ];
    let actual = decompile_synth(b"switch_three_case", code);
    assert_golden(&actual, &golden_path("switch_three_case"));
}

// ---------------------------------------------------------------------------
// Structural sanity test — all goldens conform to basic C-like shape
// ---------------------------------------------------------------------------
//
// Cheap broad-regression catcher. Walks every `.c.expected` file in
// `tests/fixtures/decompiler/` and asserts properties that any decompiled
// output should have: balanced `{`/`}`, balanced `(`/`)`, contains a
// function signature line ending in `{`, ends with `}`, contains at least
// one statement-terminating `;` or comment. Doesn't pin specific contents
// — that's what the per-fixture goldens do — but pins SHAPE invariants
// that a botched composer / emitter change would violate immediately.
#[test]
fn all_goldens_have_balanced_structure() {
    use std::fs;
    let dir = Path::new("tests/fixtures/decompiler");
    let entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("read fixtures dir")
        .filter_map(|r| r.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("expected"))
        .collect();
    assert!(
        !entries.is_empty(),
        "expected at least one .c.expected file in {:?}",
        dir
    );
    for path in &entries {
        let content = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {:?}: {}", path, e));
        let name = path.file_name().unwrap().to_string_lossy().to_string();

        let open_braces = content.matches('{').count();
        let close_braces = content.matches('}').count();
        assert_eq!(
            open_braces, close_braces,
            "{}: unbalanced braces ({} `{{` vs {} `}}`)",
            name, open_braces, close_braces
        );

        let open_parens = content.matches('(').count();
        let close_parens = content.matches(')').count();
        assert_eq!(
            open_parens, close_parens,
            "{}: unbalanced parens ({} `(` vs {} `)`)",
            name, open_parens, close_parens
        );

        assert!(
            content.contains("function_"),
            "{}: missing function_ signature prefix",
            name
        );
        assert!(
            content.contains("uint64_t function_") || content.contains("void function_"),
            "{}: function signature must start with a known return type",
            name
        );

        // Every golden should have AT LEAST one body line — either a
        // statement (`;`) or a comment block. An empty body would mean
        // the emitter dropped everything, which is a bug.
        assert!(
            content.contains(';') || content.contains("/*"),
            "{}: function body has no statements or comments",
            name
        );

        // The last non-empty line should be `}` (function close brace).
        let last_nonempty_line = content
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("");
        assert_eq!(
            last_nonempty_line.trim(),
            "}",
            "{}: last non-empty line should be `}}`, got {:?}",
            name,
            last_nonempty_line
        );
    }
}

// ---------------------------------------------------------------------------
// Fixtures 11 (cpp_vcall) and 12 (seh_handler) intentionally omitted in Phase A1
// ---------------------------------------------------------------------------
//
// Both require machinery a single-section synthesized ELF cannot express:
//   - cpp_vcall needs a vtable in `.rodata`, an object instance with a
//     vftable pointer, and either MSVC RTTI (PE) or Itanium ABI type-info
//     (ELF). Phase A7 (C++ class integration) will add the fixture as part
//     of wiring cpp_classes facts into the C emitter.
//   - seh_handler needs PE `.pdata` / `.xdata` unwind data (FH3/FH4) or
//     ELF LSDA tables. Phase A8 (exception-handler integration) will add
//     the fixture when emitting `__try { ... } __except (...) { ... }`.
//
// The four fixtures above are sufficient to detect regressions in the
// per-instruction lifter, loop detection, call enumeration, and branch
// chaining — which is everything A2 through A6 actually exercise.
