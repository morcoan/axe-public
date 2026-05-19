# Decompiler golden-file fixtures

This directory holds `.c.expected` files that pin the output of the C
decompiler (`src/c_decompiler.rs`) against checked-in expectations.
Originally Phase A1 of the Hex-Rays-parity uplift roadmap; subsequent phases
(A2/A3/A4/A5/A6/A9 + follow-on cleanup work) extend the goldens as the
decompiler gains capabilities. See the module-level `//!` doc-comment at
the top of `src/c_decompiler.rs` for the full pipeline overview.

## How it works

`tests/decompiler_golden.rs` synthesizes a small x86_64 ELF in a tempdir
(using `object::write`, matching the `tests/multi_format.rs` idiom), runs
`axe_core::analyze_path` against it, reads every `*.c` file from the
resulting `decompiled_c/` directory, and compares the concatenated output
to the matching `.c.expected` file in this directory.

The concatenation format is:

```
// === function_<hex_va>.c ===
<contents of that file>
// === function_<hex_va>.c ===
<contents of the next file>
...
```

so multi-function fixtures pin all their outputs in a single diffable file.

## Adding a new fixture

1. Add a `#[test]` to `tests/decompiler_golden.rs` (use `decompile_synth`
   as the entry point — it handles tempdir + ELF synth + axe-core
   invocation + output collection).
2. Run `BLESS=1 cargo test --test decompiler_golden -- <your_test_name>`
   once to write the initial `<name>.c.expected` file.
3. Read the generated golden file and verify the output is what you expect.
4. Commit both the test and the golden file together.

## Updating goldens after an intentional change

```sh
# Regenerate all goldens for inspection
BLESS=1 cargo test --test decompiler_golden

# Or regenerate just one
BLESS=1 cargo test --test decompiler_golden -- leaf_xor_eax_ret

# Diff before committing
git diff tests/fixtures/decompiler/
```

If the diff matches the intent of your decompiler change, commit. If it
shows regressions in fixtures you didn't intend to touch, the change has
unintended scope — investigate before re-blessing.

## Determinism

Function VAs in the generated output (`function_XXXXXXXX.c`) depend on the
ELF section layout chosen by `object::write`. For the same input bytes the
output is reproducible across runs and platforms. If a future `object`
crate update shifts the VA, all goldens regenerate at once with `BLESS=1`.

## Fixture roster (9 pinned)

| Fixture | Code shape | Pipeline coverage |
|---------|-----------|-------------------|
| `leaf_xor` | `xor eax, eax; ret` | A2 expression composer (constant inlined into return); A2.1 dead-local elim drops `eax` decl |
| `loop_inc_until_ten` | counted backedge with `jne` | A3 do-while lifting, A3.1 spurious-loop suppression, A2.2 hex normalization |
| `calls_dense` | 3 consecutive unresolved `call`s in a Win64-style prologue/epilogue | A2.3 cleaner `call_at_0xN` names; A2.2 hex normalization on stack arithmetic |
| `decision_tree` | `cmp/jne/mov/ret` forward-branch shape | Honest goto-form for forward branches; A2 inlines the const into the early return; A2.2 hex normalization |
| `arg_passthrough_sysv` | `mov rax, rdi; ret` (SysV first arg) | A4 ABI detection (ELF → SysV → rdi recognised as arg); A2.1 drops dead `rax` decl |
| `struct_access_two_offsets` | 2 reads off `rcx` at offsets 0x8, 0x10 | A6 struct-hint inference; A6.1 field-access rewrite; A2 + A2.1 collapse to 1-line return |
| `cmov_passthrough_or_keep` | `test/cmovne/ret` ternary idiom | A9 cmov lifting; A2 inlines the ternary into the return |
| `setcc_is_zero_predicate` | `test/sete/movzx/ret` boolean idiom | A9 setcc lifting; A2 substituted-region tracking (fix for nested re-substitution bug) |
| `struct_read_then_write` | read field_8, write to field_10, return | A6 + A6.1 + A2 full chain (read + write both rewritten); is_call_text bugfix surfaced here |

## Deliberate non-fixtures (deferred)

| Pattern | Why deferred | Unblocks |
|---------|--------------|----------|
| C++ vcall | needs MSVC RTTI or Itanium ABI type-info — both PE/full-OS features synth ELF can't carry | A7 (C++ class integration) |
| SEH handler | needs PE `.pdata`/`.xdata` (FH3/FH4) or ELF LSDA — both binary-format features | A8 (EH integration) |
| Switch with jump table | needs the table at a known address in the binary, hard to synth | A3 extension (region tree) |
| API call with real flow | needs PE imports that synth ELF can't carry | A5 type propagation, A7 |
| FLIRT-recognised CRT function | needs a real CRT signature corpus | A10 |
| Cross-function type unification | needs a multi-function PE | A11 |

Future work: a real PE fixture (via `object::write` with `BinaryFormat::Coff`
or a dedicated PE-write crate) would unblock most of these in one stroke.

## Phase coverage map

| Phase | Status | Fixture(s) that exercise it |
|-------|--------|------------------------------|
| A1 | shipped | (foundation — all fixtures) |
| A2 expression composer | shipped | leaf_xor, decision_tree, cmov, setcc, struct_read_then_write |
| A2.1 dead-local elim | shipped | leaf_xor, arg_passthrough_sysv, struct_access_two_offsets |
| A2.2 hex normalize | shipped | loop_inc_until_ten, decision_tree, calls_dense |
| A2.3 call-name cleanup | shipped | calls_dense |
| A3 do-while lift | shipped | loop_inc_until_ten |
| A3.1 spurious-loop fix | shipped | loop_inc_until_ten ("1 natural loop(s)" preamble) |
| A3.2 if-inversion | deferred (rationale documented) | — |
| A4 ABI detection | shipped | arg_passthrough_sysv, cmov, setcc |
| A5 type propagation + 5-tier confidence | shipped (no-op on current fixtures) | (scaffolded; visible once a PE fixture lands) |
| A6 struct-hint inference | shipped | struct_access_two_offsets, struct_read_then_write |
| A6.1 struct-field rewrite | shipped | struct_access_two_offsets, struct_read_then_write |
| A7 C++ classes | deferred (needs PE+RTTI) | — |
| A8 EH integration | deferred (needs PE+pdata) | — |
| A9 cmov + setcc | shipped | cmov_passthrough_or_keep, setcc_is_zero_predicate |
| A10 FLIRT | deferred (needs CRT corpus) | — |
| A11 whole-program types | deferred (needs multi-fn PE) | — |
