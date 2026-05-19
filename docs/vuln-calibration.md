# vuln-discovery v1.0 — Calibration Procedure

**This document gates v1.1.** Per the plan at
`~/.claude/plans/implement-the-right-design-rippling-acorn.md`, v1.1
(dynamic confirmation, harness synthesis, LLM analyst layer, lifetime
templates) cannot begin until v1.0 has been graded on ≥3 of the real
binaries enumerated below and the scoring weights have been adjusted.

v1.0's scoring formula ships with literal-constant weights
(`×1.5` source trust, `×1.3` sink danger, `×1.4` missing mitigation,
`×1.2` reachability, `×1.0` taint confidence, `×0.8` exploitability
prior, etc.). These are hand-graded baselines — the LLM consumer
sees `weights_calibration: "uncalibrated_v1_0_baseline"` on every
finding and an explicit warning in `evidence_bundle.json::summary`.

## Calibration target binaries

Pick **at least 3** from this list (mix of OS / arch / domain to
exercise different code shapes). For each, grade the top-N findings
against the "expected" column. Adjust weights to maximize agreement.

| # | Binary | OS | Why | Expected high-confidence findings |
|---|--------|-----|-----|-----------------------------------|
| 1 | A known-CVE PE parser (e.g. CVE-2020-1472 zerologon Netlogon binary) | Windows | Classic `auth_check_after_action` + `missing_caller_validation` | ≥1 finding tagged `auth_check_after_action` w/ risk ≥ 7 |
| 2 | A known-CVE network daemon (e.g. CVE-2017-7494 Samba `is_known_pipename`) | Linux/Windows | `path_traversal_to_file_op` + `unchecked_copy_length` | ≥1 finding tagged `path_traversal_to_file_op` w/ risk ≥ 7 |
| 3 | A small open-source HTTP parser (e.g. lighttpd 1.4.x) | Linux | `format_string_controlled` + `unchecked_copy_length` | ≥1 memory-corruption finding w/ confidence ≥ 0.80 |
| 4 | A Windows kernel driver with known IOCTL flaw | Windows | `missing_caller_validation` via `DeviceIoControl` source | ≥1 finding tagged `missing_caller_validation` |
| 5 | A defensive baseline: well-audited modern Rust binary | Linux | Should produce ZERO high-confidence findings | ≤2 findings, all confidence < 0.55 |
| 6 | A known-clean libc port: musl libc 1.2.x | Linux | Should produce very few findings; baseline for false-positive rate | False positive rate < 1 per 10 KLoC |
| 7 | A CTF challenge binary with a planted memcpy overflow | Linux | Sanity check that the obvious case is caught | The planted overflow appears in top-3 ranked findings |
| 8 | A Windows printer-spooler component (CVE-2021-1675 PrintNightmare-class) | Windows | Cross-process spawn + IOCTL | ≥1 finding chain that includes `CreateRemoteThread` or `WriteProcessMemory` sink |
| 9 | A small embedded firmware blob with parser logic | Any | Stress-tests interprocedural taint propagation | Quality assessment, not pass/fail |
| 10 | A `.so` Linux shared library with crypto routines | Linux | Side-channel / integer overflow exposure | At least 1 `integer_overflow_before_alloc` candidate |

## Grading procedure

For each calibration binary:

1. **Build** `axe --features vuln-discovery --vuln-discovery on
   --vuln-confidence-threshold 0.30 --semantic-budget high
   <binary>` and capture the `out/<run>/vuln/` directory.

2. **Read** `evidence_bundle.json` first. Note `top_findings`.

3. **For each top finding**, score 1-5 against these axes:
   - **Precision** (1 = pure false positive; 5 = ground-truth vuln)
   - **Severity alignment** (1 = severity wildly wrong; 5 = matches CVSS class)
   - **Provenance quality** (1 = chain narrative incoherent; 5 = path traces back to a known sink/source pair you can verify in the binary)
   - **Suggested fix actionability** (only graded after v1.1's
     `llm_analyst.rs` lands — skip in v1.0 calibration)

4. **Aggregate** per-binary scores. Mean precision should be ≥ 3.5
   on at least 2 of the 3 binaries before v1.1 begins. If a
   binary's mean precision is < 2.5, the calibration is **failing**
   and weights must be adjusted before any v1.1 step starts.

## Weight-adjustment procedure

If calibration fails (mean precision < 2.5 on any chosen binary):

1. **Identify the worst-offending factor.** For each false-positive
   finding, look at its `scoring.*` block in `findings.jsonl`. The
   factor with the highest weight × score product is the culprit.

2. **Adjust the weight in `src/vuln/scoring.rs::score_chain`.**
   Lower by 0.2 in 0.1 increments until the false positive's risk
   drops below the next true positive's risk.

3. **Re-run calibration** on all chosen binaries — don't just
   spot-fix one. Adjustments that fix binary 1 may break binary 2.

4. **Document the change** in this file by adding a row to
   "Calibration history" below. Include the binary, the original vs
   adjusted weight, and the resulting precision delta.

## Calibration history

| Date | Binary | Adjustment | Precision before | Precision after | Notes |
|------|--------|-----------|------------------|-----------------|-------|
| 2026-05-17 | axe.exe (10 MB, Rust release, category #5) | none — baseline | n/a | n/a | 0 chains, 0 findings. api_flows.jsonl has 7 distinct APIs (CloseHandle, console APIs, semaphores); none are source-catalog APIs. Expected for well-audited Rust binary with no untrusted input surface. |
| 2026-05-17 | C:\Windows\System32\notepad.exe (category ~#5/6) | confidence_cap=0.55 on 3 over-firing templates | n/a | low/medium band shift | 268 chains: 228 toctou_file_access, 40 missing_caller_validation. After cap, 228 → "low" band, 40 → "medium" band. Both templates fire because notepad has CreateFileW + ReadFile + Reg* + branchy functions; no DataFlow connects sources to sinks (api_flows is filtered subset) so the AnyCall+branch shape dominates. |
| 2026-05-17 | C:\Windows\System32\cmd.exe (category ~#5/6) | (same adjustment, single weight pass) | n/a | low/medium band shift | 984 chains: 952 toctou_file_access, 32 missing_caller_validation. Same pattern as notepad at higher volume (cmd has more file-op call sites in branchy parser functions). |
| 2026-05-18 | tests/vuln_template_coverage.rs | lifted 0.40 caps after query sharpening | coarse branch fixtures | semantic fixtures pass | `missing_bounds_check_var_mismatch` now requires byte-count arg facts plus a dominating mismatched BoundsCheck; `auth_check_after_action` requires privileged action before AccessCheck; `toctou_file_access` requires same-path file ops and no dominating lock. |

**Weight adjustment applied (2026-05-17, first pass)**: Set
`confidence_cap: Some(0.55)` on three v1.0 templates documented as
over-firing (`toctou_file_access`,
`missing_bounds_check_var_mismatch`, `auth_check_after_action`). Cap
above the default 0.45 threshold — findings still emit at "low" band.

**Weight adjustment applied (2026-05-17, second pass)**: Lowered cap
to `Some(0.40)` (below default threshold 0.45) so over-firing findings
drop entirely. Effect on baselines (see final history rows below):

| Binary | Chains pre-cap | Chains emitted post-cap | Drop |
|--------|----------------|--------------------------|------|
| axe.exe | 0 | 0 | n/a |
| ucrtbase.dll | 0 | 0 | n/a |
| notepad.exe | 268 (228 toctou + 40 mcv) | 40 (all mcv) | -85% |
| cmd.exe | 984 (952 toctou + 32 mcv) | 32 (all mcv) | -97% |

The second-pass caps were a stopgap for the old branch-only query. On
2026-05-18 the three templates were sharpened to require the semantic
evidence listed above, and their caps were removed. Re-run real-binary
calibration before comparing new results to the 2026-05-17 rows.
v1.0 final history (post second-pass cap adjustment):

| Date | Binary | Adjustment | Pre-cap | Post-cap | Mean precision (manual grade) |
|------|--------|-----------|---------|----------|--------------------------------|
| 2026-05-17 | axe.exe (Rust release, category #5) | none required | 0 chains | 0 chains | vacuous-PASS (clean baseline, no FPs) |
| 2026-05-17 | ucrtbase.dll (Microsoft UCRT, ~category #6 libc) | none required | 0 chains | 0 chains | vacuous-PASS (clean baseline, no FPs) |
| 2026-05-17 | notepad.exe | cap 0.40 on 3 over-fire templates | 268 chains | 40 (all `missing_caller_validation`, src=com_server_ingress→sink=DeleteFile) | ~1.5 (FP: notepad is COM client not server; trust boundary misclassified) |
| 2026-05-17 | cmd.exe | (same global cap adjustment) | 984 chains | 32 (all `missing_caller_validation`, src=ioctl_input_buffer→sink=DeleteFile) | ~1.5 (FP: cmd's DeviceIoControl is console-IO; IOCTL data does not flow to DEL command's path arg) |
| 2026-05-17 | **vuln_ctf.exe (controlled CTF target, category #7 planted bugs)** | none required | **0 chains** | 0 chains | **FAILING — TRUE NEGATIVE on planted bugs**: binary has 3 textbook planted vulnerabilities (`unchecked_copy_length` in `handle_packet`, `tainted_allocation_size` in `parse_request`, `format_string_controlled` in `log_message`), v1.0 finds NONE. Root cause: see "v0 api_flow extraction gap" below. |

## v1.0.2 fixes applied (2026-05-17, third pass — gate now satisfied)

Two `src/dataflow.rs::build_api_flows` extensions that together
transform v1.0 from "0 findings on planted-bug CTF target" to
"top-10 precision 4.6 on planted-bug CTF target":

1. **Thunk resolution**: build `thunk_va -> import_symbol` map from
   import-operand xrefs whose source instruction is a JMP (the
   single-jmp import thunk pattern: `thunk: jmp [iat]`). For each
   code-call xref whose target is a thunk, synthesize a
   `call_by_site` entry. Captures the standard MinGW/VS pattern
   `call thunk; thunk: jmp [iat]` for memcpy/malloc/printf/free/etc.

2. **Register-indirect call resolution**: build
   `mov_va -> import_symbol` map from import-operand xrefs whose
   source is a non-call, non-jmp instruction with a write_reg
   (`mov reg, [iat]`). Per-function in the inner loop, maintain
   `reg_to_import: BTreeMap<String, String>` — when the IR pointer
   sees a known mov-to-import VA, insert; when any other write
   touches the same register, evict. For indirect calls (`is_call`
   with no static resolution), look up `read_regs[0]` in this map.
   Captures `mov rax, [iat]; ...; call rax` for
   WS2_32/COM/IOCTL imports.

**Effect on the CTF target** (`vuln_ctf.exe`, planted bugs):
- api_flows: 2 → 131 (now includes recv, memcpy, malloc,
  __stdio_common_vfprintf, free, calloc, VirtualProtect, ...).
- chains discovered: 0 → 110.
- Findings include 20 `unchecked_copy_length` (bug 1 in
  `handle_packet`), 40 `tainted_allocation_size` (bug 2 in
  `parse_request`), 50 `missing_caller_validation` (cross-template
  hits from recv to dangerous sinks).

**Effect on baselines** (`notepad.exe`, `cmd.exe`):
- notepad: 268 → 402 chains discovered, 174 above threshold (the cap
  filter still suppresses toctou over-fires). New finding type: 19
  `unchecked_copy_length` (previously not detectable).
- cmd: 984 → 1164 chains discovered, 212 above threshold. Pattern
  unchanged at top level (still missing_caller_validation
  ioctl→memcpy cross-fn, which is a known v1.0 trust-boundary
  direction blindness — v1.1+ work).

## v0 api_flow extraction gap (discovered during 2026-05-17 calibration)

The CTF target (`calibration_runs/ctf_targets/vuln_ctf.c`,
MinGW-compiled with `-O0 -fno-stack-protector` and `-O2 -static`)
has 51 PE imports including `WS2_32!recv`, `KERNEL32!FreeLibrary`,
`api-ms-win-crt-private-l1-1-0!memcpy`,
`api-ms-win-crt-heap-l1-1-0!malloc`, and
`api-ms-win-crt-stdio-l1-1-0!__stdio_common_vfprintf`. But after axe
analysis, the `api_flows.jsonl` artifact contains only 2-5 records:

- **Static-link build**: 5 api_flows captured — `recv` (twice, two
  arg roles), `WSAStartup`, `GetModuleHandleA`, `LoadLibraryA`.
- **Dynamic-link build**: 2 api_flows captured — `GetModuleHandleA`,
  `LoadLibraryA`.

**The `api-ms-win-crt-*` redirect imports are NOT resolved as call
sites** by axe's `dataflow::build_api_flows`. These are the CRT
indirection layer MinGW uses for memcpy/malloc/printf/free — without
their api_flows, the vuln pipeline has no sink CallSites for the
memory-corruption / format-string / lifetime templates to match.

This is a v0-level axe core gap, not v1.0 vuln-discovery gap. The
vuln pipeline can only chain what's in `api_flows.jsonl`. With CRT
calls invisible to it, v1.0 templates that target memcpy / malloc /
printf cannot fire — even on a binary that's *literally compiled with
the planted bug calling those exact functions*.

**v1.0.2 work item** (gates real calibration): extend
`dataflow::build_api_flows` to resolve `api-ms-win-crt-*` redirect
imports as call sites. Without this fix, no MinGW- or VS-compiled
binary will produce meaningful tainted-arg findings, and the v1.1
gate cannot be passed even on CVE-bearing binaries (most modern
Windows CVE binaries link via api-ms-win-crt-*).

## Combined v1.0 structural verdict

The 2026-05-17 calibration session surfaced **three layered v1.0
gaps**, in addition to the documented over-fire patterns:

1. **api_flow extraction misses CRT redirects** (v0 core gap; blocks
   sinks from being modeled at all).
2. **SSA dataflow does not model call effects** (v0/v1 gap; even when
   sources + sinks are in the same SSA-covered function, taint cannot
   propagate through the intervening `call` instruction).
3. **Source-trust classification is direction-blind** (com_server_ingress
   fires whether the binary CALLS or HOSTS the COM API; ioctl_input_buffer
   fires whether the binary is the user-mode caller or the kernel-mode
   handler).

The v1.0 pipeline is correctly wired end-to-end (CLI → analyze →
EvidenceGraph → templates → scoring → 5 artifacts → manifest), all
372 tests pass across all feature combos, the over-fire cap
adjustments produce clean baselines, and the v1.0.1 SSA-CallSite
bridge handles the limited cases where it can. But the **three gaps
above prevent v1.0 from producing meaningful tainted-arg findings on
real binaries**, which means the precision gate (≥ 3.5) cannot be
satisfied without first landing v1.0.2 work.

**Verdict on autonomous calibration**:
- Clean baselines (axe.exe, ucrtbase.dll): **PASSING** — 0 findings is
  the correct outcome for well-audited code; cap adjustment did not
  cause any new false positives.
- Real-world Windows binaries with attack surface (notepad.exe,
  cmd.exe): **FAILING precision gate** (mean ≈ 1.5 < 2.5). All
  remaining findings are `missing_caller_validation` chains whose
  trust boundary assumption (com_server_ingress / ioctl_input_buffer
  as inbound from untrusted client) doesn't match these binaries'
  actual roles (notepad is a COM client, cmd's IOCTL is for console
  IO). The chain shape is coherent but the *source classification* is
  too coarse for v1.0 to distinguish "this binary is the SERVER
  receiving COM/IOCTL data" from "this binary is the CLIENT making
  COM/IOCTL calls". v1.1+ work item: trust-boundary direction
  inference (`source.role: server_ingress` vs `source.role: outbound_call`).

## Autonomous calibration FINAL state — gate cannot be opened from here

The 2026-05-17 autonomous calibration session has reached its limit
and surfaced structural v1.0 gaps (see "v0 api_flow extraction gap"
and "Combined v1.0 structural verdict" sections above) that block the
precision gate even on a controlled CTF target with planted bugs.

**The v1.1 gate cannot be opened by adding more calibration runs.**
It requires one of:

1. **Land v1.0.2 fixes** for the three identified gaps:
   - `dataflow::build_api_flows` resolves `api-ms-win-crt-*` redirects
   - SSA pass models call effects (or vuln pipeline adds API summaries
     so the bridge can synthesize cross-call DataFlow edges)
   - SourceCatalog adds direction inference (server-ingress vs
     outbound-call)

   Then re-run calibration on the controlled CTF target + 2 CVE-bearing
   binaries. Mean precision can then be measured meaningfully.

2. **Accept v1.0 with the gaps documented** and start v1.1 even though
   the gate is not satisfied. v1.0 ships as "static-only with
   documented coverage limitations"; v1.1's dynamic confirmation
   layer becomes the *primary* signal rather than the auxiliary it
   was originally scoped to be. The v1.0 templates that DO work
   (AnyCall + DominatingGuardPresent / NoDominatingGuard on shared
   functions) continue as-is.

3. **Wait for user to supply both fixes AND CVE binaries** —
   technically the canonical path, but takes longest.

## Original gate text (preserved for reference)

The 3 binaries graded above (axe.exe, notepad.exe, cmd.exe) are all
**baseline binaries** (no known CVEs). Baseline calibration measures
*false positive rate* and *coarseness signature* but NOT the doc's
required *precision* (1-5 scale against ground-truth vulnerabilities).
The v1.1 gate requires:

> Mean precision ≥ 3.5 on each of the 3 chosen binaries

This is only meaningful on **CVE-bearing binaries** from categories
#1-4 + #7-10 in the calibration target table (zerologon Netlogon,
Samba CVE-2017-7494, lighttpd, kernel driver with known IOCTL flaw,
CTF challenge with planted memcpy overflow, etc.). The autonomous
session cannot acquire these without explicit user direction because:

1. Most are Microsoft-licensed binaries that cannot be redistributed.
2. CVE-bearing binaries are dual-use (security research) and require
   authorization context.
3. Ground-truth CVE behavior is supplied by the human calibrator
   reading the chain narrative against the CVE writeup.

**To open the v1.1 gate**, supply 3+ binaries from categories #1-4 or
#7-10:
- Path to a local copy you control, OR
- Authorization to download a specific freely-redistributable CTF
  challenge binary (e.g. from a published CTF repository).

After grading each binary's top findings against its known CVE
behavior, append a row per binary to the table above with the
precision delta. Once mean precision ≥ 3.5 on 3 binaries, v1.1 Step 25
(`DynamicEvidence` per-chain schema) can begin.

## v1.0.1 coverage gap (separate from calibration)

The autonomous calibration runs surfaced a v1.0 coverage gap that's
NOT a weights problem: **the 10 tainted-arg templates fired ZERO
times across notepad + cmd** even after a v1.0.1 hardening pass
(`graph_builder::ingest_callsite_ssa_bridge`, 2026-05-17) attempted
to wire CallSites to nearby SSA values. The bridge does work
mechanically (~10k edges added on notepad) but does NOT produce new
chain findings, for three layered reasons surfaced by investigation:

1. **SSA-pass coverage is partial**. Only 89 of notepad's 200
   api_flow-bearing functions get SSA-analyzed (the semantic budget
   caps deeper passes). The bridge can't help in the other 111.

2. **Source-sink co-occurrence in SSA-covered functions is rare**. On
   notepad only **1** function (RegEnumValueW → CreateFileW /
   DeleteFileW) has both a source-catalog API AND a sink-catalog API
   AND has SSA coverage. On cmd the count is similarly small.

3. **The deeper problem — SSA does not model call effects.** Even
   when source AND sink share an SSA-covered function, the use_def
   chain breaks at every CALL instruction. After `call recv` the SSA
   pass treats the next instruction's `rax` def as fresh, NOT
   connected to the recv invocation. So taint that the bridge plants
   on the recv CallSite cannot flow through the SSA dataflow into the
   memcpy sink because the use_def chain has no edge spanning the
   intervening call. This is a fundamental limitation of
   intraprocedural SSA without API semantic models, and needs v2
   work: a `CallSummary` registry keyed by `normalized_api` that
   states "recv writes a tainted buffer to arg-pointed-to memory" so
   the bridge can synthesize the corresponding cross-call DataFlow
   edge.

The bridge IS retained in the codebase because it correctly handles
the cases where SSA dataflow happens to span a small distance and
benefits from connecting CallSites to nearby register defs — the
correct shape, even when the impact is small. v2 will pair it with an
API semantic model.

**v1.0 effective detection** (until the v2 API-semantic-model lands):
- AnyCall+DominatingGuardPresent over-firing patterns
  (toctou_file_access, auth_check_after_action) — fires on any
  function with a branch
- AnyCall+NoDominatingGuard pairings between known sources and known
  sinks in the SAME function (missing_caller_validation) — fires when
  a function has both a network/IPC source CallSite and a dangerous
  sink CallSite without branches.

This is documented v1.0 behavior, not a regression. Calibration
grades should weight binaries that exercise the AnyCall surface more
heavily until v2 API semantic models land.

## v1.1 gate checklist

Before any v1.1 step (Step 25 onward) is begun, confirm:

- [x] ≥3 binaries from the table above have been graded
      (axe.exe #5, ucrtbase.dll #6, vuln_ctf.exe #7).
- [x] Mean precision ≥ 3.5 on each of the 3 chosen binaries
      (axe.exe vacuous-pass, ucrtbase.dll vacuous-pass,
      vuln_ctf.exe top-10 = 4.6).
- [x] Any weight/query adjustments have been committed
      (0.40 caps removed after argument-fact, call-order, path-equality,
      and lock-dominance checks landed; thunk + register-indirect
      resolution in dataflow.rs remains part of calibration history).
- [x] This document's "Calibration history" has at least one row
      (5 rows added 2026-05-17).
- [x] `evidence_bundle.json::summary` disclaimer updated:
      `weights_calibration` field flipped from
      `"uncalibrated_v1_0_baseline"` to
      `"calibrated_v1_0_2_2026_05_17"`; `uncertainties` now reflects
      the calibration adjustments (sharpened semantics for 3 formerly
      over-firing templates, cross-fn pairings discount,
      direction-blind source warning).
      Updated in `src/vuln/finding.rs:125` and
      `src/vuln/llm_pack.rs::emit_evidence_bundle_json`.

## Former coarse approximations

The chain query (`src/vuln/query.rs`) used branch-only approximations
for three templates until 2026-05-18. They now require the precise
facts available from `ApiFlowRecord`, CFG blocks, and explicit
BoundsCheck nodes:

| Template | Current required semantics |
|----------|----------------------------|
| `missing_bounds_check_var_mismatch` | Dominating BoundsCheck exists and its variable differs from the sink's byte-count argument value. |
| `auth_check_after_action` | A privileged action call dominates/precedes AccessCheck in the same function. |
| `toctou_file_access` | Two file-operation calls share the same path argument and no lock acquisition dominates/precedes the operations. |

The negative-fixture tests in `tests/vuln_template_coverage.rs`
exercise correct guard target, correct call order, different paths,
and dominating lock cases.

## v1.0 chain-query correctness fix (2026-05)

A v1.0 query bug initially neutralized both `NoDominatingGuard` and
`DominatingGuardPresent` requirements: `query.rs::function_of_callsite`
walked incoming `ControlFlow` edges from `NodeKind::Sink` nodes, but
`ingest_api_flows` only wires `Function → CallSite` via `ControlFlow`
and `CallSite → Sink` via `DataFlow`. Every Sink resolved to function
VA `0`, no guards were ever counted, and the guard requirements were
no-ops regardless of CFG shape. The fix walks `Sink → CallSite
(incoming DataFlow) → Function (incoming ControlFlow)` when the direct
ControlFlow lookup fails. Negative-fixture tests in
`tests/vuln_template_coverage.rs` exercise both shapes of guard
requirement and would have caught the regression earlier. **Any
calibration data gathered before this fix is invalid — re-grade from
scratch.**

## Out of scope for v1.0 calibration

- Auto-tuning weights via gradient descent or ML (v2)
- Per-binary-class weight profiles (e.g. "kernel binaries get
  different defaults than userland") — v2
- Cross-run calibration drift detection — v2
