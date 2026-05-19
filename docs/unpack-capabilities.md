# Aurora — Capability bounds

The Aurora unpacker (`src/unpack/`, feature `unpack`) takes a packed PE and produces an **analyzable snapshot** consumed by `PEImage::from_snapshot()` back into axe-core's static + vuln-discovery pipeline. This document records what Aurora reliably handles, what's best-effort, and what's an explicit non-goal — so the LLM consumer + the analyst know what to trust.

## Reliability tiers

| Packer family          | Tier         | Trace artifact          | Notes                                                                                                                        |
| ---------------------- | ------------ | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| UPX (any version)      | **high**     | —                       | Section-name + magic-string detected; generic guard-page + entropy pipeline reliably surfaces OEP                            |
| MPRESS                 | **high**     | —                       | Section-name detected; OEP usually corroborated by ≥3 of 4 signals                                                            |
| PECompact              | **high**     | —                       | Same                                                                                                                          |
| ASPack                 | **high**     | —                       | Same                                                                                                                          |
| NsPack                 | **high**     | —                       | Same                                                                                                                          |
| Petite                 | **high**     | —                       | Section-name detected; usually completes within debug mode                                                                    |
| yoda's Crypter         | **medium**   | —                       | Detection reliable; OEP detection may need analyst review                                                                     |
| ASProtect              | **medium**   | —                       | Some variants use light virtualization that the generic path misses                                                          |
| Enigma                 | **medium**   | —                       | Variant-dependent                                                                                                            |
| PELock                 | **medium**   | —                       | Variant-dependent                                                                                                             |
| Themida ≤2.x           | **best_effort** ¹ | `devirt_trace.jsonl` | Devirt path (`unpack-emulation` feature) attempts handler-stepping; produces opcode log. May reach `medium` when 4-signal OEP corroboration confirms a reached OEP candidate. |
| VMProtect ≤2.x         | **best_effort** ¹ | `devirt_trace.jsonl` | Same shape as Themida ≤2.x with a different handler-pattern table.                                                            |
| Themida 3.x            | **best_effort** ² | `devirt_trace.jsonl` ³ | **Capped.** Modern Themida virtualization defeats the generic dispatcher walk; partial-recovery output is hard-capped at `best_effort` by Phase B5's 0.40 score rule. Opt-in via `--devirt-allow-best-effort-3x`. |
| VMProtect 3.x          | **non-goal** | —                       | Modern virtualization defeats the generic pipeline. Future work: when Themida 3.x partial recovery proves useful, the same shape can be adapted for VMProtect 3.x — the unicorn_wrap (B1) + `devirt_trace.jsonl` schema (B2) work already unblocks it. |
| Denuvo                 | **non-goal** | —                       | DRM-grade protection designed against exactly these techniques                                                                |
| Custom protectors      | **best_effort to non-goal** | sometimes `devirt_trace.jsonl` | Aurora's output marks confidence accordingly                                                                                 |

¹ `best_effort` is the floor for the ≤2.x tier; the 4-signal OEP
  corroboration may raise the final tier to `medium` (and very rarely
  `high`) for individual runs. See `src/unpack/snapshot.rs::tier_for_score`.

² Themida 3.x is **never** allowed to reach `medium` or `high` regardless of
  signal count. The cap is enforced at three independent points:
  `devirt/themida3x.rs::cap_score` clamps `raw_score ≤ 0.40`;
  `devirt/themida3x.rs::make_capped_footer` hard-codes the tier label;
  `devirt/trace.rs::TraceWriter::finalize` rejects writing a footer where
  `header.cap_reason == "themida_3x_partial"` but tier != `best_effort`.

³ Themida 3.x emits `devirt_trace.jsonl` **only** when
  `--devirt-allow-best-effort-3x` is passed. Without the flag, detection
  records the strategy + an explanatory note in the snapshot
  `uncertainties` field and skips the trace write.

## Anti-debug surface coverage

| Surface                                                  | Suppressed | Notes                                                                              |
| -------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------- |
| `PEB.BeingDebugged`                                      | ✅          | Patched via `WriteProcessMemory` post-attach                                       |
| `PEB.NtGlobalFlag`                                       | ✅          | Cleared from `0x70` to `0`                                                          |
| `IsDebuggerPresent`                                      | ✅          | Hooked via stub DLL                                                                |
| `CheckRemoteDebuggerPresent`                             | ✅          | Hooked via stub DLL                                                                |
| `NtQueryInformationProcess(ProcessDebugPort/Flags/Handle)` | ✅        | Hooked via stub DLL                                                                |
| `NtSetInformationThread(ThreadHideFromDebugger)`         | ✅          | Pretended-success                                                                  |
| Hardware-BP scan (`GetThreadContext` Dr0..Dr3)           | ❌          | Aurora's HW BPs are visible — use INT3 instead when needed                          |
| Integrity check of `kernel32.dll` against on-disk image  | ❌          | Hook trampolines fail byte-pattern compare; out of scope                            |
| Self-modifying code that rewrites its own debug-check    | ❌          | No mitigation; analyst review required                                              |

## Anti-VM surface coverage

| Surface                                                          | Spoofed | Notes                                                              |
| ---------------------------------------------------------------- | ------- | ------------------------------------------------------------------ |
| `GetSystemFirmwareTable(RSMB)`                                   | ✅       | Returns 0                                                          |
| `RegQueryValueExW` against VM-indicator keys                     | ✅       | 7 key paths covered; see `hooks/spoof_registry.rs`                  |
| `CreateToolhelp32Snapshot` / `Process32FirstW` / `NextW`         | ✅       | 13 VM-tool process names hidden                                    |
| `GetAdaptersInfo` / `GetAdaptersAddresses` MAC OUI               | ✅       | 8 vendor OUIs rewritten to Intel `00:1B:21`                         |
| `NtQuerySystemInformation(SystemModuleInformation)`              | ✅       | 17 VM-tool drivers hidden                                          |
| `cpuid` leaf 1 ECX bit 31 (hypervisor present)                   | WHP only | `unpack-whp` feature, mutually exclusive with VMware/VBox          |
| `cpuid` leaf 0 vendor string                                     | WHP only | Same                                                               |
| `cpuid` leaves `0x40000000..0xFF`                                | WHP only | Same                                                               |
| RDTSC timing oracles                                             | partial | WHP rolling counter defeats opportunistic checks; not undetectable |

## Tracer modes

| Mode     | Feature flag       | Works with VMware/VBox? | Notes                                                                                                |
| -------- | ------------------ | ----------------------- | ---------------------------------------------------------------------------------------------------- |
| `debug`  | `unpack` (default) | ✅                       | Windows debug API; works in any virt layer                                                            |
| `whp`    | `unpack-whp`       | ❌                       | Requires Hyper-V enabled on host                                                                      |
| `driver` | `unpack-driver`    | ✅                       | Requires test-signing mode OR user-supplied EV-signed `aurora_drv.sys`                                 |
| `auto`   | `unpack` (default) | depends                 | Picks best available based on host capability probe                                                  |

## Containment

Aurora's session has:

1. **Wall-clock timeout** (default 60 s, `--unpack-timeout-secs`)
2. **Event-count budget** as instruction proxy (default 100M notional, `--unpack-instr-budget`)
3. **Ctrl-C kill-switch** via `ctrlc` crate
4. **WerFault suppression** via `SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX)`

What Aurora does NOT do (analyst's responsibility — run in an isolated VM):

- Network isolation
- File-system isolation
- Child-process containment

## Snapshot reproducibility

The same packed input may produce **different snapshots across runs** due to ASLR, timing, and system state. The snapshot manifest's `uncertainties` field always carries this note. Hash snapshots, not "Aurora outputs", when comparing across runs.

## Output guarantee

Aurora emits **snapshot artifacts only** — never a re-runnable PE. The snapshot is consumed by `PEImage::from_snapshot()` and feeds the existing static + vuln-discovery pipeline. PE reconstruction (rebuilt IAT, fixed relocs, runnable headers) is an explicit non-goal — the analyst's use case is static re-analysis of unpacked code, not re-execution. If re-execution is needed, attach to the live process instead.

## Never

- **BYOVD ("Bring Your Own Vulnerable Driver")** — exploiting a vulnerable signed driver is a malware TTP, not an analysis technique. The `unpack-driver` feature requires test-signing mode or a user-supplied EV-signed driver. Aurora will never assist in loading a third-party signed driver under false pretenses.
- **Custom hook hiding against integrity checks** — out of scope.
- **Auto-classification of unpacked payload** ("this is Emotet") — axe-core's existing behavior-fact + attack-mapping does that; Aurora only produces the snapshot.
