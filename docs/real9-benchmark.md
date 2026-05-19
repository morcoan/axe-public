# real-9 external benchmark gate

`real-9` is the first external known-bug gate. It is intentionally not a
malware corpus and does not commit vulnerable binary blobs.

Safety contract:

- source-built public user-mode targets only
- no malware samples or exploit packs
- no kernel drivers
- no admin/root execution
- no system-wide installs of vulnerable libraries
- no public listeners; dynamic jobs must use file/stdin/loopback-only runners
- dynamic execution is blocked unless `--allow-vulnerable-fixtures` is present
- all fixture builds and run artifacts belong under ignored `out/real9_*` paths

The checked-in manifest is:

```powershell
benchmarks\real9\manifest.json
```

It pins the archived Google `fuzzer-test-suite` source at:

```text
6955fc97efedfda7dcc0979658b169d7eeb5ccd6
```

Clean baseline entries are also pinned to immutable upstream commits:

- c-ares `v1.34.6` peeled commit:
  `3ac47ee46edd8ea40370222f91613fc16c434853`
- libxml2 `v2.13.9` peeled commit:
  `04af2cabb9f859c198b8a553c028a87481199410`

To stage pinned public source only, without building or executing vulnerable
fixtures:

```powershell
.\benchmarks\real9\stage_real9.ps1 -Stage fetch -Out out\real9_stage
```

Equivalent raw command:

```powershell
cargo run --features vuln-discovery --bin axe-bench -- --preset real-9 --manifest benchmarks\real9\manifest.json --out out\real9_stage --real9-stage fetch --real9-source-root out\real9_sources
```

This writes `out\real9_stage\real9_stage.json`. The stage report is part of
`real9_grade.json` and the gate fails with `external_sources_not_staged` until
all external sources are pinned and ready.

To emit non-executing build plans for the staged `fuzzer-test-suite` fixtures
and the clean CMake baselines:

```powershell
.\benchmarks\real9\stage_real9.ps1 -Stage build -Out out\real9_build_plan
```

`-Stage build` does not run the vulnerable binaries and does not launch fuzzing.
It records `build_plan` entries with `executed: false`, the `build.sh` path,
or `CMakeLists.txt` path, the expected fixture output, and the exact shell
command needed for a disposable Linux/WSL/container builder.

The manifest is analysis-only until the pinned targets are staged under
`out\real9_fixtures`. A dry run that does not execute vulnerable fixtures:

```powershell
cargo run --features vuln-discovery --bin axe-bench -- --preset real-9 --manifest benchmarks\real9\manifest.json --out out\real9_gate
```

Dynamic execution requires the explicit safety flag:

```powershell
cargo run --features vuln-discovery-fuzz,vuln-discovery-trace,vuln-discovery-concolic --bin axe-bench -- --preset real-9 --manifest benchmarks\real9\manifest.json --out out\real9_gate --real9-build missing --dynamic-jobs auto --dynamic-budget-secs 60 --allow-vulnerable-fixtures --emit-repro-packets
```

The gate writes `benchmark_summary.json`, `real9_grade.json`,
`benchmark_cases.jsonl`, `benchmark_findings.jsonl`, `benchmark_report.md`,
and per-case `repro_packets/*.json` when `--emit-repro-packets` is set.

Passing Real-9 requires external known bugs to be found, clean baselines to stay
within their false-positive caps, and dynamic-required findings to have
chain-specific evidence from `fuzz`, `trace`, `concolic`, or `debug_probe`.
