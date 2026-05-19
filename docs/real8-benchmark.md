# real-8 benchmark gate

`real-8` is the current controlled breadth gate above `real-5`.
It is intentionally stricter than the planted CTF slice:

- at least 5 completed binaries
- at least 5 required known-bug findings
- no missed required findings
- no requirement failures
- collapsed precision at least 0.90
- false positives per binary at most 0.25
- at least one non-`controlled_fixture` dynamic evidence source

The checked-in source-built corpus lives at:

```powershell
benchmarks\real8\manifest.json
benchmarks\real8\src\*.c
```

Run it from the repository root:

```powershell
cargo run --features vuln-discovery --bin axe-bench -- --manifest benchmarks\real8\manifest.json --out out\real8_gate --preset real-8 --build-fixtures --fixture-out out\real8_fixtures
```

The manifest builds each fixture locally with `gcc` or
`x86_64-w64-mingw32-gcc`, runs a bounded `--axe-probe` subprocess, and
feeds the probe result back into the same vuln proof-packet path as
the static analysis. The evidence source is named
`safe_fixture_probe` so reports cannot confuse it with a generic
fuzzer, debugger trace, or concolic backend.

Current limitation: this is still a controlled source-built corpus.
It raises the operational gate to a real breadth check with dynamic
feedback and proof packets, but it is not the same thing as arbitrary
real-binary fuzzing/concolic confirmation on CVE-bearing binaries.
