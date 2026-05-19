# AXE

AXE is a deterministic reverse-engineering analysis engine for producing
machine-readable artifacts from binaries and binary folders. It is designed to
stay model-free in the analyzer itself while emitting structured output that an
external analyst or LLM workflow can inspect.

The Rust workspace currently includes:

- Multi-format binary analysis for PE, ELF, and Mach-O inputs.
- SymbolGraph, semantic index, dossier, summary, and LLM-sized packet outputs.
- Optional feature-gated vulnerability discovery, fuzzing, concolic, dynamic
  trace, and Aurora unpacking components.
- Benchmark fixtures and tests for the public artifact surface.

## Build

```powershell
cargo build
```

The default build is intentionally lightweight. Expensive or platform-specific
capabilities are behind Cargo features.

```powershell
cargo test
cargo test --features vuln-discovery
```

Windows-only or heavy optional features may require additional local setup such
as ETW permissions, WDK tooling, Hyper-V/WHP support, Z3, or Unicorn.

## Usage

Analyze one file or a folder:

```powershell
cargo run --bin axe -- <path-to-binary-or-folder> --out out
```

Run the benchmark CLI when the vulnerability-discovery feature is enabled:

```powershell
cargo run --features vuln-discovery --bin axe-bench -- --help
```

Generated analysis output belongs in ignored directories such as `out/` or
`calibration_runs/`, not in source control.

## Donations

If AXE helps your work, donations are appreciated:

- BTC: `3MsARRVoEYumH4n1jLSH6Ecvd1ToDTMb7L`
- Ethereum / EVM: `0x435E1E637b744eCf75549AafEbf82b02451CdD50`
- Solana: `JCRnqKCTKRF235PdoXx2VANoRZm5jNcW3qWTV8MB9qx1`

## Licensing

This repository is source-available under `LICENSE.md`. You may use AXE for
internal, commercial, government, academic, and security work, but you may not
resell it, repackage it as a competing standalone product, offer it as a hosted
or managed competing service, or use AXE/Aurora branding without permission.

AXE is not released under an OSI-approved open-source license.
