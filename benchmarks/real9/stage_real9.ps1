param(
    [ValidateSet("fetch", "build")]
    [string]$Stage = "fetch",

    [string]$Out = "out\real9_stage",

    [string]$SourceRoot = "out\real9_sources"
)

$ErrorActionPreference = "Stop"

cargo run --features vuln-discovery --bin axe-bench -- `
    --preset real-9 `
    --manifest benchmarks\real9\manifest.json `
    --out $Out `
    --real9-stage $Stage `
    --real9-source-root $SourceRoot
