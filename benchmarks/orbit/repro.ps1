# Reproduce Module 1+2 pipeline on the Orbit Bridge benchmark (no Rust fuzzer).
# Run from PowerShell, repo root: CrossLLM\benchmarks\orbit\repro.ps1
# Or: pwsh -File path\to\repro.ps1
param(
  [string]$OutDir = "results/orbit_repro"
)
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root.Path
python -m src.orchestrator `
  --benchmark benchmarks/orbit `
  --time-budget 60 `
  --runs 1 `
  --skip-fuzzer `
  --output $OutDir
Write-Host "Artifacts: $OutDir/atg.json, $OutDir/hypotheses.json, $OutDir/report.json"
