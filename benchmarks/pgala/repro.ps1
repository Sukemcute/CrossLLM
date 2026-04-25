# Reproduce Module 1 + 2 pipeline output for the pGALA benchmark on Windows.
$ErrorActionPreference = "Stop"

$benchmarkDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $benchmarkDir "..\..")).Path

Push-Location $repoRoot
try {
    python -m src.orchestrator `
        --benchmark $benchmarkDir `
        --time-budget 10 `
        --runs 1 `
        --rag-k 3 `
        --skip-fuzzer `
        --strict-schema `
        --progress `
        --output "results/pgala_smoke/"
}
finally {
    Pop-Location
}

Write-Output ""
Write-Output "Done. Inspect:"
Write-Output "  results/pgala_smoke/atg.json"
Write-Output "  results/pgala_smoke/hypotheses.json"
Write-Output "  results/pgala_smoke/report.json"
