# Reproduce Module 1 + 2 pipeline output for the Qubit benchmark on Windows.
# Mirror of repro.sh — keeps the smoke test runnable without a POSIX shell.

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
        --output "results/qubit_smoke/"
}
finally {
    Pop-Location
}

Write-Output ""
Write-Output "Done. Inspect:"
Write-Output "  results/qubit_smoke/atg.json"
Write-Output "  results/qubit_smoke/hypotheses.json"
Write-Output "  results/qubit_smoke/report.json"
