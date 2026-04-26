#!/usr/bin/env bash
# Reproduce Module 1 + 2 pipeline output for the Qubit benchmark.
# Run from anywhere — the script resolves paths relative to its location.
set -euo pipefail

BENCHMARK_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${BENCHMARK_DIR}/../.." && pwd)"

cd "${REPO_ROOT}"

python -m src.orchestrator \
    --benchmark "${BENCHMARK_DIR}" \
    --time-budget 10 \
    --runs 1 \
    --rag-k 3 \
    --skip-fuzzer \
    --strict-schema \
    --progress \
    --output "results/qubit_smoke/"

echo
echo "Done. Inspect:"
echo "  results/qubit_smoke/atg.json"
echo "  results/qubit_smoke/hypotheses.json"
echo "  results/qubit_smoke/report.json"
