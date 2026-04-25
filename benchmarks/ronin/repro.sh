#!/usr/bin/env bash
# Reproduce Module 1+2 pipeline on the Ronin benchmark (no Rust fuzzer).
# Prereq: from CrossLLM repo root, with Python env that has project deps.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
OUT="${1:-results/ronin_repro}"
python -m src.orchestrator \
  --benchmark benchmarks/ronin \
  --time-budget 60 \
  --runs 1 \
  --skip-fuzzer \
  --output "$OUT"
echo "Artifacts: $OUT/atg.json, $OUT/hypotheses.json, $OUT/report.json"
