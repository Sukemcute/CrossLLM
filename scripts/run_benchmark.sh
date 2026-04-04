#!/bin/bash
# Run BridgeSentry on a single benchmark
# Usage: ./scripts/run_benchmark.sh <bridge_name> [time_budget] [runs]

set -e

BRIDGE=${1:?"Usage: $0 <bridge_name> [time_budget] [runs]"}
TIME_BUDGET=${2:-600}
RUNS=${3:-5}

echo "=== Running BridgeSentry on ${BRIDGE} ==="
echo "Time budget: ${TIME_BUDGET}s | Runs: ${RUNS}"

source .venv/bin/activate

python3 src/orchestrator.py \
    --benchmark "benchmarks/${BRIDGE}/" \
    --time-budget "${TIME_BUDGET}" \
    --runs "${RUNS}" \
    --rag-k 5 \
    --beta 0.4 \
    --output "results/${BRIDGE}/"

echo "=== Results saved to results/${BRIDGE}/ ==="
