#!/bin/bash
# Run BridgeSentry on all 12 benchmarks
# Usage: ./scripts/run_all_benchmarks.sh [time_budget] [runs]

set -e

TIME_BUDGET=${1:-600}
RUNS=${2:-5}

BRIDGES=(
    "nomad"
    "wormhole"
    "polynetwork"
    "ronin"
    "harmony"
    "multichain"
    "socket"
    "orbit"
    "gempad"
    "fegtoken"
    "pgala"
    "qubit"
)

echo "=== Running BridgeSentry on all ${#BRIDGES[@]} benchmarks ==="
echo "Time budget: ${TIME_BUDGET}s | Runs: ${RUNS}"

for bridge in "${BRIDGES[@]}"; do
    echo ""
    echo "--- ${bridge} ---"
    ./scripts/run_benchmark.sh "${bridge}" "${TIME_BUDGET}" "${RUNS}"
done

echo ""
echo "=== All benchmarks completed ==="
echo "Results in results/ directory"
