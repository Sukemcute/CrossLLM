#!/usr/bin/env bash
# =============================================================================
# Baseline runner — Phase B3 of docs/PLAN_PAPER_EXPERIMENTS.md
#
# Usage:
#   bash scripts/run_baseline.sh <tool> <bridge> <run_index>
#
# Examples:
#   bash scripts/run_baseline.sh ityfuzz nomad 1
#   bash scripts/run_baseline.sh smartaxe qubit 5
#
# Output: results/baselines/<tool>/<bridge>/run_<NNN>.json
#
# Each per-tool adapter is at baselines/<tool>/adapter.sh — this top-level
# script just dispatches with normalised args (bridge metadata, output path,
# seed) so callers don't need to know per-tool quirks.
# =============================================================================

set -euo pipefail

# --- Validate args ---
if [[ $# -lt 3 ]]; then
    echo "Usage: $0 <tool> <bridge> <run_index>"
    echo "Tools: ityfuzz | smartshot | vulseye | smartaxe | gptscan | xscope"
    echo "Bridges: nomad | qubit | pgala | polynetwork | wormhole | socket | "
    echo "         ronin | harmony | multichain | orbit | fegtoken | gempad"
    exit 2
fi

TOOL="$1"
BRIDGE="$2"
RUN_IDX="$3"
SEED=$((RUN_IDX * 1000 + 42))

# --- Resolve paths ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BENCHMARK_DIR="$PROJECT_ROOT/benchmarks/$BRIDGE"
ADAPTER="$PROJECT_ROOT/baselines/$TOOL/adapter.sh"
OUTPUT_DIR="$PROJECT_ROOT/results/baselines/$TOOL/$BRIDGE"
OUTPUT_FILE="$OUTPUT_DIR/run_$(printf '%03d' "$RUN_IDX").json"

# --- Validate inputs ---
if [[ ! -d "$BENCHMARK_DIR" ]]; then
    echo "ERROR: Benchmark directory not found: $BENCHMARK_DIR"
    exit 1
fi
if [[ ! -x "$ADAPTER" ]]; then
    echo "ERROR: Adapter not found or not executable: $ADAPTER"
    echo "Did you run 'chmod +x $ADAPTER' or is the tool not yet installed?"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

# --- Dispatch to per-tool adapter ---
echo "[$(date +%H:%M:%S)] Running $TOOL on $BRIDGE (run $RUN_IDX, seed $SEED)..."
START=$(date +%s)

bash "$ADAPTER" \
    --benchmark "$BENCHMARK_DIR" \
    --bridge "$BRIDGE" \
    --run "$RUN_IDX" \
    --seed "$SEED" \
    --output "$OUTPUT_FILE" \
    --project-root "$PROJECT_ROOT" \
    || {
        echo "[$(date +%H:%M:%S)] $TOOL FAILED on $BRIDGE run $RUN_IDX"
        # Write a minimal failure record so the aggregator knows we tried
        cat > "$OUTPUT_FILE" <<EOF
{
  "tool": "$TOOL",
  "bridge": "$BRIDGE",
  "run": $RUN_IDX,
  "seed": $SEED,
  "detected": null,
  "tte_seconds": null,
  "violations": [],
  "stats": {"exit_status": "adapter_failed"},
  "stderr_excerpt": "see results/baselines/$TOOL/$BRIDGE/run_${RUN_IDX}.stderr"
}
EOF
        exit 0
    }

END=$(date +%s)
ELAPSED=$((END - START))
echo "[$(date +%H:%M:%S)] $TOOL on $BRIDGE done in ${ELAPSED}s -> $OUTPUT_FILE"
