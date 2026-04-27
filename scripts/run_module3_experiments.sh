#!/usr/bin/env bash
# =============================================================================
# BridgeSentry Module 3 — Experiment Runner (Bash / Ubuntu)
# Follows experiment_guide.html Section 8.1
#
# Runs the Rust fuzzer on mock data with multiple seeds and time budgets.
# Output: results/<bridge>/run_<seed>.json  (same structure as guide Section 8.3)
#
# Usage:
#   chmod +x scripts/run_module3_experiments.sh
#   ./scripts/run_module3_experiments.sh [--budget 600] [--runs 20] [--bridge nomad]
# =============================================================================

set -euo pipefail

# --- Default parameters (same as PowerShell version) ---
TIME_BUDGET=600     # Default 600s as per paper
RUNS=20             # Paper uses 20 independent runs
BRIDGE="nomad"      # Default benchmark

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --budget)    TIME_BUDGET="$2"; shift 2 ;;
        --runs)      RUNS="$2";        shift 2 ;;
        --bridge)    BRIDGE="$2";      shift 2 ;;
        --atg)       CUSTOM_ATG="$2";  shift 2 ;;
        --scenarios) CUSTOM_SCENARIOS="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Resolve paths (works when run from any directory) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FUZZER_DIR="$PROJECT_ROOT/src/module3_fuzzing"
FIXTURES_DIR="$PROJECT_ROOT/tests/fixtures"

ATG_FILE="${CUSTOM_ATG:-$FIXTURES_DIR/atg_mock.json}"
SCENARIOS_FILE="${CUSTOM_SCENARIOS:-$FIXTURES_DIR/hypotheses_mock.json}"
RESULTS_DIR="$PROJECT_ROOT/results/$BRIDGE"

# --- Validate inputs ---
if [[ ! -f "$ATG_FILE" ]]; then
    echo "ERROR: ATG file not found: $ATG_FILE"
    exit 1
fi
if [[ ! -f "$SCENARIOS_FILE" ]]; then
    echo "ERROR: Scenarios file not found: $SCENARIOS_FILE"
    exit 1
fi

# --- Build fuzzer (release mode for accurate timing) ---
echo ""
echo "=== Building BridgeSentry Fuzzer (release mode) ==="
cd "$FUZZER_DIR"
cargo build --release 2>&1 | tail -5   # Show last 5 lines to confirm build status
FUZZER_BIN="$FUZZER_DIR/target/release/bridgesentry-fuzzer"   # No .exe on Linux!

if [[ ! -f "$FUZZER_BIN" ]]; then
    echo "ERROR: Build failed — binary not found at: $FUZZER_BIN"
    exit 1
fi
echo "Build OK: $FUZZER_BIN"
cd "$PROJECT_ROOT"

# --- Create results directory ---
mkdir -p "$RESULTS_DIR"

# --- Run experiments (Section 8.1) ---
echo ""
echo "=== Running BridgeSentry on [$BRIDGE] ==="
echo "Time budget : ${TIME_BUDGET}s"
echo "Runs        : $RUNS"
echo "Output dir  : $RESULTS_DIR"
echo ""

START_TOTAL=$(date +%s)

for i in $(seq 1 "$RUNS"); do
    SEED=$(( i * 1000 + 42 ))   # Deterministic but varied seeds (same formula as PS1)
    OUTPUT_FILE="$RESULTS_DIR/run_$(printf '%03d' "$i").json"

    printf "  Run %3d/%d  seed=%-6d  ..." "$i" "$RUNS" "$SEED"
    START_RUN=$(date +%s)

    "$FUZZER_BIN" \
        --atg        "$ATG_FILE" \
        --scenarios  "$SCENARIOS_FILE" \
        --budget     "$TIME_BUDGET" \
        --output     "$OUTPUT_FILE" \
        --seed       "$SEED" \
        --alpha 0.3 --beta 0.4 --gamma 0.3 \
        2>/dev/null

    END_RUN=$(date +%s)
    ELAPSED=$(( END_RUN - START_RUN ))

    if [[ -f "$OUTPUT_FILE" ]]; then
        N_VIOL=$(python3 -c "import json,sys; d=json.load(open('$OUTPUT_FILE')); print(len(d.get('violations',[])))" 2>/dev/null || echo "?")
        N_ITER=$(python3 -c "import json,sys; d=json.load(open('$OUTPUT_FILE')); print(d.get('stats',{}).get('total_iterations','?'))" 2>/dev/null || echo "?")
        printf " done  %5ds  violations=%-3s  iterations=%s\n" "$ELAPSED" "$N_VIOL" "$N_ITER"
    else
        printf " FAILED (no output)\n"
    fi
done

END_TOTAL=$(date +%s)
TOTAL_ELAPSED=$(( END_TOTAL - START_TOTAL ))
echo ""
echo "=== All $RUNS runs completed in ${TOTAL_ELAPSED}s ==="
echo "Results saved to: $RESULTS_DIR"
