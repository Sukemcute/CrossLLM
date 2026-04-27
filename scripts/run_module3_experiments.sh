#!/usr/bin/env bash
# =============================================================================
# BridgeSentry Module 3 — Experiment Runner (Bash / Ubuntu)
# Follows experiment_guide.html Section 8.1
#
# Runs the Rust fuzzer on mock data or real LLM outputs with multiple seeds and time budgets.
# Output: results/<bridge>/run_<seed>.json  (same structure as guide Section 8.3)
#
# Usage:
#   chmod +x scripts/run_module3_experiments.sh
#   ./scripts/run_module3_experiments.sh [--budget 600] [--runs 20] [--bridge nomad]
#   ./scripts/run_module3_experiments.sh [--bridge nomad_mock]  # force mock fixtures
#   ./scripts/run_module3_experiments.sh [--bridge nomad]       # auto-use benchmarks/nomad/llm_outputs
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

RESULTS_DIR="$PROJECT_ROOT/results/$BRIDGE"

resolve_input_paths() {
    # Custom paths always take priority.
    if [[ -n "${CUSTOM_ATG:-}" || -n "${CUSTOM_SCENARIOS:-}" ]]; then
        ATG_FILE="${CUSTOM_ATG:-$FIXTURES_DIR/atg_mock.json}"
        SCENARIOS_FILE="${CUSTOM_SCENARIOS:-$FIXTURES_DIR/hypotheses_mock.json}"
        INPUT_MODE="custom"
        return
    fi

    # Explicit mock mode via bridge suffix, e.g. nomad_mock.
    if [[ "$BRIDGE" == *_mock ]]; then
        ATG_FILE="$FIXTURES_DIR/atg_mock.json"
        SCENARIOS_FILE="$FIXTURES_DIR/hypotheses_mock.json"
        INPUT_MODE="mock-fixture"
        return
    fi

    # Default for real benchmarks: consume Module 1/2 outputs committed in benchmark.
    local llm_dir="$PROJECT_ROOT/benchmarks/$BRIDGE/llm_outputs"
    local llm_atg="$llm_dir/atg.json"
    local llm_hyp="$llm_dir/hypotheses.json"
    if [[ -f "$llm_atg" && -f "$llm_hyp" ]]; then
        ATG_FILE="$llm_atg"
        SCENARIOS_FILE="$llm_hyp"
        INPUT_MODE="benchmark-llm"
        return
    fi

    # Fallback to mock fixtures when no real outputs are available.
    ATG_FILE="$FIXTURES_DIR/atg_mock.json"
    SCENARIOS_FILE="$FIXTURES_DIR/hypotheses_mock.json"
    INPUT_MODE="mock-fallback"
}

validate_benchmark_bundle() {
    # Only enforce benchmark bundle checks when using real benchmark data.
    if [[ "$INPUT_MODE" != "benchmark-llm" ]]; then
        return
    fi

    local benchmark_dir="$PROJECT_ROOT/benchmarks/$BRIDGE"
    local metadata_file="$benchmark_dir/metadata.json"
    local mapping_file="$benchmark_dir/mapping.json"
    local contracts_dir="$benchmark_dir/contracts"

    if [[ ! -f "$metadata_file" ]]; then
        echo "ERROR: Missing benchmark metadata: $metadata_file"
        exit 1
    fi
    if [[ ! -f "$mapping_file" ]]; then
        echo "ERROR: Missing benchmark mapping: $mapping_file"
        exit 1
    fi
    if [[ ! -d "$contracts_dir" ]]; then
        echo "ERROR: Missing benchmark contracts dir: $contracts_dir"
        exit 1
    fi
}

resolve_input_paths

# --- Validate inputs ---
if [[ ! -f "$ATG_FILE" ]]; then
    echo "ERROR: ATG file not found: $ATG_FILE"
    exit 1
fi
if [[ ! -f "$SCENARIOS_FILE" ]]; then
    echo "ERROR: Scenarios file not found: $SCENARIOS_FILE"
    exit 1
fi
validate_benchmark_bundle

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
echo "Input mode  : $INPUT_MODE"
echo "ATG file    : $ATG_FILE"
echo "Scenarios   : $SCENARIOS_FILE"
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
