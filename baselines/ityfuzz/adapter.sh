#!/usr/bin/env bash
# Adapter: BridgeSentry benchmark layout -> ItyFuzz CLI.
#
# Reads benchmarks/<bridge>/metadata.json, picks the primary contract
# address + fork block, runs ItyFuzz onchain mode, normalises output to
# results/baselines/ityfuzz/<bridge>/run_<NNN>.json.

set -euo pipefail

# --- Parse named args from run_baseline.sh ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --benchmark)    BENCHMARK_DIR="$2"; shift 2 ;;
        --bridge)       BRIDGE="$2";        shift 2 ;;
        --run)          RUN_IDX="$2";       shift 2 ;;
        --seed)         SEED="$2";          shift 2 ;;
        --output)       OUTPUT_FILE="$2";   shift 2 ;;
        --project-root) PROJECT_ROOT="$2";  shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# --- Locate ItyFuzz binary ---
ITYFUZZ_BIN="${ITYFUZZ_BIN:-$HOME/baselines/ityfuzz/ityfuzz/target/release/ityfuzz}"
if [[ ! -x "$ITYFUZZ_BIN" ]]; then
    echo "ERROR: ItyFuzz binary not found at $ITYFUZZ_BIN"
    echo "Run baselines/ityfuzz/INSTALL.md steps first."
    exit 1
fi

# --- Extract benchmark config from metadata.json ---
METADATA="$BENCHMARK_DIR/metadata.json"
if [[ ! -f "$METADATA" ]]; then
    echo "ERROR: metadata.json missing for $BRIDGE"
    exit 1
fi

# Pick the first non-EOA contract address from metadata.contracts.* as target.
# Use python for robust JSON; the project's venv has it.
PYTHON="${PYTHON:-$PROJECT_ROOT/.crossllm/bin/python}"
[[ -x "$PYTHON" ]] || PYTHON=python3

read -r TARGET_ADDR FORK_BLOCK CHAIN_ID CHAIN_NAME < <("$PYTHON" - <<EOF
import json, sys
with open("$METADATA") as f:
    m = json.load(f)
addr = ""
for k, v in (m.get("contracts") or {}).items():
    if isinstance(v, dict) and not v.get("is_eoa") and v.get("address", "").startswith("0x"):
        addr = v["address"]; break
fork = (m.get("fork") or {}).get("block_number", 0)
src = m.get("source_chain") or {}
print(addr or "0x0", fork or 0, src.get("chain_id", 1), src.get("name", "ethereum"))
EOF
)

# Map chain name to ItyFuzz's -c flag
case "$CHAIN_NAME" in
    ethereum) CHAIN_TYPE="ETH" ;;
    bsc)      CHAIN_TYPE="BSC" ;;
    polygon)  CHAIN_TYPE="POLYGON" ;;
    *)        CHAIN_TYPE="ETH" ;;  # default
esac

# Resolve RPC URL from env (set by .env)
case "$CHAIN_NAME" in
    bsc)      RPC_URL="${BSC_RPC_URL:-}" ;;
    polygon)  RPC_URL="${POLYGON_RPC_URL:-}" ;;
    *)        RPC_URL="${ETH_RPC_URL:-}" ;;
esac

if [[ -z "$RPC_URL" ]]; then
    echo "ERROR: No RPC URL configured for $CHAIN_NAME (need ETH_RPC_URL / BSC_RPC_URL in .env)"
    exit 1
fi

# Etherscan key — needed for ItyFuzz to fetch ABI
ETHERSCAN_KEY="${ETHERSCAN_API_KEY:-}"
if [[ -z "$ETHERSCAN_KEY" ]]; then
    echo "WARNING: ETHERSCAN_API_KEY not set — ItyFuzz onchain mode may fail"
    echo "         (ItyFuzz needs it to fetch contract ABI from Etherscan)"
fi

# --- Run ItyFuzz ---
WORK_DIR="$(dirname "$OUTPUT_FILE")/work_dir_run_${RUN_IDX}"
mkdir -p "$WORK_DIR"

START=$(date +%s)
RAW_LOG="$(dirname "$OUTPUT_FILE")/run_$(printf '%03d' "$RUN_IDX").raw.txt"

# 600s budget per paper convention; --concolic-timeout 60 cap concolic phases
timeout 660 "$ITYFUZZ_BIN" evm \
    -o \
    -t "$TARGET_ADDR" \
    -c "$CHAIN_TYPE" \
    -b "$FORK_BLOCK" \
    -i "$CHAIN_ID" \
    -u "$RPC_URL" \
    ${ETHERSCAN_KEY:+-k "$ETHERSCAN_KEY"} \
    --work-dir "$WORK_DIR" \
    > "$RAW_LOG" 2>&1 || EXIT_CODE=$?
EXIT_CODE="${EXIT_CODE:-0}"
END=$(date +%s)
ELAPSED=$((END - START))

# --- Parse output for detection signal ---
# ItyFuzz prints "FOUND" / "BUG" / corpus details to stdout when it triggers
# an oracle. Use simple grep heuristic.
DETECTED="false"
TTE_SEC="null"
VIOLATIONS="[]"
if grep -qiE "found vulnerability|oracle.*triggered|invariant violated|bug found" "$RAW_LOG" 2>/dev/null; then
    DETECTED="true"
    # Try to extract first detection time from log
    TTE_SEC=$(grep -oE "[0-9]+\.?[0-9]*\s*s.*found" "$RAW_LOG" 2>/dev/null | head -1 | grep -oE "^[0-9]+\.?[0-9]*" || echo "null")
    [[ -z "$TTE_SEC" ]] && TTE_SEC="null"
    VIOLATIONS='[{"id":"ityfuzz_oracle","first_detected_at_s":'"$TTE_SEC"'}]'
fi

# --- Write uniform output JSON ---
cat > "$OUTPUT_FILE" <<EOF
{
  "tool": "ityfuzz",
  "tool_version": "$(cd "$HOME/baselines/ityfuzz/ityfuzz" 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo unknown)",
  "bridge": "$BRIDGE",
  "run": $RUN_IDX,
  "seed": $SEED,
  "detected": $DETECTED,
  "tte_seconds": $TTE_SEC,
  "violations": $VIOLATIONS,
  "stats": {
    "wall_clock_s": $ELAPSED,
    "exit_status": "$([[ $EXIT_CODE -eq 0 ]] && echo ok || echo exit_${EXIT_CODE})"
  },
  "stderr_excerpt": "$(tail -20 "$RAW_LOG" 2>/dev/null | sed 's/"/\\"/g' | tr '\n' '|' | head -c 1000)",
  "raw_output_path": "$RAW_LOG"
}
EOF

echo "ItyFuzz $BRIDGE run $RUN_IDX -> detected=$DETECTED tte=${TTE_SEC}s wall=${ELAPSED}s"
