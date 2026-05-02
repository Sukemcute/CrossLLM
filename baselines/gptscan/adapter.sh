#!/usr/bin/env bash
# Adapter: BridgeSentry benchmark layout -> GPTScan (LLM-based static).

set -euo pipefail

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

GPTSCAN_DIR="${GPTSCAN_DIR:-$HOME/baselines/gptscan/GPTScan}"
PYTHON="${PYTHON:-$PROJECT_ROOT/.crossllm/bin/python}"
[[ -x "$PYTHON" ]] || PYTHON=python3

if [[ ! -d "$GPTSCAN_DIR" ]]; then
    echo "ERROR: GPTScan not installed. See baselines/gptscan/INSTALL.md"
    exit 1
fi

# Reuse our NVIDIA NIM key as OpenAI-compatible (per INSTALL.md)
if [[ -f "$PROJECT_ROOT/.env" ]]; then
    set -a; source "$PROJECT_ROOT/.env"; set +a
fi
export OPENAI_API_KEY="${NVIDIA_API_KEY:-${OPENAI_API_KEY:-}}"
export OPENAI_BASE_URL="${OPENAI_BASE_URL:-https://integrate.api.nvidia.com/v1}"
export OPENAI_MODEL="${OPENAI_MODEL:-${NVIDIA_MODEL:-openai/gpt-oss-120b}}"

if [[ -z "$OPENAI_API_KEY" ]]; then
    echo "ERROR: No LLM API key. Set NVIDIA_API_KEY in .env or OPENAI_API_KEY env."
    exit 1
fi

CONTRACTS_DIR="$BENCHMARK_DIR/contracts"
RAW_LOG="$(dirname "$OUTPUT_FILE")/run_$(printf '%03d' "$RUN_IDX").raw.txt"

# GPTScan CLI: `python src/main.py -s <source> -o <output> -k <api_key>`
# `<source>` must be a single .sol file OR a directory with foundry.toml /
# hardhat.config — our benchmarks have neither, so we loop over .sol files
# and aggregate the results.
START=$(date +%s)
> "$RAW_LOG"  # truncate
ALL_VULNS_JSON='[]'

for SOL_FILE in "$CONTRACTS_DIR"/*.sol; do
    [ -f "$SOL_FILE" ] || continue
    BASE=$(basename "$SOL_FILE" .sol)
    PER_FILE_OUT="${RAW_LOG}.${BASE}.json"

    echo "=== gptscan on ${BASE}.sol ===" >> "$RAW_LOG"
    # GPTScan loads whitelist.json from cwd — must `cd` into src/ before
    # running. Use absolute paths for source + output.
    (
        cd "$GPTSCAN_DIR/src"
        timeout 120 "$PYTHON" main.py \
            -s "$SOL_FILE" \
            -o "$PER_FILE_OUT" \
            -k "$OPENAI_API_KEY" \
            2>&1
    ) >> "$RAW_LOG" 2>&1 || true

    # Aggregate per-file results
    if [ -f "$PER_FILE_OUT" ]; then
        ALL_VULNS_JSON=$("$PYTHON" - "$PER_FILE_OUT" "$ALL_VULNS_JSON" <<'PYEOF'
import json, sys
new_path, prev_json = sys.argv[1], sys.argv[2]
prev = json.loads(prev_json)
try:
    with open(new_path) as f:
        d = json.load(f)
    items = d.get("results", []) or []
    prev.extend(items)
except Exception:
    pass
print(json.dumps(prev))
PYEOF
)
    fi
done
END=$(date +%s)
ELAPSED=$((END - START))

# Decide detected based on aggregated results
DETECTED=$("$PYTHON" - "$ALL_VULNS_JSON" <<'PYEOF'
import json, sys
items = json.loads(sys.argv[1])
print("true" if items else "false")
PYEOF
)

VIOLATIONS=$("$PYTHON" - "$ALL_VULNS_JSON" "$ELAPSED" <<'PYEOF'
import json, sys
items = json.loads(sys.argv[1])
elapsed = float(sys.argv[2])
out = [
    {"id": v.get("rule") or v.get("type") or v.get("scenario") or "unknown",
     "first_detected_at_s": elapsed,
     "function": v.get("function_name", "")}
    for v in items[:10]
]
print(json.dumps(out))
PYEOF
)
VIOLATIONS="${VIOLATIONS:-[]}"
EXIT_CODE=0

cat > "$OUTPUT_FILE" <<EOF
{
  "tool": "gptscan",
  "tool_type": "llm_static",
  "tool_version": "$(cd "$GPTSCAN_DIR" 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo unknown)",
  "model": "$OPENAI_MODEL",
  "bridge": "$BRIDGE",
  "run": $RUN_IDX,
  "seed": $SEED,
  "detected": $DETECTED,
  "tte_seconds": $ELAPSED,
  "tte_meaning": "llm_call_latency",
  "violations": $VIOLATIONS,
  "stats": {
    "wall_clock_s": $ELAPSED,
    "exit_status": "$([[ $EXIT_CODE -eq 0 ]] && echo ok || echo exit_${EXIT_CODE})"
  },
  "raw_output_path": "$RAW_LOG"
}
EOF

echo "GPTScan $BRIDGE run $RUN_IDX -> detected=$DETECTED wall=${ELAPSED}s"
