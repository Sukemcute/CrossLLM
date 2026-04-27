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

# Note: most GPTScan implementations have CLI like
# `python gptscan.py --source-dir <dir> --output <file>`
# but the exact entrypoint varies — verify with --help after install.
START=$(date +%s)
timeout 600 "$PYTHON" "$GPTSCAN_DIR/gptscan.py" \
    --source "$CONTRACTS_DIR" \
    --output "${RAW_LOG}.json" \
    --seed "$SEED" \
    > "$RAW_LOG" 2>&1 || EXIT_CODE=$?
EXIT_CODE="${EXIT_CODE:-0}"
END=$(date +%s)
ELAPSED=$((END - START))

# Parse GPTScan output (LLM returns list of detected vulns per function)
DETECTED=$("$PYTHON" - <<EOF 2>/dev/null
import json
try:
    with open("${RAW_LOG}.json") as f:
        d = json.load(f)
    vulns = d if isinstance(d, list) else d.get("vulnerabilities", []) or d.get("findings", [])
    print("true" if vulns else "false")
except Exception:
    print("null")
EOF
)
DETECTED="${DETECTED:-null}"

VIOLATIONS=$("$PYTHON" - <<EOF 2>/dev/null
import json
try:
    with open("${RAW_LOG}.json") as f:
        d = json.load(f)
    vulns = d if isinstance(d, list) else d.get("vulnerabilities", []) or d.get("findings", [])
    out = [{"id": v.get("type", v.get("category", "unknown")), "first_detected_at_s": $ELAPSED} for v in vulns[:5]]
    print(json.dumps(out))
except Exception:
    print("[]")
EOF
)
VIOLATIONS="${VIOLATIONS:-[]}"

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
