#!/usr/bin/env bash
# Adapter: BridgeSentry benchmark layout -> SmartAxe (Python static analyzer).

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

SMARTAXE_DIR="${SMARTAXE_DIR:-$HOME/baselines/smartaxe/SmartAxe}"
PYTHON="${PYTHON:-$PROJECT_ROOT/.crossllm/bin/python}"
[[ -x "$PYTHON" ]] || PYTHON=python3

if [[ ! -d "$SMARTAXE_DIR" ]]; then
    echo "ERROR: SmartAxe not installed. See baselines/smartaxe/INSTALL.md"
    exit 1
fi

CONTRACTS_DIR="$BENCHMARK_DIR/contracts"
RAW_LOG="$(dirname "$OUTPUT_FILE")/run_$(printf '%03d' "$RUN_IDX").raw.txt"

START=$(date +%s)
# SmartAxe is static analysis — run is deterministic; one run per (tool, bridge)
# but we still use run index for output path consistency with fuzzers.
timeout 600 "$PYTHON" -m smartaxe analyze \
    --contracts "$CONTRACTS_DIR" \
    --output "${RAW_LOG}.json" \
    > "$RAW_LOG" 2>&1 || EXIT_CODE=$?
EXIT_CODE="${EXIT_CODE:-0}"
END=$(date +%s)
ELAPSED=$((END - START))

# Parse SmartAxe's native JSON output. Schema varies by version; generic
# normaliser:
DETECTED=$("$PYTHON" - <<EOF 2>/dev/null
import json, sys
try:
    with open("${RAW_LOG}.json") as f:
        d = json.load(f)
    findings = d.get("findings", []) or d.get("vulnerabilities", []) or []
    print("true" if findings else "false")
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
    findings = d.get("findings", []) or d.get("vulnerabilities", []) or []
    out = [{"id": f.get("type","unknown"), "first_detected_at_s": $ELAPSED} for f in findings[:5]]
    print(json.dumps(out))
except Exception:
    print("[]")
EOF
)
VIOLATIONS="${VIOLATIONS:-[]}"

# Static analysis — TTE = analysis time = ELAPSED (no fuzz semantics)
cat > "$OUTPUT_FILE" <<EOF
{
  "tool": "smartaxe",
  "tool_type": "static_analysis",
  "tool_version": "$(cd "$SMARTAXE_DIR" 2>/dev/null && git rev-parse --short HEAD 2>/dev/null || echo unknown)",
  "bridge": "$BRIDGE",
  "run": $RUN_IDX,
  "seed": $SEED,
  "detected": $DETECTED,
  "tte_seconds": $ELAPSED,
  "tte_meaning": "static_analysis_wall_clock",
  "violations": $VIOLATIONS,
  "stats": {
    "wall_clock_s": $ELAPSED,
    "exit_status": "$([[ $EXIT_CODE -eq 0 ]] && echo ok || echo exit_${EXIT_CODE})"
  },
  "raw_output_path": "$RAW_LOG"
}
EOF

echo "SmartAxe $BRIDGE run $RUN_IDX -> detected=$DETECTED wall=${ELAPSED}s"
