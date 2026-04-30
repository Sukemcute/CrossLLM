#!/usr/bin/env bash

# Save formatted results table to timestamped text file.
# Usage examples:
#   bash scripts/save_results_table.sh
#   bash scripts/save_results_table.sh --format detail
#   bash scripts/save_results_table.sh --bridge nomad --format table

set -euo pipefail

FORMAT="table"
BRIDGE=""
RESULTS_DIR="results"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --format)
      FORMAT="$2"
      shift 2
      ;;
    --bridge)
      BRIDGE="$2"
      shift 2
      ;;
    --results-dir)
      RESULTS_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ "$FORMAT" != "table" && "$FORMAT" != "detail" && "$FORMAT" != "latex" && "$FORMAT" != "json" ]]; then
  echo "Invalid --format: $FORMAT (allowed: table|detail|latex|json)"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUMMARY_DIR="$ROOT_DIR/$RESULTS_DIR/summary"
mkdir -p "$SUMMARY_DIR"

TS="$(date +%Y%m%d_%H%M%S)"
SCOPE="${BRIDGE:-all_bridges}"
OUT_FILE="$SUMMARY_DIR/${SCOPE}_${FORMAT}_${TS}.txt"

CMD=(python3 "$ROOT_DIR/scripts/collect_results.py" --results-dir "$ROOT_DIR/$RESULTS_DIR" --format "$FORMAT")
if [[ -n "$BRIDGE" ]]; then
  CMD+=(--bridge "$BRIDGE")
fi

echo "Saving results to: $OUT_FILE"
"${CMD[@]}" | tee "$OUT_FILE"
echo "Done."

