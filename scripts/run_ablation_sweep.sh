#!/usr/bin/env bash
# RQ2 ablation sweep (real-bytecode). Variant of run_full_sweep_real.sh that
# overrides which ATG / scenarios files are fed to the fuzzer.
#
#   ABLATION=se   : generic ATG (offline) + generic scenarios (offline)
#                   -> removes LLM semantic extraction (Module 1)
#   ABLATION=rag  : real LLM ATG + generic scenarios (offline)
#                   -> removes RAG scenario guidance (Module 2)
#
# Usage: ABLATION=se  BUDGET=60 RUNS=20 bash scripts/run_ablation_sweep.sh
#        ABLATION=rag BUDGET=60 RUNS=20 bash scripts/run_ablation_sweep.sh
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN="$REPO/src/module3_fuzzing/target/release/bridgesentry-fuzzer"
[ -x "$BIN" ] || BIN="$BIN.exe"
ABLATION="${ABLATION:?set ABLATION=se|rag}"
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUTDIR="${OUTDIR:-$REPO/results/ablation_${ABLATION}_${TS}}"
BUDGET="${BUDGET:-60}"; RUNS="${RUNS:-20}"
BRIDGES="${BRIDGES:-nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad}"
[ -f "$REPO/.env" ] && { set -a; . "$REPO/.env"; set +a; }
[ -x "$BIN" ] || { echo "ERROR: binary missing: $BIN"; exit 1; }
[ -z "${ETH_RPC_URL:-}" ] && { echo "ERROR: ETH_RPC_URL not set"; exit 1; }

case "$ABLATION" in
  se)  ATG_FILE="atg_offline.json";  SCEN_FILE="hypotheses_offline.json" ;;
  rag) ATG_FILE="atg.json";          SCEN_FILE="hypotheses_offline.json" ;;
  *)   echo "ERROR: ABLATION must be se|rag"; exit 1 ;;
esac

mkdir -p "$OUTDIR"
echo "=== ablation=$ABLATION start $(date -u +%FT%TZ) outdir=$OUTDIR atg=$ATG_FILE scen=$SCEN_FILE budget=${BUDGET}s runs=$RUNS ==="
t0=$(date +%s); total=0; ok=0; fail=0
for b in $BRIDGES; do
  BENCH="$REPO/benchmarks/$b"; META="$BENCH/metadata.json"
  [ -f "$META" ] || { echo "skip $b (no metadata)"; continue; }
  ATG="$BENCH/llm_outputs/$ATG_FILE"; SCEN="$BENCH/llm_outputs/$SCEN_FILE"
  [ -f "$ATG" ] && [ -f "$SCEN" ] || { echo "skip $b (missing $ATG_FILE/$SCEN_FILE)"; continue; }
  block=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['fork']['block_number'])" "$META" 2>/dev/null)
  [ -z "${block:-}" ] && { echo "skip $b (no fork block)"; continue; }
  BOUT="$OUTDIR/$b"; mkdir -p "$BOUT"
  for r in $(seq 1 "$RUNS"); do
    seed=$((r*1000+42)); rstr=$(printf "%03d" "$r"); total=$((total+1))
    if "$BIN" --atg "$ATG" --scenarios "$SCEN" --metadata "$META" \
        --output "$BOUT/run_${rstr}.json" --budget "$BUDGET" \
        --source-rpc "$ETH_RPC_URL" --dest-rpc "$ETH_RPC_URL" \
        --source-block "$block" --dest-block "$block" --runs 1 --seed "$seed" \
        > "$BOUT/run_${rstr}.log" 2>&1; then ok=$((ok+1)); tag=ok; else fail=$((fail+1)); tag=FAIL; fi
    printf "[%6ds] %-12s %s  %s   total=%d ok=%d fail=%d\n" "$(( $(date +%s)-t0 ))" "$b" "$rstr" "$tag" "$total" "$ok" "$fail"
  done
done
echo "=== ablation=$ABLATION done in $(( $(date +%s)-t0 ))s — ok=$ok fail=$fail / total=$total ==="
echo "$OUTDIR"
