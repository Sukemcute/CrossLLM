#!/usr/bin/env bash
# RQ3 parameter-sensitivity sweep (real-bytecode). Two modes:
#   PARAM=beta VAL=0.1   -> vary fuzzer waypoint weight --beta, real atg+hypotheses
#   PARAM=k    VAL=5     -> use hypotheses_k5.json (real atg), default beta
# (k=3 uses the canonical hypotheses.json.)
#
# Usage: PARAM=beta VAL=0.1 RUNS=5 BUDGET=60 bash scripts/run_rq3_sweep.sh
set -uo pipefail
REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN="$REPO/src/module3_fuzzing/target/release/bridgesentry-fuzzer"
[ -x "$BIN" ] || BIN="$BIN.exe"
PARAM="${PARAM:?set PARAM=beta|k}"; VAL="${VAL:?set VAL}"
RUNS="${RUNS:-5}"; BUDGET="${BUDGET:-60}"; TS=$(date -u +%Y%m%dT%H%M%SZ)
OUTDIR="${OUTDIR:-$REPO/results/rq3_${PARAM}_${VAL}_${TS}}"
BRIDGES="${BRIDGES:-nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad}"
[ -f "$REPO/.env" ] && { set -a; . "$REPO/.env"; set +a; }
[ -x "$BIN" ] || { echo "ERROR: binary missing"; exit 1; }
[ -z "${ETH_RPC_URL:-}" ] && { echo "ERROR: ETH_RPC_URL not set"; exit 1; }

# resolve scenario file + extra fuzzer args
EXTRA=()
case "$PARAM" in
  beta) SCEN_FILE="hypotheses.json"; EXTRA=(--beta "$VAL") ;;
  k)    if [ "$VAL" = "3" ]; then SCEN_FILE="hypotheses.json"; else SCEN_FILE="hypotheses_k${VAL}.json"; fi ;;
  *)    echo "ERROR: PARAM must be beta|k"; exit 1 ;;
esac

mkdir -p "$OUTDIR"
echo "=== RQ3 $PARAM=$VAL start $(date -u +%FT%TZ) outdir=$OUTDIR scen=$SCEN_FILE runs=$RUNS budget=${BUDGET}s ==="
t0=$(date +%s); total=0; ok=0; fail=0
for b in $BRIDGES; do
  BENCH="$REPO/benchmarks/$b"; META="$BENCH/metadata.json"
  ATG="$BENCH/llm_outputs/atg.json"; SCEN="$BENCH/llm_outputs/$SCEN_FILE"
  [ -f "$META" ] && [ -f "$ATG" ] && [ -f "$SCEN" ] || { echo "skip $b (missing $SCEN_FILE)"; continue; }
  block=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['fork']['block_number'])" "$META" 2>/dev/null)
  [ -z "${block:-}" ] && { echo "skip $b (no block)"; continue; }
  BOUT="$OUTDIR/$b"; mkdir -p "$BOUT"
  for r in $(seq 1 "$RUNS"); do
    seed=$((r*1000+42)); rstr=$(printf "%03d" "$r"); total=$((total+1))
    if "$BIN" --atg "$ATG" --scenarios "$SCEN" --metadata "$META" \
        --output "$BOUT/run_${rstr}.json" --budget "$BUDGET" \
        --source-rpc "$ETH_RPC_URL" --dest-rpc "$ETH_RPC_URL" \
        --source-block "$block" --dest-block "$block" --runs 1 --seed "$seed" \
        "${EXTRA[@]}" > "$BOUT/run_${rstr}.log" 2>&1; then ok=$((ok+1)); tag=ok; else fail=$((fail+1)); tag=FAIL; fi
    printf "[%6ds] %-12s %s  %s   total=%d ok=%d fail=%d\n" "$(( $(date +%s)-t0 ))" "$b" "$rstr" "$tag" "$total" "$ok" "$fail"
  done
done
echo "=== RQ3 $PARAM=$VAL done in $(( $(date +%s)-t0 ))s — ok=$ok fail=$fail / total=$total ==="
echo "$OUTDIR"
