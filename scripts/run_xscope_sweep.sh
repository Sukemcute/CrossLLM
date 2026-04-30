#!/usr/bin/env bash
# Drive the XScope baseline mode across all 12 benchmarks for X4
# acceptance verification. Default budget is short (60 s × 1 run) so a
# laptop / CI smoke pass takes ~12 minutes; production sweeps override
# BUDGET and RUNS.
#
# Outputs results/baselines/xscope/<bridge>/run_NNN.json compatible
# with `scripts/verify_xscope_acceptance.py`.

set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN="$REPO/src/module3_fuzzing/target/release/bridgesentry-fuzzer"
[ -x "$BIN" ] || BIN="$BIN.exe"   # Windows fallback
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUTDIR="${OUTDIR:-$REPO/results/baselines/xscope}"
BUDGET="${BUDGET:-60}"
RUNS="${RUNS:-1}"
BRIDGES="${BRIDGES:-nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad}"

if [ -f "$REPO/.env" ]; then
    set -a; . "$REPO/.env"; set +a
fi

if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found at $BIN — build with: (cd $REPO/src/module3_fuzzing && cargo build --release)"
    exit 1
fi
if [ -z "${ETH_RPC_URL:-}" ]; then
    echo "ERROR: ETH_RPC_URL not set in environment or $REPO/.env"
    exit 1
fi

mkdir -p "$OUTDIR"
echo "=== xscope sweep start $(date -u +%FT%TZ) outdir=$OUTDIR budget=${BUDGET}s runs=$RUNS ==="

t0=$(date +%s)
total=0; ok=0; fail=0
for b in $BRIDGES; do
    BENCH="$REPO/benchmarks/$b"
    META="$BENCH/metadata.json"
    [ -f "$META" ] || { echo "skip $b (no metadata.json)"; continue; }

    # On Windows the `python3` shim is the Microsoft Store stub which
    # prints the install hint instead of running. Prefer python3, fall
    # back to python.
    block=$(python3 -c "import json,sys; m=json.load(open(sys.argv[1])); print(m['fork']['block_number'])" "$META" 2>/dev/null \
        || python -c "import json,sys; m=json.load(open(sys.argv[1])); print(m['fork']['block_number'])" "$META" 2>/dev/null)
    [ -n "${block:-}" ] || { echo "skip $b (no fork.block_number)"; continue; }

    BOUT="$OUTDIR/$b"
    mkdir -p "$BOUT"
    for r in $(seq 1 "$RUNS"); do
        seed=$((r * 1000 + 42))
        rstr=$(printf "%03d" "$r")
        out="$BOUT/run_${rstr}.json"
        log="$BOUT/run_${rstr}.log"
        total=$((total + 1))
        if "$BIN" \
            --atg "$BENCH/llm_outputs/atg.json" \
            --scenarios "$BENCH/llm_outputs/hypotheses.json" \
            --metadata "$META" \
            --baseline-mode xscope \
            --output "$out" \
            --budget "$BUDGET" \
            --source-rpc "$ETH_RPC_URL" \
            --dest-rpc "$ETH_RPC_URL" \
            --source-block "$block" \
            --dest-block "$block" \
            --runs 1 \
            --seed "$seed" \
            > "$log" 2>&1; then
            ok=$((ok + 1)); tag="ok"
        else
            fail=$((fail + 1)); tag="FAIL"
        fi
        elapsed=$(( $(date +%s) - t0 ))
        printf "[%5ds] %-12s %s  %s   total=%d ok=%d fail=%d\n" \
            "$elapsed" "$b" "$rstr" "$tag" "$total" "$ok" "$fail"
    done
done

echo "=== xscope sweep done in $(( $(date +%s) - t0 ))s — ok=$ok fail=$fail / total=$total ==="
echo "Verify: python3 scripts/verify_xscope_acceptance.py $OUTDIR"
