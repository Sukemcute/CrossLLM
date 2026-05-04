#!/usr/bin/env bash
# Full RQ1 sweep for baseline fuzzers (e.g. VulSEye, SmartShot).
#
# Default: 12 benchmarks × 20 runs × 600 s ≈ 40 h wall-clock.
#   Override BUDGET / RUNS / BRIDGES / BASELINE env to change scope.
#
# Output: results/baselines/<baseline>/<bridge>/run_NNN.json + .log

set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN="$REPO/src/module3_fuzzing/target/release/bridgesentry-fuzzer"
[ -x "$BIN" ] || BIN="$BIN.exe"   # Windows fallback
BASELINE="${BASELINE:-vulseye}"
OUTDIR="${OUTDIR:-$REPO/results/baselines/${BASELINE}}"
BUDGET="${BUDGET:-600}"
RUNS="${RUNS:-20}"
BRIDGES="${BRIDGES:-nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad}"

# Source .env so ETH_RPC_URL is available.
if [ -f "$REPO/.env" ]; then
    set -a; . "$REPO/.env"; set +a
fi

if [ ! -x "$BIN" ]; then
    echo "ERROR: binary not found at $BIN — build first: (cd $REPO/src/module3_fuzzing && cargo build --release)"
    exit 1
fi
if [ -z "${ETH_RPC_URL:-}" ]; then
    echo "ERROR: ETH_RPC_URL not set in environment or $REPO/.env"
    exit 1
fi

mkdir -p "$OUTDIR"
echo "=== baseline sweep start $(date -u +%FT%TZ) — outdir=$OUTDIR baseline=$BASELINE budget=${BUDGET}s runs=$RUNS ==="

t0=$(date +%s)
total=0; ok=0; fail=0
for b in $BRIDGES; do
    BENCH="$REPO/benchmarks/$b"
    if [ ! -d "$BENCH" ]; then
        echo "skip $b (benchmark dir missing)"
        continue
    fi
    META="$BENCH/metadata.json"
    if [ ! -f "$META" ]; then
        echo "skip $b (metadata.json missing)"
        continue
    fi

    # Read fork block from metadata.
    block=$(python3 -c "import json,sys; m=json.load(open(sys.argv[1])); print(m['fork']['block_number'])" "$META" 2>/dev/null)
    if [ -z "${block:-}" ]; then
        echo "skip $b (could not read fork.block_number)"
        continue
    fi

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
            --output "$out" \
            --budget "$BUDGET" \
            --source-rpc "$ETH_RPC_URL" \
            --dest-rpc "$ETH_RPC_URL" \
            --source-block "$block" \
            --dest-block "$block" \
            --baseline-mode "$BASELINE" \
            --runs 1 \
            --seed "$seed" \
            > "$log" 2>&1; then
            ok=$((ok + 1))
            tag="ok"
        else
            fail=$((fail + 1))
            tag="FAIL"
        fi
        elapsed=$(( $(date +%s) - t0 ))
        printf "[%6ds] %-12s %s  %s   total=%d ok=%d fail=%d\n" \
            "$elapsed" "$b" "$rstr" "$tag" "$total" "$ok" "$fail"
    done
done
