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

USER_BASELINE_SET="${BASELINE+x}"; USER_BASELINE="${BASELINE:-}"
USER_OUTDIR_SET="${OUTDIR+x}"; USER_OUTDIR="${OUTDIR:-}"
USER_BUDGET_SET="${BUDGET+x}"; USER_BUDGET="${BUDGET:-}"
USER_RUNS_SET="${RUNS+x}"; USER_RUNS="${RUNS:-}"
USER_BRIDGES_SET="${BRIDGES+x}"; USER_BRIDGES="${BRIDGES:-}"

# Source .env so ETH_RPC_URL is available. Preserve explicit caller overrides.
if [ -f "$REPO/.env" ]; then
    set -a; . "$REPO/.env"; set +a
fi
[ -n "$USER_BASELINE_SET" ] && BASELINE="$USER_BASELINE"
[ -n "$USER_OUTDIR_SET" ] && OUTDIR="$USER_OUTDIR"
[ -n "$USER_BUDGET_SET" ] && BUDGET="$USER_BUDGET"
[ -n "$USER_RUNS_SET" ] && RUNS="$USER_RUNS"
[ -n "$USER_BRIDGES_SET" ] && BRIDGES="$USER_BRIDGES"

BASELINE="${BASELINE:-vulseye}"
OUTDIR="${OUTDIR:-$REPO/results/baselines/${BASELINE}}"
BUDGET="${BUDGET:-600}"
RUNS="${RUNS:-20}"
BRIDGES="${BRIDGES:-nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad}"

BIN_IS_WINDOWS=0
case "$BIN" in
    *.exe) BIN_IS_WINDOWS=1 ;;
esac

host_path() {
    if [ "$BIN_IS_WINDOWS" -eq 1 ]; then
        if command -v wslpath >/dev/null 2>&1; then
            wslpath -w "$1"
            return
        fi
        if command -v cygpath >/dev/null 2>&1; then
            cygpath -w "$1"
            return
        fi
    fi
    printf '%s' "$1"
}

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
            --atg "$(host_path "$BENCH/llm_outputs/atg.json")" \
            --scenarios "$(host_path "$BENCH/llm_outputs/hypotheses.json")" \
            --metadata "$(host_path "$META")" \
            --output "$(host_path "$out")" \
            --budget "$BUDGET" \
            --source-rpc "$ETH_RPC_URL" \
            --dest-rpc "$ETH_RPC_URL" \
            --source-block "$block" \
            --dest-block "$block" \
            --baseline-mode "$BASELINE" \
            --runs 1 \
            --seed "$seed" \
            > "$log" 2>&1; then
            if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); c=d.get("coverage",{}); log=d.get("stats",{}).get("deployment_plan_log",[]); bb=int(c.get("basic_blocks_source",0))+int(c.get("basic_blocks_dest",0)); assert bb > 0, "zero EVM basic-block coverage"; assert any(x=="coverage_status=real_evm" for x in log), "missing coverage_status=real_evm"' "$out" >> "$log" 2>&1; then
                ok=$((ok + 1))
                tag="ok"
            else
                fail=$((fail + 1))
                tag="FAIL"
            fi
        else
            fail=$((fail + 1))
            tag="FAIL"
        fi
        elapsed=$(( $(date +%s) - t0 ))
        printf "[%6ds] %-12s %s  %s   total=%d ok=%d fail=%d\n" \
            "$elapsed" "$b" "$rstr" "$tag" "$total" "$ok" "$fail"
    done
done
