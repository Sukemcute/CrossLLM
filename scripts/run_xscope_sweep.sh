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

# Cross-platform python — Windows MS Store shim sometimes hijacks `python3`.
PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
    if python3 -c "import sys" >/dev/null 2>&1; then
        PYTHON=python3
    else
        PYTHON=python
    fi
fi

mkdir -p "$OUTDIR"
echo "=== xscope sweep start $(date -u +%FT%TZ) outdir=$OUTDIR budget=${BUDGET}s runs=$RUNS ==="

t0=$(date +%s)
total=0; ok=0; fail=0
for b in $BRIDGES; do
    BENCH="$REPO/benchmarks/$b"
    META="$BENCH/metadata.json"
    [ -f "$META" ] || { echo "skip $b (no metadata.json)"; continue; }

    block=$($PYTHON -c "import json,sys; m=json.load(open(sys.argv[1])); print(m['fork']['block_number'])" "$META" 2>/dev/null)
    [ -n "${block:-}" ] || { echo "skip $b (no fork.block_number)"; continue; }

    # X3-polish A2: route the source / destination RPCs from
    # `metadata.<chain>.rpc_env`. Falls back to ETH_RPC_URL when the
    # named env var is unset (e.g. SOLANA_RPC_URL, MOONBEAM_RPC_URL —
    # we don't have those). This unlocks BSC-resident bridges
    # (fegtoken / gempad / qubit) when BSC_RPC_URL is in .env.
    src_env=$($PYTHON -c "import json,sys; m=json.load(open(sys.argv[1])); print(m.get('source_chain',{}).get('rpc_env','ETH_RPC_URL'))" "$META" 2>/dev/null)
    dst_env=$($PYTHON -c "import json,sys; m=json.load(open(sys.argv[1])); print(m.get('destination_chain',{}).get('rpc_env','ETH_RPC_URL'))" "$META" 2>/dev/null)
    src_rpc="${!src_env:-$ETH_RPC_URL}"
    dst_rpc="${!dst_env:-$ETH_RPC_URL}"

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
            --source-rpc "$src_rpc" \
            --dest-rpc "$dst_rpc" \
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
        printf "[%5ds] %-12s %s  src=%-6s dst=%-6s   total=%d ok=%d fail=%d\n" \
            "$elapsed" "$b" "$rstr" "$src_env" "$dst_env" "$total" "$ok" "$fail"
    done
done

echo "=== xscope sweep done in $(( $(date +%s) - t0 ))s — ok=$ok fail=$fail / total=$total ==="
echo "Verify: python3 scripts/verify_xscope_acceptance.py $OUTDIR"
