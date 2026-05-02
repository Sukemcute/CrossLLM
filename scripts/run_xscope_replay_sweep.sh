#!/usr/bin/env bash
# X3-polish A3 — XScope replay-mode sweep across the 12 benchmarks.
# Bridges without a populated `metadata.exploit_replay.tx_hashes` are
# skipped automatically (the binary exits with the appropriate
# message). Bridges with cached txs replay the actual on-chain
# exploit transactions instead of the LLM-generated scenarios; this
# is the only path that reliably fires I-5 / I-6 on the per-incident
# storage / log patterns the spec §4 expected map predicts.

set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN="$REPO/src/module3_fuzzing/target/release/bridgesentry-fuzzer"
[ -x "$BIN" ] || BIN="$BIN.exe"
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
    echo "ERROR: ETH_RPC_URL not set"
    exit 1
fi

PYTHON="${PYTHON:-}"
if [ -z "$PYTHON" ]; then
    if python3 -c "import sys" >/dev/null 2>&1; then
        PYTHON=python3
    else
        PYTHON=python
    fi
fi

mkdir -p "$OUTDIR"
echo "=== xscope replay sweep start $(date -u +%FT%TZ) outdir=$OUTDIR budget=${BUDGET}s runs=$RUNS ==="

t0=$(date +%s)
total=0; ok=0; fail=0; skipped=0
for b in $BRIDGES; do
    BENCH="$REPO/benchmarks/$b"
    META="$BENCH/metadata.json"
    [ -f "$META" ] || { echo "skip $b (no metadata.json)"; continue; }

    # Bridges without tx_hashes are skipped (replay loader would error
    # out on empty cache). Pre-flight check keeps the sweep log clean.
    has_tx=$($PYTHON -c "import json,sys; m=json.load(open(sys.argv[1])); r=m.get('exploit_replay',{}); print(int(bool(r.get('tx_hashes'))))" "$META" 2>/dev/null || echo 0)
    if [ "$has_tx" != "1" ]; then
        skipped=$((skipped + 1))
        printf "[%5ds] %-12s SKIP (no exploit_replay.tx_hashes)\n" "$(( $(date +%s) - t0 ))" "$b"
        continue
    fi

    block=$($PYTHON -c "import json,sys; m=json.load(open(sys.argv[1])); print(m['fork']['block_number'])" "$META" 2>/dev/null)
    [ -n "${block:-}" ] || { echo "skip $b (no fork.block_number)"; continue; }

    # Replay-specific RPC override: `exploit_replay.rpc_env` wins over
    # `source_chain.rpc_env` so a bridge declared as ETH→BSC (like
    # qubit / pgala — `source` = the *deposit* chain) can still be
    # forked on the chain where the exploit tx actually executed.
    src_env=$($PYTHON -c "import json,sys; m=json.load(open(sys.argv[1])); print(m.get('exploit_replay',{}).get('rpc_env') or m.get('source_chain',{}).get('rpc_env','ETH_RPC_URL'))" "$META" 2>/dev/null)
    dst_env=$($PYTHON -c "import json,sys; m=json.load(open(sys.argv[1])); print(m.get('destination_chain',{}).get('rpc_env','ETH_RPC_URL'))" "$META" 2>/dev/null)
    if [ -z "${!src_env:-}" ]; then
        skipped=$((skipped + 1))
        printf "[%5ds] %-12s SKIP (env %s unset — archival RPC required)\n" "$(( $(date +%s) - t0 ))" "$b" "$src_env"
        continue
    fi
    src_rpc="${!src_env}"
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
            --baseline-mode xscopereplay \
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
        printf "[%5ds] %-12s %s  %s   total=%d ok=%d fail=%d skipped=%d\n" \
            "$elapsed" "$b" "$rstr" "$tag" "$total" "$ok" "$fail" "$skipped"
    done
done

echo "=== xscope replay sweep done in $(( $(date +%s) - t0 ))s — ok=$ok fail=$fail skipped=$skipped / total=$total ==="
echo "Verify: $PYTHON scripts/verify_xscope_acceptance.py $OUTDIR"
