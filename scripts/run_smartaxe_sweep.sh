#!/usr/bin/env bash
# SA7 — Run the SmartAxe re-impl across all 12 benchmarks.
#
# Each bridge gets a single deterministic run (SmartAxe is static
# analysis — no time budget / iteration count to vary). Per-bridge
# expected SC IDs are passed via --expected-sc so the run JSON
# carries the predicate_match summary that verify_smartaxe_acceptance.py
# consumes.
#
# Usage:
#     bash scripts/run_smartaxe_sweep.sh
#
# Override the bridge list:
#     BRIDGES="nomad polynetwork" bash scripts/run_smartaxe_sweep.sh

set -uo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
TOOL_DIR="$REPO/tools/smartaxe_reimpl"
VENV_PY="$TOOL_DIR/.venv/Scripts/python.exe"
[ -x "$VENV_PY" ] || VENV_PY="$TOOL_DIR/.venv/bin/python"

if [ ! -x "$VENV_PY" ]; then
    echo "ERROR: smartaxe-reimpl venv not found at $TOOL_DIR/.venv. Run:"
    echo "    cd $TOOL_DIR && python -m venv .venv && .venv/Scripts/python.exe -m pip install -e \".[dev]\""
    exit 1
fi

# solc-select on Windows reads VIRTUAL_ENV before falling back to
# Path.home(); a stale system VIRTUAL_ENV makes it write artifacts to
# C:\Python314 (read-only). Always clear before invoking.
unset VIRTUAL_ENV

# Ensure solc.exe (a tiny launcher in venv Scripts) is on PATH so
# crytic-compile can spawn it.
export PATH="$TOOL_DIR/.venv/Scripts:$PATH"

OUTDIR="${OUTDIR:-$REPO/results/baselines/smartaxe}"
BRIDGES="${BRIDGES:-nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad}"

# Per-bridge expected SC ID(s) — anchored to spec §4. Each value is
# a comma-separated list; multiple --expected-sc flags are emitted.
declare -A EXPECTED=(
    [nomad]="SC4"
    [qubit]="SC1,SC2"
    [pgala]="SC4,SC5"
    [polynetwork]="SC3"
    [wormhole]="SC4"
    [socket]="SC2"
    [ronin]="SC4"
    [harmony]="SC4"
    [multichain]="SC4"
    [orbit]="SC4"
    [fegtoken]="SC5"
    [gempad]="SC6"
)

mkdir -p "$OUTDIR"
echo "=== smartaxe-reimpl sweep start $(date -u +%FT%TZ) outdir=$OUTDIR ==="

t0=$(date +%s)
total=0; ok=0; fail=0
for b in $BRIDGES; do
    BENCH="$REPO/benchmarks/$b"
    META="$BENCH/metadata.json"
    CONTRACTS="$BENCH/contracts"
    if [ ! -f "$META" ]; then
        echo "skip $b (no metadata.json)"
        continue
    fi
    if [ ! -d "$CONTRACTS" ]; then
        echo "skip $b (no contracts/)"
        continue
    fi

    BOUT="$OUTDIR/$b"
    mkdir -p "$BOUT"

    # Build --expected-sc flags. Each comma-separated SC ID becomes a
    # repeated flag (the CLI uses argparse `action="append"`).
    expected_args=""
    IFS=',' read -ra SC_LIST <<< "${EXPECTED[$b]:-}"
    for sc in "${SC_LIST[@]}"; do
        [ -n "$sc" ] && expected_args+=" --expected-sc $sc"
    done

    out="$BOUT/run_001.json"
    log="$BOUT/run_001.log"
    total=$((total + 1))

    # Use a subshell so cd doesn't leak. crytic-compile path
    # normalisation breaks on absolute Windows paths (clobbers drive
    # letter to "Users:\..."), so we cd into the bridge dir and pass
    # `contracts/` as a relative path.
    if (
        cd "$BENCH" && "$VENV_PY" -m smartaxe_reimpl run \
            --contracts contracts \
            --metadata metadata.json \
            --output "$out" \
            $expected_args
    ) > "$log" 2>&1; then
        ok=$((ok + 1)); tag="ok"
    else
        fail=$((fail + 1)); tag="FAIL"
    fi
    elapsed=$(( $(date +%s) - t0 ))
    printf "[%5ds] %-12s %s   total=%d ok=%d fail=%d\n" \
        "$elapsed" "$b" "$tag" "$total" "$ok" "$fail"
done

echo "=== sweep done in $(( $(date +%s) - t0 ))s — ok=$ok fail=$fail / total=$total ==="
echo "Verify: $VENV_PY $REPO/scripts/verify_smartaxe_acceptance.py $OUTDIR"
