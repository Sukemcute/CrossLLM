#!/usr/bin/env bash
# Launch and run the SmartShot real-deploy pipeline in tmux on Ubuntu.

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)
SESSION="${SESSION:-smartshot_real_sweep}"
SMOKE_BUDGET="${SMOKE_BUDGET:-60}"
BUDGET="${BUDGET:-600}"
RUNS="${RUNS:-20}"
BRIDGES="${BRIDGES:-nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad}"
SMOKE_OUTDIR="${SMOKE_OUTDIR:-$REPO/results/baselines/smartshot_smoke}"
FULL_OUTDIR="${FULL_OUTDIR:-$REPO/results/baselines/smartshot}"
LOG_DIR="${LOG_DIR:-$REPO/logs}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOG_FILE="${LOG_FILE:-$LOG_DIR/smartshot_real_sweep_$STAMP.log}"

if [ "${1:-}" != "--inside" ]; then
    if ! command -v tmux >/dev/null 2>&1; then
        echo "ERROR: tmux is not installed. Install it with: sudo apt-get install -y tmux"
        exit 1
    fi
    if tmux has-session -t "$SESSION" 2>/dev/null; then
        echo "ERROR: tmux session already exists: $SESSION"
        echo "Attach with: tmux attach -t $SESSION"
        exit 1
    fi
    mkdir -p "$LOG_DIR"
    tmux new-session -d -s "$SESSION" \
        "cd '$REPO' && SESSION='$SESSION' SMOKE_BUDGET='$SMOKE_BUDGET' BUDGET='$BUDGET' RUNS='$RUNS' BRIDGES='$BRIDGES' SMOKE_OUTDIR='$SMOKE_OUTDIR' FULL_OUTDIR='$FULL_OUTDIR' LOG_FILE='$LOG_FILE' bash scripts/tmux_smartshot_real_sweep.sh --inside"
    echo "Started tmux session: $SESSION"
    echo "Attach: tmux attach -t $SESSION"
    echo "Log: $LOG_FILE"
    exit 0
fi

mkdir -p "$LOG_DIR" "$SMOKE_OUTDIR" "$FULL_OUTDIR"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== SmartShot real sweep tmux runner ==="
echo "started_at=$(date -u +%FT%TZ)"
echo "repo=$REPO"
echo "session=$SESSION"
echo "smoke_outdir=$SMOKE_OUTDIR"
echo "full_outdir=$FULL_OUTDIR"
echo "smoke_budget=${SMOKE_BUDGET}s"
echo "sweep_budget=${BUDGET}s"
echo "runs=$RUNS"
echo "bridges=$BRIDGES"

if [ -f "$REPO/.env" ]; then
    set -a
    . "$REPO/.env"
    set +a
fi

if [ -z "${ETH_RPC_URL:-}" ]; then
    echo "ERROR: ETH_RPC_URL is missing from environment or .env"
    exit 1
fi

echo
echo "=== build release fuzzer ==="
(cd "$REPO/src/module3_fuzzing" && cargo build --release --bin bridgesentry-fuzzer)

echo
echo "=== Nomad SmartShot smoke ==="
BASELINE=smartshot \
BRIDGES=nomad \
RUNS=1 \
BUDGET="$SMOKE_BUDGET" \
OUTDIR="$SMOKE_OUTDIR" \
bash "$REPO/scripts/run_baseline_sweep_real.sh"

echo
echo "=== 12-bridge SmartShot smoke ==="
BASELINE=smartshot \
BRIDGES="$BRIDGES" \
RUNS=1 \
BUDGET="$SMOKE_BUDGET" \
OUTDIR="$SMOKE_OUTDIR" \
bash "$REPO/scripts/run_baseline_sweep_real.sh"

echo
echo "=== smoke acceptance ==="
python3 "$REPO/scripts/verify_smartshot_acceptance.py" "$SMOKE_OUTDIR"

echo
echo "=== full SmartShot sweep ==="
BASELINE=smartshot \
BRIDGES="$BRIDGES" \
RUNS="$RUNS" \
BUDGET="$BUDGET" \
OUTDIR="$FULL_OUTDIR" \
bash "$REPO/scripts/run_baseline_sweep_real.sh"

echo
echo "=== full sweep acceptance + cited JSON ==="
python3 "$REPO/scripts/verify_smartshot_acceptance.py" "$FULL_OUTDIR"
python3 "$REPO/scripts/build_smartshot_self_run_cited.py" --input "$FULL_OUTDIR"

if [ -f "$REPO/scripts/collect_baseline_results.py" ]; then
    python3 "$REPO/scripts/collect_baseline_results.py" --format table || true
fi

echo
echo "completed_at=$(date -u +%FT%TZ)"
