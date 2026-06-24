#!/usr/bin/env bash
# RQ3 k-sweep driver: waits for any running beta sweep to finish (avoid RPC
# contention), then runs the k-sensitivity sweep for k in {1,3,5,10}.
cd /home/quoc/sukem/CrossLLM
export PATH=$HOME/.local/bin:$PATH
while pgrep -f run_rq3_sweep >/dev/null; do sleep 120; done
for KV in 1 3 5 10; do
  TS=$(date -u +%Y%m%dT%H%M%SZ)
  PARAM=k VAL=$KV RUNS=5 BUDGET=60 OUTDIR=$PWD/results/rq3_k_${KV}_$TS \
    bash scripts/run_rq3_sweep.sh
done
echo "=== RQ3 k-driver done ==="
