#!/usr/bin/env bash
# Regenerate Module 1+2 (atg.json + hypotheses.json) for all 12 benchmarks via
# the LLM pipeline (NVIDIA NIM gpt-oss-120b, free). Output -> results/<bridge>_regen/.
# Does NOT touch benchmarks/<bridge>/llm_outputs/ (copy step is done separately
# after reviewing the regenerated artifacts).
set -u
cd "$(dirname "$0")/.."

# load .env (strip CRLF) into the environment
set -a
source <(tr -d '\r' < .env)
set +a
export PYTHONIOENCODING=utf-8

BRIDGES="nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad"
echo "=== regen start | provider=$LLM_PROVIDER model=$NVIDIA_MODEL ==="
for b in $BRIDGES; do
  echo "--- [$b] $(date '+%H:%M:%S') ---"
  python -X utf8 -m src.orchestrator \
      --benchmark "benchmarks/$b" \
      --skip-fuzzer --rag-k 3 \
      --output "results/${b}_regen/" 2>&1 \
    && echo "[$b] OK" \
    || echo "[$b] FAILED (exit $?)"
done
echo "=== regen done | $(date '+%H:%M:%S') ==="
