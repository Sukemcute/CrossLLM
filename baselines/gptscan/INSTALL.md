# GPTScan install + run

> GPTScan — LLM-based vulnerability scanner.
> Original paper: "GPTScan: Detecting Logic Vulnerabilities in Smart
> Contracts by Combining GPT with Program Analysis" (ICSE 2024)
> Public artifact: https://github.com/MetaTrustLabs/GPTLens (related)
> or: https://github.com/Beokro/GPTScan (community port)

## Status

- **Repo**: community ports exist; no single canonical repo
- **Install path**: Python + LLM API key (OpenAI or compatible)
- **Input**: Solidity source files
- **Output**: JSON list of detected vulns per function

## Install

```bash
mkdir -p ~/baselines/gptscan
cd ~/baselines/gptscan
git clone --depth 1 https://github.com/Beokro/GPTScan.git
cd GPTScan
git rev-parse HEAD > ../version.txt

source ~/CrossLLM/.crossllm/bin/activate
pip install -r requirements.txt
```

## API key — option to reuse our NVIDIA NIM key

GPTScan was written for OpenAI's `gpt-4` API. NVIDIA NIM exposes an
OpenAI-compatible endpoint — we can point GPTScan there:

```bash
export OPENAI_API_KEY=$NVIDIA_API_KEY
export OPENAI_BASE_URL=https://integrate.api.nvidia.com/v1
export OPENAI_MODEL=openai/gpt-oss-120b
```

Verify GPTScan's OpenAI client respects `OPENAI_BASE_URL` (some forks
hard-code the URL — patch if needed).

## CLI

```bash
python gptscan.py \
    --source benchmarks/<bridge>/contracts/ \
    --output results/baselines/gptscan/<bridge>/run_NNN.json
```

## Run on a benchmark

```bash
GPTSCAN=~/baselines/gptscan/GPTScan
source ~/CrossLLM/.crossllm/bin/activate
set -a && source ~/CrossLLM/.env && set +a
export OPENAI_API_KEY=$NVIDIA_API_KEY
export OPENAI_BASE_URL=https://integrate.api.nvidia.com/v1

python $GPTSCAN/gptscan.py \
    --source ~/CrossLLM/benchmarks/nomad/contracts/ \
    --output ~/CrossLLM/results/baselines/gptscan/nomad/run_001.json
```

## Adapter

`baselines/gptscan/adapter.sh` — see file in same directory.

## Known issues / mitigations

- **Stochastic output**: GPTScan calls LLM with temp >0 by default →
  different results each run. Pin seed if API supports, otherwise run
  N=20 to get distribution.
- **Token cost**: each scan ~5K input tokens. NIM dev tier is free; on
  OpenAI this is ~$0.15/scan. For 12 × 20 = 240 runs, budget accordingly.
- **No TTE notion**: GPTScan is one-shot LLM call → wall-clock = LLM
  latency (~30-60s on `gpt-oss-120b`). Report as TTE for RQ1 if needed.
