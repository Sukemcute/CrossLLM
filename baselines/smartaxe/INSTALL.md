# SmartAxe install + run

> SmartAxe — cross-contract vulnerability detector (Python + Slither).
> https://github.com/CGCL-codes/SmartAxe

## Status

- **Public repo**: yes
- **Install path**: Python 3.10 + Slither (already in our venv) + custom rules
- **Input**: Solidity source files
- **Output**: JSON report with detected vulnerability patterns

## Install

```bash
mkdir -p ~/baselines/smartaxe
cd ~/baselines/smartaxe
git clone --depth 1 https://github.com/CGCL-codes/SmartAxe.git
cd SmartAxe
git rev-parse HEAD > ../version.txt

# Use existing venv (has slither already)
source ~/CrossLLM/.crossllm/bin/activate
pip install -r requirements.txt

# Or per the SmartAxe docs:
# python3 -m pip install -e .
```

Disk: <100MB. Time: ~5 minutes.

## CLI

SmartAxe is invoked as a Python module:

```bash
python -m smartaxe analyze \
    --contracts benchmarks/<bridge>/contracts/ \
    --output results/baselines/smartaxe/<bridge>/run_NNN.json
```

(Exact CLI signature varies by repo version — verify via
`python -m smartaxe --help` after install.)

## Run on a benchmark

```bash
SMARTAXE=~/baselines/smartaxe/SmartAxe
source ~/CrossLLM/.crossllm/bin/activate

# Run on Nomad
python $SMARTAXE/main.py \
    --contracts ~/CrossLLM/benchmarks/nomad/contracts/ \
    --output ~/CrossLLM/results/baselines/smartaxe/nomad/run_001.json
```

## Adapter

`baselines/smartaxe/adapter.sh` runs SmartAxe with the right contract
folder + writes uniform output JSON. See file in same directory.

## Known issues / mitigations

- **Slither version coupling**: SmartAxe was developed against a specific
  Slither version. Use `solc-select use 0.8.20` (already in our env).
- **No fuzzing time**: SmartAxe is static analysis → reports DR (yes/no)
  but **TTE is not applicable** (analysis time ≠ fuzz time). For RQ1
  table, mark TTE as "static" or report static-analysis wall-clock.
- **Output schema differs from BridgeSentry's** — adapter must normalize.
