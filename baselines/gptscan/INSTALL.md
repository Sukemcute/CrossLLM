# GPTScan install + run

> GPTScan — LLM-based vulnerability scanner.
> Original paper: "GPTScan: Detecting Logic Vulnerabilities in Smart
> Contracts by Combining GPT with Program Analysis" (ICSE 2024).
> Two related repos:
> - [MetaTrustLabs/GPTScan](https://github.com/MetaTrustLabs/GPTScan) —
>   prompts + 10 YAML rules only (no scanner code).
> - [GPTScan/GPTScan](https://github.com/GPTScan/GPTScan) — the actual
>   runnable scanner. **Use this one.**

## Status (2026-04-27)

- **Cloned** `~/baselines/gptscan/GPTScan-full/` from GPTScan/GPTScan
  (commit pinned in `version.txt`).
- **Python deps installed + patched**: working — multiple
  incompatibilities resolved (see "Install steps" below).
- **Java + SolidityCallgraph JAR**: **PENDING — needs sudo install**.
  GPTScan uses a Java-based call-graph extractor (ANTLR4) and refuses
  to run without it.
- **Recommendation**: **cite-published results** from the GPTScan
  paper Tables instead of self-running on 12 BridgeSentry benchmarks.
  Full pipeline self-host takes ~1 day per machine; paper extraction
  ~1 hour. Self-run kept as optional follow-up. See
  [`baselines/_cited_results/gptscan.json`](../_cited_results/gptscan.json)
  template once promoted.

## Install steps (if pursuing self-host)

### 1. Clone and pin

```bash
mkdir -p ~/baselines/gptscan
cd ~/baselines/gptscan
git clone --depth 1 https://github.com/GPTScan/GPTScan.git GPTScan-full
cd GPTScan-full
git rev-parse HEAD > ../version.txt
```

### 2. System packages — REQUIRES sudo

```bash
sudo apt update
sudo apt install -y default-jre default-jdk python3.11-venv
```

`default-jre` is needed for the SolidityCallgraph-1.0-SNAPSHOT JAR
that GPTScan invokes via subprocess. Without it:

```
FileNotFoundError: [Errno 2] No such file or directory: 'java'
```

### 3. Python deps

GPTScan requires `openai==0.27.8` (old API). To avoid breaking the
main BridgeSentry pipeline (which uses a custom NIM client and is
agnostic to `openai` version), use a **dedicated venv**:

```bash
python3 -m venv ~/baselines/gptscan/.venv
source ~/baselines/gptscan/.venv/bin/activate
pip install --upgrade pip

# Skip pysha3 (abandoned, won't compile on Python 3.11) and
# dbus-python (system-coupling). They're listed in requirements.txt
# but not actually needed for GPTScan's core path.
cd ~/baselines/gptscan/GPTScan-full
grep -vE '^(pysha3|dbus-python|falcon-analyzer)' requirements.txt > /tmp/gptscan_reqs.txt
pip install -r /tmp/gptscan_reqs.txt

# Install falcon-metatrust without its broken pysha3 dep
pip install --no-deps "falcon-analyzer@git+https://github.com/MetaTrustLabs/falcon-metatrust"

# Install missing extras
pip install antlr4-python3-runtime==4.12.0 antlr4-tools z3-solver==4.11.2.0 tiktoken
```

### 4. sha3 shim (one-time fix)

falcon-metatrust hardcodes `import sha3` (the pysha3 module). pysha3
is abandoned and won't compile on Python 3.11+. Create a shim that
forwards to pycryptodome's Keccak (Ethereum-compatible):

```bash
PYVER=$(python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
cat > ~/baselines/gptscan/.venv/lib/python$PYVER/site-packages/sha3.py <<'EOF'
"""Shim for the abandoned pysha3 package."""
from Crypto.Hash import keccak as _keccak

class keccak_256:
    def __init__(self, data=b""):
        self._h = _keccak.new(digest_bits=256)
        if data:
            self._h.update(data)
    def update(self, data):
        self._h.update(data)
    def digest(self):
        return self._h.digest()
    def hexdigest(self):
        return self._h.hexdigest()
EOF
```

### 5. Patch chatgpt_api.py to use NVIDIA NIM

GPTScan hardcodes `openai.api_base = "https://api.openai.com/v1"` and
model `gpt-3.5-turbo`. To redirect to NVIDIA NIM (OpenAI-compatible
endpoint, free dev tier), apply the patch script:

```bash
python ~/CrossLLM/baselines/gptscan/patch_chatgpt_api.py
```

The script (committed in this repo) injects env-var lookups for
`OPENAI_API_BASE` / `OPENAI_MODEL` / `OPENAI_MODEL_GPT4` and replaces
the hardcoded model strings. Idempotent — running twice is a no-op.

### 6. Run on a benchmark

```bash
source ~/baselines/gptscan/.venv/bin/activate
set -a && source ~/CrossLLM/.env && set +a
export OPENAI_API_KEY="$NVIDIA_API_KEY"
export OPENAI_API_BASE="https://integrate.api.nvidia.com/v1"
export OPENAI_MODEL="${NVIDIA_MODEL:-openai/gpt-oss-120b}"

cd ~/baselines/gptscan/GPTScan-full/src
python main.py \
    -s ~/CrossLLM/benchmarks/nomad/contracts/Replica.sol \
    -o /tmp/gptscan_smoke/nomad_replica.json \
    -k "$OPENAI_API_KEY"
```

GPTScan expects a **single .sol file** (or a Foundry/Hardhat project
config). Pass one file at a time; the adapter loops over
`benchmarks/<bridge>/contracts/*.sol` if multiple files exist.

## Adapter

[`adapter.sh`](adapter.sh) — see file in same directory. Currently
points at the dedicated venv at `~/baselines/gptscan/.venv/`. Update
`GPTSCAN_VENV` env var if you used a different venv path.

## Known issues / mitigations

- **Stochastic output**: GPTScan calls LLM with temp=0 (deterministic
  in theory) but the LLM provider may still vary. Pin `seed` if API
  supports.
- **Token cost**: each scan ~5K input tokens; NIM dev tier is free.
- **No TTE notion**: GPTScan is one-shot LLM call → wall-clock = LLM
  latency (~30-60s on `gpt-oss-120b`). Report as TTE for RQ1; mark
  as "static" tool type so reviewers know.
- **CallGraph JAR**: requires Java 17+ in PATH. The JAR is bundled in
  the GPTScan repo at `src/jars/SolidityCallgraph-1.0-SNAPSHOT-standalone.jar`.

## Estimated effort

| Step | Effort |
|---|---|
| Clone + Python deps + falcon patch + sha3 shim | ~1 hour |
| sudo apt install java | ~10 min (interactive) |
| First smoke test on 1 benchmark | ~10 min |
| Full sweep 12 benchmarks × 20 runs | ~6-8 hours wall-clock |
| **Or — cite published from paper** | ~1 hour |
