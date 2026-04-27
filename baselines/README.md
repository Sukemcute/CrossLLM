# Baselines for RQ1 Comparison

> Phase B của [`docs/PLAN_PAPER_EXPERIMENTS.md`](../docs/PLAN_PAPER_EXPERIMENTS.md).
> Setup + run 6 baseline tools để so sánh với BridgeSentry trên 12
> benchmarks (paper §5.3 / RQ1).

## Tổng quan 6 baselines

| Tool | Loại | Repo / paper | Input | Status (this branch) |
|---|---|---|---|---|
| **ItyFuzz** | Bytecode fuzzer (Rust) | https://github.com/fuzzland/ityfuzz | RPC fork + target addresses | **Cloned** + adapter ready; build **BLOCKED** on `sudo apt install cmake` (system pkg, interactive password) |
| **SmartShot** | Hybrid (rule + LLM) | Paper-only (no public repo at time of writing) | Solidity | Cite-published path; `_cited_results/smartshot.json` template ready (TBD-populated) |
| **VulSEye** | Symbolic + ML | Paper-only | Solidity | Cite-published path; `_cited_results/vulseye.json` template ready |
| **SmartAxe** | Static analysis (Python) | https://github.com/CGCL-codes/SmartAxe | Solidity | Adapter ready; install pending (Python-only, no system deps) |
| **GPTScan** | LLM-based static (Python) | https://github.com/Beokro/GPTScan | Solidity + OpenAI key | Adapter ready (NIM-compatible); install pending |
| **XScope** | Cross-chain analyzer | Paper-only / academic artifact | Bridge mapping | Cite-published path; `_cited_results/xscope.json` template |

## Status (2026-04-27 evening)

- **B1 install attempts**: ItyFuzz cloned ✅, nightly Rust 1.77 toolchain auto-installed ✅, but `cargo build` fails on missing `cmake` system package. Member A needs to run **`sudo apt install -y cmake build-essential libssl-dev pkg-config`** then retry build.
- **B2 adapters**: 3/3 adapter scripts shipped (ItyFuzz / SmartAxe / GPTScan).
- **B3 run experiments**: pending B1 install completion.
- **B4 cite published**: 3/3 JSON templates created; cells marked `TBD` for Member A to populate from each baseline's paper Table N (~3-6 hours).
- **Aggregator**: `scripts/collect_baseline_results.py` verified end-to-end on existing BridgeSentry data — Nomad cell renders as `✓ (0.0001±0.0000s)`.

### Next-step commands for Member A

```bash
# (1) install system deps once — needs interactive password
sudo apt install -y cmake build-essential libssl-dev pkg-config

# (2) finish ItyFuzz build (10-20 minutes)
cd ~/baselines/ityfuzz/ityfuzz
cargo build --release --no-default-features --features "evm,cmp,dataflow"

# (3) install SmartAxe + GPTScan per their INSTALL.md

# (4) smoke test pipeline (writes results/baselines/ityfuzz/nomad/run_001.json)
bash scripts/run_baseline.sh ityfuzz nomad 1
python scripts/collect_baseline_results.py --format table
```

**Lưu ý:** SmartShot, VulSEye, XScope không có public repo tại thời điểm
viết doc này. Sẽ dùng phương án **B4 (cite published results)** từ paper
gốc cho 3 tools này thay vì tự run. ItyFuzz / SmartAxe / GPTScan có
public artifact → attempt self-install.

## Directory layout

```
baselines/
├── README.md                       # this file
├── ityfuzz/
│   ├── INSTALL.md                  # per-tool install steps
│   ├── version.txt                 # commit hash + version pin
│   └── adapter.sh                  # benchmark -> tool input adapter
├── smartshot/  ...                 # similar structure
└── _cited_results/                 # B4 — extract from published papers
    ├── smartshot.json
    ├── vulseye.json
    └── xscope.json

results/baselines/<tool>/<bridge>/run_NNN.json    # output uniform format
```

## Uniform output schema

Mỗi `results/baselines/<tool>/<bridge>/run_NNN.json`:

```json
{
  "tool": "ityfuzz",
  "tool_version": "0.1.0-abc123",
  "bridge": "nomad",
  "run": 5,
  "seed": 5042,
  "detected": true,
  "tte_seconds": 38.4,
  "violations": [
    {"id": "asset_conservation", "first_detected_at_s": 38.4}
  ],
  "stats": {
    "total_iterations": 1234,
    "wall_clock_s": 600.0,
    "exit_status": "found_violation"
  },
  "stderr_excerpt": "...last 20 lines...",
  "raw_output_path": "results/baselines/ityfuzz/nomad/run_005.raw.txt"
}
```

`scripts/collect_results.py` (Phase D2) sẽ extend để merge format này
vào RQ1 comparison table.

## Reproducibility

- Mỗi tool's `version.txt` ghi commit hash + Python/Rust version dùng
  để install.
- Adapter scripts đọc `benchmarks/<bridge>/metadata.json` để lấy fork
  config + addresses → no manual config drift.
- 20 runs/cell với seeds `i*1000 + 42` (đồng bộ với BridgeSentry's seed
  formula).

## Quick start

```bash
# Install all 3 self-installable tools
bash baselines/ityfuzz/INSTALL.md   # follow steps inside
bash baselines/smartaxe/INSTALL.md
bash baselines/gptscan/INSTALL.md

# Run smoke test on Nomad
bash scripts/run_baseline.sh ityfuzz nomad 1

# Run full sweep (Phase B3)
for t in ityfuzz smartaxe gptscan; do
    for b in nomad qubit pgala polynetwork wormhole socket \
             ronin harmony multichain orbit fegtoken gempad; do
        for r in $(seq 1 20); do
            bash scripts/run_baseline.sh $t $b $r
        done
    done
done

# Aggregate (extends scripts/collect_results.py — Phase D2)
python scripts/collect_baseline_results.py --format latex
```
