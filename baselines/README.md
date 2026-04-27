# Baselines for RQ1 Comparison

> Phase B của [`docs/PLAN_PAPER_EXPERIMENTS.md`](../docs/PLAN_PAPER_EXPERIMENTS.md).
> Setup + run 6 baseline tools để so sánh với BridgeSentry trên 12
> benchmarks (paper §5.3 / RQ1).

## Tổng quan 6 baselines

| Tool | Loại | Repo / paper | Input | Status (this branch) |
|---|---|---|---|---|
| **ItyFuzz** | Bytecode fuzzer (Rust) | https://github.com/fuzzland/ityfuzz | RPC fork + target addresses | **WORKING ✅** — built (53MB binary), smoke tested on Nomad real bytecode (44.18% instruction coverage in 90s, 0 objectives in short budget) |
| **SmartShot** | Hybrid (rule + LLM) | Paper-only (no public repo at time of writing) | Solidity | Cite-published path; `_cited_results/smartshot.json` template ready (TBD-populated) |
| **VulSEye** | Symbolic + ML | Paper-only | Solidity | Cite-published path; `_cited_results/vulseye.json` template ready |
| **SmartAxe** | Static analysis (Python) | 404 on canonical URL (5 variants tried) | Solidity | Cite-published path (default); `_cited_results/smartaxe.json` template ready |
| **GPTScan** | LLM-based static (Python) | https://github.com/GPTScan/GPTScan | Solidity + OpenAI key | Self-host **partial** — Python deps + falcon-metatrust patch + sha3 shim + NIM endpoint patch done; blocked on `sudo apt install default-jre`. Cite-published also ready (`_cited_results/gptscan.json`) |
| **XScope** | Cross-chain analyzer | Paper-only / academic artifact | Bridge mapping | Cite-published path; `_cited_results/xscope.json` template |

## Status (2026-04-27 evening)

- **B1 install attempts**:
  - **ItyFuzz**: ✅ built + smoke-tested. Nomad real bytecode fuzz at 44.18% instruction coverage / 38.33% branch coverage in 90s budget. 0 objectives in short window — needs full 600s for production.
  - **GPTScan**: partial — Python pipeline patched (falcon, sha3 shim via pycryptodome, openai 0.27.x downgrade in shared venv, model env vars). Blocked on `sudo apt install default-jre` for SolidityCallgraph JAR.
  - **SmartAxe**: 404 on all canonical URLs → switched to cite-published path.
- **B2 adapters**: 3/3 adapter scripts shipped (ItyFuzz / SmartAxe / GPTScan); ItyFuzz adapter verified end-to-end.
- **B3 run experiments**: ItyFuzz unblocked; GPTScan needs Java install; SmartAxe blocked indefinitely (no public repo).
- **B4 cite published**: 5/6 JSON templates created (SmartShot, VulSEye, XScope + SmartAxe + GPTScan as backup). Cells marked `TBD` for Member A to populate from each baseline's paper Table N (~5-8 hours total).
- **Aggregator**: `scripts/collect_baseline_results.py` verified end-to-end on existing BridgeSentry data — Nomad cell renders as `✓ (0.0001±0.0000s)`.

### Next-step commands for Member A

```bash
# === ItyFuzz: ready to do full sweep ===
cd ~/CrossLLM
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
    for run in $(seq 1 20); do
        bash scripts/run_baseline.sh ityfuzz $b $run
    done
done   # ~40 hours wall-clock — overnight job

# === GPTScan: finish Java install + smoke ===
sudo apt install -y default-jre default-jdk python3.11-venv
# Then follow remaining steps in baselines/gptscan/INSTALL.md

# === Populate cited results (5 tools × ~1 hour reading + extraction) ===
# Edit baselines/_cited_results/{smartshot,vulseye,xscope,smartaxe,gptscan}.json
# Replace `null` cells with values from each paper's Table N

# === Aggregate to RQ1 LaTeX table ===
python scripts/collect_baseline_results.py --format latex > /tmp/rq1.tex
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
