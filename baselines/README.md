# Baselines for RQ1 Comparison

> Phase B của [`docs/PLAN_PAPER_EXPERIMENTS.md`](../docs/PLAN_PAPER_EXPERIMENTS.md).
> Setup + run 6 baseline tools để so sánh với BridgeSentry trên 12
> benchmarks (paper §5.3 / RQ1).

## Tổng quan 6 baselines

| Tool | Loại | Repo / paper | Input | Status (this branch) |
|---|---|---|---|---|
| **ItyFuzz** | Bytecode fuzzer (Rust) | https://github.com/fuzzland/ityfuzz | RPC fork + target addresses | TODO — install attempt below |
| **SmartShot** | Hybrid (rule + LLM) | Paper-only (no public repo at time of writing) | Solidity | TODO — cite published |
| **VulSEye** | Symbolic + ML | Paper-only | Solidity | TODO — cite published |
| **SmartAxe** | Static analysis (Python) | https://github.com/CGCL-codes/SmartAxe | Solidity | TODO — install attempt below |
| **GPTScan** | LLM-based static (Python) | https://github.com/Beokro/GPTScan | Solidity + OpenAI key | TODO — install attempt below |
| **XScope** | Cross-chain analyzer | Paper-only / academic artifact | Bridge mapping | TODO — cite published |

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
