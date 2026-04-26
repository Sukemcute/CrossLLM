# Nomad Benchmark (2022)

This benchmark reconstructs the **Nomad bridge authentication bypass** incident in a form that can be consumed by BridgeSentry/CrossLLM modules.

## Contents

```
benchmarks/nomad/
├── metadata.json
├── mapping.json
├── exploit_trace.json
├── repro.sh
├── repro.ps1
├── README.md
└── contracts/
    ├── Message.sol
    ├── Replica.sol
    ├── BridgeRouter.sol
    └── MockToken.sol
```

## Incident Summary

- Incident date: `2022-08-01`
- Estimated loss: `~$190M`
- First exploit block: `15259101` (fork base in project: `15259100`)
- Main class: `verification_bypass` (V1), with cross-chain state consistency impacts (V3)

## Why this benchmark matters

Nomad’s `Replica` authentication path accepted forged/unproven messages after an upgrade initialized `confirmAt[bytes32(0)] = 1`, making `acceptableRoot(bytes32(0))` pass.  
Because unknown message proofs default to `bytes32(0)`, attackers could call `process()` with copied calldata and modified recipient.

## Reconstruction Design

### Included (high fidelity to RCA)

- Vulnerable `Replica` logic pattern:
  - `initialize(_committedRoot)` sets `confirmAt[_committedRoot] = 1`
  - `process()` checks `acceptableRoot(messages[messageHash])`
  - Unproven message defaults to root `0x00`
- Destination payout path represented by `BridgeRouter.processAndRelease` with
  a typed `NomadMessage.Body` (domain / nonce / sender / recipient / token / amount) encoded
  the same way as `abi.encode` on that struct, so `prove → process` semantics stay explicit.
- Replay-relevant trace and mapping artifacts for Module 2 and Module 3.

### Abstracted/Simplified

- Full multi-chain infra (home/updater/watchers, Moonbeam execution details) is reduced to a local benchmark model.
- Off-chain relayer behavior is represented through scenario actions and `mapping.json`.
- Not all historical contracts are reproduced byte-for-byte.

## Repro Guidance (local)

1. From the **CrossLLM** repository root, generate ATG + hypotheses (or run the helper script):

```bash
python -m src.orchestrator \
  --benchmark benchmarks/nomad \
  --time-budget 60 \
  --runs 1 \
  --skip-fuzzer \
  --output results/nomad_smoke
```

Bash: `bash benchmarks/nomad/repro.sh [output_dir]`

PowerShell: `.\benchmarks\nomad\repro.ps1` (optional `-OutDir results\my_run`)

2. Check generated artifacts:

- `results/nomad_smoke/atg.json`
- `results/nomad_smoke/hypotheses.json`
- `results/nomad_smoke/report.json`

3. To run fuzzer end-to-end, ensure Rust binary exists and Module 3 environment is configured.

## On-chain Reference Artifacts

- Replica contract address (referenced in this benchmark metadata):
  - `0xB92336759618F55bd0F8313bd843604592E27bd8`
- Nomad ERC20 Bridge (Etherscan-labeled):
  - `0x88A69B4E698A4B090DF6CF5BD7B2D47325AD30A3`
- Official recovery wallet:
  - `0x94A84433101A10aEda762968f6995c574D1bF154`
- Representative exploitive transaction (widely cited):
  - `0xa5fe9d044e4f3e5aa5bc4c0709333cd2190cba0f4e7f16bcf73f49f83e4a5460`

## Research Sources

- Nomad official RCA:
  - https://medium.com/nomad-xyz-blog/nomad-bridge-hack-root-cause-analysis-875ad2e5aacd
- Halborn deep dive:
  - https://www.halborn.com/blog/post/the-nomad-bridge-hack-a-deeper-dive
- Etherscan labels:
  - https://etherscan.io/address/0x88a69b4e698a4b090df6cf5bd7b2d47325ad30a3
  - https://etherscan.io/address/0x94a84433101a10aeda762968f6995c574d1bf154

## Validation Checklist

- [x] `metadata.json` present
- [x] `mapping.json` present
- [x] `exploit_trace.json` present
- [x] Solidity benchmark contracts present
- [x] Contracts parse-able by Module 1 extractor (file-level)
- [ ] Full dual-chain replay parity with production incident (future work)
