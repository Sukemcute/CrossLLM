# Qubit Bridge Benchmark

Reconstructed from the **2022-01-27 Qubit Finance bridge exploit** (~$80M loss).

## Bug summary

The Ethereum-side QBridge router used a "native sentinel" code path — when
`tokenContract == address(0)` it treated the call as a native ETH deposit
and emitted a `Deposit(token, amount, recipient, nonce)` event. The deployed
router **did not validate** that the supplied `amount` matched `msg.value`,
so an attacker could call:

```solidity
deposit(token = address(0), amount = 1.875e21, recipient = attacker)
```

with `msg.value = 0` and the bridge would still emit a `Deposit` event for
~206,809 ETH worth of value. The off-chain relayer trusted the emitted event
and the BSC-side bridge minted `qXETH` to the attacker without any
cross-chain consistency check. Attacker drained the lending pool by using
the bogus `qXETH` as collateral.

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `asset_conservation` | `sourceRouter.totalLocked() == destRouter.totalMinted() - fee` | `totalLocked` stays 0 (msg.value = 0); `totalMinted` jumps to 206,809 ETH-equivalent. |
| `authorization` | Every `mint` must be preceded by a verified `lock` on the source chain | No real lock occurred — only the forged event. |

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/QBridgeETH.sol` | Source-side router with the missing `msg.value` check |
| `contracts/QBridgeBSC.sol` | Destination-side router that mints against any relayed event |
| `contracts/MockToken.sol` | Minimal `qXETH` token (xQubit) |

The bug is intentionally narrowed: the production router has thousands of
lines for AMM/pricing, but the cross-chain provenance flaw lives entirely
in the deposit event path. Module 1 should infer the lock + mint flow from
these three files; Module 2 should produce a `fake_deposit`
(verification-bypass) scenario that fires the asset-conservation invariant
with a single forged step.

## Pipeline test

```bash
# Quick offline smoke test (no API key needed)
bash benchmarks/qubit/repro.sh

# With NVIDIA NIM (sets ATG/scenarios via LLM)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/qubit/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/qubit_smoke/
```

Successful output produces `results/qubit_smoke/atg.json` with at least
the lock + mint edges and `hypotheses.json` with at least one
`fake_deposit` scenario whose first action targets the destination chain.

## References

- [Qubit Finance — Protocol Exploit Report](https://medium.com/@QubitFin/protocol-exploit-report-305c34540fa3)
- [Rekt News — Qubit Rekt](https://rekt.news/qubit-rekt/)
- [BscScan: QBridge contract](https://bscscan.com/address/0xF734985f7d40Bcc0B2E3FA5d0cb2A86C12BDF7eb)

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (3 files) |
| Trace curated | Yes (`exploit_trace.json`) |
| Cross-chain mapping documented | Yes (`mapping.json`) |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — needs BSC RPC + on-chain re-deploy |
