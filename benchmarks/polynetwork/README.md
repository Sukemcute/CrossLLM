# PolyNetwork Cross-Chain Bridge Benchmark

Reconstructed from the **2021-08-10 PolyNetwork exploit** (~$611M loss across
Ethereum, BSC, Polygon — at the time the largest DeFi exploit on record).

## Bug summary

PolyNetwork's `EthCrossChainManager` decoded a cross-chain header into
`(target, calldata)` and forwarded the call via `target.call(...)`. The
forwarded call carried `msg.sender == manager`. The bridge's storage
contract `EthCrossChainData` was guarded only by an
`onlyManager(msg.sender == manager)` modifier on `putCurEpochConPubKeyBytes`,
the function that rotated the consensus keeper key.

The attacker simply called:

```solidity
EthCrossChainManager.verifyHeaderAndExecuteTx(
    target = address(EthCrossChainData),
    calldata = abi.encodeCall(putCurEpochConPubKeyBytes, attackerKey)
)
```

The forward made `msg.sender == manager` on the destination call, the
`onlyManager` check trivially passed, and the keeper slot now pointed at
the attacker's key. The attacker then signed arbitrary withdrawal proofs
on Ethereum, BSC and Polygon and drained the bridge's lock pools.

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `authorization` | Keeper rotation must require multi-step governance, not a single forwarded call | `verifyHeaderAndExecuteTx` allowed the manager itself to call its own data contract on behalf of an external caller |
| `asset_conservation` | Withdrawals must match prior locks | Post-hijack proofs released locked assets without any matching deposit |
| `state_consistency` | Keeper state must agree across chains | Hijack ran independently on three chains, propagating the same drift |

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/EthCrossChainManager.sol` | Vulnerable manager with `verifyHeaderAndExecuteTx` |
| `contracts/EthCrossChainData.sol` | Storage contract with the `onlyManager`-guarded keeper rotation |

The reconstruction keeps the bug minimal:

* `EthCrossChainManager.verifyHeaderAndExecuteTx(target, calldata)` is the
  arbitrary-forward entrypoint.
* `EthCrossChainData.putCurEpochConPubKeyBytes` is the keeper-rotation hook
  that should have required additional governance.
* `EthCrossChainManager.signedWithdraw` is the post-hijack drain entry —
  models the "after the takeover, any signed proof passes" state.

The BSC and Polygon legs of the exploit are documented in `metadata.json`
under `secondary_chains` but **not** reconstructed in code; the bug
mechanism is identical and the fuzzer only needs to demonstrate the
takeover once.

## Pipeline test

```bash
# Quick offline smoke test
bash benchmarks/polynetwork/repro.sh

# With NVIDIA NIM (LLM-driven ATG + scenarios)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/polynetwork/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/polynetwork_smoke/
```

Successful output produces `results/polynetwork_smoke/atg.json` capturing
the manager + data nodes plus the verify/forward edges, and
`hypotheses.json` with at least one keeper-hijack scenario whose first
step targets `verifyHeaderAndExecuteTx` with the data contract as
destination.

## References

- [BlockSec — The Further Analysis of the Poly Network Attack](https://blocksecteam.medium.com/the-further-analysis-of-the-poly-network-attack-6c459199c057)
- [Rekt News — Poly Network Rekt](https://rekt.news/polynetwork-rekt/)
- [Etherscan: EthCrossChainManager](https://etherscan.io/address/0x250e76987d838a75310c34bf422ea9f1AC4Cc906)

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (2 files) |
| Trace curated | Yes — three-chain trace in `exploit_trace.json` |
| Cross-chain mapping documented | Yes |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — multi-chain replay (ETH+BSC+Polygon) is out of scope; use ETH leg only |

## Notes for reviewers

This is the most classically "cross-chain" benchmark in BridgeSentry.
Module 1 is expected to surface authorisation invariants on
`putCurEpochConPubKeyBytes`. Module 2 should emit a scenario whose first
step triggers `verifyHeaderAndExecuteTx` with `target` pointing at the
data contract — the canonical PolyNetwork pattern.
