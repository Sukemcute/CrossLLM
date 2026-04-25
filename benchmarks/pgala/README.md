# pGALA / pNetwork Bridge Incident Benchmark

Reconstructed from the **2022-11-03 pGALA incident** on BSC (~$10M loss).

## Bug summary

pNetwork operated the GALA peg between Ethereum and BSC. After a routine
upgrade of the BSC bridge custodian, **the legacy ECDSA signing key was not
rotated**. The legacy custodian therefore continued to accept mint
authorisations signed with the old key, so an attacker who possessed (or
otherwise reproduced) that key was able to call `mint()` directly and
issue ~1 billion pGALA on BSC. The attacker then dumped those tokens on
PancakeSwap before pNetwork could disable the contract.

The root cause is **operational**, not logic: there is no exotic Solidity
bug here — the bridge correctly verifies the ECDSA signature, but against
an authority that should have been retired. The benchmark intentionally
preserves that distinction so Module 1 emits an authorization-class
invariant about signer rotation and Module 2 produces a `key_compromise`
scenario.

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `authorization` | Every `mint` call must verify against the *current*, rotated signer | `LegacyCustodian.signer` slot was never updated after re-deploy |
| `asset_conservation` | BSC `totalSupply` must not exceed ETH-side `totalLockedOnEthereum` | Attacker minted 1B pGALA with zero matching ETH lock |
| `uniqueness` | Each mint nonce consumed at most once | Not violated directly — but each forged signature consumed a fresh nonce |

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/LegacyCustodian.sol` | Vulnerable bridge custodian; trusts a never-rotated `signer` slot |
| `contracts/pGALAToken.sol` | Minimal pGALA destination token |

The reconstruction deliberately keeps the bug shape minimal:

* `LegacyCustodian.mint(to, amount, nonce, sig)` recovers the signer with
  `ecrecover` and compares against the stored `signer`.
* `LegacyCustodian.rotateSigner(addr)` is the hook pNetwork **failed to
  invoke** during the upgrade.
* `LegacyCustodian.totalLockedOnEthereum` is a view fed by an off-chain
  relayer; oracles compare it against `pGALAToken.totalSupply` to detect
  unbacked mints.

## Pipeline test

```bash
# Quick offline smoke test (no API key required)
bash benchmarks/pgala/repro.sh

# With NVIDIA NIM (LLM-driven ATG + scenarios)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/pgala/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/pgala_smoke/
```

Successful output produces `results/pgala_smoke/atg.json` with at least
the mint flow plus a signer-rotation guard, and `hypotheses.json` with at
least one `key_compromise` (or equivalent) scenario whose first step
calls `mint()` with a forged signature.

## References

- [pNetwork — pGALA on BSC Token Incident (2022-11-03)](https://medium.com/pnetwork/pgala-on-bsc-token-incident-2022-11-03-a09ac6cf68f3)
- [Rekt News — pGALA Rekt](https://rekt.news/pgala-rekt/)

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (2 files) |
| Trace curated | Yes (`exploit_trace.json`) |
| Cross-chain mapping documented | Yes (`mapping.json`) |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — needs BSC archive RPC + key rotation harness |

## Notes for reviewers

The pGALA incident is the strongest example in the BridgeSentry benchmark
of an operational failure that nevertheless presents to the system under
test as a logic-class invariant violation. The fuzzer should treat
"`LegacyCustodian.signer` was rotated whenever the custodian byte-code
was upgraded" as part of the `authorization` invariant rather than relying
on cross-chain accounting alone.
