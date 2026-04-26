# Wormhole Bridge Benchmark

Reconstructed from the **2022-02-02 Wormhole bridge exploit** (~$326M loss).

## ⚠️ Solana → EVM simulation note

Wormhole's exploit happened on the **Solana** side: the
`verify_signatures` instruction accepted a forged Sysvar Instructions
account, so the program recorded a "verified" digest for a VAA the
guardian set never signed. The attacker then called `complete_wrapped`
on Solana and minted **120,000 whETH** with no backing on Ethereum.

BridgeSentry's fuzzer is **EVM-only** (revm). This benchmark therefore
models the same trust boundary on EVM:

- `WormholeCore.verifySignaturesLegacy` plays the role of the Solana
  `verify_signatures` instruction with the missing Sysvar Instructions
  validation. It writes to `legacyVerifiedSlot[slotId]` without proving
  `slotId` is bound to the canonical guardian-set record.
- `WormholeCore.parseAndVerifyVM` short-circuits to `valid = true` when
  the legacy slot for the VAA digest is set, mirroring the Solana
  program's trust in the post-`verify_signatures` record.
- `TokenBridge.completeTransfer` mints the wrapped asset to the
  attacker, mirroring `complete_wrapped` on Solana.

**Full Solana-side reproduction would require an SVM harness** outside
the scope of this thesis. This limitation is documented in paper
**Section 6** alongside the other non-EVM benchmark gaps. The EVM
reconstruction is sufficient for Module 1 (semantic extraction) and
Module 2 (attack hypothesis generation) because the ATG-relevant
trust boundary — *who is allowed to mark a VAA digest as verified* — is
preserved in the model. Module 3 (dual-EVM fuzzing) replays the
destination-side `completeTransfer` only.

## Bug summary

The Solana `verify_signatures` instruction took a `sysvar instructions`
account as a function argument, but **did not require** it to equal
`Sysvar1nstructions11111111111111111111111111`. An attacker passed a
self-controlled account whose contents claimed guardian quorum was
reached, and the program accepted it.

```text
verify_signatures(
    instructions = ATTACKER_OWNED_ACCOUNT,   // expected: Sysvar1nstructions...
    vaa_digest   = forged_digest,
    sigs         = empty,
)
→ writes record { digest: forged_digest, verified: true }

complete_wrapped(verified_record, vaa_payload(amount=120000e18, recipient=attacker))
→ mints 120,000 whETH to attacker — no collateral on Ethereum.
```

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `signature_authenticity` | Every accepted VAA digest is signed by ≥ quorum of the active guardian set | `parseAndVerifyVM` returns `valid = true` for a digest that was never signed |
| `guardian_set_authority` | Only the canonical verification record can mark a digest verified | `legacyVerifiedSlot` is writable by any caller via `verifySignaturesLegacy` |
| `asset_conservation` | `TokenBridge.totalMinted ≤ totalLocked − fee` (across chains) | 120,000 whETH minted; 0 ETH locked |
| `vaa_uniqueness` | `completed[digest]` transitions false→true at most once | (preserved — single-use enforcement still holds, the bug is upstream) |

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/WormholeCore.sol` | VAA parser + verifier with the modelled legacy-slot bug |
| `contracts/TokenBridge.sol` | Destination router that mints wrapped assets on a verified VAA |
| `contracts/WrappedAsset.sol` | Minimal mintable ERC20 representing whETH |

Module 1 should infer the verify→complete flow across the two router
contracts; Module 2 should produce a `signature_forgery` /
`verification_bypass` scenario whose first action targets the legacy
verifier and whose second action redeems the now-trusted digest.

## Pipeline test

```bash
# Quick offline smoke test (no API key needed)
bash benchmarks/wormhole/repro.sh

# With NVIDIA NIM (sets ATG/scenarios via LLM)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/wormhole/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/wormhole_smoke/
```

Successful output produces `results/wormhole_smoke/atg.json` with at
least the verify + complete edges and `hypotheses.json` with at least
one `signature_forgery` (or `verification_bypass`) scenario whose first
action calls a verifier on the source side.

## Verify

```bash
python scripts/verify_benchmark.py benchmarks/wormhole/
```

`SOLANA_RPC_URL` is intentionally **not required** — the verify script
flags missing source-chain RPC for non-EVM benchmarks but does not
fail. Only `ETH_RPC_URL` is checked against the destination addresses.

## On-chain reference artifacts

- Wormhole Token Bridge (Ethereum): `0x3ee18B2214AFF97000D974cf647E7C347E8fa585`
- Wormhole Core Bridge (Ethereum): `0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B`
- WETH (Ethereum): `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
- Solana Core Bridge program: `worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth`
- Solana Token Bridge program: `wormDTUJ6AWPNvk59vGQbDvGJmqbDTdgWgAqcLBCgUb`

## Research sources

- Extropy IO post-mortem: https://extropy-io.medium.com/solanas-wormhole-hack-post-mortem-analysis-3b68b9e88e13
- Rekt News: https://rekt.news/wormhole-rekt/
- Etherscan: https://etherscan.io/address/0x3ee18B2214AFF97000D974cf647E7C347E8fa585

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (3 files, EVM analogue of Solana programs) |
| Trace curated | Yes (`exploit_trace.json`) |
| Cross-chain mapping documented | Yes (`mapping.json`) |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — destination-side `completeTransfer` replay only; full Solana reproduction needs SVM harness (paper §6) |
