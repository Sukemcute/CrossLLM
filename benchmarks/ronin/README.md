# Ronin Bridge Benchmark

Reconstructed from the **2022-03-23 Ronin Bridge exploit** (~$624M loss
— the largest cryptocurrency theft attributed to the Lazarus Group).

## Off-chain compromise note

This is the first **V4 key-compromise** benchmark in the dataset. The
bug being modelled lives **off-chain**: Sky Mavis's spear-phishing
breach handed 5 of 9 validator private keys to the attacker, satisfying
the Ronin Bridge's 5-of-9 ECDSA threshold from a single attacker
identity. **The on-chain code in production enforced its spec
correctly** — the failed assumption is "fewer than 5 of the 9 keys can
be compromised at once".

The benchmark therefore inherits the shared
[`MockMultisig`](../_shared/MockMultisig.sol) harness with `N = 9, K = 5`
and lets Module 2's `key_compromise` / `validator_collusion` scenarios
violate the security argument by varying the *off-chain* dimension —
who controls which keys.

## The Axie DAO stale-permission backstory

Without the Axie DAO delegate the attacker would have stopped at 4-of-9
(the Sky Mavis-controlled keys) — short of the threshold. The 5th key
came from a delegate signing arrangement granted in **November 2021**:
during a user-load surge on Ronin, Axie DAO whitelisted Sky Mavis to
sign on its behalf. The operational need ended weeks later, but **the
allowlist entry was never revoked** — leaving the delegate key still
administered on Sky Mavis infrastructure when the breach happened ~5
months later. This stale-permission failure is the single most
important architectural lesson from the incident and is encoded in the
benchmark's `inv_ronin_no_stale_delegate` invariant.

## Bug summary

```text
off-chain: Lazarus spear-phishes Sky Mavis -> attacker gets 4 keys
off-chain: Axie DAO delegate still on Sky Mavis infra -> attacker gets 5th key
on-chain: |attacker's keys ∩ validator_set| = 5 = threshold

attacker calls RoninBridgeManager.execute with:
  target = address(this)
  data   = encodeCall(unlock, (WETH, attacker, 173_600e18))
  nonce  = fresh
  sigs   = 5 valid ECDSA signatures over the digest
-> threshold met, self-call lands, 173,600 WETH transferred to attacker

attacker repeats with USDC, drains 25,500,000 USDC in the same block.
```

Discovery delay: **6 days** — the attack was noticed only when a Ronin
user reported being unable to withdraw 5,000 ETH on 2022-03-29.

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `validator_set_authority` (off-chain) | Fewer than 5 of the 9 validator keys are compromised at any time | All 5 needed keys land in one attacker's hands |
| `asset_conservation` | `totalLocked[token]` only decreases for legitimate user-initiated unlocks | 173,600 WETH + 25.5M USDC unlocked to attacker without legitimate user trigger |
| `no_stale_delegate` (architectural) | Delegate signing permissions must be revoked when the operational need ends | Axie-DAO-to-Sky-Mavis delegate persisted Nov 2021 → Mar 2022 |

The on-chain `threshold_quorum_authorization` invariant (5 valid sigs ⇒
unlock) was **honoured** — the contract did exactly what it was
specified to do. That is what makes this V4 (key compromise) rather
than V1/V3.

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/RoninBridgeManager.sol` | Custody + threshold-quorum authorisation, extends shared `MockMultisig(9, 5)` |
| `contracts/WrappedToken.sol` | Generic ERC20 standing in for WETH/USDC |
| (shared) `benchmarks/_shared/MockMultisig.sol` | K-of-N ECDSA threshold harness imported via `../../_shared/` |

The lock/unlock pattern uses the **multi-sig self-call idiom**:
withdrawals are encoded as `execute(target=address(this),
data=encodeCall(unlock, ...), nonce, sigs)`. The inherited `execute`
verifies the threshold and self-calls `unlock`, which is guarded by
`require(msg.sender == address(this))` so that no path other than the
validated one can move custody.

## Pipeline test

```bash
# Quick offline smoke test (no API key needed)
bash benchmarks/ronin/repro.sh

# With NVIDIA NIM (sets ATG/scenarios via LLM)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/ronin/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/ronin_smoke/
```

Successful output produces `results/ronin_smoke/atg.json` with at least
the lock + execute + unlock edges and `hypotheses.json` with at least
one `key_compromise` (or `validator_collusion`) scenario whose first
action assumes `|attacker_keys ∩ validator_set| >= threshold`.

## Verify

```bash
python scripts/verify_benchmark.py benchmarks/ronin/
```

`RONIN_RPC_URL` is optional — the script `[skip]`s it gracefully if not
set, exactly as Wormhole does for `SOLANA_RPC_URL`. `ETH_RPC_URL` is
checked against the four Ethereum-side addresses.

## On-chain reference artifacts

- Ronin Bridge Manager (Ethereum): `0x098B716B8Aaf21512996dC57EB0615e2383E2f96`
- Ronin Bridge V2 proxy (Ethereum custody): `0x1A2a1c938CE3eC39b6D47113c7955bAa9DD454F2`
- WETH: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
- USDC: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`
- Representative WETH-drain tx: `0xc28fad5e8d5e0ce6a2eaf67b6687be5d58113e16be590824d6cfa1a94467d0b7`
- Representative USDC-drain tx: `0xed2c72ef1a552ddaec6dd1f5cddf0b59a8f37f82bdda5257d9c7c37db7bb9b08`

## Research sources

- Sky Mavis post-mortem: https://roninblockchain.substack.com/p/community-alert-ronin-validators
- Halborn analysis: https://www.halborn.com/blog/post/explained-the-ronin-hack-march-2022
- Elliptic attribution to Lazarus: https://www.elliptic.co/blog/the-ronin-hack-the-largest-known-cryptocurrency-theft-attributable-to-the-lazarus-group

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (2 files + shared `MockMultisig`) |
| Trace curated | Yes (`exploit_trace.json` — 2 fraudulent tx + Axie DAO stale-permission backstory) |
| Cross-chain mapping documented | Yes (`mapping.json`, ETH ↔ Ronin chain_id 2020) |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — Ethereum-side custody replay only; Ronin-side mint/burn is informational |
