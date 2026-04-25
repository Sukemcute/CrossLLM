# Harmony Horizon Bridge Benchmark

Reconstructed from the **2022-06-23 Harmony Horizon Bridge exploit**
(~$100M loss). Pairs with [Sprint R (Ronin)](../ronin/README.md) as the
second **V4 key-compromise** benchmark in the dataset.

## Off-chain compromise note

Same shape as Ronin: the bug being modelled lives **off-chain**. Two of
the four operator hot-wallet private keys leaked via a phishing/malware
campaign attributed to the Lazarus Group (per Elliptic), satisfying
the on-chain 2-of-4 ECDSA threshold from a single attacker identity.
**The on-chain code in production enforced its spec correctly** — the
failed assumption is "fewer than 2 of the 4 hot wallets will be
compromised at once".

## Why include both Ronin and Harmony?

The two benchmarks together stress whether Module 2's RAG retrieval
generalises the multi-sig pattern across *structurally similar* but
*not identical* incidents:

| Property | Ronin (Sprint R) | Harmony Horizon (Sprint H) |
|---|---|---|
| Loss | $624M | $100M |
| Threshold | 5 / 9 (55.6%) | 2 / 4 (50%) |
| Architectural extra | Stale Axie DAO delegate (Nov 2021 → Mar 2022) | All 4 keys reachable from a single hot-wallet host |
| Discovery delay | 6 days | Same-day |
| Distinct assets drained | 2 (WETH, USDC) | 5+ (WETH, USDC, USDT, WBTC, DAI, …) |
| Custody layout | Manager + V2 proxy | Manager + dedicated `EthBucket` |
| Attribution | Lazarus | Lazarus |

If the LLM has populated Ronin's scenarios first, RAG retrieval over
the `signature_authenticity` / `validator_set_authority` invariants
should surface a `key_compromise` template adapter for Horizon's
2-of-4. Failing this is the experiment's *positive signal* — it shows
the framework forces RAG generalisation rather than memorisation.

## Bug summary

```text
off-chain: phishing campaign vs. Harmony staff -> attacker gets 2 of 4 keys
on-chain: |attacker's keys ∩ operator_set| = 2 = threshold

attacker submits 11 batched calls to HorizonEthManager.execute, each with:
  target = address(this)
  data   = encodeCall(unlock, (token_i, recipient_i, amount_i))
  nonce  = N+i
  sigs   = 2 valid ECDSA signatures over the digest
-> threshold met for each, manager self-calls unlock, bucket releases.

Drained over ~5 blocks:
  WETH  13,100  (~$14M)
  USDC  ~$36M
  USDT  ~$14M
  WBTC  ~$6M
  DAI   ~$5M
  + smaller positions (BUSD, AAG, FXS, SUSHI, AAVE, FRAX)
```

Discovery: same-day (vs. Ronin's 6-day delay) — Harmony's monitoring
was tighter; the issue was *preventability*, not detectability.

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `validator_set_authority` (off-chain) | Fewer than 2 of the 4 operator keys are compromised at any time | Both needed keys land on a single attacker-controlled host |
| `manager_to_bucket_authority` | `EthBucket.release` reverts unless `msg.sender == manager` | Honoured — the bucket guard worked; the manager itself was the validated path |
| `asset_conservation` | `bucket.totalLocked[token]` only decreases for legitimate user-initiated unlocks | 11 receipts drain 5+ token positions across ~5 blocks without legitimate triggers |
| `operator_isolation` (architectural) | Operator hot wallets must not be reachable from a single host or phishing campaign | 2 of 4 keys reachable from one attacker foothold |

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/HorizonEthManager.sol` | Threshold authorisation + unlock dispatch, extends shared `MockMultisig(4, 2)` |
| `contracts/EthBucket.sol` | Pure custody pool with `onlyManager` guard — modelled separately so the (manager → bucket) authority-delegation edge is explicit in the ATG |
| `contracts/WrappedToken.sol` | Generic ERC20 reused for WETH / USDC / USDT / WBTC / DAI |
| (shared) `benchmarks/_shared/MockMultisig.sol` | Imported via `../../_shared/MockMultisig.sol` — same harness as Ronin, different `(N, K)` constructor args |

The `manager + bucket` split is the structural differentiator vs. Ronin
(Ronin's manager held custody directly). Module 1 should produce an ATG
with an extra contract node and a delegation edge; Module 2's invariant
`inv_horizon_manager_to_bucket_authority` is intentionally absent from
Ronin's mapping so RAG retrieval cannot just copy.

## Pipeline test

```bash
# Quick offline smoke test (no API key needed)
bash benchmarks/harmony/repro.sh

# With NVIDIA NIM (sets ATG/scenarios via LLM)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/harmony/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/harmony_smoke/
```

For the **RAG generalisation experiment**, run Ronin first and pass
its `hypotheses.json` as a seed for Harmony's RAG corpus, then check
whether Harmony's scenarios reuse the Ronin `key_compromise` template
or independently regenerate one.

## Verify

```bash
python scripts/verify_benchmark.py benchmarks/harmony/
```

`HARMONY_RPC_URL` is optional — the script `[skip]`s it gracefully if
not set, exactly as Wormhole does for `SOLANA_RPC_URL` and Ronin does
for `RONIN_RPC_URL`. `ETH_RPC_URL` is checked against the seven
Ethereum-side addresses (manager + bucket + 5 ERC20).

## On-chain reference artifacts

- Horizon Eth Manager: `0x2dCCDB493827E15a5dC8f8b72147E6c4A5620857`
- Horizon Eth Bucket: `0x84943BE3eaeC8dB3915b56F23B7D2F69bbE96d62`
- WETH: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
- USDC: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`
- USDT: `0xdAC17F958D2ee523a2206206994597C13D831ec7`
- WBTC: `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`
- DAI: `0x6B175474E89094C44Da98b954EedeAC495271d0F`
- Representative early-batch tx: `0x5fdd060b00b7d829cb15030d61031e07c7e9f1ee9a5a4e1f81e5b53c39a03a89`
- Representative later-batch tx: `0x8c4a8db5a3efbe2403f7c0e76ae9dec18f5e3def86c0c95dcf5e0ba56d2f5f00`

## Research sources

- Harmony post-mortem: https://medium.com/harmony-one/lessons-from-the-harmony-bridge-hack-1c3a72b9d58b
- Elliptic attribution: https://www.elliptic.co/blog/harmony-horizon-bridge-100-million-hack-may-be-linked-to-lazarus-group

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (3 files + shared `MockMultisig`) |
| Trace curated | Yes (`exploit_trace.json` — 11 batched txs across ~5 blocks, Lazarus attribution) |
| Cross-chain mapping documented | Yes (`mapping.json`, ETH ↔ Harmony chain_id 1666600000, 5 distinct assets) |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — Ethereum-side custody replay only; Harmony-side mint/burn is informational |
