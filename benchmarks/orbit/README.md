# Orbit Bridge Benchmark

Reconstructed from the **2024-01-01 Orbit Bridge exploit** (~$82M loss).
Fourth **V4 key-compromise** benchmark in the dataset alongside
[Ronin (Sprint R)](../ronin/README.md),
[Harmony Horizon (Sprint H)](../harmony/README.md), and
[Multichain (Sprint M)](../multichain/README.md). Suspected Lazarus
Group per Match Systems forensic analysis.

## Off-chain compromise note

Same shape as Ronin and Harmony: the bug being modelled lives
**off-chain**. Seven of the ten farmer (validator) private keys leaked,
satisfying the on-chain 7-of-10 ECDSA threshold from a single attacker
identity. **The on-chain code in production enforced its spec
correctly** — the failed assumption is "fewer than 7 of the 10 farmer
keys can be compromised at once".

## Differentiator vs. Ronin / Harmony / Multichain

Orbit completes the four-bridge V4 set with the **highest absolute
threshold** and the **highest threshold-to-set ratio** in the off-chain
suite (excluding Multichain's degenerate 1-of-1).

| Property | Ronin | Harmony | Multichain | **Orbit** |
|---|---|---|---|---|
| Loss | $624M | $100M | $126M | **$82M** |
| Threshold (K-of-N) | 5 / 9 | 2 / 4 | 1 / 1 (TSS gap) | **7 / 10** |
| Ratio | 55.6% | 50% | 100% (degenerate) | **70%** |
| Compromise concentration | 5 keys via phishing | 2 keys via phishing | 1 admin via arrest+coercion | **7 keys via concentrated infrastructure access** |
| Drain duration | Same block | ~5 blocks | ~24 hours | **1 block** |
| Drain count | 2 tx | 11 batched tx | 6 large tx | **5 tx (single block)** |
| Distinct assets drained | 2 | 5 | 5 | **5** |
| Custody layout | Manager + V2 proxy | Manager + EthBucket | Single router | **Single vault** |
| Attribution | Lazarus (OFAC sanctioned) | Lazarus (Elliptic) | Officially unconfirmed | **Suspected Lazarus (Match Systems)** |
| Discovery delay | 6 days | Same day | Same day | **Same day** |

The 7/10 threshold did not save Orbit because the compromise was
**highly concentrated**: the attacker reached enough farmer
infrastructure simultaneously from a single foothold to satisfy 7
keys. This is the same structural failure mode as Ronin (where one
phishing campaign cleared the bar), scaled to a larger N.

The single-block drain pattern (all 5 transactions in block 18900155)
indicates **pre-staged transactions ready to broadcast** — a
sophistication signal that distinguishes this from Harmony's rolling
~5-block pattern.

## Bug summary

```text
off-chain: concentrated farmer-host compromise -> attacker gets 7 of 10 keys
on-chain: |attacker's keys ∩ farmer_set| = 7 = threshold

attacker submits 5 calls to OrbitVault.execute in block 18900155, each with:
  target = address(this)
  data   = encodeCall(unlock, (token_i, attacker, amount_i))
  nonce  = N+i
  sigs   = 7 valid ECDSA signatures over the digest (ascending order)
-> threshold met for each, vault self-calls unlock, custody drains.

Drained in one block:
  WBTC  ~$30M  (largest)
  WETH  ~$10M
  USDT  ~$10M
  USDC  ~$10M
  DAI   ~$10M
  + smaller positions (BOA, TON, ORC)
```

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `validator_set_authority` (off-chain) | Fewer than 7 of the 10 farmer keys are compromised at any time | All 7 needed keys reachable from a single attacker foothold |
| `asset_conservation` | `totalLocked[token]` only decreases for legitimate user-initiated unlocks | 5 receipts drain 5 token positions in one block without legitimate triggers |
| `farmer_isolation` (architectural) | 7 of 10 farmer hosts must not be reachable from a single attacker foothold | 70% concentration ratio compromised in one campaign — highest in the dataset |

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/OrbitVault.sol` | Threshold authorisation + custody, extends shared `MockMultisig(10, 7)` |
| `contracts/WrappedToken.sol` | Generic ERC20 reused for WETH / USDT / USDC / WBTC / DAI |
| (shared) `benchmarks/_shared/MockMultisig.sol` | Imported via `../../_shared/MockMultisig.sol` — fourth consumer of the harness |

The vault holds custody directly (no separate bucket like Harmony) —
the simpler layout reads more cleanly with N=10 farmers, and Module 1's
ATG node count stays manageable. The 10 farmer addresses are
placeholders (`0x..01` through `0x..0a`) because Ozys did not publicly
disclose the production set.

## Pipeline test

```bash
# Quick offline smoke test (no API key needed)
bash benchmarks/orbit/repro.sh

# With NVIDIA NIM (sets ATG/scenarios via LLM)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/orbit/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/orbit_smoke/
```

For the **RAG generalisation experiment**, run all four V4 benchmarks
(Ronin, Harmony, Multichain, Orbit) with LLM mode and check whether
Module 2 produces a `key_compromise`-class scenario consistently
across the threshold variations (5/9, 2/4, 1/1, 7/10). See
[`docs/LLM_VERIFICATION_RONIN_HARMONY.md`](../../docs/LLM_VERIFICATION_RONIN_HARMONY.md)
for the Sprint R+H findings.

## Verify

```bash
python scripts/verify_benchmark.py benchmarks/orbit/
```

`ORBIT_RPC_URL` is optional — the script `[skip]`s it gracefully if
not set, exactly as Wormhole does for `SOLANA_RPC_URL`. `ETH_RPC_URL`
is checked against the six Ethereum-side addresses (vault + 5 ERC20
tokens). The `farmer_set_placeholders` and `attacker` entries carry
`is_eoa: true` so the bytecode check skips them.

## On-chain reference artifacts

- Orbit Vault (Ethereum): `0x1Bf68A9d1EaEe7826b3593C20a0ca93293cb489a`
- WBTC: `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`
- WETH: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
- USDT: `0xdAC17F958D2ee523a2206206994597C13D831ec7`
- USDC: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`
- DAI: `0x6B175474E89094C44Da98b954EedeAC495271d0F`
- Representative drain tx: `0x0d1024b65b4cdc78c3c0796f3d1b0d4f6b41c5fbf3fbd85ddb2f4d09a3e4d65f`
- WBTC-specific drain tx: `0xcd9d2d5b4d2eb94a71e30f6bd6e36fae6b8a9d2c3fa01e7f7d40b3a1e3f6b95a`

## Research sources

- Ozys Official: https://x.com/Ozys_Official/status/1741655068636635461
- Match Systems: https://matchsystems.io/research/orbit-bridge-hack/
- Etherscan: https://etherscan.io/address/0x1Bf68A9d1EaEe7826b3593C20a0ca93293cb489a

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (2 files + shared `MockMultisig`) |
| Trace curated | Yes (`exploit_trace.json` — 5 single-block drains, suspected Lazarus) |
| Cross-chain mapping documented | Yes (`mapping.json`, ETH ↔ Orbit chain_id 9001, 5 distinct assets) |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — Ethereum-side custody replay only; Orbit-side mint/burn is informational |
