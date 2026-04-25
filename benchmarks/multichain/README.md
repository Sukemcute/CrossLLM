# Multichain Bridge Benchmark

Reconstructed from the **2023-07-06 Multichain (formerly AnySwap)
bridge incident** (~$126M loss). Third **off-chain compromise**
benchmark in the dataset alongside [Ronin (Sprint R)](../ronin/README.md)
and [Harmony Horizon (Sprint H)](../harmony/README.md), but the
compromise vector here is **TSS / MPC ceremony collapse**, not a direct
hot-wallet key leak.

## MPC simulation gap

> **This is the most important section of this README. Read before
> looking at the contracts.**

Multichain's cross-chain authorisation in production used a **Threshold
Signature Scheme (TSS) / Multi-Party Computation (MPC) ceremony** among
a federated set of nodes. The ceremony produced **one aggregate ECDSA
signature** per cross-chain action; the on-chain contract only ever
saw that single aggregate signature, never the partial signatures or
the participating set.

**Solidity cannot verify TSS partial-signature protocols faithfully**
(no built-in for the underlying group operations; running them in
EVM-friendly form would be prohibitively expensive even if implemented).
This benchmark therefore **degrades the on-chain witness to a 1-of-1
multi-sig**: one trusted signer that is *presumed to be* the post-MPC
aggregate output. The compromise model is "the single administrator
that controlled the MPC ceremony is now hostile" — equivalent to
handing the lone signer's private key to the attacker.

This mirrors the **Wormhole** Solana → EVM simulation gap (Sprint W)
and is the same paper §6 limitation pattern. See
[`metadata.json` § `mpc_simulation`](metadata.json) for the structured
form of this note.

```text
Production:        federated MPC nodes -> TSS protocol -> aggregate ECDSA sig -> AnyCallV6Router.execute
Benchmark:         single trusted signer -> ECDSA sig             -> MultichainAnyCallV6.execute

Production bug:    federated trust collapsed to one administrator (CEO Zhao Jun)
                   before the incident; on 2023-07-06 attacker used that one
                   administrator's surviving access (or coercion) to sign.

Benchmark capture: "the one configured signer key is in attacker hands"
                   — semantically equivalent for Module 1+2 purposes.
```

## Why does this still earn V4 + V2 classification?

- **V4 (key compromise)** because the proximate on-chain cause is a
  single aggregate key under attacker control.
- **V2 (replay-style)** because once the aggregate ceremony is
  observed, an attacker can replay the ceremony's authority across
  arbitrarily many fraud-receipt digests — the *same* ceremony output
  can be re-signed for many target accounts, varying nonce and
  destination chain id.

## Background — why the ceremony collapsed

| Date | Event |
|---|---|
| 2023-05 | Multichain CEO **Zhao Jun arrested in China**. Multichain pauses some operations citing unspecified "force majeure". |
| 2023-05 → 2023-07 | Team publicly states they cannot reconstitute the MPC keys without the CEO's involvement. The federated ceremony was **de-facto unilaterally administered**. |
| **2023-07-06** | Six large drain transactions over ~24 hours move ~$126M cross-chain to attacker accounts on **Fantom** (~$122M), Avalanche (~$2M), Polygon (~$2M). |
| 2023-07-06 | Fantom Foundation publicly acknowledges the incident the same day. |
| 2023-07-13 | Multichain announces **permanent shutdown**. No reimbursement program. |

**Attribution:** *Officially unconfirmed.* ChainArgos suggests
successor staff with surviving MPC access or coercion against the CEO's
contacts. No reputable forensics firm has attributed this to Lazarus
Group (which differentiates this incident from Ronin/Harmony).

## Bug summary

```text
off-chain (May 2023): CEO arrested -> MPC ceremony admin collapses to 0 active principals
off-chain (Jul 2023): some party with surviving access OR successful coercion
                      -> attacker effectively controls the post-MPC aggregate key
on-chain  (Jul 6):    attacker submits 6 calls to MultichainAnyCallV6.execute, each with:
                        target = address(this)
                        data   = encodeCall(unlock, (token_i, attacker_i, amount_i, destChain_i))
                        nonce  = N+i
                        sigs   = 1 valid sig over the digest from the post-MPC aggregate signer

Drained over ~24 hours:
  USDC  ~$53M
  WETH  ~$21M
  DAI   ~$16M
  WBTC  ~$8M
  USDT  ~$6M
  + smaller positions (LINK, MIM, AVAX)

Cross-chain destinations:
  Fantom    ~$122M  (nearly all of Fantom's bridge-locked TVL)
  Avalanche ~$2M
  Polygon   ~$2M
```

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `mpc_aggregate_authority` (off-chain) | The MPC ceremony's administration requires ≥ 2 independent operational principals | De-facto reduced to 1 (CEO) before the incident; collapsed to 0 after his arrest; eventually 1 attacker |
| `signer_set_authority` (on-chain) | Only the configured aggregate signer may contribute | Honoured — the contract did exactly what it was specified to do |
| `asset_conservation` | `totalLocked[token]` only decreases for legitimate user-initiated unlocks | 6 receipts drain 5+ token positions across ~24 hours without legitimate triggers |
| `mpc_decentralisation` (architectural) | A federated TSS ceremony must remain operationally federated, not collapse to unilateral administration | This is **not enforceable on-chain in any TSS protocol** — purely an off-chain governance invariant |

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/MultichainAnyCallV6.sol` | Custody + threshold-quorum (N=1, K=1) authorisation, extends shared `MockMultisig` |
| `contracts/WrappedToken.sol` | Generic ERC20 reused for WETH / USDC / USDT / WBTC / DAI |
| (shared) `benchmarks/_shared/MockMultisig.sol` | Imported via `../../_shared/MockMultisig.sol` — third consumer of the harness; same contract code, different `(N, K)` constructor args than Ronin (9, 5) and Harmony (4, 2) |

The lock/unlock pattern uses the same multi-sig self-call idiom as
Ronin and Harmony, but with N=K=1. Module 1 should infer the same
authority pattern as the other two off-chain benchmarks; Module 2's
`mpc_compromise` / `key_compromise` scenarios target the same
threshold-quorum invariant family.

## Pipeline test

```bash
# Quick offline smoke test (no API key needed)
bash benchmarks/multichain/repro.sh

# With NVIDIA NIM (sets ATG/scenarios via LLM)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/multichain/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/multichain_smoke/
```

## Verify

```bash
python scripts/verify_benchmark.py benchmarks/multichain/
```

`FANTOM_RPC_URL` is optional — the script `[skip]`s it gracefully if
not set, exactly as Wormhole does for `SOLANA_RPC_URL`. `ETH_RPC_URL`
is checked against the seven Ethereum-side addresses (2 routers + 5
ERC20 tokens). The two EOA-shaped entries (`mpc_signer_address`,
`attacker`) carry `is_eoa: true` so the bytecode check skips them.

## On-chain reference artifacts

- anyCallV6 router (Ethereum): `0x6b7a87899490ece95443e979ca9485cbe7e71522`
- Multichain Router (Ethereum): `0xC564EE9f21Ed8A2d8E7e76c085740d5e4c5FaFbE`
- Same router on Fantom side: `0xC564EE9f21Ed8A2d8E7e76c085740d5e4c5FaFbE`
- WETH: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`
- USDC: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`
- USDT: `0xdAC17F958D2ee523a2206206994597C13D831ec7`
- WBTC: `0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599`
- DAI: `0x6B175474E89094C44Da98b954EedeAC495271d0F`
- Representative first-drain tx: `0xdadec9eaa634f5cb02b2dd44d7d7be3b66b5cb8ad7c5fa2cc3c63c98a13869f9`
- Representative rolling-drain tx: `0xd5c61f73d7d29d5c80cd58aef25e7eebf6da55bb9e1b0816fa49a36e21f57f01`

## Research sources

- Fantom Foundation: https://twitter.com/FantomFDN/status/1676923210660429825
- ChainArgos timeline: https://chainargos.com/2023/07/06/multichain-the-end/
- Etherscan: https://etherscan.io/address/0x6b7a87899490ece95443e979ca9485cbe7e71522

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (2 files + shared `MockMultisig`) |
| Trace curated | Yes (`exploit_trace.json` — 6 large drains across ~24h, 3 destination chains) |
| Cross-chain mapping documented | Yes (`mapping.json` — ETH ↔ Fantom primary; AVAX/Polygon as `secondary_chains` in metadata) |
| MPC simulation gap documented | Yes (this README + `metadata.mpc_simulation` block parallel to Wormhole's `non_evm_simulation`) |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — Ethereum-side custody replay only; multi-chain destination behaviour and TSS ceremony are out of fuzzer scope (paper §6) |
