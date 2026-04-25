# FEGtoken Benchmark

Reconstructed from the **2022-04-28 FEGtoken bridge incident** (~$1.3M
total across BSC + Ethereum legs). This benchmark closes the off-chain
plan with the dataset's only **V2 + V4 chained** exploit — a flash
loan (V2) amplified into a migrator-role privilege escalation (V4).

## Why this benchmark matters

Of the four off-chain compromise benchmarks (Ronin, Harmony,
Multichain, Orbit), three are pure V4 key compromises with no on-chain
*chain* of vulnerabilities. FEGtoken is the **only V2+V4 composite**
in the dataset:

- **V2 (replay-style amplification):** the flash loan satisfies a
  per-block balance check that should require sustained ownership.
- **V4 (privilege escalation):** the resulting transient migrator
  role is then used to drive `transferFrom` against unrelated users'
  approvals.

Each gate looks defensible in isolation. The composition + the lack
of a time-locked confirmation step on migrator-role changes is the
architectural root cause. This is the kind of multi-step exploit that
single-bug fuzzers (ItyFuzz, SmartShot) cannot find; it requires the
RAG hypothesis generator to assemble a plan across two distinct
contract surfaces — which is precisely why this is a useful benchmark
for BridgeSentry's Module 2.

## Bug summary

```text
Stage 1 (V2): flash-loan amplification
    attacker calls FlashLoanProvider.flashLoan(amount = 20% of FEG supply)
    -> FEGToken.balanceOf(attacker) becomes large for one transaction
    -> FEGToken.claimMigrator() passes the >=10% gate
    -> FEGToken.migrator = attacker

Stage 2 (V4): migrator-driven approval drain
    attacker calls FEGSwap.swapToSwap(MockToken, victim, attacker, victim_balance)
    -> "msg.sender == feg.migrator()" check passes
    -> MockToken.transferFrom(victim, attacker, victim_balance) succeeds
       (FEGSwap pulled this via the victim's prior approve(FEGSwap, MAX))

Stage 3: clean exit
    attacker repays flash loan with the originally borrowed FEG
    -> FlashLoanProvider's post-callback balance check passes
    -> attacker exits with the drained MockToken balance from stage 2
```

The full chain executes atomically inside a single transaction per
chain (BSC + ETH). PeckShield's analysis cites BSC as the larger
absolute leg.

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `migrator_persistence` | Migrator role must require sustained balance ownership (>= 1 confirmation block), not transient flash-loaned balance | `claimMigrator` accepts the same-block balance and writes `migrator = msg.sender` immediately |
| `caller_authorisation` | `swapToSwap` must require authorisation that ties the operation to the source-account holder (signed permit / `msg.sender == from`) | Only the migrator gate stands between attacker and victims; once held transiently, drains are unrestricted |
| `approval_consent` | `approve(FEGSwap, X)` authorises FEGSwap to act on the user's own swap requests, not arbitrary migrator-driven drains | Migrator role hijacks the approval rails |
| `flash_loan_post_balance` | Provider's post-callback balance check holds | **Honoured** — the flash-loan venue itself is not the bug |

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/FEGToken.sol` | FEG token + the `claimMigrator` transient-balance gate (V2 surface) |
| `contracts/FEGSwap.sol` | The vulnerable swap router; `swapToSwap` is gated only on `caller == migrator()` (V4 surface) |
| `contracts/FlashLoanProvider.sol` | Single-token flash-loan pool standing in for the production lending venue |
| `contracts/MockToken.sol` | Generic ERC20 victim asset (BUSD / WBNB / WETH stand-in) |

The 4-contract layout mirrors the production attack surface: one token
contract holds the role-grant primitive; one router contract holds the
approvals; one venue supplies the flash-loan precondition; one victim
asset is what actually gets drained. Module 1 should infer the (V2 ->
V4) chain — the LLM mode is expected to surface an explicit
`flash_loan_role_grant` or `flash_loan + migrator_compromise`
multi-step scenario, distinct from the single-step scenarios produced
by Ronin / Harmony / Orbit.

## Pipeline test

```bash
# Quick offline smoke test (no API key needed)
bash benchmarks/fegtoken/repro.sh

# With NVIDIA NIM (sets ATG/scenarios via LLM)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/fegtoken/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/fegtoken_smoke/
```

For the **multi-step exploit experiment**, compare FEGtoken's LLM-mode
output to the single-step V4 benchmarks (Ronin / Harmony / Orbit).
The expected differentiator is at least one scenario whose action
sequence has **>= 4 steps** spanning two contracts (Provider ->
FEGToken -> FEGSwap -> Provider) versus the single-contract,
single-action drains in the pure V4 set.

## Verify

```bash
python scripts/verify_benchmark.py benchmarks/fegtoken/
```

`BSC_RPC_URL` and `ETH_RPC_URL` are both checked. BSC public RPC
cannot serve archive queries — the script auto-falls-back to latest
block (the documented behaviour for Qubit / pGALA on BSC). The
`attacker` entry carries `is_eoa: true` so the bytecode check skips it.

## On-chain reference artifacts

- FEGSwap (BSC): `0x4b9be7e93f02d94c87c20cd71a90b6f5a3c3ca42`
- FEGToken (BSC): `0xacFC95585D80Ab62f67A14C566C1b7a49Fe91167`
- FEGSwap (Ethereum): `0x818E2013dD7D9bF4547aaabF6B617c1262578bc7`
- FEGToken (Ethereum): `0x389999216860AB8E0175387A0c90E5c52522C945`
- PancakeSwap V2 Router (flash-loan venue): `0x10ED43C718714eb63d5aA57B78B54704E256024E`

## Research sources

- PeckShield: https://peckshield.medium.com/fegtoken-incident-april-2022-a26793a1a35e
- Rekt News: https://rekt.news/feg-rekt/
- BscScan: https://bscscan.com/address/0x4b9be7e93f02d94c87c20cd71a90b6f5a3c3ca42

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (4 files: FEGToken / FEGSwap / FlashLoanProvider / MockToken) |
| Trace curated | Yes (7 stages: approval setup -> flash borrow -> claim migrator -> drain -> repay -> ETH leg repeat -> remediation) |
| Cross-chain mapping documented | Yes (BSC primary, ETH parallel deployment) |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — single-chain replay per leg; the BSC + ETH parallel attack pattern can be modelled as two independent runs |

## Closes the off-chain plan

With FEGtoken landed, [`docs/PLAN_POPULATE_OFFCHAIN.md`](../../docs/PLAN_POPULATE_OFFCHAIN.md)'s
five sprints (M0 + R + H + M + O + F) are complete. **Benchmark count:
11/12.** The remaining benchmark is GemPad ($1.9M, BSC dst, V1) — a
single-chain logic bug closer in pattern to Sprint S (Socket) than to
the off-chain V4/V2 family, intentionally scoped out of this plan and
deferred to a short Sprint G follow-up.
