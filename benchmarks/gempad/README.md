# GemPad Locker Benchmark

Reconstructed from the **2024-04 GemPad locker incident on BSC**
(~$1.9M loss). This is the dataset's twelfth and final benchmark,
closing the 12/12 reconstruction effort.

## Bug summary

GemPad is a token-launchpad service on BSC (and other chains) that
lets project teams lock liquidity / team allocations for a configurable
period to assure investors. The 2024-04 BSC-side locker exposed a
`transferLockOwnership` function intended for legitimate teams to
migrate ownership of their own locks — but the access-control check
was forgotten:

```solidity
function transferLockOwnership(uint256 lockId, address newOwner) external {
    Lock storage l = locks[lockId];
    require(l.amount > 0, "GemPad: lock not found");
    require(!l.withdrawn, "GemPad: already withdrawn");
    // VULN: missing `require(msg.sender == l.owner)`
    l.owner = newOwner;
}
```

Any caller could rewrite the `owner` field of any lock. Attacker
enumerated outstanding `lockId`s, called
`transferLockOwnership(lockId, attacker)` on each unlocked-or-soon-to-
unlock position, then called `withdraw(lockId)` to receive the locked
balance. The `withdraw` function itself is correctly authorised — what
fails is that its precondition (`Lock.owner` truthfully reflects the
depositor) is corrupted upstream.

```text
victim_project: GemPadLocker.lock(LP_token, amount, unlockTime)
                -> Lock.owner = project_deployer

attacker:       GemPadLocker.transferLockOwnership(lockId, attacker)
                -> Lock.owner = attacker (no auth check)

attacker:       GemPadLocker.withdraw(lockId)
                -> require(msg.sender == l.owner)  // passes — owner now == attacker
                -> require(block.timestamp >= unlockTime)  // passes
                -> transfer(l.owner, l.amount) — tokens sent to attacker
```

Roughly 8 lock positions across multiple project tokens drained over a
single block window before GemPad paused the locker.

## Single-chain note

GemPad runs on BSC and other chains independently — each deployment is
a separate same-chain locker. The 2024-04 incident was BSC-only, so
`source_chain == destination_chain == bsc` in [`metadata.json`](metadata.json).
The cross-chain invariant set still applies because GemPad bridges
project tokens onto BSC before they enter the locker; the V1
classification covers the verification-bypass failure regardless of how
those tokens originated.

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `lock_owner_authority` | `transferLockOwnership` must require `msg.sender == current owner` | Function rewrites `Lock.owner` from any caller — the entire bug |
| `post_lock_immutability` | After `lock()`, the `owner` field may only change via an authorised path (signed by current owner / time-locked governance) | Direct rewrites by arbitrary callers succeed |
| `asset_conservation_per_lock` | A Lock may release at most `amount` tokens, exactly once, to the original depositor | Tokens released to hijacked "owner" — per-token sum preserved, but recipient is wrong |
| `unlock_time_respected` | `withdraw` requires `block.timestamp >= unlockTime` | Honoured — not part of the bug surface |

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/GemPadLocker.sol` | The locker with the missing-auth `transferLockOwnership` (V1 surface). `lock`, `withdraw`, and the unlock-time check all enforce their specs correctly |
| `contracts/MockToken.sol` | Generic ERC20 reused for project LP and team-allocation tokens |

The bug is intentionally narrowed: production GemPad has many lock
types (token / LP / NFT / vesting), per-team metadata, fee collection,
and cross-chain bridging in. Module 1 only needs to see the
(lock -> withdraw) flow plus the `transferLockOwnership` privilege-
escalation surface; Module 2 should produce an `ownership_hijack` /
`verification_bypass` scenario whose first action targets
`transferLockOwnership` and whose second action calls `withdraw` from
the new "owner".

This is the **same V1 family as Sprint S (Socket)**:

| Property | Sprint S (Socket) | **Sprint G (GemPad)** |
|---|---|---|
| Loss | $3.3M | $1.9M |
| Vuln class | V5 (logic / business-rule) | **V1 (verification bypass)** |
| Bug surface | `performAction` accepts caller-supplied `from` | **`transferLockOwnership` accepts caller-supplied `newOwner`** |
| Fix | `require(msg.sender == fromUser)` | **`require(msg.sender == locks[lockId].owner)`** |
| Network | Ethereum (single-chain aggregator) | **BSC (single-chain locker)** |
| Drain count | ~200 victims | **~8 locks** |

Both demonstrate the canonical "forgot to check msg.sender" anti-
pattern but on different surfaces (global router approval pull vs.
per-record ownership transfer).

## Pipeline test

```bash
# Quick offline smoke test (no API key needed)
bash benchmarks/gempad/repro.sh

# With NVIDIA NIM (sets ATG/scenarios via LLM)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/gempad/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/gempad_smoke/
```

Expected LLM-mode output: at least one `verification_bypass` /
`access_control_missing` / `ownership_hijack` scenario whose first
action is `transferLockOwnership` and whose second action is
`withdraw`.

## Verify

```bash
python scripts/verify_benchmark.py benchmarks/gempad/
```

`BSC_RPC_URL` is checked. BSC public RPC cannot serve archive queries
— the script auto-falls-back to latest block (the documented behaviour
for Qubit / pGALA / FEGtoken on BSC). The `attacker` entry carries
`is_eoa: true` so the bytecode check skips it.

## On-chain reference artifacts

- GemPad Locker (BSC, placeholder per public reports): `0x4EE438bE38f8682AbB089F2bfeA48851C5e71Eae`
- Representative drained LP token: `0xeF95dF21F3b0EA0F1f2eb1A95fB04A5c7d76E3b7`

## Research sources

- GemPad Official: https://twitter.com/GemPad_app
- PeckShield Alerts: https://twitter.com/PeckShieldAlert
- BscScan: https://bscscan.com/address/0x4EE438bE38f8682AbB089F2bfeA48851C5e71Eae

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (2 files: GemPadLocker + MockToken) |
| Trace curated | Yes (`exploit_trace.json` — hijack -> withdraw chain, ~8 locks drained) |
| Cross-chain mapping documented | Yes (`mapping.json`, single-chain BSC) |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — same-chain replay only; both fuzzer chains pointed at the same BSC fork |

## Closes the 12/12 benchmark dataset

With GemPad landed, the full 12-benchmark dataset is complete:

| # | Bridge | Year | Loss | Vuln | Sprint |
|---|---|---|---|---|---|
| 1 | PolyNetwork | 2021 | $611M | V3+V4 | N |
| 2 | Wormhole | 2022 | $326M | V1 | W |
| 3 | Ronin | 2022 | $624M | V4 | R |
| 4 | Nomad | 2022 | $190M | V1+V3 | (baseline) |
| 5 | Harmony | 2022 | $100M | V4 | H |
| 6 | Multichain | 2023 | $126M | V2+V4 | M |
| 7 | Socket | 2024 | $3.3M | V5 | S |
| 8 | Orbit | 2024 | $82M | V4 | O |
| **9** | **GemPad** | **2024** | **$1.9M** | **V1** | **G** |
| 10 | FEGtoken | 2022 | $1.3M | V2+V4 | F |
| 11 | pGALA | 2022 | $10M | V1 | P |
| 12 | Qubit | 2022 | $80M | V1 | Q |

Coverage of the V1-V5 vuln-class taxonomy:

- **V1 (Verification Bypass):** Wormhole, Nomad, GemPad, pGALA, Qubit (5 benchmarks)
- **V2 (Replay Attack):** Multichain, FEGtoken (2 benchmarks)
- **V3 (State Desync):** PolyNetwork, Nomad (2 benchmarks)
- **V4 (Unauthorized Access / Key Compromise):** PolyNetwork, Ronin, Harmony, Multichain, Orbit, FEGtoken (6 benchmarks)
- **V5 (Logic / Business Rule Bug):** Socket (1 benchmark)

All 5 classes covered; V4 is the most-represented (6) which mirrors
the real distribution of bridge incidents by USD loss.
