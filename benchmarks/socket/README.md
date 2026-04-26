# Socket Gateway Benchmark

Reconstructed from the **2024-01-16 Socket Gateway exploit** (~$3.3M loss).

## Bug summary

Socket Gateway is the proxy contract behind Bungee — it routes swaps and
cross-chain bridges through per-route implementation contracts. One of
those routes (#16 in production) exposed a `performAction` function that
read the `fromUser` address from caller-supplied calldata and pulled
tokens via:

```solidity
IERC20(fromToken).transferFrom(fromUser, address(this), amount);
```

There was **no `require(msg.sender == fromUser)`** and no signed-permit
alternative. Because the gateway had thousands of pre-existing user
approvals (`approve(SocketGateway, MAX)` is the default for normal swap
usage), an attacker could call `performAction` with `fromUser = victim,
recipient = attacker` and drain every previously-approved wallet.

```solidity
performAction(
    routeId      = 16,
    fromToken    = USDC,
    toToken      = USDC,
    amount       = victim.balanceOf(USDC),
    fromUser     = victim,         // <-- attacker controls
    recipient    = attacker,       // <-- attacker controls
    swapData     = 0x
)
```

The attacker repeated this ~200 times against the largest existing
approvals before Socket paused the route.

## Single-chain note

Although Socket is also a cross-chain bridge aggregator, **this incident
broke the same-chain swap path** — funds did not cross any chain. The
`source_chain` and `destination_chain` in `metadata.json` therefore both
point to Ethereum. The cross-chain invariant set still applies because
Socket's other routes do bridge funds; the V5 (logic / business-rule)
classification covers this `caller_authorization` failure regardless of
how many chains the route actually touches.

## Affected invariants

| Category | Statement | How the exploit violates it |
|---|---|---|
| `caller_authorization` | Token movement requires `msg.sender == from` (or a signed permit pinning the op to a specific caller) | `performAction` accepts arbitrary `fromUser` and pulls regardless of caller |
| `approval_consent` | A user's `approve(spender, X)` authorizes the user themselves to spend up to X via the spender, not arbitrary callers | Gateway treated the allowance as universally-callable spending power |
| `balance_monotonicity_per_user` | A user who has not signed a tx in block B retains their balance through block B | Victims lost balance without signing |

## Reconstruction layout

| File | Purpose |
|---|---|
| `contracts/SocketGateway.sol` | Aggregator proxy with the missing caller check |
| `contracts/SwapImplementationStub.sol` | Minimal stand-in for a registered route implementation |
| `contracts/MockToken.sol` | ERC20 with `approve` + `transferFrom` (the surface the bug exploits) |

The bug is intentionally narrowed: the production Socket Gateway has
many routes, an upgradeable proxy, and complex per-route swap logic.
The cross-route indirection is cosmetic for Module 1 — what matters is
that the entry function reads `fromUser` from calldata and calls
`transferFrom(fromUser, ...)` without authorizing the caller. Module 1
should infer the (approve → transferFrom) flow; Module 2 should produce
a `caller_authorization_bypass` (or `approval_pull_drain`) scenario
whose precondition is a non-zero allowance and whose action calls
`performAction` with a victim address.

## Pipeline test

```bash
# Quick offline smoke test (no API key needed)
bash benchmarks/socket/repro.sh

# With NVIDIA NIM (sets ATG/scenarios via LLM)
set -a && source .env && set +a
python -m src.orchestrator \
    --benchmark benchmarks/socket/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/socket_smoke/
```

Successful output produces `results/socket_smoke/atg.json` with at
least the approve + performAction edges and `hypotheses.json` with at
least one `caller_authorization` (or `approval_pull` / `logic_bug`)
scenario whose first action sets up an approval and second action
fires `performAction` with a third-party `fromUser`.

## Verify

```bash
python scripts/verify_benchmark.py benchmarks/socket/
```

`SOLANA_RPC_URL` is not used; only `ETH_RPC_URL` is checked against the
destination addresses. The fork block is `19062800` (one of the blocks
just before the documented first drain at 19062857).

## On-chain reference artifacts

- Socket Gateway proxy: `0x3a23F943181408EAC424116Af7b7790c94Cb97a5`
- Attacker EOA: `0x50f9602e3105B5dDc56dE3D9f6BD98f30A28e2cF`
- USDC: `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48`
- WETH: `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2`

## Research sources

- Socket post-mortem: https://socket.tech/blog/post-mortem-socket-incident-january-16-2024
- Quill Audits analysis: https://www.quillaudits.com/blog/hack-analysis/socket-hack-analysis
- Etherscan: https://etherscan.io/address/0x3a23F943181408EAC424116Af7b7790c94Cb97a5

## Status

| Field | Value |
|---|---|
| Contracts reconstructed | Yes (3 files) |
| Trace curated | Yes (`exploit_trace.json`) |
| Cross-chain mapping documented | Yes (`mapping.json`, single-chain) |
| Module 1+2 pipeline ready | Yes |
| Module 3 dual-EVM replay ready | No — same-chain replay only; both fuzzer chains pointed at the same Ethereum fork |
