# Shared benchmark utilities

This directory holds Solidity helpers reused across multiple benchmark
folders. It is **not a benchmark itself** — there is no `metadata.json`
here, so `scripts/verify_benchmark.py` will not (and should not) be run
against it.

## Files

| File | Purpose | Used by |
|---|---|---|
| [`MockMultisig.sol`](MockMultisig.sol) | Generic K-of-N ECDSA threshold contract for off-chain key-compromise benchmarks | Sprint R (Ronin), Sprint H (Harmony), Sprint O (Orbit), Sprint M (Multichain — degraded to 1-of-1) per [`docs/PLAN_POPULATE_OFFCHAIN.md`](../../docs/PLAN_POPULATE_OFFCHAIN.md) |

## Importing from a benchmark

From any `benchmarks/<bridge>/contracts/*.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../_shared/MockMultisig.sol";

contract RoninBridgeManager is MockMultisig {
    constructor(address[] memory signers_) MockMultisig(signers_, 5) {
        // Ronin used 9 signers with 5/9 threshold; the V4 compromise
        // collapsed the threshold by handing 5 keys to the attacker.
    }

    // Bridge-specific surface (e.g. withdraw, lock, mint) wraps the
    // inherited `execute(target, value, data, nonce, sigs)` method or
    // calls `digestFor` to compute its own pre-signed-message hash.
}
```

The double-`..` is intentional: the `_shared` directory is a sibling of
the per-bridge directories (`benchmarks/_shared/` and
`benchmarks/<bridge>/contracts/`). Solidity's import path is relative
to the importing file, not to the project root.

## Why a shared file (vs. one copy per bridge)

Five of the seven outstanding off-chain benchmarks (Ronin, Harmony,
Multichain, Orbit, FEGtoken — partially) share the same threshold-quorum
authorization pattern. Duplicating the contract per benchmark would:

1. Inflate Module 1's deduplication burden (the LLM would see N near-
   identical contracts and might split the same invariant N times).
2. Make any subsequent fix to the harness (e.g. EIP-191 prefix support)
   N-place edits that drift apart.
3. Hide the *actual* per-bridge differentiator — N, K, asset set —
   under boilerplate.

Keeping the harness in `_shared/` lets each bridge's contract focus on
its specific differentiator (the constructor args and any bridge-only
auxiliary logic).

## Why no `metadata.json` here

`metadata.json` is the entry point `verify_benchmark.py` keys off. A
`_shared/` without metadata is invisible to the verify loop, which is
exactly the desired behaviour — the helper is exercised through the
benchmarks that import it, not on its own. If the verify script is ever
extended with a `--scan benchmarks/` mode, treat any subdirectory whose
name starts with `_` as private (the `_shared` underscore signals
"library, not benchmark").
