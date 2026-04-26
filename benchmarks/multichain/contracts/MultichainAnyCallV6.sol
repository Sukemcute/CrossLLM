// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../_shared/MockMultisig.sol";
import "./WrappedToken.sol";

/**
 * @title MultichainAnyCallV6 (Multichain-inspired vulnerable reconstruction)
 * @notice Models the 2023-07-06 Multichain (formerly AnySwap) bridge
 *         incident in which roughly $126M was drained from locked pools
 *         on Ethereum, BSC, and Polygon to attacker-controlled accounts
 *         on Fantom, Avalanche, and Polygon.
 *
 * @dev Reconstruction notes — MPC SIMULATION GAP
 * The bug being modelled lives **off-chain** in a Threshold Signature
 * Scheme (TSS) / Multi-Party Computation (MPC) ceremony that the
 * on-chain code never observed. In production, Multichain's MPC nodes
 * collectively produced ONE aggregate ECDSA signature per cross-chain
 * action, and the on-chain contract verified that single signature.
 * That ceremony was de-facto under unilateral control of Multichain's
 * CEO Zhao Jun, who was arrested in China in May 2023; the keys could
 * no longer be reconstituted by the team, and on 2023-07-06 the drains
 * began (likely by successor staff or coercion).
 *
 * Because TSS/MPC cannot be modelled in Solidity in any faithful way
 * (the on-chain code only ever saw a final aggregate ECDSA signature),
 * this benchmark **degrades to a 1-of-1 multi-sig**: one trusted
 * signer that is presumed to *be* the post-MPC aggregate output. The
 * compromise model is "the single administrator that controlled the
 * MPC ceremony is now hostile" — equivalent to handing the lone signer
 * key to the attacker. This mirrors how Wormhole (Sprint W) degrades
 * Solana's `verify_signatures` to an EVM-side analogue and is the same
 * paper §6 limitation pattern.
 *
 * Invariants this contract is intended to make explicit during fuzzing:
 * - mpc_aggregate_authority: every Unlocked event maps to a prior
 *   `execute` call carrying a valid signature from the post-MPC
 *   aggregate signer (the sole `signers_[0]`). The on-chain check is
 *   correct; the off-chain ceremony is what failed.
 * - asset_conservation_per_token: locked balance must dominate any
 *   release stream for the same token, across chain destinations.
 * - replay_protection: each digest = keccak256(target, value, data,
 *   nonce, this) may execute at most once.
 */
contract MultichainAnyCallV6 is MockMultisig {
    event Locked(address indexed token, address indexed depositor, uint256 amount, uint16 destChainId);
    event Unlocked(address indexed token, address indexed recipient, uint256 amount, uint16 destChainId);

    /// token => total currently locked in the bridge custody on this chain.
    mapping(address => uint256) public totalLocked;
    /// token => cumulative amount released over the bridge's lifetime.
    mapping(address => uint256) public totalReleased;

    /**
     * @param signers_ Single-element array containing the post-MPC
     *                 aggregate signer address. Production used a real
     *                 TSS ceremony; this benchmark collapses it to one
     *                 EOA-shaped signer per the MPC simulation gap doc
     *                 (see README §MPC simulation gap and metadata's
     *                 `mpc_simulation` block).
     * @dev Threshold hard-coded to 1 — the ceremony's output is a single
     *      aggregate signature; Solidity cannot verify partial-sig
     *      protocols, so the on-chain witness collapses to 1-of-1.
     */
    constructor(address[] memory signers_) MockMultisig(signers_, 1) {
        require(signers_.length == 1, "Multichain: TSS modelled as 1-of-1; see README MPC gap");
    }

    /**
     * @notice User locks `amount` of `token` on Ethereum to receive a
     *         representation on a destination chain. The destination
     *         chain id is recorded in the event so off-chain MPC nodes
     *         can address the right destination router.
     */
    function lock(address token, uint256 amount, uint16 destChainId) external {
        WrappedToken(token).transferFrom(msg.sender, address(this), amount);
        totalLocked[token] += amount;
        emit Locked(token, msg.sender, amount, destChainId);
    }

    /**
     * @notice Internal release path. Only reachable via the inherited
     *         `execute(target=address(this), data=encodeCall(unlock,...))`
     *         which means the post-MPC aggregate signer must have signed
     *         off on the (token, recipient, amount, destChainId) tuple.
     * @dev External (not internal) so it can be invoked via `target.call`
     *      from `MockMultisig.execute`. The `msg.sender == address(this)`
     *      guard restricts entry to the validated path.
     */
    function unlock(address token, address recipient, uint256 amount, uint16 destChainId) external {
        require(msg.sender == address(this), "Multichain: only via multisig");
        require(totalLocked[token] >= amount, "Multichain: overdraw");
        totalLocked[token] -= amount;
        totalReleased[token] += amount;
        WrappedToken(token).transfer(recipient, amount);
        emit Unlocked(token, recipient, amount, destChainId);
    }
}
