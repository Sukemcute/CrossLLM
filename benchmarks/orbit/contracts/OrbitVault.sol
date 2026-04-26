// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../_shared/MockMultisig.sol";
import "./WrappedToken.sol";

/**
 * @title OrbitVault (Orbit-Bridge-inspired vulnerable reconstruction)
 * @notice Models the 2024-01-01 Orbit Bridge incident: 7 of 10 farmer
 *         (validator) keys were compromised, satisfying the on-chain
 *         7-of-10 ECDSA threshold. The attacker drained roughly $82M
 *         across ETH / USDT / USDC / WBTC / DAI in a small batch of
 *         transactions on New Year's Day. Match Systems' subsequent
 *         forensic analysis attributes the incident to Lazarus Group.
 *
 * @dev Reconstruction notes
 * Like Ronin (Sprint R) and Harmony (Sprint H), the bug being modelled
 * lives **off-chain**: 7 farmer private keys leaked. The on-chain code
 * in production enforced its 7-of-10 threshold spec correctly. The
 * differentiator vs. Ronin and Harmony is purely scale: a larger
 * signer set (N=10 vs 9 vs 4) with a higher absolute threshold
 * (K=7 vs 5 vs 2). This benchmark stresses Module 1's ability to
 * enumerate signer entities without exploding the ATG's node count,
 * and tests whether the LLM still produces a `key_compromise`-class
 * scenario when the compromise ratio (70%) is the highest of any
 * benchmark in the dataset.
 *
 * The lock/unlock pattern is identical to Ronin and Harmony: a
 * withdrawal is encoded as `execute(target=address(this),
 * data=encodeCall(unlock, ...), nonce, sigs)`. The inherited
 * `MockMultisig.execute` recovers the 7+ signatures, checks the
 * threshold, and self-calls `unlock`, which guards on `msg.sender ==
 * address(this)`. Custody is held in the same contract (no separate
 * bucket) — the 3-contract layered design from Harmony added little
 * for Module 1 in offline mode and the simpler layout reads more
 * cleanly here.
 *
 * Invariants this contract is intended to make explicit during fuzzing:
 * - threshold_quorum_authorization: every Unlocked event maps to a
 *   prior `execute` call carrying >= 7 valid distinct signatures.
 * - validator_set_authority: only the 10 configured signer addresses
 *   may contribute to the quorum.
 * - asset_conservation_per_token: totalLocked[token] dominates the
 *   release stream for each token.
 */
contract OrbitVault is MockMultisig {
    event Locked(address indexed token, address indexed depositor, uint256 amount);
    event Unlocked(address indexed token, address indexed recipient, uint256 amount);

    /// token => total currently locked in the vault custody on Ethereum.
    mapping(address => uint256) public totalLocked;
    /// token => cumulative amount unlocked over the vault's lifetime.
    mapping(address => uint256) public totalUnlocked;

    /**
     * @param signers_ Farmer (validator) addresses. Production: 10
     *                 farmer pubkeys administered by Ozys-affiliated
     *                 staff and a small set of partner organisations.
     * @dev Threshold hard-coded to 7 to match the production security
     *      parameter at the time of the incident. The 7-of-10 ratio
     *      (70%) is the highest threshold-to-set ratio in the off-chain
     *      benchmark suite, but did not save Orbit because the
     *      compromise was highly concentrated (single-attacker access
     *      to enough farmer infrastructure to satisfy 7 keys).
     */
    constructor(address[] memory signers_) MockMultisig(signers_, 7) {
        require(signers_.length == 10, "Orbit: production used 10 farmers");
    }

    /**
     * @notice User locks `amount` of `token` on Ethereum to receive a
     *         representation on Orbit chain. The benchmark only models
     *         the Ethereum-side custody account; the Orbit-side mint is
     *         documented in `mapping.json`.
     */
    function lock(address token, uint256 amount) external {
        WrappedToken(token).transferFrom(msg.sender, address(this), amount);
        totalLocked[token] += amount;
        emit Locked(token, msg.sender, amount);
    }

    /**
     * @notice Internal release path. Only reachable via the inherited
     *         `execute(target=address(this), data=encodeCall(unlock,...))`
     *         which means a valid 7-of-10 quorum of the configured
     *         farmer set must have signed off on the (token, recipient,
     *         amount) tuple bound to this contract address and a fresh
     *         nonce.
     * @dev External (not internal) so it can be invoked via `target.call`
     *      from `MockMultisig.execute`. The `msg.sender == address(this)`
     *      guard restricts entry to the validated path.
     */
    function unlock(address token, address recipient, uint256 amount) external {
        require(msg.sender == address(this), "OrbitVault: only via multisig");
        require(totalLocked[token] >= amount, "OrbitVault: overdraw");
        totalLocked[token] -= amount;
        totalUnlocked[token] += amount;
        WrappedToken(token).transfer(recipient, amount);
        emit Unlocked(token, recipient, amount);
    }
}
