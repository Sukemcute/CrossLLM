// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../_shared/MockMultisig.sol";
import "./WrappedToken.sol";

/**
 * @title RoninBridgeManager (Ronin-inspired vulnerable reconstruction)
 * @notice Models the 2022-03-23 Ronin Bridge incident: 5/9 Sky Mavis +
 *         Axie DAO validator keys were compromised, satisfying the
 *         on-chain threshold and authorising two fraudulent withdrawals
 *         (173,600 WETH + 25.5M USDC, ~$624M total).
 *
 * @dev Reconstruction notes
 * The bug being modelled lives **off-chain**: the attacker obtained 5
 * validator private keys (4 Sky Mavis + 1 Axie DAO delegate that Sky
 * Mavis still held after the November 2021 surge-helping arrangement
 * was never revoked). The on-chain code in production enforced its spec
 * correctly — the assumption "fewer than 5 of the 9 keys can be
 * compromised at once" is what failed. This benchmark reflects that:
 * the contract is faithful to the original threshold-quorum design,
 * and Module 2's `key_compromise` scenario varies the *who controls
 * which keys* off-chain dimension to violate the security argument.
 *
 * The lock/unlock pattern follows the "self-call via multisig" idiom:
 * a withdrawal is approved by submitting `execute(target=address(this),
 * data=encodeCall(unlock, ...))` to the inherited multi-sig. The
 * inherited `execute` recovers signers, checks the threshold, and then
 * self-calls `unlock`, which guards on `msg.sender == address(this)`
 * to ensure only the validated path can move custody.
 *
 * Invariants this contract is intended to violate during fuzzing:
 * - threshold_quorum_authorization: every Unlocked event maps to a
 *   prior `execute` call with >= 5 valid signers signed.
 * - validator_set_authority: only addresses in the constructor's signer
 *   set can contribute to the quorum.
 * - asset_conservation: totalLocked[token] >= sum of unlocked amounts
 *   for `token` (no overdraw).
 */
contract RoninBridgeManager is MockMultisig {
    event TokenRegistered(address indexed token);
    event Locked(address indexed token, address indexed depositor, uint256 amount);
    event Unlocked(address indexed token, address indexed recipient, uint256 amount);

    /// token => true once registered for cross-chain transfer.
    mapping(address => bool) public registered;
    /// token => total currently locked in the bridge custody.
    mapping(address => uint256) public totalLocked;
    /// token => cumulative amount unlocked over the bridge's lifetime.
    mapping(address => uint256) public totalUnlocked;

    /**
     * @param signers_ Validator addresses (production: 9 — 4 Sky Mavis,
     *                 4 Axie DAO + 1 Axie-DAO-delegated-to-Sky-Mavis).
     * @dev Threshold hard-coded to 5 to match the production security
     *      parameter at the time of the incident.
     */
    constructor(address[] memory signers_) MockMultisig(signers_, 5) {
        require(signers_.length == 9, "RoninBridge: production used 9 signers");
    }

    function registerToken(address token) external {
        // Production has governance gating. For benchmark purposes
        // any caller can register — this is not the bug under test.
        registered[token] = true;
        emit TokenRegistered(token);
    }

    /**
     * @notice User locks `amount` of `token` on Ethereum to receive a
     *         representation on Ronin chain. The benchmark only models
     *         the Ethereum-side custody account; the Ronin-side mint
     *         is documented in `mapping.json`.
     */
    function lock(address token, uint256 amount) external {
        require(registered[token], "RoninBridge: token not registered");
        WrappedToken(token).transferFrom(msg.sender, address(this), amount);
        totalLocked[token] += amount;
        emit Locked(token, msg.sender, amount);
    }

    /**
     * @notice Internal release path. Only reachable via the inherited
     *         `execute(target=address(this), data=encodeCall(unlock,...))`
     *         which means a valid 5-of-9 quorum of the configured signer
     *         set must have signed off on the (token, recipient, amount)
     *         tuple bound to this contract address and a fresh nonce.
     * @dev External (not internal) so it can be invoked via `target.call`
     *      from `MockMultisig.execute`. The `msg.sender == address(this)`
     *      guard restricts entry to that path.
     */
    function unlock(address token, address recipient, uint256 amount) external {
        require(msg.sender == address(this), "RoninBridge: only via multisig");
        require(totalLocked[token] >= amount, "RoninBridge: overdraw");
        totalLocked[token] -= amount;
        totalUnlocked[token] += amount;
        WrappedToken(token).transfer(recipient, amount);
        emit Unlocked(token, recipient, amount);
    }
}
