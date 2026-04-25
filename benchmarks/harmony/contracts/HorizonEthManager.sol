// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../_shared/MockMultisig.sol";
import "./EthBucket.sol";

/**
 * @title HorizonEthManager (Harmony-Horizon-inspired vulnerable reconstruction)
 * @notice Models the 2022-06-23 Harmony Horizon Bridge incident: 2 of 4
 *         operator hot-wallet keys were compromised, satisfying the
 *         on-chain 2-of-4 ECDSA threshold. The attacker issued 11
 *         batched withdrawals across ETH/USDC/USDT/WBTC/DAI for ~$100M.
 *
 * @dev Reconstruction notes
 * Like Ronin (Sprint R), the bug being modelled lives **off-chain**:
 * private keys leaked via a Sky Mavis-style hot-wallet compromise
 * (Lazarus Group attribution per Elliptic). The on-chain code in
 * production enforced its 2-of-4 threshold spec correctly. The
 * differentiator vs. Ronin is the much smaller threshold-to-set ratio
 * (2/4 = 50%, vs. Ronin's 5/9 = 55%) and the asset diversity (5+
 * tokens drained in one campaign).
 *
 * The manager and the custody bucket are split into two contracts here
 * — production Horizon used a similar manager/lock-pool layered design.
 * Splitting them gives Module 1 more semantic entities to reason about
 * (manager + bucket + token + signer-set), and exercises whether RAG
 * retrieval over the Ronin scenarios generalises to a structurally
 * similar but not identical layout.
 *
 * Invariants this contract is intended to make explicit during fuzzing:
 * - threshold_quorum_authorization: every Unlock event maps to a prior
 *   `execute` call carrying >= 2 valid distinct signatures.
 * - validator_set_authority: only the 4 configured signer addresses may
 *   contribute to the quorum.
 * - manager_to_bucket_authority: only this manager can call
 *   `EthBucket.release` (modelled by EthBucket's onlyManager guard).
 * - asset_conservation_per_token: bucket's locked balance must dominate
 *   any release stream for the same token.
 */
contract HorizonEthManager is MockMultisig {
    event Locked(address indexed token, address indexed depositor, uint256 amount);
    event Unlocked(address indexed token, address indexed recipient, uint256 amount);

    EthBucket public immutable bucket;

    /**
     * @param signers_ Operator hot-wallet addresses (production: 4).
     * @param bucket_  Address of the EthBucket custody pool whose
     *                 `manager` must equal this contract's address.
     * @dev Threshold hard-coded to 2 to match Horizon's production
     *      security parameter at the time of the incident.
     */
    constructor(address[] memory signers_, address bucket_) MockMultisig(signers_, 2) {
        require(signers_.length == 4, "Horizon: production used 4 operators");
        bucket = EthBucket(bucket_);
    }

    /**
     * @notice User locks `amount` of `token` on Ethereum to receive a
     *         representation on Harmony. Locked balance is held in the
     *         shared EthBucket — manager only validates and dispatches.
     */
    function lock(address token, uint256 amount) external {
        bucket.deposit(token, msg.sender, amount);
        emit Locked(token, msg.sender, amount);
    }

    /**
     * @notice Internal release path. Only reachable via the inherited
     *         `execute(target=address(this), data=encodeCall(unlock,...))`
     *         which means a valid 2-of-4 quorum of the configured signer
     *         set must have signed off on the (token, recipient, amount)
     *         tuple bound to this manager's address and a fresh nonce.
     * @dev External (not internal) so it can be invoked via `target.call`
     *      from `MockMultisig.execute`. Two layers of authority:
     *        1. `msg.sender == address(this)` ensures we entered through
     *           the validated multi-sig path.
     *        2. `bucket.onlyManager` ensures the custody pool only
     *           releases when this manager asks.
     */
    function unlock(address token, address recipient, uint256 amount) external {
        require(msg.sender == address(this), "Horizon: only via multisig");
        bucket.release(token, recipient, amount);
        emit Unlocked(token, recipient, amount);
    }
}
