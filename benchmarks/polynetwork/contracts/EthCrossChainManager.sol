// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./EthCrossChainData.sol";

/**
 * @title EthCrossChainManager (PolyNetwork-inspired vulnerable reconstruction)
 * @notice Models the manager contract that forwarded arbitrary calldata
 *         on behalf of the bridge.
 *
 * @dev Reconstruction notes (paper Section 6, BlockSec writeup)
 * The original ``EthCrossChainManager.verifyHeaderAndExecuteTx`` decoded a
 * cross-chain message into ``(toContract, methodName, args)`` and invoked
 * ``toContract.call(...)`` to execute the destination-side handler. The
 * critical flaw was that the manager itself was the ``manager`` of the
 * data contract; calling
 *
 *     verifyHeaderAndExecuteTx(target = EthCrossChainData,
 *                              call   = putCurEpochConPubKeyBytes(attacker))
 *
 * forwarded the call with ``msg.sender == manager`` and the
 * ``onlyManager`` guard on the data contract trivially passed. The
 * attacker subsequently signed arbitrary withdrawal proofs on Ethereum,
 * BSC and Polygon.
 *
 * Bug class (paper taxonomy):
 *   V3 (state desync between source/destination) +
 *   V4 (key compromise / unauthorised access).
 */
contract EthCrossChainManager {
    EthCrossChainData public immutable data;

    event CrossChainExecuted(address indexed target, bool success, bytes result);

    constructor(address dataAddr) {
        data = EthCrossChainData(dataAddr);
    }

    /**
     * @notice Verify a cross-chain header and execute the encoded
     *         destination call.
     * @dev VULN: ``target`` is supplied by the caller. The legitimate flow
     *      expects ``target`` to be a whitelisted handler contract; the
     *      production code did not enforce this, so the attacker passed
     *      ``target = address(data)`` and ``call = putCurEpochConPubKeyBytes(...)``.
     *      The forwarded call carries ``msg.sender == this`` which satisfies
     *      ``EthCrossChainData.onlyManager``.
     */
    function verifyHeaderAndExecuteTx(address target, bytes calldata call_) external {
        // Production code performs Merkle-proof header verification here; we
        // omit the heavy crypto for the reconstruction. Module 1 should still
        // emit an authorisation invariant about ``target`` being trusted.
        (bool success, bytes memory result) = target.call(call_);
        emit CrossChainExecuted(target, success, result);
    }

    /// @notice Sign-and-broadcast a withdrawal once the keeper has been hijacked.
    /// @dev Production used cross-chain proofs; we keep the signature as a
    ///      stand-in so the fuzzer can model "drain after key takeover".
    function signedWithdraw(address recipient, uint256 amount, uint256 nonce) external {
        // Honest invariants would check `data.curEpochConPubKey` against a
        // trusted off-chain authority. After the takeover this slot points
        // at the attacker key, so withdrawals signed by the attacker pass.
        require(!data.processed(nonce), "EthCrossChainManager: replay");
        data.markProcessed(nonce);
        // (No actual transfer in the reconstruction — Module 3 supplies
        // GlobalState balance bookkeeping.)
        emit CrossChainExecuted(recipient, true, abi.encode(amount, nonce));
    }
}
