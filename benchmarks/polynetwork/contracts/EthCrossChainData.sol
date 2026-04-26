// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title EthCrossChainData (PolyNetwork-inspired vulnerable reconstruction)
 * @notice Storage contract that holds the bridge keeper public key.
 *
 * @dev Reconstruction notes
 * In the real PolyNetwork deployment, ``EthCrossChainData`` was the storage
 * contract and ``EthCrossChainManager`` was the manager that called it.
 * The single guard on the keeper-rotation function was an ``onlyManager``
 * modifier which only checked ``msg.sender == manager``.
 *
 * Because the manager itself accepted arbitrary external calls in
 * ``verifyHeaderAndExecuteTx`` (see :contract:`EthCrossChainManager`), the
 * attacker tricked the manager into invoking
 * ``putCurEpochConPubKeyBytes(attackerKey)`` on the data contract — and the
 * `onlyManager` check passed because ``msg.sender`` was indeed the manager.
 *
 * This file models the storage shape so the asset-conservation /
 * authorisation invariants Module 1 generates can reason about keeper
 * rotation.
 */
contract EthCrossChainData {
    /// Manager contract authorised to mutate keeper state.
    address public manager;

    /// Active keeper / consensus public key. Changing this slot is what
    /// the attacker accomplished by tricking the manager into calling
    /// ``putCurEpochConPubKeyBytes`` on its own behalf.
    bytes public curEpochConPubKeyBytes;
    address public curEpochConPubKey;

    /// Replay protection used by the production bridge for inbound proofs.
    mapping(uint256 => bool) public processed;

    event KeeperRotated(address indexed previous, address indexed current);

    constructor(address manager_) {
        manager = manager_;
    }

    modifier onlyManager() {
        require(msg.sender == manager, "EthCrossChainData: not manager");
        _;
    }

    /**
     * @notice Replace the consensus public key. SHOULD be reachable only via
     *         a multi-step governance flow; in PolyNetwork it was reachable
     *         directly because the manager forwarded arbitrary calldata.
     */
    function putCurEpochConPubKeyBytes(bytes calldata newKey) external onlyManager {
        emit KeeperRotated(curEpochConPubKey, _firstAddress(newKey));
        curEpochConPubKeyBytes = newKey;
        curEpochConPubKey = _firstAddress(newKey);
    }

    function markProcessed(uint256 nonce) external onlyManager {
        processed[nonce] = true;
    }

    /// @dev Helper to extract a single address out of the encoded key blob.
    function _firstAddress(bytes calldata blob) internal pure returns (address) {
        if (blob.length < 20) return address(0);
        return address(uint160(uint256(bytes32(blob[:32]))));
    }
}
