// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Message.sol";

/**
 * @title Replica (Nomad-inspired vulnerable reconstruction)
 * @notice Models the incident: unproven messages map to root 0x00; initialize(0x00) sets confirmAt[0]=1.
 *
 * Message flow (simplified):
 * - Legitimate path: `prove(messageHash, root)` then later `process(message)` after optimistic window.
 * - Exploit path: skip `prove`; `messages[hash]` stays 0x00; if `confirmAt[0x00]==1`, `acceptableRoot(0x00)` passes.
 */
contract Replica {
    using NomadMessage for NomadMessage.Body;

    bytes32 public committedRoot;
    uint256 public optimisticSeconds;
    bool public initialized;

    mapping(bytes32 => uint256) public confirmAt;
    mapping(bytes32 => bytes32) public messages;
    mapping(bytes32 => bool) public processed;
    mapping(uint32 => mapping(uint32 => bool)) public nonceUsed;

    bytes32 internal constant LEGACY_STATUS_PROVEN = bytes32(uint256(1));
    bytes32 internal constant LEGACY_STATUS_PROCESSED = bytes32(uint256(2));

    event Proven(bytes32 indexed messageHash, bytes32 indexed root);
    event Processed(bytes32 indexed messageHash, address indexed recipient, uint256 amount);

    function initialize(bytes32 _committedRoot, uint256 _optimisticSeconds) external {
        require(!initialized, "already initialized");
        initialized = true;
        committedRoot = _committedRoot;
        optimisticSeconds = _optimisticSeconds;
        confirmAt[_committedRoot] = 1;
    }

    function prove(bytes32 messageHash, bytes32 root) external {
        messages[messageHash] = root;
        if (confirmAt[root] == 0) {
            confirmAt[root] = block.timestamp + optimisticSeconds;
        }
        emit Proven(messageHash, root);
    }

    function acceptableRoot(bytes32 _root) public view returns (bool) {
        if (_root == LEGACY_STATUS_PROVEN) return true;
        if (_root == LEGACY_STATUS_PROCESSED) return false;
        uint256 _time = confirmAt[_root];
        if (_time == 0) return false;
        return block.timestamp >= _time;
    }

    function process(bytes calldata message) external returns (bool) {
        NomadMessage.Body memory body = abi.decode(message, (NomadMessage.Body));
        bytes32 messageHash = keccak256(message);
        require(!processed[messageHash], "already processed");
        require(!nonceUsed[body.originDomain][body.nonce], "nonce replay");
        require(acceptableRoot(messages[messageHash]), "!proven");
        nonceUsed[body.originDomain][body.nonce] = true;
        processed[messageHash] = true;
        emit Processed(messageHash, body.recipient, body.amount);
        return true;
    }
}
