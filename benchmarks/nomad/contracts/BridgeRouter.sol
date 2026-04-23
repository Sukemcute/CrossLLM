// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./Replica.sol";
import "./MockToken.sol";
import "./Message.sol";

/**
 * @title BridgeRouter (benchmark reconstruction)
 * @notice Destination path: only after `Replica.process` succeeds, mint to recipient in payload.
 */
contract BridgeRouter {
    Replica public immutable replica;
    MockToken public immutable token;

    mapping(bytes32 => bool) public consumedMessage;

    event BridgeProcessed(
        bytes32 indexed msgHash,
        uint32 indexed originDomain,
        uint32 indexed nonce,
        address recipient,
        uint256 amount
    );

    constructor(address replica_, address token_) {
        replica = Replica(replica_);
        token = MockToken(token_);
    }

    function processAndRelease(NomadMessage.Body calldata body) external {
        bytes memory encoded = abi.encode(
            body.originDomain,
            body.destinationDomain,
            body.nonce,
            body.sender,
            body.recipient,
            body.token,
            body.amount
        );
        bytes32 msgHash = keccak256(encoded);
        require(!consumedMessage[msgHash], "already consumed");

        bool ok = replica.process(encoded);
        require(ok, "replica process failed");

        consumedMessage[msgHash] = true;
        token.mint(body.recipient, body.amount);
        emit BridgeProcessed(msgHash, body.originDomain, body.nonce, body.recipient, body.amount);
    }
}
