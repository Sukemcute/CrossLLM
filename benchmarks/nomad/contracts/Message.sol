// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Nomad-style cross-chain message (benchmark model)
 * @notice Mirrors the *shape* of Nomad messages (origin/destination/nonce/sender/recipient/token/amount)
 *         for realistic encoding; not a byte-for-byte copy of production Message.sol.
 */
library NomadMessage {
    struct Body {
        uint32 originDomain;
        uint32 destinationDomain;
        uint32 nonce;
        address sender;
        address recipient;
        address token;
        uint256 amount;
    }

    function encode(Body memory m) internal pure returns (bytes memory) {
        return abi.encode(m);
    }

    function decode(bytes memory data) internal pure returns (Body memory) {
        return abi.decode(data, (Body));
    }

    function hash(Body memory m) internal pure returns (bytes32) {
        return keccak256(encode(m));
    }
}
