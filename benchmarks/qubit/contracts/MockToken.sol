// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockToken (xQubit on BSC)
 * @notice Minimal ERC-20-compatible token modelling the destination-chain xToken.
 * @dev Only the storage and events Module 1 / Module 3 need to reason about
 *      asset conservation are implemented. Use external production tokens for
 *      real on-chain replay.
 */
contract MockToken {
    string public constant name = "xQubit";
    string public constant symbol = "xQUBIT";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    address public minter;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        minter = msg.sender;
    }

    function mint(address to, uint256 amount) external {
        // For a benchmark, we accept calls from the bridge router; in a
        // production deployment this would be `require(msg.sender == minter)`.
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
}
