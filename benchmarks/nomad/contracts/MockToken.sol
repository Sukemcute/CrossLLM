// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockToken
 * @notice Minimal ERC20-like token for benchmark payouts.
 */
contract MockToken {
    string public name = "Nomad Benchmark Token";
    string public symbol = "NBT";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function mint(address to, uint256 amount) external {
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }
}
