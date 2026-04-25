// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title WrappedAsset
 * @notice Minimal mintable ERC20 used to represent whETH (the wrapped-ETH
 *         token Wormhole minted on Solana). Kept self-contained so the
 *         benchmark compiles without an OZ dependency.
 */
contract WrappedAsset {
    string public name;
    string public symbol;
    uint8 public immutable decimals;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    address public minter;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(string memory name_, string memory symbol_, uint8 decimals_, address minter_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
        minter = minter_;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == minter, "WrappedAsset: not minter");
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }
}
