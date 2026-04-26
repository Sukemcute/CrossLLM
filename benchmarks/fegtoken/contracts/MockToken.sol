// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockToken
 * @notice Generic ERC20 standing in for a non-FEG asset that real
 *         users had approved FEGSwap to spend (e.g. USDT, BUSD, or
 *         BNB-pegged stablecoins). The 2022-04-28 incident drained
 *         such approvals via the migrator role-grant on FEGSwap. Kept
 *         self-contained so the benchmark compiles without OZ.
 */
contract MockToken {
    string public name;
    string public symbol;
    uint8 public immutable decimals;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory name_, string memory symbol_, uint8 decimals_) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "MockToken: allowance");
        if (a != type(uint256).max) {
            allowance[from][msg.sender] = a - amount;
        }
        require(balanceOf[from] >= amount, "MockToken: balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
