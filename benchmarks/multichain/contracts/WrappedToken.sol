// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title WrappedToken
 * @notice Minimal ERC20 standing in for the assets Multichain custodied
 *         on Ethereum: WETH, USDC, USDT, WBTC, DAI (and smaller
 *         positions in LINK, MIM, AVAX). Reused across the asset set
 *         with different `(name, symbol, decimals)` constructor args.
 *         Self-contained so the benchmark compiles without OZ.
 */
contract WrappedToken {
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

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "WrappedToken: balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "WrappedToken: allowance");
        if (a != type(uint256).max) {
            allowance[from][msg.sender] = a - amount;
        }
        require(balanceOf[from] >= amount, "WrappedToken: balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
