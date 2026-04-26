// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./WrappedToken.sol";

/**
 * @title EthBucket (Harmony-Horizon-inspired custody pool)
 * @notice Pure custody contract. Holds the Ethereum-side ERC20 balances
 *         that the manager unlocks against signed withdrawal receipts.
 *         Separated from the manager so Module 1 sees an explicit
 *         authority-delegation edge (manager -> bucket).
 *
 * @dev The manager-only release guard is a layered defence: even if the
 *      manager's quorum check were misapplied, the bucket still pins
 *      releases to a single privileged caller. The Harmony incident
 *      defeated this by compromising the manager's signing keys, not by
 *      bypassing the bucket — so this contract correctly enforces its
 *      spec and is presented as such to Module 1.
 */
contract EthBucket {
    event Deposited(address indexed token, address indexed from, uint256 amount);
    event Released(address indexed token, address indexed to, uint256 amount);

    address public immutable manager;
    /// token => total currently held by the bucket on the Ethereum side.
    mapping(address => uint256) public totalLocked;
    /// token => cumulative amount released over the bucket's lifetime.
    mapping(address => uint256) public totalReleased;

    constructor(address manager_) {
        require(manager_ != address(0), "EthBucket: zero manager");
        manager = manager_;
    }

    function deposit(address token, address from, uint256 amount) external {
        require(msg.sender == manager, "EthBucket: only manager");
        WrappedToken(token).transferFrom(from, address(this), amount);
        totalLocked[token] += amount;
        emit Deposited(token, from, amount);
    }

    function release(address token, address recipient, uint256 amount) external {
        require(msg.sender == manager, "EthBucket: only manager");
        require(totalLocked[token] >= amount, "EthBucket: overdraw");
        totalLocked[token] -= amount;
        totalReleased[token] += amount;
        WrappedToken(token).transfer(recipient, amount);
        emit Released(token, recipient, amount);
    }
}
