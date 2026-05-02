// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Minimal cross-chain-bridge-shaped contract used as a SA3 unit-test
/// fixture. Carries each of the four protected-resource categories
/// the spec calls out (R1 state R/W, R2 internal call, R3 external
/// call, R4 emit) plus a couple of `require` predicates so the
/// CfgNode.requires field is non-empty.

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract TinyBridge {
    // R1 — state variables
    address public admin;
    mapping(bytes32 => bool) public processed;
    uint256 public totalLocked;

    // R4 — events the caller is meant to observe
    event Lock(address indexed sender, address token, uint256 amount, bytes32 messageHash);
    event Unlock(address indexed recipient, uint256 amount, bytes32 messageHash);

    constructor() {
        admin = msg.sender;
    }

    /// Source-chain deposit. Carries:
    ///   - R1 read of `admin`
    ///   - R3 external call IERC20.transferFrom
    ///   - R1 write of `totalLocked`
    ///   - R4 emit Lock
    ///   - SC2-style argument check (amount > 0 / token != 0)
    function deposit(IERC20 token, uint256 amount, bytes32 messageHash) external {
        require(amount > 0, "amount=0");
        require(address(token) != address(0), "token=0");
        require(!processed[messageHash], "replayed");

        // R3 external call
        bool ok = token.transferFrom(msg.sender, address(this), amount);
        require(ok, "transferFrom failed");

        // R1 writes
        totalLocked += amount;
        processed[messageHash] = true;

        // R4 emit
        emit Lock(msg.sender, address(token), amount, messageHash);
    }

    /// Destination-chain unlock — intentionally missing the SC4
    /// signature-check so SA5's omission detector has something to
    /// flag.
    function unlock(address recipient, uint256 amount, bytes32 messageHash) external {
        // R1 read + write
        require(!processed[messageHash], "already processed");
        processed[messageHash] = true;

        // R2 internal call
        _release(recipient, amount);

        // R4 emit
        emit Unlock(recipient, amount, messageHash);
    }

    function _release(address to, uint256 amount) internal {
        // R1 write through state mutation
        totalLocked -= amount;
        // (no real ERC20 transfer in this fixture — just demonstrates
        //  the R2 internal-call edge from `unlock` to here)
        to; amount;
    }
}
