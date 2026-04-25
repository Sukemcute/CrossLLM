// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title pGALAToken (BSC reconstruction)
 * @notice Minimal ERC-20-shaped destination-chain token. Production code uses
 *         pNetwork's ``ERC777`` peg-token; we keep just the storage and events
 *         that Module 1 / Module 3 reason about (asset conservation,
 *         minter authority).
 */
contract pGALAToken {
    string public constant name = "pNetwork GALA (BSC)";
    string public constant symbol = "pGALA";
    uint8 public constant decimals = 18;

    /// Authorised minter — only the current bridge custodian should hold this role.
    address public minter;

    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        minter = msg.sender;
    }

    /// @notice Mint pGALA. Production restricts this to the current custodian.
    function mint(address to, uint256 amount) external {
        // For benchmark purposes the custodian is allowed to mint.
        // In production this would be `require(msg.sender == minter, ...);`
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    /// @notice Owner hook to point the token at a new custodian (was used by
    ///         pNetwork in the redeploy that introduced the bug).
    function setMinter(address newMinter) external {
        minter = newMinter;
    }
}
