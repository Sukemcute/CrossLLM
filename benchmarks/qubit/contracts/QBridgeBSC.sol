// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockToken.sol";

/**
 * @title QBridgeBSC (Qubit-inspired destination router)
 * @notice Mints xQubit on BSC against deposit events relayed from Ethereum.
 *
 * @dev Reconstruction notes
 * The destination router trusted the relayed `(token, amount, recipient,
 * nonce)` tuple and called `MockToken.mint(recipient, amount)` without any
 * cross-chain consistency check beyond a nonce uniqueness bit. There is no
 * mechanism to compare `amount` with the ETH actually locked on the source
 * chain, which is what made the deposit-event forgery turn into actual
 * minted balance.
 *
 * Invariants this contract is intended to violate during fuzzing:
 * - asset_conservation: `totalMinted` should never exceed `totalLocked`
 *   (modelled here by reading from the source-side router via off-chain
 *   relay state — Module 3 supplies this through GlobalState).
 * - uniqueness: each `(nonce, recipient)` should be processed at most once.
 */
contract QBridgeBSC {
    event Mint(address indexed recipient, uint256 amount, uint64 nonce);

    MockToken public immutable xQubit;
    mapping(uint64 => bool) public processed;
    uint256 public totalMinted;

    constructor(address xQubitAddr) {
        xQubit = MockToken(xQubitAddr);
    }

    /**
     * @notice Process a relayed deposit event and mint xQubit to the recipient.
     * @dev Trusts `amount` blindly. Combined with QBridgeETH's missing
     *      `msg.value` check, this yields the asset-conservation violation.
     */
    function process(address recipient, uint256 amount, uint64 nonce_) external {
        require(!processed[nonce_], "QBridgeBSC: replay");
        processed[nonce_] = true;
        totalMinted += amount;
        xQubit.mint(recipient, amount);
        emit Mint(recipient, amount, nonce_);
    }
}
