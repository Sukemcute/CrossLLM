// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./FEGToken.sol";

/**
 * @title IFlashLoanReceiver
 * @notice Callback interface the FlashLoanProvider invokes mid-loan.
 */
interface IFlashLoanReceiver {
    function onFlashLoan(uint256 amount, bytes calldata data) external;
}

/**
 * @title FlashLoanProvider (mock)
 * @notice Single-token flash-loan pool standing in for the production
 *         lending venue (PancakeSwap or similar) that supplied the
 *         FEG balance in the 2022-04-28 incident. Implements the
 *         standard "transfer -> callback -> require post-balance >=
 *         pre-balance" pattern.
 *
 * @dev The provider contract itself is not vulnerable — flash loans
 *      are correctly bounded by the post-callback balance check. The
 *      V2 (replay-style) classification of FEGtoken comes from
 *      *downstream* misuse: the flash-loaned FEG temporarily satisfies
 *      `FEGToken.claimMigrator`'s balance threshold, which is the gate
 *      that should not be defeatable by transient balances.
 */
contract FlashLoanProvider {
    FEGToken public immutable feg;

    constructor(address feg_) {
        feg = FEGToken(feg_);
    }

    /**
     * @notice Borrow `amount` of FEG; caller must repay in the same
     *         transaction by ensuring the provider's FEG balance is
     *         restored before this function returns.
     */
    function flashLoan(uint256 amount, bytes calldata data) external {
        uint256 balanceBefore = feg.balanceOf(address(this));
        require(balanceBefore >= amount, "FlashLoanProvider: insufficient liquidity");
        feg.transfer(msg.sender, amount);
        IFlashLoanReceiver(msg.sender).onFlashLoan(amount, data);
        require(feg.balanceOf(address(this)) >= balanceBefore, "FlashLoanProvider: not repaid");
    }
}
