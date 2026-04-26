// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SwapImplementationStub
 * @notice Minimal stand-in for a Socket route's swap implementation. The
 *         production deployment had per-route logic (Uniswap-V3, 1inch,
 *         0x, etc.). For Module 1+2 the only relevant fact is that a route
 *         exists and is reachable via SocketGateway.routes; the body is
 *         immaterial because the bug lives in SocketGateway, not here.
 */
contract SwapImplementationStub {
    event StubInvoked(address fromToken, address toToken, uint256 amount);

    function executeSwap(address fromToken, address toToken, uint256 amount, bytes calldata /*data*/) external {
        emit StubInvoked(fromToken, toToken, amount);
    }
}
