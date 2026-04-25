// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockToken.sol";

/**
 * @title SocketGateway (Socket-Bungee inspired vulnerable reconstruction)
 * @notice Reconstructs the 2024-01-16 SocketGateway exploit. The aggregator
 *         exposed a swap route whose `performAction` function read the
 *         `fromUser` address from caller-supplied calldata and pulled tokens
 *         via `transferFrom(fromUser, ...)` without verifying
 *         `msg.sender == fromUser`. Because users had previously approved
 *         SocketGateway to spend their tokens, an attacker drained ~$3.3M
 *         across many wallets.
 *
 * @dev Reconstruction notes
 * The production deployment routes calls through an upgradeable proxy and
 * dispatches to per-route implementation contracts (Route #16 was the
 * affected one). The benchmark collapses this to a single contract because
 * the bug lives entirely in the (caller -> from) authorization gap; the
 * proxy/route indirection is cosmetic for Module 1's purposes.
 *
 * Invariants this contract is intended to violate during fuzzing:
 * - caller_authorization: any token movement must be authorized by the
 *   token's owner (msg.sender == from OR explicit signed permit).
 * - approval_consent: prior `approve()` to the gateway authorises the
 *   gateway to act *on behalf of msg.sender*, not on behalf of arbitrary
 *   third parties whose only mistake was approving the same gateway.
 */
contract SocketGateway {
    event RouteRegistered(uint32 indexed routeId, address indexed implementation);
    event SwapPerformed(
        address indexed caller,
        address indexed fromUser,
        address indexed recipient,
        address fromToken,
        address toToken,
        uint256 amount
    );

    address public owner;

    /// routeId => implementation address (whitelisted swap implementations).
    mapping(uint32 => address) public routes;

    /// Aggregate of pulled balances across all swaps — sound view used to
    /// detect the asset-conservation impact of the exploit.
    uint256 public totalPulled;

    constructor() {
        owner = msg.sender;
    }

    function registerRoute(uint32 routeId, address impl) external {
        require(msg.sender == owner, "SocketGateway: not owner");
        routes[routeId] = impl;
        emit RouteRegistered(routeId, impl);
    }

    /**
     * @notice Vulnerable swap entrypoint.
     * @dev VULN: the function trusts the caller-supplied `fromUser` and
     *      pulls tokens via `transferFrom(fromUser, ...)`. Because Socket
     *      users had previously approved this contract to spend their
     *      tokens for legitimate swaps, anyone can call this with
     *      `fromUser = victim` and drain the victim's approval allowance
     *      for the corresponding token.
     *
     *      The fix is the missing `require(msg.sender == fromUser)` (or a
     *      signed permit that pins the operation to a specific caller).
     */
    function performAction(
        uint32 routeId,
        address fromToken,
        address toToken,
        uint256 amount,
        address fromUser,
        address recipient,
        bytes calldata /*swapData*/
    ) external {
        address impl = routes[routeId];
        require(impl != address(0), "SocketGateway: unknown route");

        // VULN: missing `require(msg.sender == fromUser);`
        // Pull tokens from a user the attacker does not control.
        MockToken(fromToken).transferFrom(fromUser, address(this), amount);
        totalPulled += amount;

        // In production, the route's swap implementation would convert
        // fromToken -> toToken and forward output to `recipient`. The
        // benchmark forwards the same balance unchanged; the bug expresses
        // itself the moment `transferFrom` succeeds, regardless of the
        // downstream swap behaviour.
        MockToken(toToken).mint(recipient, amount);

        emit SwapPerformed(msg.sender, fromUser, recipient, fromToken, toToken, amount);
    }
}
