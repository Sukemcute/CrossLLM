// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title QBridgeETH (Qubit-inspired vulnerable reconstruction)
 * @notice Models the deposit-side flaw of QBridge from the 2022-01-27 incident.
 *
 * @dev Reconstruction notes
 * The original Qubit deposit router used a "native sentinel" code path: when
 * `tokenContract == address(0)` the router skipped the ERC20 transfer and
 * relied on `msg.value` for native ETH deposits. The deployed router carried
 * a legacy alternate path (the `safeTransferFrom` chain that fronted the
 * native sentinel) which **did not validate `msg.value > 0`**. Calling
 * `deposit(address(0), amount, recipient)` with `msg.value == 0` therefore
 * still emitted a `Deposit` event for an arbitrary `amount`. The cross-chain
 * relayer trusted that event and the BSC-side QBridge minted xQubit against
 * it.
 *
 * This reconstruction keeps the bug shape minimal so Module 1 can recognise
 * the relevant entities (router, recipient, amount) and Module 2 can produce
 * a verification-bypass scenario aimed at the asset-conservation invariant.
 */
contract QBridgeETH {
    /// Emitted on every deposit; relayed to BSC.
    event Deposit(
        address indexed token,
        uint256 amount,
        address indexed recipient,
        uint64 nonce
    );

    /// Sentinel used by the router to mean "native ETH".
    address public constant NATIVE = address(0);

    uint64 public nonce;
    /// Total ETH actually transferred into the contract (sound view of deposits).
    uint256 public totalLocked;

    /**
     * @notice Vulnerable deposit entrypoint.
     * @dev The native-sentinel branch (`token == NATIVE`) skips the
     *      `msg.value == amount` check that the secure path performs, so an
     *      attacker submits `deposit(NATIVE, 1e21, attacker)` with
     *      `msg.value == 0` and the relayer treats the emitted event as a
     *      legitimate cross-chain transfer.
     */
    function deposit(address token, uint256 amount, address recipient) external payable {
        if (token == NATIVE) {
            // VULN: missing `require(msg.value == amount)`.
            // Bookkeeping mirrors what really happened on-chain after msg.value=0.
            totalLocked += msg.value;
        } else {
            // Normal ERC-20 path (kept structural — no IERC20 call here so the
            // benchmark stays self-contained and Slither/forge can compile it).
            totalLocked += amount;
        }

        emit Deposit(token, amount, recipient, ++nonce);
    }
}
