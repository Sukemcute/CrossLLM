// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockToken.sol";

/**
 * @title GemPadLocker (GemPad-inspired vulnerable reconstruction)
 * @notice Models the 2024-04 GemPad token-locker incident on BSC.
 *         GemPad is a token-launchpad service that lets project teams
 *         lock liquidity / team allocations for a configurable period
 *         to assure investors. The 2024-04 exploit drained ~$1.9M from
 *         locked positions because the locker's ownership-transfer
 *         path lacked an authorisation check.
 *
 * @dev Reconstruction notes
 * The bug being modelled is a classic **V1 verification bypass**:
 * `transferLockOwnership` reassigns the `owner` field of an existing
 * lock without checking that `msg.sender` is the current owner. An
 * attacker calls it on any lock to take ownership, then waits for the
 * unlock timestamp (or notes which positions are already unlocked) and
 * calls `withdraw` to receive the locked balance. The `withdraw`
 * function itself is correctly authorised — what fails is the
 * pre-condition that `owner` truthfully reflects who created the lock.
 *
 * The contract is intentionally narrowed: production GemPad has many
 * lock types (token / LP / NFT / vesting), per-team metadata, fee
 * collection, etc. Module 1 only needs to see the (lock -> withdraw)
 * flow plus the `transferLockOwnership` privilege-escalation surface;
 * Module 2 should produce an `ownership_hijack` / `verification_bypass`
 * scenario whose first action targets `transferLockOwnership` and
 * whose second action calls `withdraw` from the new "owner".
 *
 * Invariants this contract is intended to violate during fuzzing:
 * - lock_owner_authority: only the original `lock()` caller may be
 *   recorded as `Lock.owner`; reassignment must require the current
 *   owner's authorisation.
 * - asset_conservation_per_lock: a `Lock` may release at most
 *   `Lock.amount` tokens, exactly once, to the original depositor.
 */
contract GemPadLocker {
    struct Lock {
        address owner;
        address token;
        uint256 amount;
        uint256 unlockTime;
        bool withdrawn;
    }

    event LockCreated(uint256 indexed lockId, address indexed owner, address indexed token, uint256 amount, uint256 unlockTime);
    event OwnershipTransferred(uint256 indexed lockId, address indexed previousOwner, address indexed newOwner);
    event Withdrawn(uint256 indexed lockId, address indexed to, uint256 amount);

    mapping(uint256 => Lock) public locks;
    uint256 public nextLockId;

    /// Aggregate sound-view of locked balance — sum across all active locks.
    /// Useful for asset-conservation invariant checks.
    mapping(address => uint256) public totalLocked;

    /**
     * @notice Lock `amount` of `token` until `unlockTime`. The caller
     *         is recorded as the lock's owner and is the only address
     *         legitimately able to withdraw.
     */
    function lock(address token, uint256 amount, uint256 unlockTime) external returns (uint256 id) {
        require(unlockTime > block.timestamp, "GemPad: unlockTime in past");
        MockToken(token).transferFrom(msg.sender, address(this), amount);
        id = nextLockId++;
        locks[id] = Lock({
            owner: msg.sender,
            token: token,
            amount: amount,
            unlockTime: unlockTime,
            withdrawn: false
        });
        totalLocked[token] += amount;
        emit LockCreated(id, msg.sender, token, amount, unlockTime);
    }

    /**
     * @notice Reassign ownership of `lockId` to `newOwner`.
     * @dev VULN: missing `require(msg.sender == locks[lockId].owner)`.
     *      Anyone can rewrite the owner of any lock, then withdraw it
     *      after `unlockTime` has elapsed (or immediately for locks
     *      whose timer has already expired). This is the entire bug
     *      surface — the rest of the locker enforces its spec.
     */
    function transferLockOwnership(uint256 lockId, address newOwner) external {
        Lock storage l = locks[lockId];
        require(l.amount > 0, "GemPad: lock not found");
        require(!l.withdrawn, "GemPad: already withdrawn");
        // VULN: missing `require(msg.sender == l.owner)`
        address previous = l.owner;
        l.owner = newOwner;
        emit OwnershipTransferred(lockId, previous, newOwner);
    }

    /**
     * @notice Withdraw a fully-unlocked position to its current owner.
     * @dev Correctly authorised — the bug is upstream in
     *      `transferLockOwnership`. Once that hijacks `owner`, this
     *      function dutifully transfers the balance to the new "owner"
     *      because the on-chain authority chain is now corrupted.
     */
    function withdraw(uint256 lockId) external {
        Lock storage l = locks[lockId];
        require(msg.sender == l.owner, "GemPad: not owner");
        require(block.timestamp >= l.unlockTime, "GemPad: still locked");
        require(!l.withdrawn, "GemPad: already withdrawn");
        l.withdrawn = true;
        totalLocked[l.token] -= l.amount;
        MockToken(l.token).transfer(l.owner, l.amount);
        emit Withdrawn(lockId, l.owner, l.amount);
    }
}
