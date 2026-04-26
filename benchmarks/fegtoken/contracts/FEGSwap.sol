// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./FEGToken.sol";
import "./MockToken.sol";

/**
 * @title FEGSwap (FEGtoken-inspired vulnerable swap router)
 * @notice Models the swap router that the 2022-04-28 FEG incident
 *         drained. Production FEGSwap had a `swapToSwap` entry point
 *         whose access control collapsed to "caller is migrator".
 *         Combined with FEGToken's transient-balance migrator gate,
 *         a flash loan satisfies the migrator check and the function
 *         pulls from arbitrary users' allowances to FEGSwap.
 *
 * @dev Reconstruction notes
 * Real users who intended to use FEG's swap functionality typically
 * called `MockToken.approve(FEGSwap, MAX)`. The router stored those
 * allowances and was supposed to consume them only on legitimate
 * swap paths driven by the protocol's own routing logic. The
 * `swapToSwap` admin path was meant to be an internal helper for the
 * migrator role; making it externally callable + only-migrator-gated
 * (rather than internal + called from a vetted swap path) is what
 * made the V2+V4 chain reachable.
 *
 * Invariants this contract is intended to violate during fuzzing:
 * - migrator_authorisation: only a sustained migrator may move user
 *   funds via swapToSwap (not a transient-balance flash-loan migrator).
 * - approval_consent: a user's approve(FEGSwap, X) authorises FEGSwap
 *   to act *on the user's own swap requests*, not on arbitrary
 *   migrator-driven drains targeted at the user's allowance.
 */
contract FEGSwap {
    event SwapToSwap(address indexed token, address indexed from, address indexed to, uint256 amount);

    FEGToken public immutable feg;

    constructor(address feg_) {
        feg = FEGToken(feg_);
    }

    /**
     * @notice Privileged swap entry point that pulls `amount` of `tokenA`
     *         from `from` (using `from`'s prior approval to FEGSwap) and
     *         delivers it to `to`.
     * @dev VULN: the only access control is `msg.sender == feg.migrator()`.
     *      Combined with FEGToken's transient-balance migrator
     *      assignment, an attacker who flash-borrows enough FEG to
     *      claim the migrator role can drain any user who has approved
     *      FEGSwap, with `from` and `to` both attacker-controlled.
     */
    function swapToSwap(address tokenA, address from, address to, uint256 amount) external {
        require(msg.sender == feg.migrator(), "FEGSwap: caller is not migrator");
        // VULN: pulls from arbitrary `from` using FEGSwap's accumulated
        // approval rights — there is no signed authorisation from `from`
        // pinning this specific operation to a specific caller.
        MockToken(tokenA).transferFrom(from, to, amount);
        emit SwapToSwap(tokenA, from, to, amount);
    }
}
