// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title FEGToken (FEGtoken-inspired vulnerable reconstruction)
 * @notice Models the migrator role-grant primitive that the 2022-04-28
 *         FEGtoken incident abused. The attacker satisfied a transient
 *         balance-threshold check via a flash loan, claimed the
 *         migrator role, then used that role to drain user approvals
 *         from FEGSwap.
 *
 * @dev Reconstruction notes
 * Production FEGToken's migrator role was administered through a
 * governance path that included instantaneous balance checks. The
 * specific code path the attacker abused was indirectly reachable
 * through the staking/migration flow; for benchmark purposes this is
 * collapsed to a single `claimMigrator()` entry point that gates only
 * on a transient balance threshold (the canonical anti-pattern that
 * flash loans defeat).
 *
 * The bug being modelled has two layers:
 * - V2 (replay-style / flash-loan amplification): the migrator gate
 *   accepts a balance check that holds for one block only — a flash
 *   loan satisfies the check inside one transaction.
 * - V4 (privilege escalation / role compromise): once the attacker is
 *   migrator, they can authorise arbitrary FEGSwap operations including
 *   approval-based drains of unrelated users' funds.
 */
contract FEGToken {
    string public name = "FEG Token";
    string public symbol = "FEG";
    uint8 public constant decimals = 18;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    /// Address currently holding the migrator role. The attacker
    /// transiently became this after a flash loan.
    address public migrator;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event MigratorClaimed(address indexed newMigrator);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "FEG: balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "FEG: allowance");
        if (a != type(uint256).max) {
            allowance[from][msg.sender] = a - amount;
        }
        require(balanceOf[from] >= amount, "FEG: balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }

    /**
     * @notice Claim the migrator role by demonstrating a transient
     *         balance threshold (>= 10% of supply).
     * @dev VULN: the gate is satisfied by *current-block* balance.
     *      A flash loan inflates `balanceOf[msg.sender]` for the
     *      duration of one transaction, which is sufficient to pass
     *      this check and write `migrator = msg.sender`. Once the
     *      flash loan repays, the attacker has no remaining FEG —
     *      but the migrator assignment persists (the production code
     *      had no time-locked confirmation step).
     */
    function claimMigrator() external {
        require(balanceOf[msg.sender] >= totalSupply / 10, "FEG: need 10% holding");
        migrator = msg.sender;
        emit MigratorClaimed(msg.sender);
    }
}
