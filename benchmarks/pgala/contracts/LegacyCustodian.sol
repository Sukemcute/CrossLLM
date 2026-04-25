// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./pGALAToken.sol";

/**
 * @title LegacyCustodian (pGALA-inspired vulnerable reconstruction)
 * @notice Models the 2022-11-03 pGALA / pNetwork incident.
 *
 * @dev Reconstruction notes
 * pNetwork re-deployed the pGALA bridge custodian on BSC after a contract
 * upgrade without retiring the old signing key. The legacy custodian
 * therefore remained authoritative for mint operations. An attacker who
 * still held (or could otherwise produce) the legacy ECDSA signature was
 * able to call mint() directly, mint ~1B pGALA on BSC, and dump them on
 * PancakeSwap before pNetwork could disable the contract.
 *
 * Bug class (paper taxonomy): V1 (verification bypass via stale credentials).
 *
 * Key invariants this contract is intended to violate during fuzzing:
 * - authorization: mint must require a CURRENT, non-rotated signer.
 * - asset_conservation: pGALA total supply on BSC must not exceed the
 *   ERC-20 GALA backing locked on Ethereum (modelled as the
 *   ``totalLockedOnEthereum`` view).
 * - uniqueness: each (nonce) consumed at most once.
 */
contract LegacyCustodian {
    /// Authoritative signer for mint operations.
    /// VULN: this slot was not rotated after the bridge re-deploy, so an
    /// attacker with a legacy private key continues to bypass the verification.
    address public signer;

    /// Replay protection.
    mapping(uint64 => bool) public used;

    /// Destination token. The custodian is the sole minter in production.
    pGALAToken public immutable pGALA;

    /// Invariant view: ETH-side locked amount that *should* back pGALA on BSC.
    /// Set externally (e.g. by relayer) and read by oracles / fuzzer.
    uint256 public totalLockedOnEthereum;

    event Mint(address indexed to, uint256 amount, uint64 nonce);
    event SignerRotated(address indexed previous, address indexed current);

    constructor(address signer_, address pGALAAddr) {
        signer = signer_;
        pGALA = pGALAToken(pGALAAddr);
    }

    /**
     * @notice Mint pGALA against an off-chain signed authorization.
     * @dev `sig` is an ECDSA signature over keccak256(to, amount, nonce).
     *      In the real incident the verification succeeded because the
     *      legacy ``signer`` was never updated after re-deploy.
     */
    function mint(address to, uint256 amount, uint64 nonce, bytes calldata sig) external {
        require(!used[nonce], "LegacyCustodian: replay");
        bytes32 digest = keccak256(abi.encode(to, amount, nonce));
        address recovered = _recover(digest, sig);
        require(recovered == signer, "LegacyCustodian: bad signer");

        used[nonce] = true;
        pGALA.mint(to, amount);
        emit Mint(to, amount, nonce);
    }

    /// @notice Operator hook to acknowledge cross-chain locks for invariant accounting.
    function setLocked(uint256 newLocked) external {
        totalLockedOnEthereum = newLocked;
    }

    /// @notice Owner-style hook that *should* have been used to retire the legacy key.
    function rotateSigner(address newSigner) external {
        emit SignerRotated(signer, newSigner);
        signer = newSigner;
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        // Use calldata loads to keep the reconstruction self-contained.
        assembly {
            let p := sig.offset
            r := calldataload(p)
            s := calldataload(add(p, 32))
            v := byte(0, calldataload(add(p, 64)))
        }
        if (v < 27) v += 27;
        return ecrecover(digest, v, r, s);
    }
}
