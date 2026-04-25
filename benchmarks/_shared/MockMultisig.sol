// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockMultisig
 * @notice Generic K-of-N ECDSA threshold harness for off-chain compromise
 *         benchmarks (Ronin, Harmony, Orbit). Each bridge configures N
 *         signer addresses + threshold K at construction.
 *
 * @dev Compromise model
 * The bug in those incidents lives **off-chain**: the attacker obtained
 * K signers' private keys (key compromise per V4) or a TSS/MPC ceremony
 * collapsed (V2 + V4). The on-chain code in production enforced its
 * spec correctly — what failed was the assumption "fewer than K signers
 * will be compromised". This contract therefore enforces the spec
 * faithfully: K valid distinct signatures over the digest authorise an
 * arbitrary call. Module 1+2 will see (a) the threshold-quorum
 * authorization invariant and (b) a `key_compromise` scenario that
 * collapses the security argument by varying who controls the keys.
 *
 * Digest construction uses `abi.encode` (not `abi.encodePacked`) to avoid
 * hash collisions across argument boundaries, and includes
 * `address(this)` so a digest signed for one bridge cannot be replayed
 * against another that happens to share signers (cross-domain replay
 * — relevant for Lazarus-style multi-bridge campaigns).
 *
 * Invariants this contract is intended to make explicit during fuzzing:
 * - threshold_quorum_authorization: every Executed event must correspond
 *   to >= threshold valid distinct signatures over the digest.
 * - signer_set_authority: only addresses in the constructor's `signers_`
 *   list may contribute to the quorum.
 * - digest_uniqueness: each (target, value, data, nonce, address(this))
 *   tuple may execute at most once.
 */
contract MockMultisig {
    address[] public signers;
    uint256 public threshold;
    mapping(address => bool) public isSigner;
    mapping(bytes32 => bool) public executed;

    event Executed(bytes32 indexed digest, address indexed target, uint256 value, bytes data);

    constructor(address[] memory signers_, uint256 threshold_) {
        require(signers_.length > 0, "MockMultisig: empty signer set");
        require(threshold_ > 0 && threshold_ <= signers_.length, "MockMultisig: bad threshold");
        signers = signers_;
        threshold = threshold_;
        for (uint256 i; i < signers_.length; ++i) {
            require(signers_[i] != address(0), "MockMultisig: zero signer");
            require(!isSigner[signers_[i]], "MockMultisig: duplicate signer");
            isSigner[signers_[i]] = true;
        }
    }

    function signerCount() external view returns (uint256) {
        return signers.length;
    }

    /**
     * @notice Execute an arbitrary call once `threshold` signers have signed
     *         the digest = keccak256(abi.encode(target, value, data, nonce, this)).
     *         Signatures must be sorted by recovered signer address (ascending,
     *         strictly increasing) — this both prevents duplicate-signer
     *         padding attacks and gives a deterministic ordering for
     *         downstream re-signing.
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        bytes[] calldata sigs
    ) external returns (bytes memory) {
        bytes32 digest = digestFor(target, value, data, nonce);
        require(!executed[digest], "MockMultisig: replay");
        require(sigs.length >= threshold, "MockMultisig: below threshold");

        address last = address(0);
        for (uint256 i; i < sigs.length; ++i) {
            address recovered = _recover(digest, sigs[i]);
            require(isSigner[recovered], "MockMultisig: not signer");
            require(uint160(recovered) > uint160(last), "MockMultisig: duplicate or unsorted");
            last = recovered;
        }

        executed[digest] = true;
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "MockMultisig: call failed");
        emit Executed(digest, target, value, data);
        return ret;
    }

    /**
     * @notice Pure helper that derived contracts can use to compute the
     *         digest off-chain (or on-chain in tests). Bound to this
     *         contract's address to prevent cross-domain replay.
     */
    function digestFor(
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(abi.encode(target, value, data, nonce, address(this)));
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "MockMultisig: bad sig length");
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        return ecrecover(digest, v, r, s);
    }

    receive() external payable {}
}
