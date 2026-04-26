// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title WormholeCore (Wormhole-inspired vulnerable reconstruction)
 * @notice EVM-side approximation of Wormhole's VAA (Verified Action Approval)
 *         verification surface. Models the trust boundary that the 2022-02-02
 *         exploit broke on the Solana side (`verify_signatures` accepting a
 *         spoofed Sysvar Instructions account).
 *
 * @dev Reconstruction notes
 * The original incident occurred on Solana: the `solana_program::sysvar::instructions`
 * account fed to `verify_signatures` was not validated against the canonical
 * Sysvar1nstructions1111 address, so the program accepted a forged instructions
 * record claiming guardian signatures had been verified. The attacker then
 * submitted a "verified" VAA to `complete_wrapped` and minted ~120,000 whETH
 * with no backing on Ethereum.
 *
 * Because BridgeSentry's fuzzer is EVM-only (revm), this reconstruction models
 * the analogous trust boundary on an EVM core contract: `parseAndVerifyVM` reads
 * a hashed signature digest from a caller-supplied storage key without binding
 * that key to the canonical guardian-set storage slot. An attacker that can
 * write to *any* storage key (e.g. via a different verify-signatures helper
 * that lacks address validation) can pre-stage a forged digest and the core
 * will treat it as guardian-approved. See paper Section 6 for the limitation.
 *
 * Invariants this contract is intended to violate during fuzzing:
 * - signature_authenticity: every accepted VAA must hash to a digest signed by
 *   the active guardian set's quorum.
 * - guardian_set_authority: only `currentGuardianSet`'s pubkeys can mark a
 *   digest as verified.
 */
contract WormholeCore {
    struct VM {
        uint8 version;
        uint32 timestamp;
        uint32 nonce;
        uint16 emitterChainId;
        bytes32 emitterAddress;
        uint64 sequence;
        uint8 consistencyLevel;
        bytes payload;
        uint32 guardianSetIndex;
        bytes32 hash;
    }

    /// Emitted whenever a VAA digest is recorded as verified.
    event VAAVerified(bytes32 indexed digest, uint32 guardianSetIndex);

    /// Active guardian set index. Production contract bumps on rotation.
    uint32 public currentGuardianSetIndex;

    /// guardianSetIndex => list of guardian pubkeys (address-form for EVM).
    mapping(uint32 => address[]) internal guardianSets;

    /// guardianSetIndex => required signature quorum (~2/3 in production).
    mapping(uint32 => uint256) public guardianQuorum;

    /// digest => true once a VAA has been verified. Production contract has
    /// no such cache; we expose it so the bug is observable from tests.
    mapping(bytes32 => bool) public verifiedDigests;

    /// VULN-MODEL: a side-channel storage map that the legacy
    /// `verify_signatures` helper writes to, keyed by an attacker-supplied
    /// "instruction account" pseudo-id. Modelled here as a `bytes32` slot
    /// caller can poison without proving ownership of the canonical sysvar.
    mapping(bytes32 => bool) public legacyVerifiedSlot;

    function registerGuardianSet(uint32 index, address[] calldata keys, uint256 quorum_) external {
        // Simplified: production has governance VAA gating. For benchmark
        // purposes we let tests preload a canonical set.
        guardianSets[index] = keys;
        guardianQuorum[index] = quorum_;
        if (index >= currentGuardianSetIndex) {
            currentGuardianSetIndex = index;
        }
    }

    /**
     * @notice Legacy "fast path" verifier — analogue of the Solana
     *         `verify_signatures` instruction that accepted an unauthenticated
     *         Sysvar Instructions account.
     * @dev VULN: writes to `legacyVerifiedSlot[slotId]` without validating that
     *      `slotId` corresponds to the active guardian set's signing record.
     *      Any caller can pre-mark an arbitrary digest as verified.
     */
    function verifySignaturesLegacy(bytes32 slotId, bytes32 /*digest*/, bytes calldata /*sigs*/) external {
        // VULN: missing `require(slotId == _canonicalSlotFor(currentGuardianSetIndex))`
        // and missing real ECDSA verification against `guardianSets[currentGuardianSetIndex]`.
        legacyVerifiedSlot[slotId] = true;
    }

    /**
     * @notice Parses an encoded VAA and either accepts it on the strict path
     *         (signature quorum recomputed against the active guardian set)
     *         or short-circuits via the legacy slot if it is already marked.
     * @dev The legacy short-circuit is the modelled bug. In production this
     *      corresponds to the Solana program trusting the post-`verify_signatures`
     *      record without re-checking the Sysvar Instructions account.
     */
    function parseAndVerifyVM(bytes calldata encodedVM)
        external
        returns (VM memory vm, bool valid, string memory reason)
    {
        vm = _parseVM(encodedVM);

        // Replay protection on the digest cache.
        if (verifiedDigests[vm.hash]) {
            return (vm, false, "already verified");
        }

        // VULN-MODEL: the legacy slot is keyed by `vm.hash` directly, so an
        // attacker who poisoned `legacyVerifiedSlot[vm.hash]` via
        // `verifySignaturesLegacy` is now treated as having a signed VAA.
        if (legacyVerifiedSlot[vm.hash]) {
            verifiedDigests[vm.hash] = true;
            emit VAAVerified(vm.hash, vm.guardianSetIndex);
            return (vm, true, "");
        }

        // Strict path: would recover ECDSA signers from the trailing
        // signature blob and compare against guardianSets[vm.guardianSetIndex].
        // Kept structural so Module 1 sees the intended control flow without
        // dragging in an ecrecover dependency for the offline smoke test.
        address[] storage keys = guardianSets[vm.guardianSetIndex];
        if (keys.length == 0) {
            return (vm, false, "unknown guardian set");
        }
        // (Real implementation: count signatures, verify each via ecrecover,
        //  require count >= guardianQuorum[vm.guardianSetIndex].)
        return (vm, false, "strict path requires real signatures");
    }

    function _parseVM(bytes calldata encodedVM) internal pure returns (VM memory vm) {
        // Minimal parse: rely on abi.decode of a struct payload so the
        // benchmark stays self-contained. Production parses a custom binary
        // VAA layout; the field set we expose here matches the same logical
        // record the fuzzer needs to reason about.
        (
            vm.version,
            vm.timestamp,
            vm.nonce,
            vm.emitterChainId,
            vm.emitterAddress,
            vm.sequence,
            vm.consistencyLevel,
            vm.payload,
            vm.guardianSetIndex
        ) = abi.decode(
            encodedVM,
            (uint8, uint32, uint32, uint16, bytes32, uint64, uint8, bytes, uint32)
        );
        vm.hash = keccak256(encodedVM);
    }
}
