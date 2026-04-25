// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./WormholeCore.sol";
import "./WrappedAsset.sol";

/**
 * @title TokenBridge (Wormhole-inspired destination router)
 * @notice EVM-side reconstruction of the destination router that mints
 *         wrapped assets in response to a verified VAA. Pairs with
 *         WormholeCore's modelled bug — once a forged VAA is accepted, this
 *         router mints whETH (or any registered wrapped asset) to the
 *         attacker without further checks.
 *
 * @dev Reconstruction notes
 * In the production Wormhole TokenBridge, `completeTransfer` calls into the
 * Core contract's `parseAndVerifyVM`, then dispatches by payload type to
 * `_completeWrapped` (mint) or `_completeNative` (release locked tokens).
 * The 2022-02 incident was bounded to the wrapped-mint path on Solana; we
 * model only that path on EVM.
 *
 * Invariants this contract is intended to violate during fuzzing:
 * - asset_conservation: `WrappedAsset.totalSupply()` must be backed by an
 *   equal amount of locked native tokens on the source chain.
 * - vaa_uniqueness: each VAA digest can be redeemed at most once.
 */
contract TokenBridge {
    event TransferCompleted(bytes32 indexed digest, address indexed recipient, uint256 amount, address wrapped);

    WormholeCore public immutable core;

    /// (originChainId, originAddress) => wrappedAsset on this chain.
    mapping(uint16 => mapping(bytes32 => address)) public wrappedAssets;

    /// digest => true after redemption.
    mapping(bytes32 => bool) public completed;

    /// totalMinted across every wrapped asset issued by this bridge — sound
    /// view for the asset_conservation invariant.
    uint256 public totalMinted;

    constructor(address coreAddr) {
        core = WormholeCore(coreAddr);
    }

    function registerWrappedAsset(uint16 originChainId, bytes32 originAddress, address wrapped) external {
        wrappedAssets[originChainId][originAddress] = wrapped;
    }

    /**
     * @notice Redeems a VAA carrying a transfer payload by minting the
     *         appropriate wrapped asset to the recipient.
     * @dev Trusts `core.parseAndVerifyVM` for all authenticity. Once the core
     *      contract accepts a forged VAA via the legacy slot, this function
     *      mints unbacked tokens.
     */
    function completeTransfer(bytes calldata encodedVM) external {
        (WormholeCore.VM memory vm, bool valid, string memory reason) = core.parseAndVerifyVM(encodedVM);
        require(valid, reason);
        require(!completed[vm.hash], "TokenBridge: replay");
        completed[vm.hash] = true;

        Transfer memory t = _parseTransferPayload(vm.payload);
        address wrapped = wrappedAssets[t.tokenChain][t.tokenAddress];
        require(wrapped != address(0), "TokenBridge: unregistered asset");

        totalMinted += t.amount;
        WrappedAsset(wrapped).mint(t.recipient, t.amount);
        emit TransferCompleted(vm.hash, t.recipient, t.amount, wrapped);
    }

    struct Transfer {
        uint8 payloadID;
        uint256 amount;
        bytes32 tokenAddress;
        uint16 tokenChain;
        address recipient;
        uint16 recipientChain;
        uint256 fee;
    }

    function _parseTransferPayload(bytes memory payload) internal pure returns (Transfer memory t) {
        (
            t.payloadID,
            t.amount,
            t.tokenAddress,
            t.tokenChain,
            t.recipient,
            t.recipientChain,
            t.fee
        ) = abi.decode(payload, (uint8, uint256, bytes32, uint16, address, uint16, uint256));
    }
}
