"""Batch-apply X3-polish (C2) metadata additions to all 12 benchmarks.

For each `benchmarks/<bridge>/metadata.json`:
- Add `address_aliases`: map ATG node names that don't substring-match a
  metadata `contracts` key to a key that does. Fixes the bb_src=0 mode
  identified in `docs/REIMPL_XSCOPE_X4_OUTCOME.md` §3.1.
- Add `auth_witness`: per-bridge recipe (kind + contract_key + optional
  threshold) used by C3 to populate `AuthWitness` from the
  storage-write trace landed in C1.

Idempotent — re-running on an already-updated metadata leaves it
unchanged.

Usage:
    python scripts/_apply_x3polish_metadata.py
"""

from __future__ import annotations

import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(REPO, "benchmarks")


# Per-bridge ATG-node-name → contracts-key alias map. Each ATG node
# listed here either does not substring-match any metadata key or
# matches the wrong one (e.g. "WrappedToken" with no metadata entry).
# Keys on the right MUST exist in `contracts.{key}` of the same metadata.
ALIASES = {
    "fegtoken": {
        "FEGSwap": "feg_swap_eth",
        "FEGToken": "feg_token_bsc",
        "MockToken": "feg_token_bsc",
        "FlashLoanProvider": "flashloan_provider",
        # C4: bridge / relay variants the LLM scenarios invent.
        "AuthorizedRelayer": "feg_swap_bsc",
        "BridgeContract": "feg_swap_bsc",
        "BridgeFeeManager": "feg_swap_bsc",
        "BridgeRelay": "feg_swap_bsc",
        "MessageBridge": "feg_swap_bsc",
        "Relay": "feg_swap_bsc",
        "RelayHub": "feg_swap_bsc",
        "RelayNode_Compromised": "feg_swap_bsc",
        "RelayX": "feg_swap_bsc",
        "SocketRelay": "feg_swap_bsc",
        "AttackerContract": "attacker",
        "AttackerRelayProxy": "attacker",
    },
    "gempad": {
        "GemPadLocker": "gempad_locker",
        "MockToken": "victim_lp_token",
        # C4: bridge / relay / attacker variants.
        "BridgeRelayer": "gempad_locker",
        "GemPadRelayer": "gempad_locker",
        "Relayer": "gempad_locker",
        "MaliciousToken": "victim_lp_token",
        "MaliciousReceiver": "attacker",
        "AttackerMaliciousToken": "attacker",
    },
    "harmony": {
        "WrappedToken": "weth_ethereum",
        # C4: relay / signer / recipient variants.
        "HarmonyRelay": "horizon_eth_manager",
        "Relay": "horizon_eth_manager",
        "SignerSet": "horizon_eth_manager",
        "Token": "weth_ethereum",
        "MalRecipient": "attacker",
    },
    "multichain": {
        "WrappedToken": "weth_ethereum",
    },
    "nomad": {
        "BridgeRouter": "erc20_bridge_ethereum",
        "Replica": "replica_ethereum",
        "MockToken": "erc20_bridge_ethereum",
        "NomadMessage": "replica_ethereum",
    },
    "orbit": {
        "OrbitVault": "orbit_vault",
        "WrappedToken": "weth_ethereum",
        "MockMultisig": "orbit_vault",
    },
    "pgala": {
        "LegacyCustodian": "pgala_token_legacy",
        "pGALAToken": "pgala_token_relaunch",
    },
    "polynetwork": {
        "EthCrossChainData": "eth_cross_chain_data",
        "EthCrossChainManager": "eth_cross_chain_manager",
    },
    "qubit": {
        "QBridgeETH": "exploit_minted_token",
        "QBridgeBSC": "exploit_minted_token",
        "xQubit": "exploit_minted_token",
        "MockToken": "exploit_minted_token",
        # C4: capitalisation + relay variants.
        "xQUBIT": "exploit_minted_token",
        "MaliciousLock": "exploit_minted_token",
        "QBridgeRelay": "exploit_minted_token",
        "QubitRelay": "exploit_minted_token",
        "RelayBSC": "exploit_minted_token",
        "RelayNode": "exploit_minted_token",
        "RelayOracle": "exploit_minted_token",
    },
    "ronin": {
        "WrappedToken": "weth_ethereum",
    },
    "socket": {
        "SocketGateway": "socket_gateway",
        "SwapImplementationStub": "socket_gateway",
        "MockToken": "socket_gateway",
    },
    "wormhole": {
        "WormholeCore": "wormhole_core_eth",
        "TokenBridge": "token_bridge_eth",
        "WrappedAsset": "weth_ethereum",
    },
}


# Per-bridge auth-witness recipe. `kind` selects the AuthWitness variant
# C3 will construct from the SSTORE trace; `contract_key` points into
# `contracts.{key}`; `threshold` is the multisig quorum. Recipes set to
# `none` mean the bridge's predicted predicate (per spec §4) does NOT
# need I-6 — typically I-1 / I-2 / I-5 are the hot predicates.
AUTH_WITNESS = {
    "fegtoken":    {"kind": "none",      "contract_key": "feg_token_bsc"},
    "gempad":      {"kind": "none",      "contract_key": "gempad_locker"},
    "harmony":     {"kind": "multisig",  "contract_key": "horizon_eth_manager", "threshold": 2},
    "multichain":  {"kind": "mpc",       "contract_key": "multichain_router_eth"},
    "nomad":       {"kind": "zero_root", "contract_key": "replica_ethereum"},
    "orbit":       {"kind": "multisig",  "contract_key": "orbit_vault", "threshold": 7},
    "pgala":       {"kind": "mpc",       "contract_key": "pgala_token_relaunch"},
    "polynetwork": {"kind": "mpc",       "contract_key": "eth_cross_chain_manager"},
    "qubit":       {"kind": "none",      "contract_key": "exploit_minted_token"},
    "ronin":       {"kind": "multisig",  "contract_key": "ronin_bridge_v2_proxy", "threshold": 5},
    "socket":      {"kind": "none",      "contract_key": "socket_gateway"},
    "wormhole":    {"kind": "mpc",       "contract_key": "wormhole_core_eth"},
}


def update_metadata(bridge: str) -> tuple[bool, str]:
    """Returns (changed, message). Idempotent."""
    path = os.path.join(BENCH, bridge, "metadata.json")
    if not os.path.isfile(path):
        return False, f"missing {path}"

    with open(path, encoding="utf-8") as f:
        meta = json.load(f)

    changed = False
    contracts = meta.get("contracts", {})

    # Validate that aliases point at real contract keys.
    aliases = ALIASES.get(bridge, {})
    for src, dst in aliases.items():
        if dst not in contracts:
            return False, f"alias target '{dst}' not in contracts (bridge={bridge}, src={src})"
    if aliases and meta.get("address_aliases") != aliases:
        meta["address_aliases"] = aliases
        changed = True

    # Validate that auth_witness.contract_key points at a real contract.
    aw = AUTH_WITNESS.get(bridge)
    if aw is not None:
        if aw["contract_key"] not in contracts:
            return False, (
                f"auth_witness.contract_key '{aw['contract_key']}' not in contracts "
                f"(bridge={bridge})"
            )
        if meta.get("auth_witness") != aw:
            meta["auth_witness"] = aw
            changed = True

    if changed:
        # Pretty-print with 2-space indent + final newline so the diff
        # against existing JSON is minimal.
        with open(path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
            f.write("\n")
        return True, "updated"
    return False, "no-op"


def main() -> int:
    bridges = sorted(
        d for d in os.listdir(BENCH)
        if os.path.isdir(os.path.join(BENCH, d)) and not d.startswith("_")
    )
    n_changed = 0
    for b in bridges:
        ok, msg = update_metadata(b)
        if ok:
            n_changed += 1
            tag = "WROTE"
        elif msg == "no-op":
            tag = "noop "
        else:
            tag = "ERROR"
        print(f"  {tag} {b:12} {msg}")
        if tag == "ERROR":
            return 1
    print()
    print(f"{n_changed}/{len(bridges)} metadata files updated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
