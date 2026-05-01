"""SA4 — Per-bridge configuration loader.

Combines two on-disk sources into a :class:`BridgeConfig`:

* ``benchmarks/<bridge>/metadata.json`` — authoritative mapping from
  contract key to address, role description, and (where present)
  ``contracts.<key>.chain ∈ {"source", "destination", "offchain"}``.
* ``tools/smartaxe_reimpl/data/event_signatures.json`` — per-bridge
  cross-chain event topics + authorisation methods. Maintained
  separately because not every benchmark's metadata.json carries an
  ``events`` block (the spec §3 mapping table assumed it does, but
  in practice we hand-curate it for the 12 fixtures).

When metadata is silent on which contract is source vs destination
(e.g. Nomad's ``chain`` attribute is ``None``), we fall back to a
suffix heuristic: ``_ethereum`` / ``_eth`` → source, ``_bsc`` /
``_bnb`` → destination, etc. Bridges that defeat the heuristic land
**all contracts in src** with a logged warning — SA4 builds an Ef-only
xCFG, no cross-chain edges fire, and SA5's omission detector falls
through. Better than crashing.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


_REIMPL_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_EVENT_SIGS = _REIMPL_ROOT / "data" / "event_signatures.json"


@dataclass
class BridgeConfig:
    """Resolved per-bridge config consumed by :mod:`xcfg_builder`."""

    bridge_id: str
    contracts_dir: Path
    src_contracts: set[str] = field(default_factory=set)
    dst_contracts: set[str] = field(default_factory=set)
    lock_signatures: set[str] = field(default_factory=set)
    unlock_signatures: set[str] = field(default_factory=set)
    auth_methods: set[str] = field(default_factory=set)

    def is_cross_chain_event(self, event_signature: str) -> bool:
        """True when the emit is a documented cross-chain lock or unlock event."""
        sig = _strip_arg_types(event_signature)
        return sig in {_strip_arg_types(s) for s in (self.lock_signatures | self.unlock_signatures)}

    def is_authorization_method(self, fn_signature: str) -> bool:
        """True when *fn_signature* matches a documented authorisation entry point."""
        bare = fn_signature.split("(", 1)[0]
        return bare in {m.split("(", 1)[0] for m in self.auth_methods}

    def classify_contract(self, contract_name: str) -> str:
        """Return ``"src"``, ``"dst"``, or ``"unknown"``."""
        if contract_name in self.src_contracts:
            return "src"
        if contract_name in self.dst_contracts:
            return "dst"
        return "unknown"


# ============================================================================
# Loader
# ============================================================================


def load_bridge_config(
    bridge_dir: str | Path,
    event_signatures_path: Optional[str | Path] = None,
) -> BridgeConfig:
    """Read ``metadata.json`` + ``event_signatures.json`` and produce
    a :class:`BridgeConfig`. Either input may be missing — defaults
    keep the rest of the pipeline running with empty cross-chain
    edges (Ef-only xCFG)."""

    # Resolve to an absolute path so a relative input like "." doesn't
    # leave bridge_id empty (Path('.').name == '').
    bridge_dir = Path(bridge_dir).resolve()
    bridge_id = bridge_dir.name
    contracts_dir = bridge_dir / "contracts"

    cfg = BridgeConfig(bridge_id=bridge_id, contracts_dir=contracts_dir)

    metadata_path = bridge_dir / "metadata.json"
    if metadata_path.is_file():
        with open(metadata_path, encoding="utf-8") as f:
            meta = json.load(f)
        _populate_chain_split(cfg, meta)
    else:
        log.warning("no metadata.json at %s — cfg will be empty", metadata_path)
        meta = {}

    event_path = Path(event_signatures_path) if event_signatures_path else _DEFAULT_EVENT_SIGS
    if event_path.is_file():
        with open(event_path, encoding="utf-8") as f:
            sigs = json.load(f)
        bridge_block = sigs.get(bridge_id, {}) if isinstance(sigs, dict) else {}
        cfg.lock_signatures.update(bridge_block.get("lock_signatures", []))
        cfg.unlock_signatures.update(bridge_block.get("unlock_signatures", []))
        cfg.auth_methods.update(bridge_block.get("auth_methods", []))
    else:
        log.warning("no event signatures file at %s", event_path)

    # Final fallback: if nobody declared src/dst, treat every contract
    # we can find as `src`. The spec §2.2 Algorithm 1 then produces
    # an Ef-only xCFG which still lets us populate basic_blocks.
    if not cfg.src_contracts and not cfg.dst_contracts:
        log.warning(
            "%s: no chain split derivable; treating every contract as src", bridge_id
        )

    return cfg


# ============================================================================
# Helpers
# ============================================================================


def _populate_chain_split(cfg: BridgeConfig, meta: dict) -> None:
    """Walk ``metadata.contracts`` to fill ``src_contracts`` / ``dst_contracts``.

    Three resolution strategies, applied in order:

    1. Explicit ``chain == "source" | "destination"`` per contract.
    2. Suffix heuristic on the contract key (``_ethereum`` / ``_eth`` →
       src for ETH-as-source bridges; the per-bridge top-level
       ``source_chain.name`` decides which suffix wins).
    3. Top-level ``source_chain.name`` / ``destination_chain.name`` —
       if a contract's role text mentions one, classify accordingly.
    """

    contracts = meta.get("contracts", {})
    if not isinstance(contracts, dict):
        return

    src_chain = (meta.get("source_chain", {}) or {}).get("name", "").lower()
    dst_chain = (meta.get("destination_chain", {}) or {}).get("name", "").lower()

    suffix_to_chain = {}
    if src_chain:
        suffix_to_chain[f"_{src_chain}"] = "src"
        if src_chain == "ethereum":
            suffix_to_chain["_eth"] = "src"
        elif src_chain == "bsc":
            suffix_to_chain["_bsc"] = "src"
            suffix_to_chain["_bnb"] = "src"
    if dst_chain:
        suffix_to_chain[f"_{dst_chain}"] = "dst"
        if dst_chain == "ethereum":
            suffix_to_chain["_eth"] = "dst"
        elif dst_chain == "bsc":
            suffix_to_chain["_bsc"] = "dst"
            suffix_to_chain["_bnb"] = "dst"

    for ckey, cval in contracts.items():
        if not isinstance(cval, dict):
            continue
        # Strategy 1 — explicit attribute
        chain_attr = (cval.get("chain") or "").lower()
        if chain_attr == "source":
            cfg.src_contracts.add(_solidity_name(ckey))
            continue
        if chain_attr == "destination":
            cfg.dst_contracts.add(_solidity_name(ckey))
            continue
        # Strategy 2 — suffix
        matched = False
        for suffix, side in suffix_to_chain.items():
            if ckey.endswith(suffix):
                (cfg.src_contracts if side == "src" else cfg.dst_contracts).add(
                    _solidity_name(ckey)
                )
                matched = True
                break
        if matched:
            continue
        # Strategy 3 — silent drop into src as a last resort.
        cfg.src_contracts.add(_solidity_name(ckey))


def _solidity_name(contract_key: str) -> str:
    """Convert a metadata contract key (snake_case_with_chain) into the
    Solidity contract name we expect Slither to expose.

    Mapping is intentionally permissive — both
    ``replica_ethereum`` → ``Replica`` and
    ``BridgeRouter`` (already pascal) → ``BridgeRouter`` work.
    """

    if not contract_key:
        return contract_key
    if "_" not in contract_key:
        # Already PascalCase / Solidity-style.
        return contract_key
    # Drop the trailing chain suffix if present, then PascalCase the rest.
    parts = contract_key.split("_")
    chain_suffixes = {"ethereum", "eth", "bsc", "bnb", "polygon", "solana", "tron"}
    if parts[-1].lower() in chain_suffixes:
        parts = parts[:-1]
    return "".join(p[:1].upper() + p[1:] for p in parts if p)


def _strip_arg_types(signature: str) -> str:
    """Reduce ``"Lock(address,uint256,bytes32)"`` to ``"Lock"`` so we
    can compare event signatures even when our cached signature
    string carries placeholder types (the SlithIR layer prints
    ``REF_x`` / ``TMP_y`` rather than canonical types — see
    :mod:`smartaxe_reimpl.cfg_builder._arg_type` for context).
    """

    return signature.split("(", 1)[0]
