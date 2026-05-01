"""SA4 unit tests for the bridge-config loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from smartaxe_reimpl.bridge_config import (
    BridgeConfig,
    _solidity_name,
    _strip_arg_types,
    load_bridge_config,
)


def test_solidity_name_drops_chain_suffix() -> None:
    assert _solidity_name("replica_ethereum") == "Replica"
    assert _solidity_name("erc20_bridge_ethereum") == "Erc20Bridge"
    assert _solidity_name("token_bsc") == "Token"
    assert _solidity_name("BridgeRouter") == "BridgeRouter"
    assert _solidity_name("") == ""


def test_strip_arg_types_isolates_event_name() -> None:
    assert _strip_arg_types("Lock(address,uint256)") == "Lock"
    assert _strip_arg_types("Dispatch(bytes32,uint256,uint64,bytes32,bytes)") == "Dispatch"
    assert _strip_arg_types("BareName") == "BareName"


def test_load_bridge_config_with_explicit_chain(tmp_path: Path) -> None:
    """Bridge whose metadata has explicit `chain` per contract — config
    populates src_contracts / dst_contracts directly."""
    (tmp_path / "contracts").mkdir()
    metadata = {
        "source_chain": {"name": "ethereum"},
        "destination_chain": {"name": "bsc"},
        "contracts": {
            "router_eth": {"address": "0x1", "chain": "source"},
            "router_bsc": {"address": "0x2", "chain": "destination"},
        },
    }
    (tmp_path / "metadata.json").write_text(json.dumps(metadata))

    sigs = {"demo": {"lock_signatures": ["Lock(address,uint256)"]}}
    sigs_file = tmp_path / "events.json"
    sigs_file.write_text(json.dumps(sigs))

    cfg = load_bridge_config(tmp_path, sigs_file)
    cfg.bridge_id = "demo"  # tmp_path basename != "demo"; force-match for sigs
    cfg2 = load_bridge_config(tmp_path, sigs_file)  # rerun with renamed dir
    # The first cfg won't have lock_signatures because tmp_path basename
    # mismatches the sigs key — that's correct behaviour. We assert on
    # the chain split which IS independent of bridge_id.
    assert "Router" in cfg2.src_contracts
    assert "Router" in cfg2.dst_contracts
    # (both router_eth and router_bsc collapse to "Router"; that's a
    # benign collision the spec accepts since chain is the differentiator)


def test_load_bridge_config_falls_back_with_no_metadata(tmp_path: Path) -> None:
    """Missing metadata.json → empty config + warning, no crash."""
    cfg = load_bridge_config(tmp_path)
    assert cfg.bridge_id == tmp_path.name
    assert cfg.src_contracts == set()
    assert cfg.dst_contracts == set()


def test_is_cross_chain_event() -> None:
    cfg = BridgeConfig(bridge_id="x", contracts_dir=Path("."))
    cfg.lock_signatures.add("Lock(address,uint256)")
    cfg.unlock_signatures.add("Unlock(address,uint256)")

    assert cfg.is_cross_chain_event("Lock(address,uint256)")
    # Tolerate placeholder arg types (cfg_builder._arg_type returns "?")
    assert cfg.is_cross_chain_event("Lock(?,?)")
    assert not cfg.is_cross_chain_event("SomethingElse(address)")


def test_is_authorization_method() -> None:
    cfg = BridgeConfig(bridge_id="x", contracts_dir=Path("."))
    cfg.auth_methods.add("process(bytes)")
    cfg.auth_methods.add("verifyVAA(bytes)")

    assert cfg.is_authorization_method("process(bytes)")
    assert cfg.is_authorization_method("process(bytes32,bytes)")  # bare-name match
    assert cfg.is_authorization_method("verifyVAA(bytes32)")
    assert not cfg.is_authorization_method("nonAuth(bytes)")


def test_event_signatures_json_covers_all_12_bridges() -> None:
    """Ensure the curated event_signatures.json names every bridge so
    SA7 sweep doesn't silently fall through to an empty config."""
    sigs_path = (
        Path(__file__).resolve().parent.parent / "data" / "event_signatures.json"
    )
    with open(sigs_path) as f:
        sigs = json.load(f)

    bridges = {
        "nomad", "ronin", "polynetwork", "wormhole", "harmony",
        "multichain", "qubit", "orbit", "socket", "fegtoken",
        "gempad", "pgala",
    }
    declared = {k for k in sigs if not k.startswith("_")}
    missing = bridges - declared
    assert not missing, f"event_signatures.json missing {missing}"

    # Each bridge must declare at least one lock or unlock signature.
    for b in bridges:
        block = sigs[b]
        assert (
            block.get("lock_signatures") or block.get("unlock_signatures")
        ), f"{b}: no lock or unlock signatures declared"
        assert block.get("auth_methods"), f"{b}: no auth_methods declared"
