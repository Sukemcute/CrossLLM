"""Tests for the Slither-based Solidity parser.

Slither is an optional dependency. Tests skip gracefully when it is not
installed, but exercise the full happy-path when it is.
"""

from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path

import pytest

from src.module1_semantic.slither_parser import (
    _classify_role,
    _flow_for_role,
    _guess_chain,
    _guess_roles,
    parse_with_slither,
)


_SLITHER_AVAILABLE = importlib.util.find_spec("slither") is not None


def test_guess_chain_destination_keywords():
    assert _guess_chain("DestRouter") == "destination"
    assert _guess_chain("Replica") == "destination"
    assert _guess_chain("WrappedToken") == "destination"


def test_guess_chain_defaults_to_source():
    assert _guess_chain("BridgeRouter") == "source"
    assert _guess_chain("MyToken") == "source"


def test_guess_roles_router():
    roles = _guess_roles("BridgeRouter")
    assert "router_contract" in roles


def test_guess_roles_token():
    roles = _guess_roles("MyToken")
    assert "token_contract" in roles


def test_guess_roles_validator():
    roles = _guess_roles("OracleSet")
    assert "validator" in roles


def test_classify_role_deposit_variants():
    assert _classify_role("deposit") == "deposit"
    assert _classify_role("lockTokens") == "deposit"
    assert _classify_role("send") == "deposit"


def test_classify_role_relay_variants():
    assert _classify_role("dispatch") == "relay"
    assert _classify_role("processMessage") == "relay"
    assert _classify_role("handle") == "relay"


def test_classify_role_admin_variants():
    assert _classify_role("transferOwnership") == "admin"
    assert _classify_role("pause") == "admin"
    assert _classify_role("setFee") == "admin"


def test_flow_for_role_returns_none_for_view():
    assert _flow_for_role("view") is None
    assert _flow_for_role("other") is None


def test_flow_for_role_deposit():
    flow = _flow_for_role("deposit")
    assert flow == {
        "src": "user",
        "dst": "bridge",
        "label": "lock",
        "token": "UNKNOWN",
        "conditions": [],
    }


def test_parse_with_slither_returns_none_when_missing(tmp_path: Path):
    """Slither cannot parse a non-solidity file — must return None gracefully."""
    if not _SLITHER_AVAILABLE:
        pytest.skip("slither-analyzer not installed")
    bad = tmp_path / "not_solidity.sol"
    bad.write_text("THIS IS NOT SOLIDITY", encoding="utf-8")
    assert parse_with_slither(str(bad)) is None


@pytest.mark.skipif(not _SLITHER_AVAILABLE, reason="slither-analyzer not installed")
def test_parse_with_slither_full_extraction(tmp_path: Path):
    """Happy path: feed a real bridge skeleton, check entities + roles populated."""
    src = tmp_path / "MiniBridge.sol"
    src.write_text(
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;

            contract MiniBridge {
                event Deposited(address indexed user, uint256 amount);
                uint256 public totalLocked;

                function deposit(uint256 amount) external payable {
                    require(amount > 0, "amount");
                    totalLocked += amount;
                    emit Deposited(msg.sender, amount);
                }

                function processMessage(bytes calldata data) external {
                    require(data.length > 0, "data");
                }
            }
            """
        ).strip(),
        encoding="utf-8",
    )

    payload = parse_with_slither(str(src))
    if payload is None:
        pytest.skip("Slither could not compile this Solidity version locally")

    names = [f["name"] for f in payload["functions"]]
    assert "deposit" in names
    assert "processMessage" in names

    roles = {f["name"]: f["role"] for f in payload["functions"]}
    assert roles["deposit"] == "deposit"
    assert roles["processMessage"] == "relay"

    flows = [f["label"] for f in payload["asset_flows"]]
    assert "lock" in flows  # from deposit role
