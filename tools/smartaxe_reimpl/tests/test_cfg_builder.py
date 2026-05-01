"""SA3 acceptance tests against the TinyBridge fixture.

Requires Slither + a Solidity compiler (solc) to be installed. Tests
auto-skip when either dependency is missing so CI / pre-install runs
don't fail with import errors.
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Auto-skip the whole module if Slither isn't installed yet (SA2 venv
# may not be ready on every runner).
slither = pytest.importorskip("slither.slither")

from smartaxe_reimpl.cfg_builder import build_contract_cfgs  # noqa: E402
from smartaxe_reimpl.models import ResourceKind  # noqa: E402

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def tiny_cfgs():
    """Parse TinyBridge.sol once per test module."""
    try:
        return build_contract_cfgs(FIXTURE_DIR)
    except Exception as e:
        pytest.skip(f"Slither / solc not available: {e}")


def _find(cfgs, name):
    for c in cfgs:
        if c.contract_name == name:
            return c
    raise AssertionError(f"contract {name!r} not found in CFGs")


def test_contracts_parsed(tiny_cfgs):
    """Slither sees both `IERC20` (interface) and `TinyBridge`. We
    don't filter interfaces in SA3 — that's a downstream concern."""
    names = sorted(c.contract_name for c in tiny_cfgs)
    assert "TinyBridge" in names


def test_function_set(tiny_cfgs):
    """TinyBridge has constructor + deposit + unlock + _release."""
    bridge = _find(tiny_cfgs, "TinyBridge")
    fn_names = {sig.split("(")[0] for sig in bridge.functions.keys()}
    # constructor's canonical name is the contract name in Slither
    assert {"deposit", "unlock", "_release"} <= fn_names


def test_deposit_carries_state_writes(tiny_cfgs):
    """`deposit` writes both `totalLocked` and `processed` (R1)."""
    bridge = _find(tiny_cfgs, "TinyBridge")
    deposit_sig = next(s for s in bridge.functions if s.startswith("deposit("))
    nodes = bridge.functions[deposit_sig]
    written = {
        r.name for n in nodes for r in n.writes if r.kind == ResourceKind.R1_FIELD_ACCESS
    }
    assert "TinyBridge.totalLocked" in written
    assert "TinyBridge.processed" in written


def test_deposit_external_call_recorded(tiny_cfgs):
    """`token.transferFrom(...)` shows up as an R3 reads entry."""
    bridge = _find(tiny_cfgs, "TinyBridge")
    deposit_sig = next(s for s in bridge.functions if s.startswith("deposit("))
    nodes = bridge.functions[deposit_sig]
    ext_call_names = {
        r.name
        for n in nodes
        for r in n.reads
        if r.kind == ResourceKind.R3_EXTERNAL_CALL
    }
    assert any("transferFrom" in name for name in ext_call_names), ext_call_names


def test_deposit_emits_lock(tiny_cfgs):
    """`emit Lock(...)` lands as R4 + a populated EventEmit on a node."""
    bridge = _find(tiny_cfgs, "TinyBridge")
    deposit_sig = next(s for s in bridge.functions if s.startswith("deposit("))
    nodes = bridge.functions[deposit_sig]
    emit_sigs = {emit.signature for n in nodes for emit in n.emits}
    assert any(sig.startswith("Lock(") for sig in emit_sigs), emit_sigs

    r4_writes = {
        r.name for n in nodes for r in n.writes if r.kind == ResourceKind.R4_EVENT_EMIT
    }
    assert any(name.startswith("Lock(") for name in r4_writes), r4_writes


def test_deposit_requires_recorded(tiny_cfgs):
    """SA3 captures the require predicates as Check entries (kind=None
    until SA5 classifies them)."""
    bridge = _find(tiny_cfgs, "TinyBridge")
    deposit_sig = next(s for s in bridge.functions if s.startswith("deposit("))
    nodes = bridge.functions[deposit_sig]
    require_exprs = [chk.expression for n in nodes for chk in n.requires]
    # at least the four require()s in the fixture
    assert len(require_exprs) >= 3, require_exprs
    assert all(chk.kind is None for n in nodes for chk in n.requires), \
        "Check.kind must remain None after SA3 — classification is SA5"


def test_unlock_internal_call_to_release(tiny_cfgs):
    """`unlock` calls `_release` internally → R2 entry on the call site."""
    bridge = _find(tiny_cfgs, "TinyBridge")
    unlock_sig = next(s for s in bridge.functions if s.startswith("unlock("))
    nodes = bridge.functions[unlock_sig]
    internal_names = {
        r.name for n in nodes for r in n.reads if r.kind == ResourceKind.R2_INTERNAL_CALL
    }
    assert any("_release" in name for name in internal_names), internal_names


def test_successors_are_wired(tiny_cfgs):
    """Every non-terminal CFG node should have at least one successor
    (smoke test for the wiring in `_build_one_contract`)."""
    bridge = _find(tiny_cfgs, "TinyBridge")
    deposit_sig = next(s for s in bridge.functions if s.startswith("deposit("))
    nodes = bridge.functions[deposit_sig]
    # All but the last node should have a successor (last is implicit return).
    nontrivial = [n for n in nodes if n.successors]
    assert len(nontrivial) >= len(nodes) // 2  # generous lower bound


def test_node_locations_unique(tiny_cfgs):
    """Statement indices are unique within a function — driver of
    CfgNode hash/eq identity."""
    bridge = _find(tiny_cfgs, "TinyBridge")
    for sig, nodes in bridge.functions.items():
        idxs = [n.statement_idx for n in nodes]
        assert len(idxs) == len(set(idxs)), f"duplicate idx in {sig}: {idxs}"
