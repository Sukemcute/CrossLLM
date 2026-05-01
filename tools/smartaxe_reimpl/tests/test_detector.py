"""SA5 unit tests for detect_ccv (omission + path inconsistency)."""

from __future__ import annotations

from pathlib import Path

import pytest

from smartaxe_reimpl.bridge_config import BridgeConfig
from smartaxe_reimpl.detector import detect_ccv
from smartaxe_reimpl.models import (
    Check,
    CfgNode,
    ContractCfg,
    Resource,
    ResourceKind,
)
from smartaxe_reimpl.xcfg_builder import build_xcfg
from smartaxe_reimpl.xdfg_builder import build_xdfg


def _bridge_cfg() -> BridgeConfig:
    return BridgeConfig(bridge_id="t", contracts_dir=Path("."))


# ===========================================================================
# Omission detector
# ===========================================================================


def test_omission_fires_on_unguarded_external_call() -> None:
    """An R3 external call with no guarding check at all → omission."""
    n0 = CfgNode("Bridge", "unlock(bytes32)", "<entry>", 0)
    n1 = CfgNode("Bridge", "unlock(bytes32)", "_release(...)", 1)
    n1.reads.add(
        Resource(
            "IERC20.transfer",
            ResourceKind.R3_EXTERNAL_CALL,
            n1.location,
        )
    )
    n0.successors.append(n1)
    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["unlock(bytes32)"] = [n0, n1]

    xcfg = build_xcfg([], [cfg], _bridge_cfg())
    xdfg = build_xdfg(xcfg)
    violations = detect_ccv(xcfg, xdfg)

    omissions = [v for v in violations if v.kind == "omission"]
    assert any(
        v.resource_kind == "R3" and "IERC20.transfer" in v.resource_name
        for v in omissions
    )


def test_omission_silenced_when_guard_dominates_resource() -> None:
    """A high-confidence guard (P1 dominates) should suppress the
    omission."""
    n0 = CfgNode("Bridge", "unlock(bytes32)", "require(signers >= threshold)", 0)
    n0.requires.append(
        Check(
            expression="require(signers >= threshold)",
            kind=None,  # classifier will land it as SC4
            location=n0.location,
        )
    )
    n1 = CfgNode("Bridge", "unlock(bytes32)", "_release", 1)
    n1.reads.add(
        Resource(
            "IERC20.transfer",
            ResourceKind.R3_EXTERNAL_CALL,
            n1.location,
        )
    )
    n0.successors.append(n1)
    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["unlock(bytes32)"] = [n0, n1]

    xcfg = build_xcfg([], [cfg], _bridge_cfg())
    xdfg = build_xdfg(xcfg)
    violations = detect_ccv(xcfg, xdfg)

    omissions = [
        v
        for v in violations
        if v.kind == "omission" and v.resource_kind == "R3"
    ]
    # P1 fires (same fn, ancestor) at 0.95 → above threshold 0.5.
    assert not omissions, [v.description for v in omissions]


def test_omission_threshold_respected() -> None:
    """A guard scoring < threshold should NOT silence the omission."""
    # Place the check in a different function so only P4 (semantic) fires.
    n_other = CfgNode("Bridge", "elsewhere()", "require(amount > 0)", 0)
    n_other.requires.append(
        Check("require(amount > 0)", None, n_other.location)
    )
    n_target = CfgNode("Bridge", "unlock()", "transferFrom(amount)", 0)
    n_target.reads.add(
        Resource("transferFrom.amount", ResourceKind.R3_EXTERNAL_CALL, n_target.location)
    )

    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["elsewhere()"] = [n_other]
    cfg.functions["unlock()"] = [n_target]

    xcfg = build_xcfg([], [cfg], _bridge_cfg())
    xdfg = build_xdfg(xcfg)

    # P4 fires (shared identifier `amount`) at 0.70 → above threshold 0.5,
    # so omission is suppressed when threshold = 0.5. Bumping threshold
    # to 0.75 should make the omission re-emerge.
    silent = detect_ccv(xcfg, xdfg, threshold=0.5)
    loud = detect_ccv(xcfg, xdfg, threshold=0.75)

    omiss_silent = [v for v in silent if v.kind == "omission" and v.resource_kind == "R3"]
    omiss_loud = [v for v in loud if v.kind == "omission" and v.resource_kind == "R3"]
    assert len(omiss_loud) > len(omiss_silent)


def test_omission_predicts_sc_id() -> None:
    """The omission violation populates a best-guess `sc_id` so the
    SA6/SA7 verifier can match against per-bridge expected SC sets."""
    n = CfgNode("Bridge", "deposit(uint256)", "transferFrom(...)", 0)
    n.reads.add(
        Resource(
            "IERC20.transferFrom",
            ResourceKind.R3_EXTERNAL_CALL,
            n.location,
        )
    )
    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["deposit(uint256)"] = [n]
    xcfg = build_xcfg([], [cfg], _bridge_cfg())
    xdfg = build_xdfg(xcfg)
    violations = detect_ccv(xcfg, xdfg)
    sc_ids = {v.sc_id for v in violations if v.kind == "omission"}
    # `transferFrom` → SC1 per the heuristic in detector._predict_sc_for_resource.
    assert "SC1" in sc_ids


# ===========================================================================
# Path inconsistency detector
# ===========================================================================


def test_path_inconsistency_fires_on_diverging_guards() -> None:
    """Two paths reach the same resource with different guard sets."""
    entry = CfgNode("Bridge", "fn()", "<entry>", 0)
    guarded = CfgNode("Bridge", "fn()", "require(signers >= threshold)", 1)
    guarded.requires.append(
        Check("require(signers >= threshold)", None, guarded.location)
    )
    bypass = CfgNode("Bridge", "fn()", "noCheck", 2)
    target = CfgNode("Bridge", "fn()", "_release", 3)
    target.reads.add(
        Resource(
            "IERC20.transfer",
            ResourceKind.R3_EXTERNAL_CALL,
            target.location,
        )
    )
    # Two paths: entry → guarded → target  AND  entry → bypass → target
    entry.successors.extend([guarded, bypass])
    guarded.successors.append(target)
    bypass.successors.append(target)

    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["fn()"] = [entry, guarded, bypass, target]
    xcfg = build_xcfg([], [cfg], _bridge_cfg())
    xdfg = build_xdfg(xcfg)
    violations = detect_ccv(xcfg, xdfg)

    inconsistencies = [v for v in violations if v.kind == "path_inconsistency"]
    assert any(
        "IERC20.transfer" in v.resource_name for v in inconsistencies
    ), [v.description for v in violations]
