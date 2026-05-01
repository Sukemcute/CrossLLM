"""SA5 unit tests for P1..P5 pattern matchers + score()."""

from __future__ import annotations

from pathlib import Path

from smartaxe_reimpl.bridge_config import BridgeConfig
from smartaxe_reimpl.models import (
    Check,
    CfgNode,
    ContractCfg,
    Resource,
    ResourceKind,
)
from smartaxe_reimpl.pattern_inference import (
    P1_CONF,
    P2_CONF,
    P3_CONF,
    P4_CONF,
    P5_CONF,
    PATTERN_TABLE,
    score,
)
from smartaxe_reimpl.xcfg_builder import build_xcfg
from smartaxe_reimpl.xdfg_builder import build_xdfg


def test_pattern_table_carries_paper_confidences() -> None:
    """Spec §2.5 Table 2 verbatim."""
    assert PATTERN_TABLE["P1"][1] == 0.95
    assert PATTERN_TABLE["P2"][1] == 0.60
    assert PATTERN_TABLE["P3"][1] == 0.60
    assert PATTERN_TABLE["P4"][1] == 0.70
    assert PATTERN_TABLE["P5"][1] == 0.80


def _empty_cfg() -> tuple:
    """Return an empty xCFG/xDFG suitable as a baseline graph for
    isolated pattern tests that only need explicit nodes."""
    bcfg = BridgeConfig(bridge_id="t", contracts_dir=Path("."))
    xcfg = build_xcfg([], [], bcfg)
    xdfg = build_xdfg(xcfg)
    return bcfg, xcfg, xdfg


# ---------------------------------------------------------------------------
# P3 — same basic block
# ---------------------------------------------------------------------------


def test_p3_same_basic_block_fires() -> None:
    """Check and resource on the SAME CfgNode → P3 wins (0.60)
    when no other pattern matches."""
    n = CfgNode("Bridge", "fn(uint256)", "complex stuff", 0)
    chk = Check("doSomethingObscure(x)", None, n.location)  # avoid P4
    res = Resource("xyzWidget", ResourceKind.R3_EXTERNAL_CALL, n.location)  # avoid P4
    _, xcfg, xdfg = _empty_cfg()
    conf, match = score(chk, n, res, n, xcfg, xdfg)
    assert conf == P3_CONF
    assert match.pattern == "P3"


# ---------------------------------------------------------------------------
# P4 — semantic correlation (shared identifier / type)
# ---------------------------------------------------------------------------


def test_p4_shared_identifier_fires() -> None:
    """`require(amount > 0)` and `transfer(amount)` share `amount`."""
    chk_node = CfgNode("Bridge", "deposit(uint256)", "require(amount > 0)", 0)
    chk = Check("require(amount > 0)", "SC2", chk_node.location)
    # Resource has the same `amount` token in its name.
    other = CfgNode("Bridge", "deposit(uint256)", "transfer(amount)", 1)
    res = Resource("token.transfer.amount", ResourceKind.R3_EXTERNAL_CALL, other.location)

    _, xcfg, xdfg = _empty_cfg()
    conf, match = score(chk, chk_node, res, other, xcfg, xdfg)
    assert match is not None
    assert conf >= P4_CONF
    # P4 should be the winner because no Ef edges exist (no P1/P2)
    # and check_node != resource_node (no P3) and no xDFG edges (no P5).
    assert match.pattern == "P4"


def test_p4_disjoint_identifiers_no_match() -> None:
    """Stop-words shouldn't drive P4 false positives."""
    chk_node = CfgNode("Bridge", "fn()", "uint x = 0", 0)
    chk = Check("uint x = 0", None, chk_node.location)
    other = CfgNode("Bridge", "fn()", "address y", 1)
    res = Resource("y.something", ResourceKind.R3_EXTERNAL_CALL, other.location)
    _, xcfg, xdfg = _empty_cfg()
    conf, _ = score(chk, chk_node, res, other, xcfg, xdfg)
    assert conf == 0.0


# ---------------------------------------------------------------------------
# P1 — direct dominance (Ef-ancestor in same function)
# ---------------------------------------------------------------------------


def test_p1_direct_dominance_fires() -> None:
    """check_node → ... → resource_node along Ef edges (same fn)."""
    n0 = CfgNode("Bridge", "deposit(uint256)", "require(amount > 0)", 0)
    n1 = CfgNode("Bridge", "deposit(uint256)", "transferFrom", 1)
    n0.successors.append(n1)
    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["deposit(uint256)"] = [n0, n1]

    bcfg = BridgeConfig(bridge_id="t", contracts_dir=Path("."))
    xcfg = build_xcfg([cfg], [], bcfg)
    xdfg = build_xdfg(xcfg)

    chk = Check("require(amount > 0)", "SC2", n0.location)
    res = Resource("IERC20.transferFrom", ResourceKind.R3_EXTERNAL_CALL, n1.location)
    conf, match = score(chk, n0, res, n1, xcfg, xdfg)
    assert match is not None
    assert match.pattern == "P1"
    assert conf == P1_CONF


def test_p1_disabled_for_different_functions() -> None:
    """Cross-function P1 doesn't fire (not strictly intra-function)."""
    n0 = CfgNode("Bridge", "deposit(uint256)", "require(x)", 0)
    n1 = CfgNode("Bridge", "unlock(bytes32)", "transferFrom", 0)
    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["deposit(uint256)"] = [n0]
    cfg.functions["unlock(bytes32)"] = [n1]

    bcfg = BridgeConfig(bridge_id="t", contracts_dir=Path("."))
    xcfg = build_xcfg([cfg], [], bcfg)
    xdfg = build_xdfg(xcfg)

    chk = Check("require(x)", None, n0.location)  # avoid P4
    res = Resource("ZZ.transferFrom", ResourceKind.R3_EXTERNAL_CALL, n1.location)
    conf, match = score(chk, n0, res, n1, xcfg, xdfg)
    # No P1 (different functions); also no other patterns → 0.0.
    assert conf == 0.0


# ---------------------------------------------------------------------------
# P5 — data-flow dependency through xDFG
# ---------------------------------------------------------------------------


def test_p5_direct_dataflow_fires() -> None:
    """A direct DataEdge from check_node to resource_node fires P5."""
    n0 = CfgNode("Bridge", "fn(uint256)", "x = computeRoot(args)", 0)
    n1 = CfgNode("Bridge", "fn(uint256)", "verify(x)", 1)
    shared = Resource("Bridge.x", ResourceKind.R1_FIELD_ACCESS, n0.location)
    n0.writes.add(shared)
    n1.reads.add(Resource("Bridge.x", ResourceKind.R1_FIELD_ACCESS, n1.location))
    n0.successors.append(n1)

    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["fn(uint256)"] = [n0, n1]

    bcfg = BridgeConfig(bridge_id="t", contracts_dir=Path("."))
    xcfg = build_xcfg([cfg], [], bcfg)
    xdfg = build_xdfg(xcfg)

    chk = Check("computeRoot(args)", None, n0.location)
    res = Resource("verifierOracle", ResourceKind.R3_EXTERNAL_CALL, n1.location)
    conf, match = score(chk, n0, res, n1, xcfg, xdfg)
    # P1 also fires (same function, ancestor) — P1 wins because 0.95 > 0.80.
    assert match.pattern == "P1"


# ---------------------------------------------------------------------------
# Score = max() — multiple patterns yield the highest confidence.
# ---------------------------------------------------------------------------


def test_score_returns_max_confidence_across_patterns() -> None:
    """When P1 (0.95) and P3 (0.60) both fire, score is 0.95."""
    n = CfgNode("Bridge", "fn()", "require(amount > 0)", 0)
    chk = Check("require(amount > 0)", "SC2", n.location)
    # Same node and same identifier → P3 + P4 both fire.
    res = Resource("amount", ResourceKind.R3_EXTERNAL_CALL, n.location)

    _, xcfg, xdfg = _empty_cfg()
    conf, match = score(chk, n, res, n, xcfg, xdfg)
    # P3 is 0.60 and P4 is 0.70; max is P4.
    assert conf == P4_CONF
    assert match.pattern == "P4"


def test_no_match_returns_zero() -> None:
    n = CfgNode("Bridge", "fn()", "obscure", 0)
    n2 = CfgNode("Other", "g()", "ext", 0)
    chk = Check("obscure", None, n.location)
    res = Resource("ext", ResourceKind.R3_EXTERNAL_CALL, n2.location)
    _, xcfg, xdfg = _empty_cfg()
    conf, match = score(chk, n, res, n2, xcfg, xdfg)
    assert conf == 0.0
    assert match is None
