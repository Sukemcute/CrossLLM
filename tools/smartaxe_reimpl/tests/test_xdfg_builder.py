"""SA4 unit tests for xDFG construction (the three propagation rules)."""

from __future__ import annotations

from pathlib import Path

from smartaxe_reimpl.bridge_config import BridgeConfig
from smartaxe_reimpl.models import (
    CfgNode,
    ContractCfg,
    EventEmit,
    Resource,
    ResourceKind,
)
from smartaxe_reimpl.xcfg_builder import build_xcfg
from smartaxe_reimpl.xdfg_builder import build_xdfg


def _shared_resource(name: str, location: str) -> Resource:
    """Create an R1 resource — used to wire writes/reads identical
    enough for the Ef rule to match (matched by resource.name)."""
    return Resource(name, ResourceKind.R1_FIELD_ACCESS, location)


def test_ef_propagation_writes_intersect_reads() -> None:
    """If src.writes ∩ dst.reads is non-empty along an Ef edge, an Ef
    DataEdge with that resource appears in the xDFG."""
    n0 = CfgNode("Bridge", "fn(uint256)", "x = 1", 0)
    n1 = CfgNode("Bridge", "fn(uint256)", "use x", 1)
    shared = _shared_resource("Bridge.x", "Bridge.fn:0")
    n0.writes.add(shared)
    n1.reads.add(_shared_resource("Bridge.x", "Bridge.fn:1"))
    n0.successors.append(n1)

    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["fn(uint256)"] = [n0, n1]

    bridge_cfg = BridgeConfig(bridge_id="x", contracts_dir=Path("."))
    xcfg = build_xcfg([cfg], [], bridge_cfg)
    xdfg = build_xdfg(xcfg)

    ef_edges = [e for e in xdfg.edges if e.kind == "ef"]
    assert len(ef_edges) == 1
    assert ef_edges[0].variable.name == "Bridge.x"


def test_ef_propagation_disjoint_writes_reads_no_edge() -> None:
    """No DataEdge if writes and reads share no resource name."""
    n0 = CfgNode("Bridge", "fn(uint256)", "x = 1", 0)
    n1 = CfgNode("Bridge", "fn(uint256)", "y = 2", 1)
    n0.writes.add(_shared_resource("Bridge.x", "Bridge.fn:0"))
    n1.reads.add(_shared_resource("Bridge.y", "Bridge.fn:1"))
    n0.successors.append(n1)

    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["fn(uint256)"] = [n0, n1]

    bridge_cfg = BridgeConfig(bridge_id="x", contracts_dir=Path("."))
    xcfg = build_xcfg([cfg], [], bridge_cfg)
    xdfg = build_xdfg(xcfg)
    assert [e for e in xdfg.edges if e.kind == "ef"] == []


def test_ee_propagation_emit_args_to_relayer() -> None:
    """Ee rule: arguments of the cross-chain emit propagate to the relayer."""
    n0 = CfgNode("Bridge", "deposit(uint256)", "emit Lock", 0)
    n0.emits.append(
        EventEmit(
            signature="Lock(address,uint256)",
            arguments=("msg.sender", "amount"),
            location="Bridge.deposit:0",
        )
    )
    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["deposit(uint256)"] = [n0]

    bridge_cfg = BridgeConfig(bridge_id="x", contracts_dir=Path("."))
    bridge_cfg.lock_signatures.add("Lock(address,uint256)")

    xcfg = build_xcfg([cfg], [], bridge_cfg)
    xdfg = build_xdfg(xcfg)

    ee_edges = [e for e in xdfg.edges if e.kind == "ee"]
    # Two arguments → two Ee DataEdges.
    assert len(ee_edges) == 2
    arg_names = {e.variable.name.rsplit("::", 1)[-1] for e in ee_edges}
    assert arg_names == {"msg.sender", "amount"}


def test_ei_propagation_auth_args_from_relayer() -> None:
    """Ei rule: parameters of the auth method propagate from the relayer."""
    entry = CfgNode("DstBridge", "unlock(bytes32,bytes)", "<entry>", 0)
    # Slither models function parameters as state-variable-shaped
    # resources on the entry node's reads set.
    entry.reads.add(_shared_resource("messageHash", "DstBridge.unlock:0"))
    entry.reads.add(_shared_resource("signature", "DstBridge.unlock:0"))

    cfg = ContractCfg("DstBridge", "/tmp/dst.sol")
    cfg.functions["unlock(bytes32,bytes)"] = [entry]

    bridge_cfg = BridgeConfig(bridge_id="x", contracts_dir=Path("."))
    bridge_cfg.auth_methods.add("unlock(bytes32,bytes)")

    xcfg = build_xcfg([], [cfg], bridge_cfg)
    xdfg = build_xdfg(xcfg)

    ei_edges = [e for e in xdfg.edges if e.kind == "ei"]
    var_names = {e.variable.name for e in ei_edges}
    assert var_names == {"messageHash", "signature"}


def test_xdfg_node_dedup() -> None:
    """A resource that appears in multiple edges is registered once
    in xdfg.nodes — hashable Resource identity drives the de-dup."""
    n0 = CfgNode("Bridge", "fn(uint256)", "x = 1", 0)
    n1 = CfgNode("Bridge", "fn(uint256)", "use x", 1)
    n2 = CfgNode("Bridge", "fn(uint256)", "use x again", 2)
    shared = _shared_resource("Bridge.x", "Bridge.fn:0")
    n0.writes.add(shared)
    n1.reads.add(_shared_resource("Bridge.x", "Bridge.fn:1"))
    n2.reads.add(_shared_resource("Bridge.x", "Bridge.fn:2"))
    n0.successors.append(n1)
    n0.successors.append(n2)

    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["fn(uint256)"] = [n0, n1, n2]

    bridge_cfg = BridgeConfig(bridge_id="x", contracts_dir=Path("."))
    xcfg = build_xcfg([cfg], [], bridge_cfg)
    xdfg = build_xdfg(xcfg)

    # Two Ef edges (n0→n1, n0→n2) but only ONE node entry for
    # `Bridge.x` since the writes-side resource is the same.
    assert len([e for e in xdfg.edges if e.kind == "ef"]) == 2
    assert len(xdfg.nodes) == 1
    assert xdfg.nodes[0].name == "Bridge.x"


def test_xdfg_helpers() -> None:
    """edges_into / edges_from filter correctly."""
    n0 = CfgNode("Bridge", "fn(uint256)", "x = 1", 0)
    n1 = CfgNode("Bridge", "fn(uint256)", "use x", 1)
    n0.writes.add(_shared_resource("Bridge.x", "Bridge.fn:0"))
    n1.reads.add(_shared_resource("Bridge.x", "Bridge.fn:1"))
    n0.successors.append(n1)

    cfg = ContractCfg("Bridge", "/tmp/b.sol")
    cfg.functions["fn(uint256)"] = [n0, n1]

    xcfg = build_xcfg([cfg], [], BridgeConfig("x", Path(".")))
    xdfg = build_xdfg(xcfg)

    assert xdfg.edges_into(n1) == [e for e in xdfg.edges if e.dst == n1]
    assert xdfg.edges_from(n0) == [e for e in xdfg.edges if e.src == n0]
