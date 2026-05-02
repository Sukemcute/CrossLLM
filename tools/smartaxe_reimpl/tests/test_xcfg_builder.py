"""SA4 unit tests for xCFG construction.

Two tiers:

1. **Pure-Python**: hand-construct ``ContractCfg`` instances with
   known emit / require shapes and verify Algorithm-1 produces the
   expected Ee / Ei edges.
2. **Slither-driven** (auto-skip if Slither/solc missing): run the
   pipeline on the TinyBridge fixture treated as both source and
   destination side. We don't assert on the absolute edge counts
   (those depend on Slither's IR layout) — just that emits are
   detected and the basic-block set is non-empty.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from smartaxe_reimpl.bridge_config import BridgeConfig
from smartaxe_reimpl.models import (
    Check,
    CfgNode,
    ContractCfg,
    EventEmit,
    Resource,
    ResourceKind,
)
from smartaxe_reimpl.xcfg_builder import (
    Edge,
    XCfg,
    build_xcfg,
    partition_cfgs,
)


# ============================================================================
# Pure-Python tier
# ============================================================================


def _src_contract_with_emit() -> ContractCfg:
    """Hand-built source-side CFG: deposit() emits Lock at idx 1."""
    n0 = CfgNode("Bridge", "deposit(uint256)", "<entry>", 0)
    n1 = CfgNode("Bridge", "deposit(uint256)", "emit Lock", 1)
    n1.emits.append(
        EventEmit(
            signature="Lock(address,uint256)",
            arguments=("msg.sender", "amount"),
            location="Bridge.deposit:1",
        )
    )
    n0.successors.append(n1)
    cfg = ContractCfg("Bridge", "/tmp/bridge.sol")
    cfg.functions["deposit(uint256)"] = [n0, n1]
    return cfg


def _dst_contract_with_auth_fn() -> ContractCfg:
    """Destination-side CFG with an `unlock(...)` function that
    counts as an authorisation entry-point."""
    e0 = CfgNode(
        "DstBridge", "unlock(bytes32,bytes)", "<entry>", 0
    )
    e0.reads.add(Resource("messageHash", ResourceKind.R1_FIELD_ACCESS, "DstBridge.unlock:0"))
    e0.reads.add(Resource("signature", ResourceKind.R1_FIELD_ACCESS, "DstBridge.unlock:0"))
    cfg = ContractCfg("DstBridge", "/tmp/dst.sol")
    cfg.functions["unlock(bytes32,bytes)"] = [e0]
    return cfg


def _config_for_handcrafted() -> BridgeConfig:
    cfg = BridgeConfig(bridge_id="hand", contracts_dir=Path("."))
    cfg.lock_signatures.add("Lock(address,uint256)")
    cfg.auth_methods.add("unlock(bytes32,bytes)")
    return cfg


def test_basic_blocks_lifted_from_per_contract_cfgs() -> None:
    src = _src_contract_with_emit()
    dst = _dst_contract_with_auth_fn()
    cfg = _config_for_handcrafted()
    g = build_xcfg([src], [dst], cfg)
    assert len(g.basic_blocks) == 3  # 2 src nodes + 1 dst entry node


def test_ef_edges_lifted_from_successors() -> None:
    src = _src_contract_with_emit()
    cfg = _config_for_handcrafted()
    g = build_xcfg([src], [], cfg)
    # n0 → n1 is the only intra-chain successor we wired.
    assert len(g.edges_ef) == 1
    assert g.edges_ef[0].src.statement_idx == 0
    assert g.edges_ef[0].dst.statement_idx == 1


def test_ee_edge_emitted_for_documented_event() -> None:
    src = _src_contract_with_emit()
    cfg = _config_for_handcrafted()
    g = build_xcfg([src], [], cfg)

    assert len(g.edges_ee) == 1
    e = g.edges_ee[0]
    assert e.kind == "ee"
    assert e.dst is g.relayer  # informing the relayer
    assert isinstance(e.src, CfgNode) and "emit Lock" in e.src.statement


def test_no_ee_edge_when_event_not_documented() -> None:
    src = _src_contract_with_emit()
    cfg = BridgeConfig(bridge_id="x", contracts_dir=Path("."))
    # NO lock_signatures registered → emit is not cross-chain.
    g = build_xcfg([src], [], cfg)
    assert g.edges_ee == []


def test_ei_edge_emitted_for_documented_auth_method() -> None:
    dst = _dst_contract_with_auth_fn()
    cfg = _config_for_handcrafted()
    g = build_xcfg([], [dst], cfg)

    assert len(g.edges_ei) == 1
    e = g.edges_ei[0]
    assert e.kind == "ei"
    assert e.src is g.relayer
    # Destination is the function entry node.
    assert isinstance(e.dst, CfgNode)
    assert e.dst.statement_idx == 0
    assert e.dst.function == "unlock(bytes32,bytes)"


def test_no_ei_edge_when_function_not_in_auth_whitelist() -> None:
    dst = _dst_contract_with_auth_fn()
    cfg = BridgeConfig(bridge_id="x", contracts_dir=Path("."))
    # No auth_methods registered.
    g = build_xcfg([], [dst], cfg)
    assert g.edges_ei == []


def test_partition_cfgs_uses_classify_contract() -> None:
    """`partition_cfgs` defers to BridgeConfig.classify_contract,
    falling back to src for unknown contracts."""
    cfg = BridgeConfig(bridge_id="x", contracts_dir=Path("."))
    cfg.src_contracts.add("Bridge")
    cfg.dst_contracts.add("DstBridge")

    src_only = ContractCfg("Bridge", "/tmp/a.sol")
    dst_only = ContractCfg("DstBridge", "/tmp/b.sol")
    unknown = ContractCfg("Mystery", "/tmp/c.sol")

    src, dst = partition_cfgs([src_only, dst_only, unknown], cfg)
    src_names = {c.contract_name for c in src}
    dst_names = {c.contract_name for c in dst}
    assert "Bridge" in src_names and "Mystery" in src_names
    assert dst_names == {"DstBridge"}


def test_xcfg_helpers_successors_predecessors() -> None:
    """XCfg.successors_of / predecessors_of walk all edge kinds."""
    src = _src_contract_with_emit()
    cfg = _config_for_handcrafted()
    g = build_xcfg([src], [], cfg)

    # The emit node has both an Ef successor (to itself None — last
    # node) and an Ee successor (to relayer).
    emit_node = src.functions["deposit(uint256)"][1]
    succs = g.successors_of(emit_node)
    assert g.relayer in succs


# ============================================================================
# Slither-driven tier
# ============================================================================


pytestmark_slither = pytest.mark.usefixtures()
slither = pytest.importorskip("slither.slither")

from smartaxe_reimpl.cfg_builder import build_contract_cfgs  # noqa: E402

FIXTURE_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def tiny_pipeline_xcfg():
    """Run cfg_builder + xcfg_builder on TinyBridge.sol treated as
    both src (Lock emit) and dst (auth method = unlock)."""
    try:
        cfgs = build_contract_cfgs(FIXTURE_DIR)
    except Exception as e:  # solc / Slither config failure
        pytest.skip(f"Slither / solc not available: {e}")
    bridge_cfg = BridgeConfig(bridge_id="tiny", contracts_dir=FIXTURE_DIR)
    bridge_cfg.lock_signatures.add("Lock(address,address,uint256,bytes32)")
    bridge_cfg.unlock_signatures.add("Unlock(address,uint256,bytes32)")
    bridge_cfg.auth_methods.add("unlock(address,uint256,bytes32)")
    bridge_cfg.src_contracts.add("TinyBridge")  # treat as src for Lock
    bridge_cfg.dst_contracts.add("TinyBridge")  # AND dst for unlock auth
    return cfgs, bridge_cfg


def test_pipeline_produces_nonempty_xcfg(tiny_pipeline_xcfg) -> None:
    cfgs, bridge_cfg = tiny_pipeline_xcfg
    src, dst = partition_cfgs(cfgs, bridge_cfg)
    # TinyBridge is in both src + dst sets so partition routes it to
    # whichever is checked first (src wins per the implementation).
    g = build_xcfg(src, dst, bridge_cfg)
    assert g.basic_blocks, "no basic blocks lifted"
    assert g.edges_ef, "no Ef edges"


def test_pipeline_finds_emit_lock_event(tiny_pipeline_xcfg) -> None:
    """When the bridge config registers Lock(...) as a lock signature,
    the deposit function's emit must produce an Ee edge to the relayer."""
    cfgs, bridge_cfg = tiny_pipeline_xcfg
    # Force TinyBridge into the src list specifically, no fallback.
    bridge_cfg.dst_contracts.discard("TinyBridge")
    src, dst = partition_cfgs(cfgs, bridge_cfg)
    g = build_xcfg(src, dst, bridge_cfg)
    assert g.edges_ee, "no Ee edges produced for documented Lock emit"
