"""Pure-Python unit tests for the SA3 dataclasses (no Slither needed)."""

from __future__ import annotations

from smartaxe_reimpl.models import (
    Check,
    CfgNode,
    ContractCfg,
    EventEmit,
    Resource,
    ResourceKind,
)


def test_resource_kind_enum_covers_paper_taxonomy() -> None:
    """All four R1..R4 categories from spec §2.4 must be representable."""

    assert ResourceKind.R1_FIELD_ACCESS.value == "R1"
    assert ResourceKind.R2_INTERNAL_CALL.value == "R2"
    assert ResourceKind.R3_EXTERNAL_CALL.value == "R3"
    assert ResourceKind.R4_EVENT_EMIT.value == "R4"


def test_resource_is_external_or_event() -> None:
    """is_external_or_event() drives the SA5 omission detector — only
    R3/R4 resources are scanned for missing security checks."""

    sv = Resource("Bridge.totalLocked", ResourceKind.R1_FIELD_ACCESS, "Bridge.deposit:3")
    ext = Resource("IERC20.transferFrom", ResourceKind.R3_EXTERNAL_CALL, "Bridge.deposit:3")
    evt = Resource("Lock(...)", ResourceKind.R4_EVENT_EMIT, "Bridge.deposit:7")

    assert not sv.is_external_or_event()
    assert ext.is_external_or_event()
    assert evt.is_external_or_event()


def test_cfg_node_identity_by_location() -> None:
    """Two CfgNode instances with the same (contract, function, idx)
    must hash and compare equal — set/dict de-dup correctness."""

    a = CfgNode(contract="Bridge", function="deposit", statement="x = 1", statement_idx=3)
    b = CfgNode(contract="Bridge", function="deposit", statement="x = 1", statement_idx=3)
    c = CfgNode(contract="Bridge", function="deposit", statement="x = 2", statement_idx=4)

    assert a == b
    assert hash(a) == hash(b)
    assert a != c
    assert {a, b, c} == {a, c}


def test_cfg_node_location_format() -> None:
    n = CfgNode("Bridge", "deposit(uint256)", "amt > 0", 0)
    assert n.location == "Bridge.deposit(uint256):0"


def test_event_emit_construction() -> None:
    e = EventEmit(
        signature="Lock(address,uint256)",
        arguments=("msg.sender", "amt"),
        location="Bridge.deposit:7",
    )
    assert e.signature.startswith("Lock(")
    assert "msg.sender" in e.arguments


def test_check_unclassified_initially() -> None:
    """SA3 leaves Check.kind=None — SC1..SC6 classification is SA5's job."""

    c = Check(expression="amount > 0", kind=None, location="Bridge.deposit:0")
    assert c.kind is None


def test_contract_cfg_helpers() -> None:
    """Sanity: all_nodes() returns concatenated function bodies, and
    function_entry returns the first node (idx 0)."""

    n0 = CfgNode("Bridge", "deposit(uint256)", "<entry>", 0)
    n1 = CfgNode("Bridge", "deposit(uint256)", "amt > 0", 1)
    n2 = CfgNode("Bridge", "unlock(uint256)", "<entry>", 0)

    cfg = ContractCfg("Bridge", "/tmp/bridge.sol")
    cfg.functions["deposit(uint256)"] = [n0, n1]
    cfg.functions["unlock(uint256)"] = [n2]

    assert cfg.all_nodes() == [n0, n1, n2]
    assert cfg.function_entry("deposit(uint256)") is n0
    assert cfg.function_entry("nonexistent") is None
