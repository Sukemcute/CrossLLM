"""Tests for ATG Builder module."""

from src.module1_semantic.atg_builder import ATGNode, ATGEdge, ATG


def test_atg_node_creation():
    node = ATGNode(
        node_id="lock_pool",
        node_type="contract",
        chain="source",
        address="0xABC",
    )
    assert node.node_id == "lock_pool"
    assert node.chain == "source"


def test_atg_edge_creation():
    edge = ATGEdge(
        src="user_A",
        dst="lock_pool",
        label="lock",
        conditions=["amount > 0"],
    )
    assert edge.label == "lock"


def test_atg_structure():
    atg = ATG()
    atg.nodes.append(ATGNode("user_A", "user", "source"))
    atg.edges.append(ATGEdge("user_A", "lock_pool", "lock"))
    assert len(atg.nodes) == 1
    assert len(atg.edges) == 1
