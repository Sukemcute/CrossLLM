"""Tests for the typed :class:`Condition` dataclass and ATGEdge sync."""

from __future__ import annotations

from src.module1_semantic.atg_builder import (
    CONDITION_TYPES,
    ATGBuilder,
    ATGEdge,
    Condition,
    parse_condition,
)


def test_parse_condition_classifies_hashlock():
    c = parse_condition("require(keccak256(secret) == hashlock)")
    assert c.type == "hashlock"
    assert "keccak256" in c.params["expression"]


def test_parse_condition_classifies_timelock():
    c = parse_condition("require(block.timestamp >= deadline)")
    assert c.type == "timelock"


def test_parse_condition_classifies_signature():
    c = parse_condition("require(ecrecover(msg, v, r, s) == signer)")
    assert c.type == "signature"


def test_parse_condition_classifies_nonce():
    c = parse_condition("require(!processed[nonce])")
    assert c.type == "nonce"


def test_parse_condition_classifies_balance():
    c = parse_condition("require(amount <= totalSupply)")
    assert c.type == "balance"


def test_parse_condition_falls_back_to_generic():
    c = parse_condition("foo == bar")
    assert c.type == "generic"


def test_parse_condition_idempotent_for_condition_input():
    c = Condition(type="hashlock", params={"expression": "x"})
    assert parse_condition(c) is c


def test_parse_condition_accepts_dict_input():
    c = parse_condition({"type": "timelock", "params": {"expression": "y"}})
    assert c.type == "timelock"
    assert c.params == {"expression": "y"}


def test_condition_to_dict_roundtrip():
    c = Condition(type="hashlock", params={"expression": "keccak256(s)"})
    d = c.to_dict()
    assert d == {"type": "hashlock", "params": {"expression": "keccak256(s)"}}


def test_condition_to_string_uses_expression_when_present():
    c = Condition(type="timelock", params={"expression": "block.timestamp >= t"})
    assert "block.timestamp" in c.to_string()


def test_atg_edge_set_conditions_keeps_string_and_typed_in_sync():
    edge = ATGEdge(src="user", dst="bridge", label="lock")
    edge.set_conditions(["require(keccak256(s) == h)", "block.number > t"])
    assert len(edge.condition_objects) == 2
    assert edge.condition_objects[0].type == "hashlock"
    assert edge.condition_objects[1].type == "timelock"
    # String projection preserves original expression.
    assert "keccak256" in edge.conditions[0]


def test_atg_builder_to_json_emits_typed_view():
    builder = ATGBuilder()
    semantics = {
        "entities": [{"entity_id": "u", "entity_type": "user", "chain": "source"}],
        "asset_flows": [
            {
                "src": "u",
                "dst": "b",
                "label": "lock",
                "conditions": ["require(amount > 0)", "require(keccak256(x) == h)"],
            }
        ],
    }
    atg = builder.build(semantics)
    js = builder.to_json(atg)
    edge = js["edges"][0]
    assert "conditions" in edge
    assert "condition_objects" in edge
    types = [c["type"] for c in edge["condition_objects"]]
    assert "balance" in types
    assert "hashlock" in types


def test_atg_builder_from_json_typed_view_round_trip():
    builder = ATGBuilder()
    payload = {
        "bridge_name": "x",
        "version": "1.0",
        "nodes": [{"node_id": "u", "node_type": "user", "chain": "source", "address": ""}],
        "edges": [
            {
                "edge_id": "e1",
                "src": "u",
                "dst": "b",
                "label": "lock",
                "token": "WETH",
                "function_signature": "lock(uint)",
                "conditions": ["legacy string"],
                "condition_objects": [
                    {"type": "nonce", "params": {"expression": "!processed[n]"}}
                ],
            }
        ],
        "invariants": [],
    }
    atg = builder.from_json(payload)
    assert atg.edges[0].condition_objects[0].type == "nonce"


def test_condition_types_constant_lists_canonical_set():
    assert "hashlock" in CONDITION_TYPES
    assert "timelock" in CONDITION_TYPES
    assert "signature" in CONDITION_TYPES
    assert "nonce" in CONDITION_TYPES
    assert "balance" in CONDITION_TYPES
    assert "generic" in CONDITION_TYPES
