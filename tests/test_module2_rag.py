"""Module 2 (RAG scenario generation) tests."""

from __future__ import annotations

from src.module2_rag.embedder import ExploitEmbedder
from src.module2_rag.knowledge_base import ExploitKnowledgeBase
from src.module2_rag.scenario_gen import AttackScenarioGenerator
from src.module2_rag.templates import TEMPLATES, get_template, instantiate_template


def _base_atg() -> dict:
    return {
        "bridge_name": "nomad",
        "nodes": [
            {
                "node_id": "source_router",
                "node_type": "contract",
                "chain": "source",
                "address": "",
                "functions": [],
            }
        ],
        "edges": [
            {
                "edge_id": "e1",
                "src": "user",
                "dst": "source_router",
                "label": "lock",
                "token": "WETH",
                "conditions": [],
                "function_signature": "deposit(uint256)",
            }
        ],
    }


def test_knowledge_base_load_and_filter():
    kb = ExploitKnowledgeBase(data_dir="src/module2_rag/data")
    kb.load()
    assert len(kb.exploits) >= 2
    assert len(kb.get_by_vuln_class("fake_deposit")) >= 1


def test_embedder_search_returns_results():
    kb = ExploitKnowledgeBase(data_dir="src/module2_rag/data")
    kb.load()
    emb = ExploitEmbedder()
    emb.build_index(kb.exploits)
    results = emb.search("verification bypass mint", top_k=2)
    assert len(results) >= 1


def test_scenario_generator_fallback_shape():
    invariants = [
        {
            "invariant_id": "inv_asset_conservation",
            "category": "asset_conservation",
            "description": "locked equals minted",
            "predicate": "sum(locked)==sum(minted)",
            "solidity_assertion": "assert(true);",
            "related_edges": ["e1"],
        }
    ]
    gen = AttackScenarioGenerator(top_k=2)
    scenarios = gen.generate(_base_atg(), invariants)
    assert len(scenarios) == 1
    scenario = scenarios[0]
    assert scenario["target_invariant"] == "inv_asset_conservation"
    assert len(scenario["actions"]) >= 1
    assert isinstance(scenario.get("waypoints"), list)


def test_fallback_templates_differ_by_vuln_class():
    gen = AttackScenarioGenerator(top_k=2)
    atg = _base_atg()

    replay_inv = {
        "invariant_id": "inv_uniqueness",
        "category": "uniqueness",
        "description": "no replay",
        "predicate": "nonce unique",
        "solidity_assertion": "require(!processed[nonce]);",
        "related_edges": ["e1"],
    }
    replay_scenarios = gen.generate(atg, [replay_inv])
    replay_actions = replay_scenarios[0]["actions"]
    assert any((a.get("action") or "").lower() in {"replay", "replayed"} for a in replay_actions)
    assert replay_scenarios[0]["vulnerability_class"] == "replay_attack"

    conservation_inv = {
        "invariant_id": "inv_asset_conservation",
        "category": "asset_conservation",
        "description": "balance",
        "predicate": "locked==minted",
        "solidity_assertion": "assert(true);",
        "related_edges": ["e1"],
    }
    conservation_scenarios = gen.generate(atg, [conservation_inv])
    conservation_actions = conservation_scenarios[0]["actions"]
    # Nomad-style fake_deposit template injects a zero-root message.
    msg_values = [
        (a.get("params") or {}).get("message", "")
        for a in conservation_actions
    ]
    assert any("0x00" in str(m) for m in msg_values)
    assert conservation_scenarios[0]["vulnerability_class"] == "fake_deposit"


def test_state_based_waypoints_use_predicates():
    gen = AttackScenarioGenerator()
    scenario = {
        "actions": [
            {
                "step": 1,
                "chain": "source",
                "function": "dispatch",
                "params": {"amount": "1000000000000000000"},
                "description": "deposit",
            },
            {
                "step": 2,
                "chain": "destination",
                "function": "handle",
                "params": {"amount": "1000000000000000000"},
                "description": "mint",
            },
            {
                "step": 3,
                "chain": "relay",
                "action": "replay",
                "params": {},
                "description": "replay",
            },
        ]
    }
    waypoints = gen._extract_waypoints(scenario)
    assert len(waypoints) == 3
    assert "totalLocked" in waypoints[0]["predicate"]
    assert "totalMinted" in waypoints[1]["predicate"]
    assert "relay.message_count" in waypoints[2]["predicate"]


def test_zero_root_predicate_triggered_for_nomad_style_action():
    gen = AttackScenarioGenerator()
    scenario = {
        "actions": [
            {
                "step": 1,
                "chain": "destination",
                "function": "process",
                "params": {
                    "message": "0x0000000000000000000000000000000000000000000000000000000000000000"
                },
                "description": "zero root",
            }
        ]
    }
    waypoints = gen._extract_waypoints(scenario)
    assert waypoints[0]["predicate"] == "replica.zero_root_accepted == true"


def test_template_registry_covers_primary_vuln_classes():
    expected = {
        "fake_deposit",
        "replay_attack",
        "state_desync",
        "signature_forgery",
        "key_compromise",
        "logic_bug",
        "timeout_manipulation",
    }
    assert expected <= set(TEMPLATES.keys())


def test_instantiate_template_substitutes_contract_and_defaults():
    template = get_template("replay_attack")
    actions = instantiate_template(template, contract="router_x")
    assert all(a.get("contract") in {"router_x", None} for a in actions)
    amounts = [(a.get("params") or {}).get("amount") for a in actions if a.get("params")]
    assert any(amt == "1000000000000000000" for amt in amounts)
