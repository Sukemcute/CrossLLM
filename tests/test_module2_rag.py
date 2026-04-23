from src.module2_rag.embedder import ExploitEmbedder
from src.module2_rag.knowledge_base import ExploitKnowledgeBase
from src.module2_rag.scenario_gen import AttackScenarioGenerator


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
    atg = {
        "bridge_name": "nomad",
        "nodes": [{"node_id": "source_router", "node_type": "contract", "chain": "source", "address": "", "functions": []}],
        "edges": [{"edge_id": "e1", "src": "user", "dst": "source_router", "label": "lock", "token": "WETH", "conditions": [], "function_signature": "deposit(uint256)"}],
    }
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
    scenarios = gen.generate(atg, invariants)
    assert len(scenarios) == 1
    s = scenarios[0]
    assert s["target_invariant"] == "inv_asset_conservation"
    assert len(s["actions"]) >= 1
    assert isinstance(s.get("waypoints"), list)
