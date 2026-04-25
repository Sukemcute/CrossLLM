"""Module 1 (semantic extraction + invariant synthesis) tests."""

from __future__ import annotations

from src.module1_semantic.atg_builder import ATGBuilder
from src.module1_semantic.extractor import SemanticExtractor
from src.module1_semantic.invariant_synth import InvariantSynthesizer


SIMPLE_BRIDGE = """
contract MiniBridge {
    event Deposited(address indexed user, uint256 amount);
    uint256 public totalLocked;

    function deposit(uint256 amount) external {
        require(amount > 0, "amount");
        totalLocked += amount;
        emit Deposited(msg.sender, amount);
    }

    function mint(uint256 amount) external {
        // minimal mint stub for ATG coverage
    }

    function process() external {}
}
"""


def test_extractor_builds_semantics():
    extractor = SemanticExtractor()
    sem = extractor.extract(SIMPLE_BRIDGE, "MiniBridge")
    assert "entities" in sem
    assert "functions" in sem
    assert len(sem["functions"]) >= 2


def test_atg_builder_outputs_edges():
    extractor = SemanticExtractor()
    builder = ATGBuilder()
    sem = extractor.extract(SIMPLE_BRIDGE, "MiniBridge")
    atg = builder.build(sem)
    assert len(atg.nodes) >= 1
    assert len(atg.edges) >= 1


def test_invariant_synthesizer_outputs_core_categories():
    extractor = SemanticExtractor()
    builder = ATGBuilder()
    synth = InvariantSynthesizer()
    sem = extractor.extract(SIMPLE_BRIDGE, "MiniBridge")
    atg_json = builder.to_json(builder.build(sem))
    invariants = synth.synthesize(atg_json)
    categories = {inv["category"] for inv in invariants}
    assert "authorization" in categories
    assert "uniqueness" in categories


def test_invariant_synth_fallback_without_api():
    """Offline conftest clears env vars; fallback must return core 4 categories."""
    synth = InvariantSynthesizer()
    atg = {
        "bridge_name": "test",
        "nodes": [],
        "edges": [
            {"edge_id": "e1", "label": "lock", "src": "u", "dst": "b"},
            {"edge_id": "e2", "label": "mint", "src": "b", "dst": "u"},
        ],
    }
    invariants = synth.synthesize(atg)
    categories = {inv["category"] for inv in invariants}
    assert {"asset_conservation", "authorization", "uniqueness", "timeliness"} <= categories


def test_invariant_synth_consistency_drops_duplicates():
    synth = InvariantSynthesizer()
    candidates = [
        {
            "invariant_id": "a",
            "predicate": "x > 0",
            "category": "asset_conservation",
            "description": "",
            "solidity_assertion": "",
        },
        {
            "invariant_id": "b",
            "predicate": "x>0",  # same after whitespace normalization
            "category": "asset_conservation",
            "description": "",
            "solidity_assertion": "",
        },
        {
            "invariant_id": "c",
            "predicate": "y == 1",
            "category": "uniqueness",
            "description": "",
            "solidity_assertion": "",
        },
    ]
    result = synth._cross_check_consistency(candidates)
    ids = [inv["invariant_id"] for inv in result]
    assert ids == ["a", "c"]


def test_invariant_synth_parses_wrapped_json_response():
    synth = InvariantSynthesizer()
    content = """```json
{"invariants": [{"invariant_id": "inv_test", "category": "uniqueness",
  "description": "d", "predicate": "p", "solidity_assertion": "require(true);"}]}
```"""
    parsed = synth._parse_response(content)
    assert len(parsed) == 1
    assert parsed[0]["invariant_id"] == "inv_test"


def test_invariant_synth_rejects_missing_fields():
    synth = InvariantSynthesizer()
    content = '{"invariants": [{"invariant_id": "x", "category": "uniqueness"}]}'
    parsed = synth._parse_response(content)
    # Missing description/predicate/solidity_assertion -> filtered out.
    assert parsed == []
