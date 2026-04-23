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

    function process() external {}
}
"""


def test_extractor_builds_semantics():
    extractor = SemanticExtractor()
    sem = extractor.extract(SIMPLE_BRIDGE, "MiniBridge")
    assert "entities" in sem
    assert "functions" in sem
    assert len(sem["functions"]) >= 1


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
