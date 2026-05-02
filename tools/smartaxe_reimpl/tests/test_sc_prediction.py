"""SA6 regressions for the per-resource SC prediction heuristic.

These cover the calibrations that landed during the PolyNetwork
reproduction (`docs/REIMPL_SMARTAXE_SA6_REPORT.md`):

* low-level-call resources land as SC3 (PolyNetwork router pattern)
* `verifyHeaderAndExecuteTx` host function name biases towards SC3
* SlithIR expression noise (`bool`, `tuple`) doesn't trigger P4
  semantic-correlation false positives
"""

from __future__ import annotations

from pathlib import Path

from smartaxe_reimpl.detector import _predict_sc_for_resource
from smartaxe_reimpl.models import CfgNode, Resource, ResourceKind
from smartaxe_reimpl.pattern_inference import _matches_p4
from smartaxe_reimpl.bridge_config import BridgeConfig  # noqa: F401  (kept for symmetry)


def _node(fn: str = "fn()", contract: str = "X", idx: int = 0) -> CfgNode:
    return CfgNode(contract=contract, function=fn, statement="", statement_idx=idx)


def test_low_level_call_predicts_sc3() -> None:
    """The PolyNetwork target.call(call_) shape lands as SC3."""
    r = Resource(
        name="TUPLE_0(bool,bytes) = LOW_LEVEL_CALL, dest:target, function:call, arguments:['call_']",
        kind=ResourceKind.R3_EXTERNAL_CALL,
        location="EthCrossChainManager.verifyHeaderAndExecuteTx(address,bytes):3",
    )
    host = _node(fn="verifyHeaderAndExecuteTx(address,bytes)", contract="EthCrossChainManager", idx=3)
    assert _predict_sc_for_resource(r, host) == "SC3"


def test_executetx_host_fn_predicts_sc3_even_for_high_level() -> None:
    """A function named like the bridge router lands SC3 even when
    the resource is a high-level call (defensive against compilers
    that lower target.call to high_level_call)."""
    r = Resource(
        name="SomeContract.handleMessage",
        kind=ResourceKind.R3_EXTERNAL_CALL,
        location="X.executeTx(bytes):2",
    )
    host = _node(fn="executeTx(bytes)", contract="X", idx=2)
    assert _predict_sc_for_resource(r, host) == "SC3"


def test_transferfrom_still_predicts_sc1() -> None:
    """Pre-existing rule: transferFrom resources still SC1."""
    r = Resource(
        name="IERC20.transferFrom",
        kind=ResourceKind.R3_EXTERNAL_CALL,
        location="Bridge.deposit:3",
    )
    host = _node(fn="deposit(uint256)", contract="Bridge", idx=3)
    assert _predict_sc_for_resource(r, host) == "SC1"


def test_verify_signature_predicts_sc4() -> None:
    """Sig-verification helpers land as SC4 (withdraw verification)."""
    r = Resource(
        name="SigVerifier.verifySignatures",
        kind=ResourceKind.R3_EXTERNAL_CALL,
        location="Bridge.unlock:5",
    )
    host = _node(fn="unlock(bytes)", contract="Bridge", idx=5)
    assert _predict_sc_for_resource(r, host) == "SC4"


def test_p4_no_false_positive_on_solidity_types() -> None:
    """`bool` shared between `require(bool,string)(...)` and a
    LOW_LEVEL_CALL resource name shouldn't fire P4 (the calibration
    that unblocked SA6)."""
    from smartaxe_reimpl.models import Check
    chk = Check(
        expression="require(bool,string)(! data.processed(nonce),'EthCrossChainManager: replay')",
        kind=None,
        location="X.fn:0",
    )
    res = Resource(
        name="TUPLE_0(bool,bytes) = LOW_LEVEL_CALL, dest:target, function:call, arguments:['call_']",
        kind=ResourceKind.R3_EXTERNAL_CALL,
        location="X.fn:1",
    )
    assert not _matches_p4(chk, res)


def test_p4_still_fires_on_real_identifier_overlap() -> None:
    """The original `amount` overlap example must still fire."""
    from smartaxe_reimpl.models import Check
    chk = Check(expression="require(amount > 0)", kind="SC2", location="X.fn:0")
    res = Resource(
        name="token.transfer.amount",
        kind=ResourceKind.R3_EXTERNAL_CALL,
        location="X.fn:1",
    )
    assert _matches_p4(chk, res)
