"""SA5 unit tests for the SC1..SC6 classifier."""

from __future__ import annotations

from smartaxe_reimpl.models import Check
from smartaxe_reimpl.security_checks import (
    SECURITY_CHECK_TABLE,
    apply_classification,
    classify_check,
)


def _check(expr: str) -> Check:
    return Check(expression=expr, kind=None, location="X.fn:0")


def test_table_covers_six_categories() -> None:
    """Spec §2.4 Table 1 has exactly SC1..SC6."""
    assert set(SECURITY_CHECK_TABLE) == {f"SC{i}" for i in range(1, 7)}


def test_sc1_transferfrom_success_check() -> None:
    assert classify_check(_check("require(token.transferFrom(msg.sender, address(this), amount))")) == "SC1"
    assert classify_check(_check("ok = token.balanceOf(address(this)) > 0")) == "SC1"


def test_sc2_argument_validation() -> None:
    assert classify_check(_check("require(amount > 0, 'amount=0')")) == "SC2"
    assert classify_check(_check("require(token != address(0), 'token=0')")) == "SC2"
    assert classify_check(_check("require(recipient != address(0))")) == "SC2"


def test_sc3_router_correctness() -> None:
    assert classify_check(_check("require(msg.sender == bridge)")) == "SC3"
    assert classify_check(_check("require(_executeCrossChainTx(...))")) == "SC3"
    assert classify_check(_check("modifier onlyBridge() { ... }")) == "SC3"


def test_sc4_withdraw_verification() -> None:
    assert classify_check(_check("require(signers >= threshold)")) == "SC4"
    assert classify_check(_check("require(acceptableRoot(root))")) == "SC4"
    assert classify_check(_check("require(block.timestamp <= deadline)")) == "SC4"
    assert classify_check(_check("verifyVM(vm)")) == "SC4"


def test_sc5_replay_prevention() -> None:
    assert classify_check(_check("require(!processed[messageHash])")) == "SC5"
    assert classify_check(_check("processed[messageHash] = true")) == "SC5"
    assert classify_check(_check("require(!nullified[hash])")) == "SC5"


def test_sc6_release_correctness() -> None:
    assert classify_check(_check("require(recipient == decoded.recipient)")) == "SC6"
    assert classify_check(_check("require(messageHash == keccak256(payload))")) == "SC6"


def test_unclassified_returns_none() -> None:
    """Unrecognised predicates return None — they still contribute via
    P3 (same basic block) in pattern inference but don't get an SC label."""
    assert classify_check(_check("doSomethingObscure(x)")) is None
    assert classify_check(_check("")) is None


def test_apply_classification_preserves_existing_kind() -> None:
    pre = Check(expression="anything", kind="SC1", location="X.fn:0")
    out = apply_classification(pre)
    assert out.kind == "SC1"
    # Should be the SAME object (no mutation needed) or an equivalent one.
    assert out.expression == pre.expression


def test_apply_classification_sets_kind_when_none() -> None:
    pre = _check("require(amount > 0)")
    out = apply_classification(pre)
    assert out.kind == "SC2"


def test_sc5_wins_over_sc2_for_processed_pattern() -> None:
    """`!processed[hash]` is structurally a `!= 0` pattern under
    naive matching; the rule order in security_checks puts SC5 first
    so processed-mapping predicates land as SC5."""
    assert classify_check(_check("require(!processed[hash])")) == "SC5"
