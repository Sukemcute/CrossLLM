"""SA5 — security check classification (spec §2.4 Table 1).

Each ``Check`` produced by SA3 carries a free-form ``expression`` text
(extracted from Slither's ``node.expression``). Classification maps
that text into one of six SC IDs the paper defines, by pattern-matching
on a small vocabulary that covers the bridge-protocol checks listed in
Table 1. Patterns are intentionally conservative — false positives in
SC labelling produce false-positive *guarding-check* score bumps, which
under-flag CCVs (the spec calls "omission" the dominant target so we
can tolerate this).

The taxonomy:

| ID  | Looks for                                                              |
|-----|------------------------------------------------------------------------|
| SC1 | `transferFrom` / `balanceOf` / non-zero balance delta                  |
| SC2 | `> 0` on amount, `!= address(0)` on token / recipient                  |
| SC3 | `msg.sender == bridge / relayer / owner` / cross-chain router gate    |
| SC4 | signers ≥ threshold / `acceptableRoot` / `block.timestamp <= deadline` |
| SC5 | `!processed[hash]` / `processed[hash] = true`                          |
| SC6 | `recipient == decoded.recipient` / hash-of-decoded-payload match       |

When no rule matches, returns ``None`` and the check is treated as
"unclassified" (still counted by P3 same-basic-block heuristic with
its 0.60 confidence — useful when SC labels are ambiguous in
hand-written contracts).
"""

from __future__ import annotations

import re
from typing import Optional

from .models import Check

# Table 1 verbatim (spec §2.4) — SC ID → human description.
SECURITY_CHECK_TABLE: dict[str, str] = {
    "SC1": "deposit success check (transferFrom returns true / non-zero balance delta)",
    "SC2": "deposit argument validation (amount > 0, token != 0, recipient != 0)",
    "SC3": "cross-chain router correctness (msg.sender == bridge / executeCrossChainTx ok)",
    "SC4": "withdraw verification (sigs >= threshold / acceptableRoot / deadline)",
    "SC5": "repetitive withdrawal prevention (require !processed[hash]; processed[hash] = true)",
    "SC6": "release correctness (recipient == decoded.recipient)",
}


# Pre-compiled regexes — order matters: more specific rules first.
_SC1_RE = re.compile(
    r"(transferfrom|balanceof|balance\s*[+-]=|delta|"
    r"safetransferfrom)",
    re.IGNORECASE,
)
_SC2_RE = re.compile(
    r"(amount\s*>\s*0|"
    r">\s*0\s*(\)|,)|"  # any "> 0" near a require closure
    r"!=\s*address\s*\(\s*0\s*\)|"
    r"!=\s*0x0|"
    r"!=\s*address\(0\))",
    re.IGNORECASE,
)
_SC3_RE = re.compile(
    r"(msg\.sender\s*==|"
    r"_executecrosschaintx|"
    r"onlybridge|"
    r"onlyrelayer|"
    r"onlyowner|"
    r"only_owner)",
    re.IGNORECASE,
)
_SC4_RE = re.compile(
    r"(signers\s*>=|"
    r"signatures\s*>=|"
    r"sigcount\s*>=|"
    r"acceptableroot|"
    r"verifysig|"
    r"verifysignatures|"
    r"verifyvm|"
    r"\bdeadline\b|"
    r"block\.timestamp\s*<=|"
    r"block\.timestamp\s*<|"
    r"threshold)",
    re.IGNORECASE,
)
_SC5_RE = re.compile(
    r"(!\s*processed\s*\[|"
    r"processed\s*\[[^\]]+\]\s*=\s*true|"
    r"!\s*nullified\s*\[|"
    r"!\s*used\s*\[|"
    r"isconsumed)",
    re.IGNORECASE,
)
_SC6_RE = re.compile(
    r"(recipient\s*==|"
    r"decoded\.recipient|"
    r"hash\s*==\s*keccak|"
    r"messagehash\s*==)",
    re.IGNORECASE,
)


_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # SC1 first because `transferFrom` is the strongest signal.
    ("SC1", _SC1_RE),
    # SC5 before SC2 — `!processed[hash]` looks like SC2's `!= 0`
    # pattern under naive matching, but the `processed[` token wins.
    ("SC5", _SC5_RE),
    # SC6 next — recipient-match has its own selector.
    ("SC6", _SC6_RE),
    ("SC4", _SC4_RE),
    ("SC3", _SC3_RE),
    ("SC2", _SC2_RE),
)


def classify_check(check: Check) -> Optional[str]:
    """Return the first SC ID whose pattern matches *check.expression*.

    Mutates nothing — call sites copy the result back onto the Check
    via :func:`apply_classification` if they want the SC label
    persisted on the dataclass.
    """

    expr = check.expression or ""
    if not expr:
        return None
    for sc_id, regex in _RULES:
        if regex.search(expr):
            return sc_id
    return None


def apply_classification(check: Check) -> Check:
    """Return a new :class:`Check` with ``kind`` set to the classified
    SC ID (or unchanged if the check is already classified)."""

    if check.kind is not None:
        return check
    return Check(
        expression=check.expression,
        kind=classify_check(check),
        location=check.location,
    )
