"""SA5 — security check classification (spec §2.4 Table 1).

Stub: SA5 will classify each :class:`Check` predicate into SC1..SC6
by pattern matching on its expression text. Hardcoded table per spec.
"""

from __future__ import annotations

# Table 1 verbatim (spec §2.4) — SC ID → human description.
SECURITY_CHECK_TABLE: dict[str, str] = {
    "SC1": "deposit success check (transferFrom returns true / non-zero balance delta)",
    "SC2": "deposit argument validation (amount > 0, token != 0, recipient != 0)",
    "SC3": "cross-chain router correctness (msg.sender == bridge / executeCrossChainTx ok)",
    "SC4": "withdraw verification (sigs >= threshold / acceptableRoot / deadline)",
    "SC5": "repetitive withdrawal prevention (require !processed[hash]; processed[hash] = true)",
    "SC6": "release correctness (recipient == decoded.recipient)",
}


def classify_check(*args, **kwargs):  # noqa: D401, ANN001
    """SA5 stub."""

    raise NotImplementedError("classify_check is SA5 — not yet implemented")
