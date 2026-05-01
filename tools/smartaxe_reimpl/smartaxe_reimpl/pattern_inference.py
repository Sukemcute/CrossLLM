"""SA5 — probabilistic pattern inference (spec §2.5 Table 2 P1..P5).

Stub: SA5 will land the ``score(c, r) = max P_i.confidence if matches``
function. Confidences are hardcoded from Table 2.
"""

from __future__ import annotations

# Table 2 (spec §2.5).
PATTERN_TABLE: dict[str, tuple[str, float]] = {
    "P1": ("direct control-flow dependency (c dominates r)", 0.95),
    "P2": ("indirect dominance / same struct-mapping membership", 0.60),
    "P3": ("c and r share a basic block", 0.60),
    "P4": ("semantic correlation (shared identifier / type)", 0.70),
    "P5": ("data-flow dependency via Gd", 0.80),
}


def score(*args, **kwargs) -> float:  # noqa: D401, ANN001
    """SA5 stub. Will return ``max(P_i.confidence for matches)``."""

    raise NotImplementedError("score is SA5 — not yet implemented")
