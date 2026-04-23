"""
Invariant Synthesizer — Generates protocol invariants from ATG using LLM.

Four invariant categories:
1. Asset Conservation: locked_value - fee == minted_value
2. Authorization: mint must be preceded by valid deposit + relay
3. Uniqueness: each deposit consumed at most once (nonce)
4. Timeliness: locked assets refundable after timeout
"""


from __future__ import annotations

from typing import Any


class InvariantSynthesizer:
    """Generate and validate protocol invariants from ATG."""

    def __init__(self, model: str = "gpt-4o"):
        self.model = model

    def synthesize(self, atg: dict) -> list[dict]:
        """Generate candidate invariants from ATG structure."""
        edges = atg.get("edges", [])
        edge_ids = [e.get("edge_id", "") for e in edges]
        has_lock = any(e.get("label") == "lock" for e in edges)
        has_mint = any(e.get("label") == "mint" for e in edges)
        has_unlock = any(e.get("label") == "unlock" for e in edges)

        invariants: list[dict[str, Any]] = [
            {
                "invariant_id": "inv_asset_conservation",
                "category": "asset_conservation",
                "description": "Locked value (minus fee) should match minted/unlocked value.",
                "predicate": "sum(locked) - fee == sum(minted_or_unlocked)",
                "solidity_assertion": "assert(totalLocked() >= totalMinted() + totalUnlocked());",
                "related_edges": edge_ids,
            },
            {
                "invariant_id": "inv_authorization",
                "category": "authorization",
                "description": "Mint/unlock requires valid prior source-chain lock and proof verification.",
                "predicate": "mint_or_unlock -> exists(valid_lock && verified_message)",
                "solidity_assertion": "require(isVerified(messageHash) && lockExists(nonce), 'unauthorized mint/unlock');",
                "related_edges": [eid for eid in edge_ids if eid],
            },
            {
                "invariant_id": "inv_uniqueness",
                "category": "uniqueness",
                "description": "Each deposit/nonce can be consumed at most once.",
                "predicate": "processed[nonce] == false before consume",
                "solidity_assertion": "require(!processed[nonce], 'replay');",
                "related_edges": edge_ids,
            },
            {
                "invariant_id": "inv_timeliness",
                "category": "timeliness",
                "description": "Locked assets become refundable after timeout if destination action not finalized.",
                "predicate": "expired(timeout) && !finalized -> refundable",
                "solidity_assertion": "require(block.timestamp >= lockTime + timeout, 'too early');",
                "related_edges": edge_ids,
            },
        ]

        # Trim invariants to scenario shape if graph is very small.
        if not (has_lock and (has_mint or has_unlock)):
            invariants = [inv for inv in invariants if inv["category"] != "asset_conservation"] + [
                {
                    "invariant_id": "inv_state_consistency",
                    "category": "state_consistency",
                    "description": "Cross-chain state transitions must not diverge from protocol flow.",
                    "predicate": "next_state in allowed_transitions",
                    "solidity_assertion": "assert(validTransition(currentState, nextState));",
                    "related_edges": edge_ids,
                }
            ]
        return invariants

    def validate(self, invariants: list[dict], normal_traces: list) -> list[dict]:
        """Filter invariants against normal transaction traces (prune false positives)."""
        if not normal_traces:
            return invariants

        filtered = []
        for inv in invariants:
            if self._trace_likely_conflicts(inv, normal_traces):
                continue
            filtered.append(inv)
        return filtered

    def compile_to_solidity(self, invariant: dict) -> str:
        """Compile invariant to executable Solidity assertion."""
        assertion = invariant.get("solidity_assertion", "").strip()
        if assertion:
            return assertion
        predicate = invariant.get("predicate", "true")
        return f"assert({predicate});"

    def _trace_likely_conflicts(self, invariant: dict, traces: list[dict]) -> bool:
        """
        Lightweight filter: if a trace explicitly marks an invariant as expected-false,
        drop it from synthesized set.
        """
        inv_id = invariant.get("invariant_id")
        for tr in traces:
            expected_false = tr.get("expected_false_invariants", [])
            if inv_id in expected_false:
                return True
        return False
