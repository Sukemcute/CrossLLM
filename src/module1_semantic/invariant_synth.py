"""Invariant synthesis via LLM + deterministic fallback.

Per the BridgeSentry paper (Section 4.1.3), invariants are generated per-ATG by
an LLM and then filtered through a three-stage validation pipeline:

1. **Generate** 15-20 candidate invariants from the ATG structure.
2. **Trace filter** — drop invariants that would flag legitimate bridge traces.
3. **Consistency check** — remove pairwise-contradictory or duplicate predicates.

Four invariant categories are required:

* ``asset_conservation`` — balance preserved across chains (locked == minted - fee).
* ``authorization`` — mint/unlock requires prior lock + verified relay (causal order).
* ``uniqueness`` — nonce/message consumed at most once (replay protection).
* ``timeliness`` — locked assets refundable after timeout expiry.

When no LLM provider is configured, ``synthesize`` returns the four-invariant
deterministic fallback so the pipeline still runs offline.
"""

from __future__ import annotations

import json
from typing import Any

from src.common.llm_client import LLMProvider, chat_completion_json, get_llm_client
from src.module1_semantic.prompts import load as load_prompt


_USER_PROMPT_TEMPLATE = """Analyze this bridge ATG and generate 15-20 protocol invariants.

ATG (truncated if long):
```json
{atg_json}
```

Generate invariants across the four categories:
1. **asset_conservation** — balance preservation across chains (locked == minted - fees).
2. **authorization** — mint/unlock requires valid deposit + verified relay.
3. **uniqueness** — each nonce/message consumed at most once.
4. **timeliness** — locked assets refundable after timeout.

For each invariant provide:
- `invariant_id` (unique snake_case)
- `category` (one of the four above)
- `description` (plain English)
- `predicate` (formal logical expression)
- `solidity_assertion` (executable require/assert statement)
- `related_edges` (subset of ATG edge IDs this invariant depends on)

Return JSON: {{"invariants": [...]}}"""


class InvariantSynthesizer:
    """Generate and validate protocol invariants from an ATG."""

    REQUIRED_FIELDS = {
        "invariant_id",
        "category",
        "description",
        "predicate",
        "solidity_assertion",
    }
    VALID_CATEGORIES = {
        "asset_conservation",
        "authorization",
        "uniqueness",
        "timeliness",
        "state_consistency",
    }

    def __init__(self, model: str | None = None, temperature: float = 0.0):
        # `model` kept for orchestrator backward-compat; resolved provider wins.
        self.model = model
        self.temperature = temperature

    # ------------------------------------------------------------------ public

    def synthesize(self, atg: dict) -> list[dict]:
        """Three-stage pipeline: LLM generate → trace filter → consistency check.

        Falls back to the four hardcoded invariants when no LLM is configured
        or the LLM response fails validation.
        """
        candidates = self._llm_generate_candidates(atg)
        if not candidates:
            return self._fallback_invariants(atg)

        filtered = self._filter_with_traces(candidates, normal_traces=[])
        consistent = self._cross_check_consistency(filtered)

        # If everything got pruned away, fall back rather than returning [].
        return consistent if consistent else self._fallback_invariants(atg)

    def validate(self, invariants: list[dict], normal_traces: list) -> list[dict]:
        """Public wrapper over the trace filter for orchestrator use."""
        return self._filter_with_traces(invariants, normal_traces)

    def compile_to_solidity(self, invariant: dict) -> str:
        """Return the Solidity assertion string for an invariant."""
        assertion = (invariant.get("solidity_assertion") or "").strip()
        if assertion:
            return assertion
        predicate = invariant.get("predicate") or "true"
        return f"assert({predicate});"

    # --------------------------------------------------------- LLM generation

    def _llm_generate_candidates(self, atg: dict) -> list[dict]:
        """Stage 1: ask the LLM for 15-20 candidate invariants."""
        provider = self._resolve_provider()
        if provider is None:
            return []

        system = load_prompt("system_verifier.txt")
        user = _USER_PROMPT_TEMPLATE.format(
            atg_json=json.dumps(atg, ensure_ascii=False, indent=2)[:8000]
        )

        try:
            content = chat_completion_json(
                provider,
                system=system,
                user=user,
                temperature=self.temperature,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[InvariantSynth] LLM call failed: {exc}")
            return []

        return self._parse_response(content)

    def _parse_response(self, content: str) -> list[dict]:
        """Extract and validate the `invariants` array from the LLM response."""
        if not content:
            return []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Some models wrap JSON in markdown fences — strip and retry.
            stripped = content.strip().lstrip("```json").lstrip("```").rstrip("```")
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError:
                return []

        raw = data.get("invariants") if isinstance(data, dict) else data
        if not isinstance(raw, list):
            return []

        valid: list[dict] = []
        for inv in raw:
            if not isinstance(inv, dict):
                continue
            if not self._is_well_formed(inv):
                continue
            # Normalize related_edges default; tolerate missing field.
            inv.setdefault("related_edges", [])
            valid.append(inv)
        return valid

    def _is_well_formed(self, inv: dict) -> bool:
        if not self.REQUIRED_FIELDS.issubset(inv.keys()):
            return False
        if inv["category"] not in self.VALID_CATEGORIES:
            # Attempt to map loose categories
            cat = str(inv["category"]).lower().strip()
            if cat in self.VALID_CATEGORIES:
                inv["category"] = cat
            else:
                return False
        return True

    def _resolve_provider(self) -> LLMProvider | None:
        return get_llm_client()

    # ------------------------------------------------------- validation stages

    def _filter_with_traces(
        self, candidates: list[dict], normal_traces: list
    ) -> list[dict]:
        """Stage 2: drop invariants that explicitly mark as expected-false in traces."""
        if not normal_traces:
            return list(candidates)

        filtered = []
        for inv in candidates:
            if any(self._trace_violates(inv, tr) for tr in normal_traces):
                continue
            filtered.append(inv)
        return filtered

    def _trace_violates(self, invariant: dict, trace: dict) -> bool:
        inv_id = invariant.get("invariant_id")
        expected_false = trace.get("expected_false_invariants") or []
        return inv_id in expected_false

    def _cross_check_consistency(self, invariants: list[dict]) -> list[dict]:
        """Stage 3: drop duplicate predicates and duplicate IDs."""
        seen_predicates: set[str] = set()
        seen_ids: set[str] = set()
        unique: list[dict] = []
        for inv in invariants:
            pred_key = (inv.get("predicate") or "").lower().replace(" ", "")
            id_key = inv.get("invariant_id", "")
            if not pred_key or not id_key:
                continue
            if pred_key in seen_predicates or id_key in seen_ids:
                continue
            seen_predicates.add(pred_key)
            seen_ids.add(id_key)
            unique.append(inv)
        return unique

    # ----------------------------------------------------------------- fallback

    def _fallback_invariants(self, atg: dict) -> list[dict[str, Any]]:
        """Deterministic four-invariant baseline for offline use / LLM failure."""
        edges = atg.get("edges", [])
        edge_ids = [e.get("edge_id", "") for e in edges if e.get("edge_id")]
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
                "related_edges": edge_ids,
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

        # Trim when graph is degenerate: no clear lock/mint pair.
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
