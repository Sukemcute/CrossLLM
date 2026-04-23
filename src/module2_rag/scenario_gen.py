"""
Attack Scenario Generator — Uses RAG + LLM to generate plausible attack sequences.

Input:  ATG + invariants (from Module 1) + retrieved exploits (from knowledge base)
Output: Attack scenarios with action sequences + semantic waypoints
"""

from __future__ import annotations

import json
import os
from typing import Any

from .embedder import ExploitEmbedder
from .knowledge_base import ExploitKnowledgeBase


class AttackScenarioGenerator:
    """Generate attack scenarios using RAG over historical exploit knowledge."""

    def __init__(self, model: str = "gpt-4o", top_k: int = 5):
        self.model = model
        self.top_k = top_k
        self.kb = ExploitKnowledgeBase()
        self.embedder = ExploitEmbedder()
        self._kb_ready = False

    def generate(self, atg: dict, invariants: list[dict]) -> list[dict]:
        """Generate attack scenarios for each invariant.

        For each invariant:
        1. Query knowledge base for similar exploits
        2. Construct prompt with ATG + invariant + retrieved exploits
        3. LLM generates concrete action sequence as rational adversary
        4. Extract semantic waypoints from generated scenario
        """
        self._ensure_kb()
        scenarios: list[dict[str, Any]] = []
        nodes = {n.get("node_id", ""): n for n in atg.get("nodes", [])}
        default_contract = next((n for n in nodes if n and nodes[n].get("node_type") == "contract"), "bridge")
        bridge_name = atg.get("bridge_name", "unknown")

        for idx, inv in enumerate(invariants, start=1):
            query = f"{inv.get('category', '')} {inv.get('description', '')} {inv.get('predicate', '')}".strip()
            retrieved = self.embedder.search(query, top_k=self.top_k) if self._kb_ready else []
            scenario = self._try_llm_generate(atg, inv, retrieved)
            if not scenario:
                scenario = self._fallback_scenario(idx, inv, retrieved, default_contract, bridge_name)
            scenario["waypoints"] = self._extract_waypoints(scenario)
            scenarios.append(scenario)

        return scenarios

    def _build_prompt(self, atg: dict, invariant: dict, similar_exploits: list[dict]) -> str:
        """Build prompt for attack scenario generation."""
        exploits_text = []
        for e in similar_exploits[: self.top_k]:
            exploits_text.append(
                {
                    "exploit_id": e.get("exploit_id", ""),
                    "vulnerability_class": e.get("vulnerability_class", ""),
                    "attack_stage": e.get("attack_stage", ""),
                    "summary": e.get("summary", ""),
                }
            )
        return (
            "Generate one cross-chain attack scenario as JSON object matching hypotheses.schema.json scenario shape.\n"
            f"ATG: {json.dumps(atg, ensure_ascii=False)[:7000]}\n"
            f"Invariant: {json.dumps(invariant, ensure_ascii=False)}\n"
            f"Similar exploits: {json.dumps(exploits_text, ensure_ascii=False)}\n"
            "Return fields: scenario_id,target_invariant,vulnerability_class,confidence,actions,retrieved_exploits."
        )

    def _extract_waypoints(self, scenario: dict) -> list[dict]:
        """Extract semantic waypoints from generated scenario."""
        waypoints: list[dict[str, Any]] = []
        actions = scenario.get("actions", [])
        for action in actions:
            step = action.get("step", 0)
            desc = action.get("description", f"step-{step}")
            predicate = f"reached_step_{step}"
            if action.get("chain") == "relay":
                predicate = "relay_message_modified_or_forwarded"
            elif action.get("function"):
                predicate = f"called_{action.get('function')}"
            waypoints.append(
                {
                    "waypoint_id": f"w{step}",
                    "after_step": int(step),
                    "predicate": predicate,
                    "description": desc,
                }
            )
        return waypoints

    def _ensure_kb(self) -> None:
        if self._kb_ready:
            return
        self.kb.load()
        if self.kb.exploits:
            self.embedder.build_index(self.kb.exploits)
            self._kb_ready = True

    def _fallback_scenario(
        self,
        idx: int,
        invariant: dict,
        retrieved: list[dict],
        contract: str,
        bridge_name: str,
    ) -> dict[str, Any]:
        vuln_class = self._class_from_invariant(invariant)
        retrieved_ids = [e.get("exploit_id", "") for e in retrieved if e.get("exploit_id")]
        return {
            "scenario_id": f"s{idx}_{vuln_class}",
            "target_invariant": invariant.get("invariant_id", "inv_unknown"),
            "vulnerability_class": vuln_class,
            "confidence": 0.65 if retrieved_ids else 0.45,
            "actions": [
                {
                    "step": 1,
                    "chain": "source",
                    "contract": contract,
                    "function": "deposit",
                    "params": {"amount": "1000000000000000000"},
                    "description": "Legitimate deposit on source chain",
                },
                {
                    "step": 2,
                    "chain": "relay",
                    "action": "tamper",
                    "params": {"field": "amount", "value": "999000000000000000000"},
                    "description": "Tamper relay payload before destination processing",
                },
                {
                    "step": 3,
                    "chain": "destination",
                    "contract": contract,
                    "function": "process",
                    "params": {"bridge": bridge_name},
                    "description": "Process manipulated message on destination chain",
                },
            ],
            "retrieved_exploits": retrieved_ids,
        }

    def _class_from_invariant(self, invariant: dict) -> str:
        cat = (invariant.get("category") or "").lower()
        mapping = {
            "asset_conservation": "fake_deposit",
            "authorization": "signature_forgery",
            "uniqueness": "replay_attack",
            "timeliness": "timeout_manipulation",
            "state_consistency": "state_desync",
        }
        return mapping.get(cat, "logic_bug")

    def _try_llm_generate(self, atg: dict, invariant: dict, retrieved: list[dict]) -> dict[str, Any] | None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return None
        try:
            from openai import OpenAI

            client = OpenAI(api_key=api_key)
            prompt = self._build_prompt(atg, invariant, retrieved)
            resp = client.chat.completions.create(
                model=self.model,
                temperature=0.3,
                response_format={"type": "json_object"},
                messages=[{"role": "user", "content": prompt}],
            )
            content = resp.choices[0].message.content or "{}"
            data = json.loads(content)
            if not isinstance(data, dict):
                return None
            # Normalize fields expected by schema.
            data.setdefault("target_invariant", invariant.get("invariant_id", "inv_unknown"))
            data.setdefault("retrieved_exploits", [e.get("exploit_id", "") for e in retrieved if e.get("exploit_id")])
            return data
        except Exception:
            return None
