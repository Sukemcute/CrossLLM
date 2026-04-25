"""Attack Scenario Generator — RAG + LLM + template fallback.

Pipeline per invariant:

1. Build an embedding query from the invariant category/description/predicate.
2. Retrieve top-k similar exploits from the knowledge base (FAISS or numpy).
3. Ask the LLM (OpenAI or NVIDIA NIM) for a concrete, fuzzer-executable
   action sequence, framed as a "rational adversary" (system prompt).
4. If the LLM is unavailable or returns an invalid response, pick a
   vulnerability-class-specific template from :mod:`.templates` instead of
   a single uniform fallback.
5. Attach state-predicate waypoints so the Rust fuzzer reward function
   has real checkpoints to aim at.
"""

from __future__ import annotations

import json
from typing import Any

from src.common.llm_client import chat_completion_json, get_llm_client

from .embedder import ExploitEmbedder
from .knowledge_base import ExploitKnowledgeBase
from .prompts import load as load_prompt
from .templates import get_template, instantiate_template


class AttackScenarioGenerator:
    """Generate attack scenarios using RAG over historical exploit knowledge."""

    # Invariant category -> attack/vulnerability class used for template lookup.
    CATEGORY_TO_CLASS = {
        "asset_conservation": "fake_deposit",
        "authorization": "signature_forgery",
        "uniqueness": "replay_attack",
        "timeliness": "timeout_manipulation",
        "state_consistency": "state_desync",
    }

    def __init__(self, model: str = "gpt-4o-mini", top_k: int = 5, temperature: float = 0.3):
        self.model = model  # Kept for backward-compat; shared client may override.
        self.top_k = top_k
        self.temperature = temperature
        self.kb = ExploitKnowledgeBase()
        self.embedder = ExploitEmbedder()
        self._kb_ready = False

    # -------------------------------------------------------------- public API

    def generate(self, atg: dict, invariants: list[dict]) -> list[dict]:
        """Generate one scenario per invariant (LLM or template fallback)."""
        self._ensure_kb()
        scenarios: list[dict[str, Any]] = []

        nodes = atg.get("nodes", [])
        default_contract = self._pick_default_contract(nodes)
        bridge_name = atg.get("bridge_name", "unknown")

        for idx, inv in enumerate(invariants, start=1):
            query = self._build_query(inv)
            retrieved = (
                self.embedder.search(query, top_k=self.top_k)
                if self._kb_ready
                else []
            )
            scenario = self._try_llm_generate(atg, inv, retrieved)
            if not self._scenario_usable(scenario):
                scenario = self._fallback_scenario(
                    idx, inv, retrieved, default_contract, bridge_name
                )
            scenario["waypoints"] = self._extract_waypoints(scenario)
            scenarios.append(scenario)

        return scenarios

    # ---------------------------------------------------------- LLM generation

    def _try_llm_generate(
        self, atg: dict, invariant: dict, retrieved: list[dict]
    ) -> dict[str, Any] | None:
        provider = get_llm_client()
        if provider is None:
            return None

        system = load_prompt("system_adversary.txt")
        user = self._build_prompt(atg, invariant, retrieved)

        try:
            content = chat_completion_json(
                provider,
                system=system,
                user=user,
                temperature=self.temperature,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[ScenarioGen] LLM call failed: {exc}")
            return None

        return self._parse_scenario(content, invariant, retrieved)

    def _parse_scenario(
        self, content: str, invariant: dict, retrieved: list[dict]
    ) -> dict[str, Any] | None:
        if not content:
            return None
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            stripped = content.strip().lstrip("```json").lstrip("```").rstrip("```")
            try:
                data = json.loads(stripped)
            except json.JSONDecodeError:
                return None

        if not isinstance(data, dict):
            return None

        # Unwrap if LLM nested the scenario.
        if "scenario" in data and isinstance(data["scenario"], dict):
            data = data["scenario"]

        # Normalize required fields so downstream (Rust fuzzer) deserialization works.
        return self._normalize_scenario(data, invariant, retrieved)

    def _normalize_scenario(
        self, data: dict, invariant: dict, retrieved: list[dict]
    ) -> dict[str, Any]:
        """Fill in required fields the LLM may omit (step numbers, chain, defaults)."""
        data.setdefault(
            "target_invariant", invariant.get("invariant_id", "inv_unknown")
        )
        data.setdefault(
            "retrieved_exploits",
            [e.get("exploit_id", "") for e in retrieved if e.get("exploit_id")],
        )
        data.setdefault(
            "scenario_id", f"s_{invariant.get('invariant_id', 'unknown')}_llm"
        )
        data.setdefault(
            "vulnerability_class", self._class_from_invariant(invariant)
        )
        try:
            data["confidence"] = float(data.get("confidence", 0.5))
        except (TypeError, ValueError):
            data["confidence"] = 0.5

        raw_actions = data.get("actions") or []
        if not isinstance(raw_actions, list):
            raw_actions = []

        normalized_actions: list[dict[str, Any]] = []
        for idx, action in enumerate(raw_actions, start=1):
            if not isinstance(action, dict):
                continue
            try:
                action["step"] = int(action.get("step", idx))
            except (TypeError, ValueError):
                action["step"] = idx
            action["chain"] = str(action.get("chain", "destination")).lower()
            if not isinstance(action.get("params"), dict):
                action["params"] = {}
            action.setdefault("description", f"Step {action['step']}")
            normalized_actions.append(action)
        data["actions"] = normalized_actions

        return data

    def _build_prompt(
        self, atg: dict, invariant: dict, similar_exploits: list[dict]
    ) -> str:
        exploits_summary = [
            {
                "exploit_id": e.get("exploit_id", ""),
                "vulnerability_class": e.get("vulnerability_class", ""),
                "attack_stage": e.get("attack_stage", ""),
                "summary": e.get("summary", "")[:400],
            }
            for e in similar_exploits[: self.top_k]
        ]
        return (
            "Design ONE concrete cross-chain attack scenario that violates the given invariant.\n"
            "Return JSON matching the `Scenario` shape from hypotheses.schema.json.\n\n"
            f"Target invariant:\n{json.dumps(invariant, ensure_ascii=False, indent=2)}\n\n"
            f"ATG (truncated if long):\n{json.dumps(atg, ensure_ascii=False)[:7000]}\n\n"
            f"Similar historical exploits:\n{json.dumps(exploits_summary, ensure_ascii=False, indent=2)}\n\n"
            "Required JSON fields: scenario_id, target_invariant, vulnerability_class, "
            "confidence (0..1), actions (list of steps with chain/contract/function/params/description), "
            "retrieved_exploits. 2-6 actions max."
        )

    # --------------------------------------------------------- fallback logic

    def _fallback_scenario(
        self,
        idx: int,
        invariant: dict,
        retrieved: list[dict],
        contract: str,
        bridge_name: str,
    ) -> dict[str, Any]:
        vuln_class = self._class_from_invariant(invariant)
        template = get_template(vuln_class)

        # Prefer substitution values drawn from retrieved exploits when they
        # provide a concrete amount / attacker.
        extra_subs: dict[str, str] = {}
        for record in retrieved:
            loss = record.get("loss_usd")
            if isinstance(loss, (int, float)) and loss > 0:
                # Rough heuristic: use 1 ETH per $3000 to shape amount magnitude.
                extra_subs.setdefault("amount", str(int(max(loss, 1) / 3000) * 10**18))
                break

        actions = instantiate_template(template, contract=contract, extra_subs=extra_subs)
        retrieved_ids = [e.get("exploit_id", "") for e in retrieved if e.get("exploit_id")]

        confidence = 0.75 if retrieved_ids else 0.5
        return {
            "scenario_id": f"s{idx}_{vuln_class}_{bridge_name}",
            "target_invariant": invariant.get("invariant_id", "inv_unknown"),
            "vulnerability_class": vuln_class,
            "confidence": confidence,
            "actions": actions,
            "retrieved_exploits": retrieved_ids,
        }

    def _class_from_invariant(self, invariant: dict) -> str:
        cat = (invariant.get("category") or "").lower()
        return self.CATEGORY_TO_CLASS.get(cat, "logic_bug")

    # ----------------------------------------------------- waypoint extraction

    def _extract_waypoints(self, scenario: dict) -> list[dict]:
        """Convert action sequence to state-predicate waypoints.

        The Rust fuzzer's :mod:`scenario_sim` module recognises these
        predicate strings and maps them to simulated global-state checks.
        """
        waypoints: list[dict[str, Any]] = []
        actions = scenario.get("actions", [])
        cumulative_amount = 0

        for i, action in enumerate(actions, start=1):
            step = int(action.get("step", i))
            chain = (action.get("chain") or "").lower()
            function = (action.get("function") or "").lower()
            act = (action.get("action") or "").lower()
            params = action.get("params", {}) or {}
            description = action.get("description", f"After step {step}")

            amt_str = str(params.get("amount", ""))
            if amt_str:
                try:
                    cumulative_amount += int(amt_str)
                except ValueError:
                    pass

            predicate = self._predicate_for_action(
                chain=chain,
                function=function,
                act=act,
                params=params,
                cumulative_amount=cumulative_amount,
                step=step,
            )

            waypoints.append(
                {
                    "waypoint_id": f"w{step}",
                    "after_step": step,
                    "predicate": predicate,
                    "description": description,
                }
            )
        return waypoints

    def _predicate_for_action(
        self,
        *,
        chain: str,
        function: str,
        act: str,
        params: dict,
        cumulative_amount: int,
        step: int,
    ) -> str:
        # Source-chain deposits / locks.
        if chain == "source" and function in {"dispatch", "deposit", "lock", "send"}:
            base = cumulative_amount or 1_000_000_000_000_000_000
            return f"sourceRouter.totalLocked() >= {base}"

        # Source-chain refunds after mint = state desync hint.
        if chain == "source" and function in {"refund", "unlock"}:
            return "destRouter.totalMinted() > 0 && sourceRouter.refunded > 0"

        # Destination mints / unlocks.
        if chain == "destination" and function in {
            "mint",
            "handle",
            "release",
            "verifyandexecute",
            "executewithdraw",
        }:
            base = cumulative_amount or 1_000_000_000_000_000_000
            return f"destRouter.totalMinted() >= {base}"

        # Destination process — check zero-root / processed flag.
        if chain == "destination" and function in {"process", "proveandprocess"}:
            msg = str(params.get("message", ""))
            if msg and set(msg.strip()[2:] if msg.startswith("0x") else msg) <= {"0"} and msg:
                return "replica.zero_root_accepted == true"
            return "replica.processedMessages(messageHash) == true"

        # Relay manipulation modes.
        if chain == "relay":
            if act in {"replay", "replayed"}:
                return "relay.message_count > sourceRouter.deposits_count"
            if act in {"tamper", "tampered"}:
                return (
                    "relay.pendingMessage.amount != sourceRouter.deposits(nonce).amount"
                )
            if act in {"delay", "delayed"}:
                return "relay.delayed_count > 0"
            return "relay.message_count > 0"

        return f"step_{step}_executed"

    # --------------------------------------------------------------- helpers

    def _ensure_kb(self) -> None:
        if self._kb_ready:
            return
        self.kb.load()
        if self.kb.exploits:
            self.embedder.build_index(self.kb.exploits)
            self._kb_ready = True

    def _scenario_usable(self, scenario: dict[str, Any] | None) -> bool:
        if not scenario:
            return False
        actions = scenario.get("actions")
        if not isinstance(actions, list) or not actions:
            return False
        return True

    def _pick_default_contract(self, nodes: list[dict]) -> str:
        for node in nodes:
            if node.get("node_type") == "contract":
                return node.get("node_id") or "bridge"
        return "bridge"

    def _build_query(self, invariant: dict) -> str:
        parts = [
            invariant.get("category", ""),
            invariant.get("description", ""),
            invariant.get("predicate", ""),
        ]
        return " ".join(p for p in parts if p).strip()
