"""
Semantic Extractor — Uses LLM to parse bridge smart contract source code
and extract entities, functions, asset flows, and guards.

Input:  Solidity source files + optional Relayer code
Output: Structured JSON with entities, functions, asset_flows, guards
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


FUNCTION_RE = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)", re.DOTALL)
CONTRACT_RE = re.compile(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)")
EVENT_RE = re.compile(r"\bevent\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)")
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


class SemanticExtractor:
    """Extract protocol semantics from bridge source code using LLM."""

    def __init__(self, model: str = "gpt-4o", temperature: float = 0.2):
        self.model = model
        self.temperature = temperature

    def extract(self, source_code: str, contract_name: str) -> dict:
        """Analyze source code and return structured semantic information."""
        source_code = source_code or ""
        entities = self._extract_entities(source_code, contract_name)
        functions = self._extract_functions(source_code)
        guards = self._extract_guards(source_code)
        asset_flows = self._infer_asset_flows(functions)

        # Keep offline-first behavior for reproducibility; enrich with LLM if available.
        llm_payload = self._try_llm_extract(source_code, contract_name)
        if isinstance(llm_payload, dict):
            entities = llm_payload.get("entities", entities)
            functions = llm_payload.get("functions", functions)
            guards = llm_payload.get("guards", guards)
            asset_flows = llm_payload.get("asset_flows", asset_flows)

        return {
            "contract_name": contract_name,
            "entities": entities,
            "functions": functions,
            "asset_flows": asset_flows,
            "guards": guards,
            "metadata": {
                "model": self.model,
                "temperature": self.temperature,
                "llm_used": bool(llm_payload),
            },
        }

    def extract_from_file(self, file_path: str) -> dict:
        """Load source file and extract semantics."""
        path = Path(file_path)
        code = path.read_text(encoding="utf-8")
        contract_name = path.stem
        return self.extract(code, contract_name)

    def _extract_entities(self, source_code: str, contract_name: str) -> list[dict[str, Any]]:
        entities: list[dict[str, Any]] = [
            {
                "entity_id": "user",
                "entity_type": "user",
                "chain": "source",
                "address": "",
                "roles": ["caller"],
            },
            {
                "entity_id": contract_name.lower(),
                "entity_type": "contract",
                "chain": "source",
                "address": self._first_address(source_code),
                "roles": ["bridge_contract"],
            },
        ]

        for name in CONTRACT_RE.findall(source_code):
            entity_id = name.lower()
            if not any(e["entity_id"] == entity_id for e in entities):
                entities.append(
                    {
                        "entity_id": entity_id,
                        "entity_type": "contract",
                        "chain": "destination" if "dest" in entity_id or "target" in entity_id else "source",
                        "address": "",
                        "roles": ["support_contract"],
                    }
                )

        if "relay" in source_code.lower() or "message" in source_code.lower():
            entities.append(
                {
                    "entity_id": "relay",
                    "entity_type": "relay",
                    "chain": "offchain",
                    "address": "",
                    "roles": ["message_forwarder"],
                }
            )
        return entities

    def _extract_functions(self, source_code: str) -> list[dict[str, Any]]:
        functions: list[dict[str, Any]] = []
        for fn_name, raw_params in FUNCTION_RE.findall(source_code):
            params = [p.strip() for p in raw_params.split(",") if p.strip()]
            functions.append(
                {
                    "name": fn_name,
                    "signature": f"{fn_name}({','.join(params)})",
                    "parameters": params,
                    "mutability": self._infer_mutability(source_code, fn_name),
                    "visibility": self._infer_visibility(source_code, fn_name),
                }
            )
        return functions

    def _extract_guards(self, source_code: str) -> list[str]:
        guards = re.findall(r"require\s*\((.*?)\)\s*;", source_code, re.DOTALL)
        cleaned = [" ".join(g.split()) for g in guards]
        return cleaned[:50]

    def _infer_asset_flows(self, functions: list[dict[str, Any]]) -> list[dict[str, str]]:
        flows: list[dict[str, str]] = []
        for fn in functions:
            name = fn["name"].lower()
            if any(k in name for k in ("deposit", "lock")):
                flows.append({"src": "user", "dst": "bridge", "label": "lock"})
            elif any(k in name for k in ("mint", "release", "unlock", "withdraw")):
                flows.append({"src": "bridge", "dst": "user", "label": "unlock"})
            elif "relay" in name or "process" in name:
                flows.append({"src": "relay", "dst": "bridge", "label": "verify"})
        return flows

    def _infer_mutability(self, source_code: str, fn_name: str) -> str:
        block = self._extract_function_block(source_code, fn_name)
        if "view" in block:
            return "view"
        if "pure" in block:
            return "pure"
        return "nonpayable"

    def _infer_visibility(self, source_code: str, fn_name: str) -> str:
        block = self._extract_function_block(source_code, fn_name)
        for vis in ("public", "external", "internal", "private"):
            if vis in block:
                return vis
        return "public"

    def _extract_function_block(self, source_code: str, fn_name: str) -> str:
        pattern = re.compile(rf"function\s+{re.escape(fn_name)}\b(.*?)\{{", re.DOTALL)
        match = pattern.search(source_code)
        return match.group(1) if match else ""

    def _first_address(self, source_code: str) -> str:
        match = ADDRESS_RE.search(source_code)
        return match.group(0) if match else ""

    def _try_llm_extract(self, source_code: str, contract_name: str) -> dict[str, Any] | None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return None
        try:
            from openai import OpenAI

            client = OpenAI(api_key=api_key)
            prompt = (
                "Extract bridge semantics as JSON with keys: entities, functions, asset_flows, guards. "
                f"Contract name: {contract_name}\n\n{source_code[:12000]}"
            )
            res = client.chat.completions.create(
                model=self.model,
                temperature=self.temperature,
                response_format={"type": "json_object"},
                messages=[{"role": "user", "content": prompt}],
            )
            content = res.choices[0].message.content or "{}"
            return json.loads(content)
        except Exception:
            return None
