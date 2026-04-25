"""
Semantic Extractor — Uses LLM to parse bridge smart contract source code
and extract entities, functions, asset flows, and guards.

Input:  Solidity source files + optional Relayer code
Output: Structured JSON with entities, functions, asset_flows, guards

Pipeline (per file)
-------------------
1. **Slither IR** (primary, when ``slither-analyzer`` is installed and the
   contract compiles): structured AST-level extraction handling inheritance,
   modifiers, multi-line declarations, etc.
2. **Regex baseline** (fallback): cheap pattern matching that runs offline
   and handles non-standard sources Slither cannot compile.
3. **LLM enrichment** (optional, when ``OPENAI_API_KEY`` / ``NVIDIA_API_KEY``
   is set): replaces or augments the structured fields with semantic insight.

Each step is a no-op when its prerequisites are missing, so the extractor
always returns a well-formed dict.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from src.common.llm_client import chat_completion_json, get_llm_client

from .prompts import load as load_prompt
from .slither_parser import parse_with_slither


FUNCTION_RE = re.compile(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)", re.DOTALL)
CONTRACT_RE = re.compile(r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)")
EVENT_RE = re.compile(r"\bevent\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)")
ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


class SemanticExtractor:
    """Extract protocol semantics from bridge source code using LLM."""

    def __init__(self, model: str | None = None, temperature: float = 0.0):
        # `model` is kept for orchestrator backward-compat; resolved provider wins.
        self.model = model
        self.temperature = temperature

    def extract(self, source_code: str, contract_name: str) -> dict:
        """Analyze a Solidity source string and return structured semantics.

        ``extract_from_file`` should be preferred when a real file path is
        available, because Slither requires a file on disk.
        """
        return self._extract_internal(
            source_code=source_code or "",
            contract_name=contract_name,
            file_path=None,
        )

    def extract_from_file(self, file_path: str) -> dict:
        """Load a Solidity source file and extract semantics.

        Slither needs the file path to resolve ``import`` statements, so we
        prefer the file-aware path whenever possible.
        """
        path = Path(file_path)
        code = path.read_text(encoding="utf-8")
        return self._extract_internal(
            source_code=code,
            contract_name=path.stem,
            file_path=str(path),
        )

    # -------------------------------------------------------------- internal

    def _extract_internal(
        self,
        source_code: str,
        contract_name: str,
        file_path: str | None,
    ) -> dict:
        # Stage 1: Slither IR (primary structured parser).
        slither_payload: dict[str, Any] | None = None
        parser_used = "regex"
        if file_path:
            slither_payload = parse_with_slither(file_path)
            if slither_payload is not None:
                parser_used = "slither"

        if slither_payload is not None:
            entities = slither_payload.get("entities", [])
            functions = slither_payload.get("functions", [])
            asset_flows = slither_payload.get("asset_flows", [])
            guards = slither_payload.get("guards", [])
        else:
            # Stage 2: regex baseline.
            entities = self._extract_entities(source_code, contract_name)
            functions = self._extract_functions(source_code)
            guards = self._extract_guards(source_code)
            asset_flows = self._infer_asset_flows(functions)

        # Stage 3: LLM enrichment (optional, replaces fields when keys present).
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
                "parser": parser_used,
                "llm_used": bool(llm_payload),
            },
        }

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
        provider = get_llm_client()
        if provider is None:
            return None

        system = load_prompt("system_auditor.txt")
        user = (
            "Extract bridge semantics from the following Solidity source as JSON.\n"
            "Required top-level keys: entities, functions, asset_flows, guards.\n"
            "- entities: [{entity_id, entity_type, chain, address, roles}]\n"
            "- functions: [{name, signature, parameters, mutability, visibility, role}]\n"
            "- asset_flows: [{src, dst, label, token, function_signature, conditions}]\n"
            "- guards: [string]\n\n"
            f"Contract name: {contract_name}\n\n"
            f"Source:\n```solidity\n{source_code[:12000]}\n```"
        )

        try:
            content = chat_completion_json(
                provider,
                system=system,
                user=user,
                temperature=self.temperature,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[Extractor] LLM call failed: {exc}")
            return None

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

        return data if isinstance(data, dict) else None
