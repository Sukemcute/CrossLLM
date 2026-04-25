"""Slither-based Solidity parser for Module 1 semantic extraction.

Slither (via the ``slither-analyzer`` package) builds a complete IR of a
Solidity contract — far more robust than the regex baseline at handling
inheritance, modifiers, multi-line declarations, and inline comments.

Behavior
--------
* Returns a dict with the same shape as :class:`SemanticExtractor` output
  (entities, functions, asset_flows, guards) so it can be a drop-in primary.
* Skips test/mock contracts and interfaces.
* Classifies each function role from its name (deposit, withdraw, mint, burn,
  relay, admin, view, other).
* Returns ``None`` on any compilation/parse failure so callers can fall back
  to the regex extractor.

Why not always use Slither?
---------------------------
Slither requires the right ``solc`` binary for the contract's pragma. In
fuzzer-style benchmarks where contracts are reconstructed quickly, a
working install is not always available. The regex extractor is the safety
net.
"""

from __future__ import annotations

from typing import Any


def parse_with_slither(file_path: str) -> dict[str, Any] | None:
    """Run Slither on ``file_path`` and emit semantic dict, or None on failure."""
    try:
        from slither.slither import Slither  # type: ignore
    except ImportError:
        return None

    try:
        sl = Slither(file_path)
    except Exception as exc:  # noqa: BLE001
        # solc resolution / parse error / IR build error — treat as fallback signal.
        print(f"[Slither] Failed to compile {file_path}: {exc}")
        return None

    entities: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    asset_flows: list[dict[str, Any]] = []
    guards: set[str] = set()

    for contract in sl.contracts:
        if _skip_contract(contract):
            continue

        entities.append(
            {
                "entity_id": contract.name.lower(),
                "entity_type": "contract",
                "chain": _guess_chain(contract.name),
                "address": "",
                "roles": _guess_roles(contract.name),
            }
        )

        for func in contract.functions:
            if func.is_constructor:
                continue
            visibility = getattr(func, "visibility", "public")
            if visibility in ("internal", "private") and not _is_externally_reachable(func):
                continue

            params = [str(p.type) for p in getattr(func, "parameters", [])]
            role = _classify_role(func.name)
            functions.append(
                {
                    "name": func.name,
                    "signature": f"{func.name}({','.join(params)})",
                    "parameters": params,
                    "mutability": _mutability(func),
                    "visibility": visibility,
                    "role": role,
                }
            )

            for guard in _extract_guards(func):
                guards.add(guard)

            flow = _flow_for_role(role)
            if flow is not None:
                flow["function_signature"] = f"{func.name}({','.join(params)})"
                asset_flows.append(flow)

    if not entities and not functions:
        return None

    return {
        "entities": entities,
        "functions": functions,
        "asset_flows": asset_flows,
        "guards": list(guards)[:50],
    }


# ---------------------------------------------------------------- heuristics


def _skip_contract(contract: Any) -> bool:
    name = (contract.name or "").lower()
    if getattr(contract, "is_interface", False):
        return True
    if any(token in name for token in ("test", "mock", "fake", "harness")):
        return True
    return False


def _guess_chain(name: str) -> str:
    n = (name or "").lower()
    if any(x in n for x in ("dest", "target", "mint", "wrap", "replica", "outbound", "destination")):
        return "destination"
    return "source"


def _guess_roles(name: str) -> list[str]:
    n = (name or "").lower()
    roles: list[str] = []
    if any(x in n for x in ("router", "bridge", "gateway", "messenger")):
        roles.append("router_contract")
    if any(x in n for x in ("token", "erc20", "erc721", "erc1155")):
        roles.append("token_contract")
    if "replica" in n:
        roles.append("message_receiver")
    if any(x in n for x in ("home", "outbox", "dispatcher")):
        roles.append("message_sender")
    if any(x in n for x in ("oracle", "validator", "guardian")):
        roles.append("validator")
    return roles or ["support_contract"]


def _classify_role(fn_name: str) -> str:
    n = (fn_name or "").lower()
    if any(x in n for x in ("deposit", "lock", "send")):
        return "deposit"
    if any(x in n for x in ("withdraw", "release", "unlock")):
        return "withdraw"
    if "mint" in n:
        return "mint"
    if "burn" in n:
        return "burn"
    if any(x in n for x in ("relay", "process", "handle", "dispatch", "forward")):
        return "relay"
    if any(x in n for x in ("admin", "owner", "pause", "upgrade", "init", "set", "transferowner")):
        return "admin"
    if n.startswith(("get", "is", "has", "view", "balance")):
        return "view"
    return "other"


def _flow_for_role(role: str) -> dict[str, Any] | None:
    flows: dict[str, dict[str, Any]] = {
        "deposit": {"src": "user", "dst": "bridge", "label": "lock"},
        "withdraw": {"src": "bridge", "dst": "user", "label": "unlock"},
        "mint": {"src": "bridge", "dst": "user", "label": "mint"},
        "burn": {"src": "user", "dst": "bridge", "label": "burn"},
        "relay": {"src": "relay", "dst": "bridge", "label": "verify"},
    }
    base = flows.get(role)
    if base is None:
        return None
    return {**base, "token": "UNKNOWN", "conditions": []}


def _is_externally_reachable(func: Any) -> bool:
    """Best-effort: a private/internal function counts if any caller is external."""
    try:
        callers = getattr(func, "all_reachable_from_functions", None) or set()
        for c in callers:
            if getattr(c, "visibility", "internal") in ("public", "external"):
                return True
    except Exception:  # noqa: BLE001
        pass
    return False


def _mutability(func: Any) -> str:
    if getattr(func, "view", False):
        return "view"
    if getattr(func, "pure", False):
        return "pure"
    if getattr(func, "payable", False):
        return "payable"
    return "nonpayable"


def _extract_guards(func: Any) -> list[str]:
    """Pull ``require(...)`` and modifier names from the Slither function IR."""
    guards: list[str] = []

    for modifier in getattr(func, "modifiers", []) or []:
        name = getattr(modifier, "name", None)
        if name:
            guards.append(f"modifier:{name}")

    for node in getattr(func, "nodes", []) or []:
        node_type = getattr(getattr(node, "type", None), "name", "")
        if node_type not in ("IF", "THROW", "EXPRESSION"):
            continue
        expr = str(getattr(node, "expression", "") or "")
        low = expr.lower()
        if "require" in low or "assert" in low:
            guards.append(expr[:200])

    return guards[:10]  # cap per-function noise
