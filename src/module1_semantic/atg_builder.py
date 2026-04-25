"""
ATG Builder — Constructs Atomic Transfer Graph from extracted semantics.

Based on the ATG formalism by Dübler et al.:
  G = (N, A, Λ, Φ) where
  - N = nodes (users, contracts, relay)
  - A = directed arcs (asset transfers, messages)
  - Λ = arc labels (lock, unlock, mint, burn, relay, verify)
  - Φ = protocol invariants

Typed conditions
----------------
Sprint 3 introduces a typed :class:`Condition` dataclass on top of the raw
``list[str]`` ``conditions`` field. Each ``ATGEdge.condition_objects`` lists
typed predicates (``hashlock``, ``timelock``, ``signature``, ``nonce``,
``balance``, or ``generic``) so downstream tooling can reason about edge
guards without re-parsing strings.

Wire format compatibility
~~~~~~~~~~~~~~~~~~~~~~~~~
The Rust fuzzer's :class:`AtgEdge` deserializer still expects
``conditions: Vec<String>``. ``to_json`` therefore emits the legacy
list-of-strings shape and adds an optional ``condition_objects`` array.
The Rust side ignores unknown fields (``serde`` default), so existing
binaries keep working without changes.
"""

from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------- typed conditions

CONDITION_TYPES = (
    "hashlock",
    "timelock",
    "signature",
    "nonce",
    "balance",
    "generic",
)


@dataclass
class Condition:
    """Typed edge condition (e.g. hashlock, timelock, signature, nonce, balance).

    The original free-form expression (``require(...)`` body, etc.) is
    preserved in ``params['expression']`` so downstream tools can render it.
    """

    type: str  # one of CONDITION_TYPES
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "params": dict(self.params)}

    def to_string(self) -> str:
        """Legacy string projection for the Rust fuzzer wire format."""
        expr = self.params.get("expression")
        if expr:
            return str(expr)
        return f"{self.type}({_compact(self.params)})"


def _compact(params: dict[str, Any]) -> str:
    return ", ".join(f"{k}={v}" for k, v in params.items() if k != "expression")


def parse_condition(text: str | dict | Condition) -> Condition:
    """Heuristically classify a string condition into a typed :class:`Condition`.

    Accepts already-typed input (``Condition`` instance or dict) and returns
    it unchanged so callers can mix string/dict forms in the same list.
    """
    if isinstance(text, Condition):
        return text
    if isinstance(text, dict):
        return Condition(
            type=str(text.get("type", "generic")),
            params=dict(text.get("params") or {}),
        )

    s = str(text or "")
    low = s.lower()
    if "hash" in low or "keccak" in low or "merkle" in low:
        return Condition(type="hashlock", params={"expression": s})
    if "timestamp" in low or "block.number" in low or "timeout" in low or "deadline" in low:
        return Condition(type="timelock", params={"expression": s})
    if "ecrecover" in low or "signature" in low or low.startswith("sig"):
        return Condition(type="signature", params={"expression": s})
    if "nonce" in low or "processed" in low or "consumed" in low:
        return Condition(type="nonce", params={"expression": s})
    if "balance" in low or "amount" in low or "value" in low or "totalsupply" in low:
        return Condition(type="balance", params={"expression": s})
    return Condition(type="generic", params={"expression": s})


@dataclass
class ATGNode:
    """A node in the Atomic Transfer Graph."""
    node_id: str
    node_type: str  # "user" | "contract" | "relay"
    chain: str      # "source" | "destination" | "offchain"
    address: str = ""


@dataclass
class ATGEdge:
    """A directed edge in the Atomic Transfer Graph.

    ``conditions`` keeps the legacy list-of-strings projection consumed by
    the Rust fuzzer. ``condition_objects`` is the typed view used by
    Python-side analysis; both are kept in sync via :meth:`set_conditions`.
    """
    src: str
    dst: str
    label: str       # "lock" | "unlock" | "mint" | "burn" | "relay" | "verify"
    edge_id: str = ""
    token: str = "UNKNOWN"
    function_signature: str = ""
    conditions: list = field(default_factory=list)
    condition_objects: list[Condition] = field(default_factory=list)

    def set_conditions(self, raw: list[Any]) -> None:
        """Populate both ``conditions`` (strings) and ``condition_objects`` from a mixed list."""
        typed = [parse_condition(c) for c in raw]
        self.condition_objects = typed
        self.conditions = [c.to_string() for c in typed]


@dataclass
class ATG:
    """Atomic Transfer Graph representing a bridge protocol."""
    nodes: list[ATGNode] = field(default_factory=list)
    edges: list[ATGEdge] = field(default_factory=list)
    invariants: list[dict[str, Any]] = field(default_factory=list)


class ATGBuilder:
    """Build ATG from semantic extraction output."""

    def build(self, semantics: dict) -> ATG:
        """Construct ATG from extracted semantic information."""
        atg = ATG()
        entities = semantics.get("entities", [])
        functions = semantics.get("functions", [])
        flows = semantics.get("asset_flows", [])

        for ent in entities:
            atg.nodes.append(
                ATGNode(
                    # Use ``or default`` instead of ``get(key, default)`` because the
                    # LLM occasionally emits explicit ``null`` for these fields, and
                    # the schema requires strings.
                    node_id=(ent.get("entity_id") or ent.get("name") or "").strip() or "node",
                    node_type=ent.get("entity_type") or ent.get("type") or "contract",
                    chain=ent.get("chain") or "source",
                    address=ent.get("address") or "",
                )
            )

        edge_idx = 1
        for flow in flows:
            label = flow.get("label", "verify")
            src = flow.get("src", "user")
            dst = flow.get("dst", "bridge")
            edge = ATGEdge(
                edge_id=f"e{edge_idx}",
                src=src,
                dst=dst,
                label=label,
                token=flow.get("token", "UNKNOWN"),
                function_signature=flow.get("function_signature", self._guess_signature(label, functions)),
            )
            edge.set_conditions(flow.get("conditions", []))
            atg.edges.append(edge)
            edge_idx += 1

        # Fallback when no flows were inferred: derive edges from function names
        if not atg.edges:
            for fn in functions:
                label = self._label_from_fn(fn.get("name", ""))
                edge = ATGEdge(
                    edge_id=f"e{edge_idx}",
                    src="user" if label in ("lock", "burn") else "bridge",
                    dst="bridge" if label in ("lock", "verify") else "user",
                    label=label,
                    token="UNKNOWN",
                    function_signature=fn.get("signature", ""),
                )
                edge.set_conditions([])
                atg.edges.append(edge)
                edge_idx += 1

        return atg

    def to_json(self, atg: ATG) -> dict:
        """Serialize ATG to JSON-compatible dict."""
        return {
            "bridge_name": "unknown_bridge",
            "version": "1.0",
            "nodes": [
                {
                    "node_id": n.node_id,
                    "node_type": n.node_type,
                    "chain": n.chain,
                    "address": n.address,
                    "functions": [],
                }
                for n in atg.nodes
            ],
            "edges": [
                {
                    "edge_id": e.edge_id or f"e{i+1}",
                    "src": e.src,
                    "dst": e.dst,
                    "label": e.label,
                    "token": e.token,
                    # Wire format: legacy list-of-strings (Rust fuzzer compat).
                    "conditions": e.conditions,
                    # Optional typed view (Rust ignores unknown fields).
                    "condition_objects": [c.to_dict() for c in e.condition_objects],
                    "function_signature": e.function_signature,
                }
                for i, e in enumerate(atg.edges)
            ],
            "invariants": atg.invariants,
        }

    def from_json(self, data: dict) -> ATG:
        """Deserialize ATG from JSON dict.

        Accepts both the legacy ``conditions: [str, ...]`` shape and the typed
        ``condition_objects: [{"type": ..., "params": ...}]`` form.
        """
        atg = ATG()
        for node in data.get("nodes", []):
            atg.nodes.append(
                ATGNode(
                    node_id=node.get("node_id", ""),
                    node_type=node.get("node_type", "contract"),
                    chain=node.get("chain", "source"),
                    address=node.get("address", ""),
                )
            )
        for edge in data.get("edges", []):
            edge_obj = ATGEdge(
                edge_id=edge.get("edge_id", ""),
                src=edge.get("src", ""),
                dst=edge.get("dst", ""),
                label=edge.get("label", "verify"),
                token=edge.get("token", "UNKNOWN"),
                function_signature=edge.get("function_signature", ""),
            )
            # Prefer typed condition_objects when present, else parse strings.
            typed = edge.get("condition_objects")
            if isinstance(typed, list) and typed:
                edge_obj.set_conditions(typed)
            else:
                edge_obj.set_conditions(edge.get("conditions", []))
            atg.edges.append(edge_obj)
        atg.invariants = data.get("invariants", [])
        return atg

    def _guess_signature(self, label: str, functions: list[dict[str, Any]]) -> str:
        for fn in functions:
            if self._label_from_fn(fn.get("name", "")) == label:
                return fn.get("signature", "")
        return ""

    def _label_from_fn(self, fn_name: str) -> str:
        n = (fn_name or "").lower()
        if any(k in n for k in ("deposit", "lock")):
            return "lock"
        if any(k in n for k in ("mint",)):
            return "mint"
        if any(k in n for k in ("burn",)):
            return "burn"
        if any(k in n for k in ("unlock", "release", "withdraw")):
            return "unlock"
        if any(k in n for k in ("relay", "process", "verify")):
            return "verify"
        return "verify"
