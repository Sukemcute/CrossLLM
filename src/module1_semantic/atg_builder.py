"""
ATG Builder — Constructs Atomic Transfer Graph from extracted semantics.

Based on the ATG formalism by Dübler et al.:
  G = (N, A, Λ, Φ) where
  - N = nodes (users, contracts, relay)
  - A = directed arcs (asset transfers, messages)
  - Λ = arc labels (lock, unlock, mint, burn, relay, verify)
  - Φ = protocol invariants
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ATGNode:
    """A node in the Atomic Transfer Graph."""
    node_id: str
    node_type: str  # "user" | "contract" | "relay"
    chain: str      # "source" | "destination" | "offchain"
    address: str = ""


@dataclass
class ATGEdge:
    """A directed edge in the Atomic Transfer Graph."""
    src: str
    dst: str
    label: str       # "lock" | "unlock" | "mint" | "burn" | "relay" | "verify"
    edge_id: str = ""
    token: str = "UNKNOWN"
    function_signature: str = ""
    conditions: list = field(default_factory=list)


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
                    node_id=ent.get("entity_id", ""),
                    node_type=ent.get("entity_type", "contract"),
                    chain=ent.get("chain", "source"),
                    address=ent.get("address", ""),
                )
            )

        edge_idx = 1
        for flow in flows:
            label = flow.get("label", "verify")
            src = flow.get("src", "user")
            dst = flow.get("dst", "bridge")
            atg.edges.append(
                ATGEdge(
                    edge_id=f"e{edge_idx}",
                    src=src,
                    dst=dst,
                    label=label,
                    token=flow.get("token", "UNKNOWN"),
                    function_signature=flow.get("function_signature", self._guess_signature(label, functions)),
                    conditions=flow.get("conditions", []),
                )
            )
            edge_idx += 1

        # Fallback when no flows were inferred: derive edges from function names
        if not atg.edges:
            for fn in functions:
                label = self._label_from_fn(fn.get("name", ""))
                atg.edges.append(
                    ATGEdge(
                        edge_id=f"e{edge_idx}",
                        src="user" if label in ("lock", "burn") else "bridge",
                        dst="bridge" if label in ("lock", "verify") else "user",
                        label=label,
                        token="UNKNOWN",
                        function_signature=fn.get("signature", ""),
                        conditions=[],
                    )
                )
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
                    "conditions": e.conditions,
                    "function_signature": e.function_signature,
                }
                for i, e in enumerate(atg.edges)
            ],
            "invariants": atg.invariants,
        }

    def from_json(self, data: dict) -> ATG:
        """Deserialize ATG from JSON dict."""
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
            atg.edges.append(
                ATGEdge(
                    edge_id=edge.get("edge_id", ""),
                    src=edge.get("src", ""),
                    dst=edge.get("dst", ""),
                    label=edge.get("label", "verify"),
                    token=edge.get("token", "UNKNOWN"),
                    function_signature=edge.get("function_signature", ""),
                    conditions=edge.get("conditions", []),
                )
            )
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
