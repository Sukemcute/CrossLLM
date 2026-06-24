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

import re
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


# ---------------------------------------------------------- node normalization
# LLM asset-flow extraction frequently fills ``src``/``dst`` with *function
# parameter names* (``from``/``to``/``msg.sender``) or raw addresses rather than
# actual entities, producing placeholder nodes and leaving real contracts
# disconnected. We collapse these into a small set of canonical actor roles so
# the graph reflects entity-level asset flow rather than parameter noise.
_CALLER_ALIASES = {
    "msg.sender", "msgsender", "sender", "caller", "tx.origin", "txorigin",
    "from", "src", "source", "owner", "spender", "attacker", "user", "eoa",
    "account", "payer", "holder",
}
_RECIPIENT_ALIASES = {
    "to", "recipient", "receiver", "dst", "destination", "beneficiary", "payee",
}
_ZERO_RE = re.compile(r"^0x0+$")
_ACTOR_TYPE = {"User": "user", "Recipient": "user", "ZeroAddress": "external"}


def canonical_endpoint(name: Any) -> str:
    """Map a parameter-name / address endpoint to a canonical actor, else keep it.

    Real entity names (e.g. ``FEGSwap``, ``QBridgeETH``) are returned unchanged.
    """
    if not name:
        return str(name or "")
    raw = str(name).strip()
    key = raw.lower()
    for tok in ("(parameter)", "parameter"):
        key = key.replace(tok, "")
    key = key.strip().strip("_()").replace(" ", "")
    if not key:
        return raw
    if _ZERO_RE.match(key) or key in {"address(0)", "zero", "zeroaddress", "null", "0x0"}:
        return "ZeroAddress"
    if key in _CALLER_ALIASES:
        return "User"
    if key in _RECIPIENT_ALIASES:
        return "Recipient"
    return raw


def normalize_atg_dict(atg: dict) -> dict:
    """Clean an ATG JSON dict in place: canonicalize endpoints, dedup nodes/edges.

    Deterministic and LLM-free, so it is safe to apply both inside the pipeline
    (``ATGBuilder.to_json``) and at visualization time. Idempotent.
    """
    # 1. canonicalize edge endpoints + sanitize null scalar fields.
    #    The LLM occasionally emits explicit ``null`` for string fields (e.g.
    #    ``"token": null``); the Rust fuzzer deserializes these as ``String``
    #    (not ``Option<String>``) and panics on null. Coerce to safe defaults.
    for e in atg.get("edges", []):
        e["src"] = canonical_endpoint(e.get("src", ""))
        e["dst"] = canonical_endpoint(e.get("dst", ""))
        e["label"] = e.get("label") or "verify"
        e["token"] = e.get("token") or "UNKNOWN"
        e["function_signature"] = e.get("function_signature") or ""
        if e.get("conditions") is None:
            e["conditions"] = []

    # 2. canonicalize + dedup nodes by node_id (keep the richest record)
    merged: dict[str, dict] = {}
    order: list[str] = []
    for n in atg.get("nodes", []):
        nid = canonical_endpoint(n.get("node_id", ""))
        if not nid:
            continue
        node = {**n, "node_id": nid}
        node["node_type"] = node.get("node_type") or "contract"
        node["chain"] = node.get("chain") or "source"
        node["address"] = node.get("address") or ""
        if nid not in merged:
            merged[nid] = node
            order.append(nid)
        else:
            cur = merged[nid]
            if not cur.get("address") and node.get("address"):
                cur["address"] = node["address"]
            if cur.get("chain") in (None, "", "unknown") and node.get("chain") not in (None, "", "unknown"):
                cur["chain"] = node["chain"]

    # 3. ensure every edge endpoint exists as a node
    for e in atg.get("edges", []):
        for ep in (e.get("src"), e.get("dst")):
            if ep and ep not in merged:
                merged[ep] = {
                    "node_id": ep,
                    "node_type": _ACTOR_TYPE.get(ep, "contract"),
                    "chain": "external" if ep in _ACTOR_TYPE else "source",
                    "address": "",
                    "functions": [],
                }
                order.append(ep)
    atg["nodes"] = [merged[k] for k in order]

    # 4. drop exact-duplicate edges, reindex edge_id
    seen: set = set()
    deduped: list[dict] = []
    idx = 1
    for e in atg.get("edges", []):
        sig = (e.get("src"), e.get("dst"), e.get("label"),
               e.get("function_signature"), tuple(e.get("conditions") or []))
        if sig in seen:
            continue
        seen.add(sig)
        e["edge_id"] = f"e{idx}"
        idx += 1
        deduped.append(e)
    atg["edges"] = deduped
    return atg


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

    def set_conditions(self, raw: list[Any] | str | dict | None) -> None:
        """Populate both ``conditions`` (strings) and ``condition_objects`` from a mixed list.

        LLM responses sometimes return ``null`` for ``conditions`` when no
        conditions apply, which would otherwise crash the iteration. Treat
        ``None`` and missing-but-supplied values as an empty list.

        They also sometimes return a single condition as a bare ``str`` (e.g.
        ``"require(!processed(nonce))"``) or a single ``dict`` instead of a
        one-element list. Iterating a bare string yields individual characters,
        producing one bogus condition per character; coerce such scalars into a
        single-element list first.
        """
        if not raw:
            self.condition_objects = []
            self.conditions = []
            return
        if isinstance(raw, (str, dict)):
            raw = [raw]
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
                token=flow.get("token") or "UNKNOWN",
                function_signature=flow.get("function_signature") or self._guess_signature(label, functions),
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
        """Serialize ATG to JSON-compatible dict (normalized: deduped + canonical actors)."""
        result = {
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
        return normalize_atg_dict(result)

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
