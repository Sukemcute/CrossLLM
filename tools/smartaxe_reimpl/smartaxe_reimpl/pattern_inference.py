"""SA5 — probabilistic pattern inference (spec §2.5 Table 2 P1..P5).

For each ``(check, resource)`` pair we compute the max confidence
across five patterns; this is the SmartAxe paper's "prior probability"
formulation. The detector (:mod:`smartaxe_reimpl.detector`) consumes
``score(c, r) > threshold`` to decide whether a guard exists.

Patterns implemented verbatim from the spec:

| P  | Confidence | Description                                                         |
|----|------------|---------------------------------------------------------------------|
| P1 | 0.95       | Direct control-flow dominance: c's node strictly dominates r's node |
| P2 | 0.60       | Indirect dominance OR same struct/mapping membership                |
| P3 | 0.60       | Same basic-block proximity                                          |
| P4 | 0.70       | Semantic correlation (shared identifier / type)                     |
| P5 | 0.80       | Data-flow dependency: c flows to r through xDFG                     |

We deliberately do **not** implement Slither's full dominator analysis
— the bridge-protocol contracts we care about are small (<5K LOC each)
and a BFS-from-root suffices for P1/P2. If a future bridge needs more
precision, swap ``_dominates`` for ``slither.utils.dominators``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional

from .models import Check, CfgNode, Resource
from .xcfg_builder import XCfg
from .xdfg_builder import XDfg

# ============================================================================
# Table 2 verbatim — paper's "prior probability" confidences.
# ============================================================================

PATTERN_TABLE: dict[str, tuple[str, float]] = {
    "P1": ("direct control-flow dominance (c dominates r on Gc)", 0.95),
    "P2": ("indirect dominance / same struct-mapping membership", 0.60),
    "P3": ("c and r share a basic block", 0.60),
    "P4": ("semantic correlation (shared identifier / type)", 0.70),
    "P5": ("data-flow dependency via Gd", 0.80),
}

P1_CONF = 0.95
P2_CONF = 0.60
P3_CONF = 0.60
P4_CONF = 0.70
P5_CONF = 0.80


@dataclass(frozen=True)
class PatternMatch:
    """Trace info for which pattern fired with what confidence."""

    pattern: str  # "P1" .. "P5"
    confidence: float


# ============================================================================
# Public entry point: score(c, r) = max P_i.confidence for matches.
# ============================================================================


def score(
    check: Check,
    check_node: CfgNode,
    resource: Resource,
    resource_node: CfgNode,
    xcfg: XCfg,
    xdfg: XDfg,
) -> tuple[float, Optional[PatternMatch]]:
    """Return ``(max_confidence, winning_match)`` for the (c, r) pair.

    ``check_node`` is the CfgNode the *check* was lifted from
    (predicate-bearing); ``resource_node`` is where *resource* is
    consumed (R3 / R4 surface). Both are needed because patterns are
    relative to the graph location, not just the values themselves.
    """

    matches: list[PatternMatch] = []

    if _matches_p1(check_node, resource_node, xcfg):
        matches.append(PatternMatch("P1", P1_CONF))
    if _matches_p2(check_node, resource_node, xcfg, check, resource):
        matches.append(PatternMatch("P2", P2_CONF))
    if _matches_p3(check_node, resource_node):
        matches.append(PatternMatch("P3", P3_CONF))
    if _matches_p4(check, resource):
        matches.append(PatternMatch("P4", P4_CONF))
    if _matches_p5(check_node, resource_node, xdfg):
        matches.append(PatternMatch("P5", P5_CONF))

    if not matches:
        return 0.0, None
    winner = max(matches, key=lambda m: m.confidence)
    return winner.confidence, winner


# ============================================================================
# Per-pattern matchers
# ============================================================================


def _matches_p1(
    check_node: CfgNode, resource_node: CfgNode, xcfg: XCfg
) -> bool:
    """Direct dominance: every Ef path from a function's entry to
    *resource_node* must pass through *check_node*. Approximated by
    ancestor reachability: the check is a Ef-ancestor and lives in
    the same function (else it can't dominate)."""

    if check_node.contract != resource_node.contract:
        return False
    if check_node.function != resource_node.function:
        return False
    return _is_ef_ancestor(check_node, resource_node, xcfg)


def _matches_p2(
    check_node: CfgNode,
    resource_node: CfgNode,
    xcfg: XCfg,
    check: Check,
    resource: Resource,
) -> bool:
    """Indirect dominance OR same struct/mapping membership.

    *Indirect dominance* = the check is reachable from any ancestor
    that also reaches the resource (cross-function via internal calls).

    *Resource membership* = the check predicate references the same
    storage slot as the resource (e.g. `processed[hash]` and
    `processed[hash] = true` both touch the same mapping).
    """

    if _is_ef_ancestor(check_node, resource_node, xcfg):
        return True

    # Membership heuristic: pull the bare identifier from the resource
    # name (drop signature paren tail) and test for its appearance in
    # the check expression.
    resource_token = _bare_token(resource.name)
    expr = check.expression or ""
    if resource_token and resource_token in expr:
        return True

    return False


def _matches_p3(check_node: CfgNode, resource_node: CfgNode) -> bool:
    """Same basic-block proximity — identical CfgNode identity."""
    return check_node == resource_node


def _matches_p4(check: Check, resource: Resource) -> bool:
    """Semantic correlation — the check's expression and the
    resource's name share at least one non-trivial identifier.

    "Non-trivial" = an alphanumeric token longer than 2 chars and
    not in a stop-list of generic Solidity tokens.
    """

    stop = {"address", "uint", "bytes", "true", "false", "the", "and"}
    expr_tokens = {t.lower() for t in re.findall(r"[A-Za-z_]\w+", check.expression or "")}
    res_tokens = {t.lower() for t in re.findall(r"[A-Za-z_]\w+", resource.name or "")}
    expr_tokens -= stop
    res_tokens -= stop
    expr_tokens = {t for t in expr_tokens if len(t) > 2}
    res_tokens = {t for t in res_tokens if len(t) > 2}
    return bool(expr_tokens & res_tokens)


def _matches_p5(
    check_node: CfgNode, resource_node: CfgNode, xdfg: XDfg
) -> bool:
    """Data-flow dependency via Gd — there is a DataEdge whose src
    is *check_node* (or a node in its sub-graph) and whose dst is
    *resource_node*."""

    if not xdfg.edges:
        return False
    # Direct edge from check to resource node.
    direct = any(e.src == check_node and e.dst == resource_node for e in xdfg.edges)
    if direct:
        return True
    # One-hop through a shared data-edge midpoint.
    midpoints = {e.dst for e in xdfg.edges if e.src == check_node}
    return any(
        e.src in midpoints and e.dst == resource_node for e in xdfg.edges
    )


# ============================================================================
# Helpers
# ============================================================================


def _is_ef_ancestor(ancestor: CfgNode, target: CfgNode, xcfg: XCfg) -> bool:
    """BFS forward from *ancestor* over Ef edges; return True if we
    can reach *target*. Bound depth at 64 to keep pathological
    contracts fast (none of our 12 benchmarks needs more)."""

    if ancestor == target:
        return False  # P3 territory, not P1/P2
    visited: set[CfgNode] = set()
    frontier: list[CfgNode] = [ancestor]
    depth = 0
    max_depth = 64
    while frontier and depth < max_depth:
        next_frontier: list[CfgNode] = []
        for node in frontier:
            if node in visited:
                continue
            visited.add(node)
            for edge in xcfg.edges_ef:
                if edge.src == node and isinstance(edge.dst, CfgNode):
                    if edge.dst == target:
                        return True
                    next_frontier.append(edge.dst)
        frontier = next_frontier
        depth += 1
    return False


def _bare_token(name: str) -> str:
    """Pull the leading identifier out of a resource name. Examples:

    >>> _bare_token('TinyBridge.processed')
    'processed'
    >>> _bare_token('IERC20.transferFrom')
    'transferFrom'
    >>> _bare_token('Lock(address,uint256)')
    'Lock'
    """

    head = name.split("(", 1)[0]
    if "." in head:
        head = head.rsplit(".", 1)[1]
    return head
