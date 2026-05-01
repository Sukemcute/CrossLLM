"""SA4 — xDFG construction (paper §4.3, spec §2.3).

Three propagation rules over the xCFG's three edge kinds:

* **Ef rule** — standard intra-chain dataflow. For each Ef edge whose
  source writes a resource that the destination reads, draw a DataEdge
  carrying that resource.
* **Ee rule** — only the *arguments of the emitted event* propagate
  across an emitting edge. The variables forwarded are the
  ``EventEmit.arguments`` of whichever emit on the source node
  triggered the Ee edge.
* **Ei rule** — only the *arguments of the authorisation method*
  invoked at the destination propagate across an informing edge. We
  read those from the destination node's CFG entry (the function's
  first node carries the parameter list as state-variable reads in
  Slither's model).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from .models import CfgNode, Resource, ResourceKind
from .xcfg_builder import XCfg

log = logging.getLogger(__name__)


# ============================================================================
# Spec §2.3 — DataEdge / XDfg
# ============================================================================


@dataclass(frozen=True)
class DataEdge:
    """One edge of the xDFG. Carries the resource that flowed."""

    src: object
    dst: object
    variable: Resource
    kind: str  # "ef" | "ee" | "ei"


@dataclass
class XDfg:
    """G_d = (N_d, E_d) — variables / arguments tracked + their flow."""

    nodes: list[Resource] = field(default_factory=list)
    edges: list[DataEdge] = field(default_factory=list)

    def edges_into(self, target: object) -> list[DataEdge]:
        return [e for e in self.edges if e.dst == target]

    def edges_from(self, source: object) -> list[DataEdge]:
        return [e for e in self.edges if e.src == source]


# ============================================================================
# Public entry point
# ============================================================================


def build_xdfg(xcfg: XCfg) -> XDfg:
    """Apply the three propagation rules to *xcfg* and return the xDFG."""

    g = XDfg()
    seen: set[Resource] = set()

    # ---- Ef rule: writes ∩ reads carry a DataEdge --------------------
    for edge in xcfg.edges_ef:
        if not (isinstance(edge.src, CfgNode) and isinstance(edge.dst, CfgNode)):
            continue
        for r in edge.src.writes:
            if any(r.name == rr.name for rr in edge.dst.reads):
                g.edges.append(DataEdge(edge.src, edge.dst, r, "ef"))
                _add_node_once(g, r, seen)

    # ---- Ee rule: emit arguments propagate to the relayer ------------
    for edge in xcfg.edges_ee:
        if not isinstance(edge.src, CfgNode):
            continue
        # The matching emit at this node is whichever EventEmit triggered
        # the Ee edge. We can't tell which without storing it on the
        # edge, so we forward arguments of every cross-chain-shaped emit
        # — over-approximation is safe (false negatives in the omission
        # detector are the only risk; over-propagation only widens the
        # reachable set).
        for emit in edge.src.emits:
            for arg_repr in emit.arguments:
                arg_res = Resource(
                    name=f"{emit.signature}::arg::{arg_repr}",
                    kind=ResourceKind.R4_EVENT_EMIT,
                    location=edge.src.location,
                )
                g.edges.append(DataEdge(edge.src, edge.dst, arg_res, "ee"))
                _add_node_once(g, arg_res, seen)

    # ---- Ei rule: authorisation arguments propagate from the relayer -
    # The dst of an Ei edge is the entry CfgNode of the authorisation
    # function. Its `reads` set contains the function parameters
    # (Slither models them as state-variable-shaped resources for the
    # entry node). We forward each as an Ei DataEdge.
    for edge in xcfg.edges_ei:
        if not isinstance(edge.dst, CfgNode):
            continue
        for r in edge.dst.reads:
            g.edges.append(DataEdge(edge.src, edge.dst, r, "ei"))
            _add_node_once(g, r, seen)

    log.info(
        "xDFG built: %d nodes, edges Ef/Ee/Ei = %d/%d/%d",
        len(g.nodes),
        sum(1 for e in g.edges if e.kind == "ef"),
        sum(1 for e in g.edges if e.kind == "ee"),
        sum(1 for e in g.edges if e.kind == "ei"),
    )
    return g


# ============================================================================
# Helpers
# ============================================================================


def _add_node_once(g: XDfg, r: Resource, seen: set[Resource]) -> None:
    if r in seen:
        return
    seen.add(r)
    g.nodes.append(r)
