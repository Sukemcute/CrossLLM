"""SA4 — xCFG construction (paper §4.3 Algorithm 1, spec §2.2).

The xCFG is a single graph that stitches per-contract CFGs from both
the source and destination chains together via two cross-chain edge
kinds:

* ``Ee`` (emitting) — from a basic block emitting a documented
  cross-chain event to the abstract ``RelayerNode``. The relayer is
  the off-chain agent that observes this event and forwards a
  message to the destination chain.
* ``Ei`` (informing) — from the relayer to a destination-chain basic
  block performing an authorisation check on the forwarded message.

Plus the standard intra-chain ``Ef`` edges lifted from per-contract
``CfgNode.successors``.

This module ships only the structure-building algorithm. Whether
each emitted event counts as cross-chain (and which dst function
counts as authorisation) is delegated to :class:`BridgeConfig`
(see :mod:`smartaxe_reimpl.bridge_config`).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .bridge_config import BridgeConfig
from .models import CfgNode, ContractCfg

log = logging.getLogger(__name__)


# ============================================================================
# Spec §2.2 — Edge / RelayerNode / ClientNode / XCfg
# ============================================================================


@dataclass
class RelayerNode:
    """N_r — one synthetic node representing the off-chain relayer."""

    name: str = "relay"


@dataclass
class ClientNode:
    """N_l — one synthetic node representing the abstract end-user / client."""

    name: str = "user"


@dataclass(frozen=True)
class Edge:
    """An edge of one of three kinds (paper §4.3).

    ``src`` / ``dst`` may be a :class:`CfgNode`, :class:`RelayerNode`,
    or :class:`ClientNode`. We don't constrain the union at the type
    level because Python's static-type ergonomics for the resulting
    union are noisy and the four call sites dispatch on ``kind``
    anyway.
    """

    src: object
    dst: object
    kind: str  # "ef" intra-chain | "ee" emitting | "ei" informing


@dataclass
class XCfg:
    """G_c = (N_c, E_c) where N_c = N_b ∪ {relayer} ∪ {client}."""

    basic_blocks: list[CfgNode] = field(default_factory=list)
    relayer: RelayerNode = field(default_factory=RelayerNode)
    client: ClientNode = field(default_factory=ClientNode)
    edges_ef: list[Edge] = field(default_factory=list)
    edges_ee: list[Edge] = field(default_factory=list)
    edges_ei: list[Edge] = field(default_factory=list)

    # ---------------- introspection helpers (used by tests + SA5) ----------

    def all_edges(self) -> list[Edge]:
        return [*self.edges_ef, *self.edges_ee, *self.edges_ei]

    def successors_of(self, node: object) -> list[object]:
        """Outgoing neighbours of *node* across all edge kinds."""
        return [e.dst for e in self.all_edges() if e.src is node or e.src == node]

    def predecessors_of(self, node: object) -> list[object]:
        return [e.src for e in self.all_edges() if e.dst is node or e.dst == node]


# ============================================================================
# Public entry point
# ============================================================================


def build_xcfg(
    src_cfgs: Iterable[ContractCfg],
    dst_cfgs: Iterable[ContractCfg],
    config: BridgeConfig,
) -> XCfg:
    """Build the cross-chain CFG given per-contract CFGs and a config.

    *src_cfgs* and *dst_cfgs* are typically partitioned by classifying
    :class:`ContractCfg` instances against ``config.classify_contract``
    (see :func:`partition_cfgs`).
    """

    src_cfgs = list(src_cfgs)
    dst_cfgs = list(dst_cfgs)
    g = XCfg()

    # 1. Pull every CFG node into the basic-block set + lift intra-chain
    #    successor edges to Ef.
    for ccfg in src_cfgs + dst_cfgs:
        for node in ccfg.all_nodes():
            g.basic_blocks.append(node)
            for succ in node.successors:
                g.edges_ef.append(Edge(src=node, dst=succ, kind="ef"))

    # 2. Emitting edges (Ee). Source-chain nodes that emit a cross-chain
    #    event get an edge to the relayer. (We keep one edge per emit,
    #    not deduplicated by event signature — the same handler may emit
    #    two events on different paths and SA5 needs each occurrence.)
    n_ee_emitted = 0
    for ccfg in src_cfgs:
        for node in ccfg.all_nodes():
            for emit in node.emits:
                if config.is_cross_chain_event(emit.signature):
                    g.edges_ee.append(Edge(src=node, dst=g.relayer, kind="ee"))
                    n_ee_emitted += 1

    # 3. Informing edges (Ei). Destination-chain nodes whose enclosing
    #    function is a documented authorisation entry-point get an
    #    incoming edge from the relayer. The first node of each such
    #    function (the entry node) is the canonical attachment point —
    #    SA5 then walks Ef-successors from there to find the body of
    #    the authorisation predicate.
    n_ei_emitted = 0
    for ccfg in dst_cfgs:
        for fn_sig, nodes in ccfg.functions.items():
            if not config.is_authorization_method(fn_sig):
                continue
            if not nodes:
                continue
            entry = nodes[0]
            g.edges_ei.append(Edge(src=g.relayer, dst=entry, kind="ei"))
            n_ei_emitted += 1

    log.info(
        "xCFG built: %d basic blocks, Ef=%d, Ee=%d, Ei=%d",
        len(g.basic_blocks),
        len(g.edges_ef),
        n_ee_emitted,
        n_ei_emitted,
    )
    return g


# ============================================================================
# Helpers
# ============================================================================


def partition_cfgs(
    cfgs: Iterable[ContractCfg], config: BridgeConfig
) -> tuple[list[ContractCfg], list[ContractCfg]]:
    """Split a flat list of :class:`ContractCfg` into ``(src, dst)`` per
    :class:`BridgeConfig`. Contracts the config can't classify go to
    *src* with a debug log — same fallback strategy as
    :func:`bridge_config._populate_chain_split`.
    """

    src: list[ContractCfg] = []
    dst: list[ContractCfg] = []
    for ccfg in cfgs:
        side = config.classify_contract(ccfg.contract_name)
        if side == "src":
            src.append(ccfg)
        elif side == "dst":
            dst.append(ccfg)
        else:
            log.debug(
                "contract %s unclassified by bridge_config — defaulting to src",
                ccfg.contract_name,
            )
            src.append(ccfg)
    return src, dst
