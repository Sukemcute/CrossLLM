"""SA4 — xCFG construction (paper §4.3 Algorithm 1).

Stub: the actual edge-construction (Ee + Ei) lands in SA4. SA3 ships
only the per-contract :class:`ContractCfg` collection; SA4 wires them
into the cross-chain :class:`XCfg` graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .models import CfgNode


@dataclass
class RelayerNode:
    name: str = "relay"


@dataclass
class ClientNode:
    name: str = "user"


@dataclass(frozen=True)
class Edge:
    src: object  # CfgNode | RelayerNode | ClientNode
    dst: object
    kind: str  # "ef" intra-chain, "ee" emitting, "ei" informing


@dataclass
class XCfg:
    """G_c = (N_c, E_c) where N_c = N_b ∪ N_r ∪ N_l (spec §2.2)."""

    basic_blocks: list[CfgNode] = field(default_factory=list)
    relayer: RelayerNode = field(default_factory=RelayerNode)
    client: ClientNode = field(default_factory=ClientNode)
    edges_ef: list[Edge] = field(default_factory=list)
    edges_ee: list[Edge] = field(default_factory=list)
    edges_ei: list[Edge] = field(default_factory=list)


def build_xcfg(*args, **kwargs) -> Optional[XCfg]:  # noqa: D401, ANN001
    """SA4 stub — returns None until SA4 lands."""

    raise NotImplementedError("build_xcfg is SA4 — not yet implemented")
