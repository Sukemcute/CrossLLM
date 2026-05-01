"""SA4 — xDFG construction (paper §4.3 propagation rules).

Stub: SA4 implements the three propagation rules over Ef / Ee / Ei
edges. SA3 ships only the per-contract reads/writes that this builder
will consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Resource


@dataclass(frozen=True)
class DataEdge:
    src: object
    dst: object
    variable: Resource
    kind: str  # "ef" / "ee" / "ei"


@dataclass
class XDfg:
    nodes: list[Resource] = field(default_factory=list)
    edges: list[DataEdge] = field(default_factory=list)


def build_xdfg(*args, **kwargs):  # noqa: D401, ANN001
    """SA4 stub."""

    raise NotImplementedError("build_xdfg is SA4 — not yet implemented")
