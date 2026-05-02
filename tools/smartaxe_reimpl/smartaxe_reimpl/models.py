"""Shared dataclasses for SmartAxe re-impl (spec §2).

Lives in its own module so cfg_builder / xcfg_builder / xdfg_builder /
security_checks / pattern_inference all import from one place. Names
match the spec verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # avoid hard import — Slither types only used as hints
    pass


# ============================================================================
# Resource (spec §2.4 Table — protected resource taxonomy R1..R4)
# ============================================================================


class ResourceKind(str, Enum):
    """Paper §4.4 — protected resource categories."""

    R1_FIELD_ACCESS = "R1"  # state-variable read/write
    R2_INTERNAL_CALL = "R2"  # internal method invocation
    R3_EXTERNAL_CALL = "R3"  # ABI / high-level / low-level external call
    R4_EVENT_EMIT = "R4"  # event emission


@dataclass(frozen=True)
class Resource:
    """A protected resource — either a state-var, call, or event emit.

    `name` is the canonical identifier (e.g. `"Bridge.processed"` or
    `"IERC20.transferFrom"`). `kind` tags which Table-1/2 patterns are
    eligible. `location` is "<contract>.<function>:<statement_idx>" for
    de-duplication and JSON reporting.
    """

    name: str
    kind: ResourceKind
    location: str

    def is_external_or_event(self) -> bool:
        return self.kind in (ResourceKind.R3_EXTERNAL_CALL, ResourceKind.R4_EVENT_EMIT)


# ============================================================================
# Event emit + check predicate (spec §2.1 CfgNode fields)
# ============================================================================


@dataclass(frozen=True)
class EventEmit:
    """A single ``emit Foo(args...)`` statement."""

    signature: str  # canonical event signature, e.g. "Lock(address,uint256,address)"
    arguments: tuple[str, ...]  # decoded arg names / expressions
    location: str


@dataclass(frozen=True)
class Check:
    """A predicate guarding the rest of the statement (require / if-revert).

    The `kind` field maps to spec §2.4 Table 1 SC1..SC6 IDs once the
    detector classifies the predicate's shape. We keep both the raw
    expression and the classification so unit tests can inspect both.
    """

    expression: str  # the Solidity-level predicate text
    kind: Optional[str]  # "SC1".."SC6" or None when unclassified
    location: str


# ============================================================================
# CfgNode — the per-contract / per-function CFG node (spec §2.1)
# ============================================================================


@dataclass
class CfgNode:
    """One node of a single-chain CFG.

    Mirrors spec §2.1 verbatim. Identity is by `(contract, function,
    statement_idx)` — handled via `__hash__` so the node can live in
    `set[CfgNode]` (used by reach-set computations and `xCFG`
    construction).
    """

    contract: str
    function: str  # canonical signature, e.g. "deposit(address,uint256)"
    statement: str  # the Solidity statement at this node, or "" for entry
    statement_idx: int  # 0-based index within the function body
    successors: list["CfgNode"] = field(default_factory=list, repr=False)
    reads: set[Resource] = field(default_factory=set, repr=False)
    writes: set[Resource] = field(default_factory=set, repr=False)
    emits: list[EventEmit] = field(default_factory=list, repr=False)
    requires: list[Check] = field(default_factory=list, repr=False)

    @property
    def location(self) -> str:
        return f"{self.contract}.{self.function}:{self.statement_idx}"

    # Identity by location — two CfgNode instances representing the same
    # statement compare equal and hash to the same bucket. This is what
    # set / dict lookups in the xCFG builder rely on.
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, CfgNode):
            return NotImplemented
        return (
            self.contract == other.contract
            and self.function == other.function
            and self.statement_idx == other.statement_idx
        )

    def __hash__(self) -> int:
        return hash((self.contract, self.function, self.statement_idx))


# ============================================================================
# Per-contract CFG — the SA3 output container.
# ============================================================================


@dataclass
class ContractCfg:
    """All CfgNodes for one contract, indexed by function signature."""

    contract_name: str
    source_path: str
    functions: dict[str, list[CfgNode]] = field(default_factory=dict)

    def all_nodes(self) -> list[CfgNode]:
        return [n for fn_nodes in self.functions.values() for n in fn_nodes]

    def function_entry(self, fn_signature: str) -> Optional[CfgNode]:
        nodes = self.functions.get(fn_signature)
        return nodes[0] if nodes else None
