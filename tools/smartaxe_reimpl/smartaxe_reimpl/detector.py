"""SA5/SA6 — top-level CCV detector (spec §2.6 ``detect_ccv``).

Two violation classes per the paper:

1. **Access-control omission** — a protected resource (R3 external
   call or R4 event emit) reachable on a path that lacks any guarding
   check with score(c, r) ≥ ``threshold``.
2. **Path inconsistency** — among paths reaching the same resource,
   the set of guarding checks differs (one path is guarded, another
   is not, or guards differ in kind).

The threshold defaults to 0.5 — calibrated to the paper's "all
associations above 0 confidence contribute" wording with a midpoint
between P3 (0.60) and P4 (0.70). SA6 may re-tune against the
PolyNetwork validation example.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .models import Check, CfgNode, ContractCfg, Resource, ResourceKind
from .pattern_inference import score
from .security_checks import apply_classification
from .xcfg_builder import XCfg
from .xdfg_builder import XDfg

log = logging.getLogger(__name__)


DEFAULT_OMISSION_THRESHOLD = 0.5
PATH_ENUMERATION_LIMIT = 32


@dataclass
class Violation:
    """One CCV finding emitted by :func:`detect_ccv`."""

    kind: str  # "omission" | "path_inconsistency"
    sc_id: Optional[str]  # e.g. "SC4"; None for path_inconsistency
    location: str
    resource_name: str
    resource_kind: str
    max_score: float
    description: str
    guarding_checks: list[str] = field(default_factory=list)


def detect_ccv(
    xcfg: XCfg,
    xdfg: XDfg,
    threshold: float = DEFAULT_OMISSION_THRESHOLD,
) -> list[Violation]:
    """Run the two §2.6 detection rules over *xcfg* and *xdfg*."""

    violations: list[Violation] = []

    # Pre-compute: every check in the xCFG with its host node + SC class.
    classified: list[tuple[Check, CfgNode]] = []
    for node in xcfg.basic_blocks:
        for chk in node.requires:
            classified.append((apply_classification(chk), node))

    # ---------------- Rule 1: omission -----------------------------------
    for node in xcfg.basic_blocks:
        protected = [r for r in (node.reads | node.writes) if r.is_external_or_event()]
        for r in protected:
            best_score = 0.0
            best_check_label = ""
            best_sc: Optional[str] = None
            guarding: list[str] = []
            for chk, chk_node in classified:
                conf, match = score(chk, chk_node, r, node, xcfg, xdfg)
                if conf > 0:
                    label = f"{chk.kind or '?'}@{chk_node.location}: {_short(chk.expression)}"
                    guarding.append(label)
                if conf > best_score:
                    best_score = conf
                    best_check_label = label  # noqa: F841
                    best_sc = chk.kind
            if best_score < threshold:
                violations.append(
                    Violation(
                        kind="omission",
                        sc_id=_predict_sc_for_resource(r, node),
                        location=node.location,
                        resource_name=r.name,
                        resource_kind=r.kind.value,
                        max_score=best_score,
                        description=(
                            f"resource {r.kind.value} {r.name!r} reached at "
                            f"{node.location} with no guard above threshold "
                            f"{threshold:.2f} (best={best_score:.2f})"
                        ),
                        guarding_checks=guarding,
                    )
                )

    # ---------------- Rule 2: path inconsistency -------------------------
    for r_node in xcfg.basic_blocks:
        protected = [r for r in (r_node.reads | r_node.writes) if r.is_external_or_event()]
        for r in protected:
            paths = _enumerate_paths_to(r_node, xcfg)
            if len(paths) <= 1:
                continue
            check_sets: list[frozenset[str]] = []
            for path in paths:
                cs: set[str] = set()
                for n in path:
                    for chk in n.requires:
                        cls = apply_classification(chk)
                        if cls.kind:
                            cs.add(cls.kind)
                check_sets.append(frozenset(cs))
            if len(set(check_sets)) > 1:
                violations.append(
                    Violation(
                        kind="path_inconsistency",
                        sc_id=None,
                        location=r_node.location,
                        resource_name=r.name,
                        resource_kind=r.kind.value,
                        max_score=0.0,
                        description=(
                            f"{len(paths)} paths reach {r.name!r} at "
                            f"{r_node.location} with differing guard sets "
                            f"{sorted({tuple(sorted(s)) for s in check_sets})}"
                        ),
                    )
                )

    log.info("detect_ccv: %d violations", len(violations))
    return violations


# ============================================================================
# Helpers
# ============================================================================


def _enumerate_paths_to(
    target: CfgNode, xcfg: XCfg, limit: int = PATH_ENUMERATION_LIMIT
) -> list[list[CfgNode]]:
    """Return up to *limit* simple paths terminating at *target*.

    Sources are CfgNodes that lack any incoming Ef edge from another
    CfgNode in the same function — i.e. function entry points. We
    walk Ef forward from each entry and collect distinct paths.
    """

    same_fn_nodes = [
        n
        for n in xcfg.basic_blocks
        if n.contract == target.contract and n.function == target.function
    ]
    if not same_fn_nodes:
        return []

    incoming: dict[CfgNode, list[CfgNode]] = {n: [] for n in same_fn_nodes}
    for edge in xcfg.edges_ef:
        if (
            isinstance(edge.src, CfgNode)
            and isinstance(edge.dst, CfgNode)
            and edge.dst in incoming
            and edge.src.contract == target.contract
            and edge.src.function == target.function
        ):
            incoming[edge.dst].append(edge.src)

    entries = [n for n, preds in incoming.items() if not preds]
    if not entries:
        # Fallback: lowest-statement_idx node treated as entry.
        entries = [min(same_fn_nodes, key=lambda n: n.statement_idx)]

    paths: list[list[CfgNode]] = []

    def dfs(node: CfgNode, trail: list[CfgNode]) -> None:
        if len(paths) >= limit:
            return
        new_trail = trail + [node]
        if node == target:
            paths.append(new_trail)
            return
        # Recurse over Ef successors.
        for edge in xcfg.edges_ef:
            if (
                edge.src == node
                and isinstance(edge.dst, CfgNode)
                and edge.dst in incoming  # same function
                and edge.dst not in trail  # avoid cycles
            ):
                dfs(edge.dst, new_trail)

    for entry in entries:
        dfs(entry, [])

    return paths


def _short(text: str, n: int = 60) -> str:
    text = text.replace("\n", " ")
    return text if len(text) <= n else text[: n - 3] + "..."


def _predict_sc_for_resource(r: Resource, host_node: Optional[CfgNode] = None) -> Optional[str]:
    """Best-effort guess of which SC *should* guard this resource —
    used to fill the ``sc_id`` field on omission violations so the
    SA6 / SA7 verifier can match against per-bridge expected SC maps.

    Heuristic split (R3 external calls → SC1/SC3/SC4/SC6, R4 emits →
    SC2/SC5) consults both the resource name and (optionally) the
    enclosing function name. Low-level forwarding calls land as SC3
    (cross-chain-router correctness — the PolyNetwork pattern),
    high-level transferFrom/release/verify call into the
    deposit/withdraw paths.
    """

    name_lower = r.name.lower()
    fn_lower = (host_node.function.lower() if host_node else "")
    if r.kind == ResourceKind.R3_EXTERNAL_CALL:
        # Cross-chain router forwarding — `target.call(call_)` on the
        # manager contract. The PolyNetwork SC3 omission lives here.
        if "low_level_call" in name_lower:
            return "SC3"
        if (
            "executecrosschain" in name_lower
            or "verifyheader" in fn_lower
            or "executetx" in fn_lower
            or "router" in name_lower
        ):
            return "SC3"
        if "transferfrom" in name_lower:
            return "SC1"
        if "release" in name_lower or "withdraw" in name_lower:
            return "SC6"
        if "verify" in name_lower or "signature" in name_lower or "sig" in name_lower:
            return "SC4"
        return "SC4"  # default for external mutators on bridge surfaces
    if r.kind == ResourceKind.R4_EVENT_EMIT:
        if "deposit" in name_lower or "lock" in name_lower:
            return "SC2"
        if "withdraw" in name_lower or "unlock" in name_lower:
            return "SC5"
        return "SC2"
    return None
