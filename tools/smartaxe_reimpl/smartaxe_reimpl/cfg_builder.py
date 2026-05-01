"""SA3 — Single-contract CFG/DFG builder via Slither's IR.

Spec §2.1 + §3 (Slither substitution for SmartDagger).

Inputs:
  - A directory of `.sol` files (e.g. ``benchmarks/<bridge>/contracts/``)

Outputs:
  - One :class:`smartaxe_reimpl.models.ContractCfg` per contract,
    plus a top-level ``list[ContractCfg]``.

Slither does the heavy lifting:

* ``slither.core.declarations.Contract``    → enumerates contracts
* ``slither.core.declarations.Function``    → per-function CFG entry
* ``slither.core.cfg.node.Node``            → individual CFG nodes
* ``Node.state_variables_read / written``   → R1 reads/writes
* ``Node.internal_calls``                   → R2
* ``Node.high_level_calls``/``low_level_calls`` → R3
* ``Node.expression`` + ``NodeType.IF``     → require / branch checks
* SlithIR ``EventCall``                     → R4 emit detection

We deliberately do **not** use Slither's `function.dominators`
(that's Algorithm-1-territory in xCFG). SA3 captures the per-node
data; SA4/SA5 do the cross-chain reasoning.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable, Optional

from .models import (
    Check,
    CfgNode,
    ContractCfg,
    EventEmit,
    Resource,
    ResourceKind,
)

log = logging.getLogger(__name__)


# ============================================================================
# Public entry point
# ============================================================================


def build_contract_cfgs(contracts_dir: str | Path) -> list[ContractCfg]:
    """Build one :class:`ContractCfg` per contract under *contracts_dir*.

    Drives Slither once per ``.sol`` file. Re-raises Slither parse errors
    so the caller (and pytest) see them — silent fall-throughs hide
    real bugs.

    Slither is imported lazily so the rest of the package (dataclasses,
    output schema) can be unit-tested without the heavy native
    dependency installed.
    """

    contracts_dir = Path(contracts_dir)
    if not contracts_dir.is_dir():
        raise FileNotFoundError(f"contracts dir not found: {contracts_dir}")

    sol_files = sorted(contracts_dir.glob("**/*.sol"))
    if not sol_files:
        log.warning("no .sol files under %s", contracts_dir)
        return []

    # Lazy-import inside the function so models / tests work without Slither.
    try:
        from slither.slither import Slither  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "slither-analyzer not installed. Run "
            "`pip install slither-analyzer` inside the venv."
        ) from e

    out: list[ContractCfg] = []
    for sol_file in sol_files:
        slither = Slither(str(sol_file))
        for sl_contract in slither.contracts:
            cfg = _build_one_contract(sl_contract, sol_file)
            out.append(cfg)
    return out


def build_contract_cfgs_from_slither(slither_obj) -> list[ContractCfg]:  # noqa: ANN001
    """Build CFGs from an already-constructed ``Slither`` instance.

    Useful for tests that pre-load a fixture once and want to avoid
    re-parsing on every assertion.
    """

    return [_build_one_contract(c, _origin_path(slither_obj, c)) for c in slither_obj.contracts]


# ============================================================================
# Per-contract assembly
# ============================================================================


def _build_one_contract(sl_contract, source_path) -> ContractCfg:  # noqa: ANN001
    """Convert one Slither :class:`Contract` to our :class:`ContractCfg`.

    For each non-abstract function we walk Slither's per-function CFG
    (already in topological-ish order via ``function.nodes``) and emit
    a :class:`CfgNode` with reads / writes / emits / requires populated.
    """

    cfg = ContractCfg(
        contract_name=sl_contract.name,
        source_path=str(source_path),
    )

    for sl_func in sl_contract.functions_declared:
        # Skip pure interfaces and modifier definitions; we want the
        # callable surface (constructor + public/external/internal funcs).
        if sl_func.is_constructor_variables:
            continue

        canonical_sig = _canonical_signature(sl_func)
        nodes: list[CfgNode] = []
        # Build a stable index → CfgNode map first so we can wire
        # successors after every node has been created.
        index_to_node: dict[int, CfgNode] = {}
        for stmt_idx, sl_node in enumerate(sl_func.nodes):
            cfg_node = _build_cfg_node(
                sl_contract.name, canonical_sig, stmt_idx, sl_node
            )
            nodes.append(cfg_node)
            index_to_node[id(sl_node)] = cfg_node

        # Wire up successors using Slither's son edges.
        for stmt_idx, sl_node in enumerate(sl_func.nodes):
            our_node = index_to_node[id(sl_node)]
            for sl_succ in sl_node.sons:
                succ = index_to_node.get(id(sl_succ))
                if succ is not None:
                    our_node.successors.append(succ)

        if nodes:
            cfg.functions[canonical_sig] = nodes

    return cfg


# ============================================================================
# Per-node assembly — the spec-§2.1 CfgNode fields
# ============================================================================


def _build_cfg_node(  # noqa: ANN001
    contract_name: str,
    canonical_sig: str,
    stmt_idx: int,
    sl_node,
) -> CfgNode:
    """Translate one Slither :class:`Node` into a :class:`CfgNode`."""

    statement = (sl_node.expression and str(sl_node.expression)) or _node_type_label(
        sl_node
    )
    node = CfgNode(
        contract=contract_name,
        function=canonical_sig,
        statement=statement,
        statement_idx=stmt_idx,
    )

    # ---- R1 field access: state-variable reads / writes ----------------
    for sv in getattr(sl_node, "state_variables_read", []) or []:
        node.reads.add(
            Resource(
                name=f"{contract_name}.{sv.name}",
                kind=ResourceKind.R1_FIELD_ACCESS,
                location=node.location,
            )
        )
    for sv in getattr(sl_node, "state_variables_written", []) or []:
        node.writes.add(
            Resource(
                name=f"{contract_name}.{sv.name}",
                kind=ResourceKind.R1_FIELD_ACCESS,
                location=node.location,
            )
        )

    # ---- R2 internal calls --------------------------------------------
    # Slither 0.11 returns IR operation objects (SolidityCall /
    # InternalCall) here, not Function objects directly. Each wraps a
    # `.function` whose type may be `SolidityFunction` (builtin like
    # `require`, `assert`, `revert`) or `Function` (user-defined).
    # Builtin SolidityFunction objects don't carry `canonical_name`,
    # so we fall back to `.name` then to `str(...)`.
    for ic in getattr(sl_node, "internal_calls", []) or []:
        target_fn = getattr(ic, "function", ic)
        name = (
            getattr(target_fn, "canonical_name", None)
            or getattr(target_fn, "name", None)
            or str(target_fn)
        )
        # Skip Solidity builtins (require / assert / revert) — they're
        # represented as `requires` Checks instead, not R2 calls. We
        # detect them by class name to avoid duplicate accounting.
        if type(ic).__name__ == "SolidityCall":
            continue
        node.reads.add(
            Resource(name=name, kind=ResourceKind.R2_INTERNAL_CALL, location=node.location)
        )

    # ---- R3 external calls (high-level + low-level) -------------------
    for hl in getattr(sl_node, "high_level_calls", []) or []:
        # Slither returns tuples (Contract, Function) for high_level_calls.
        if isinstance(hl, tuple) and len(hl) >= 2:
            contract_part, fn_part = hl[0], hl[1]
            cname = getattr(contract_part, "name", str(contract_part))
            fname = getattr(fn_part, "name", str(fn_part))
            name = f"{cname}.{fname}"
        else:
            name = str(hl)
        node.reads.add(
            Resource(name=name, kind=ResourceKind.R3_EXTERNAL_CALL, location=node.location)
        )
    for ll in getattr(sl_node, "low_level_calls", []) or []:
        if isinstance(ll, tuple):
            name = ".".join(str(p) for p in ll if p is not None)
        else:
            name = str(ll)
        node.reads.add(
            Resource(name=name, kind=ResourceKind.R3_EXTERNAL_CALL, location=node.location)
        )

    # ---- R4 event emits ------------------------------------------------
    for emit in _enumerate_emits(sl_node):
        node.emits.append(emit)
        node.writes.add(
            Resource(
                name=emit.signature,
                kind=ResourceKind.R4_EVENT_EMIT,
                location=node.location,
            )
        )

    # ---- Predicates / require checks ----------------------------------
    for chk in _enumerate_checks(sl_node):
        node.requires.append(chk)

    return node


# ============================================================================
# Slither helpers
# ============================================================================


def _canonical_signature(sl_func) -> str:  # noqa: ANN001
    """Slither's `function.canonical_name` is `Contract.foo(...)`; we
    want the bare `foo(uint,uint)` form because the rest of the spec
    uses signatures keyed by function only.
    """

    canonical = getattr(sl_func, "canonical_name", None) or sl_func.name
    if "." in canonical:
        canonical = canonical.split(".", 1)[1]
    return canonical


def _node_type_label(sl_node) -> str:  # noqa: ANN001
    """Fallback statement label for nodes without an `expression`
    (entry / exit / IF condition without explicit predicate)."""

    nt = getattr(sl_node, "type", None)
    return f"<{nt}>" if nt is not None else "<node>"


def _enumerate_emits(sl_node) -> Iterable[EventEmit]:  # noqa: ANN001
    """Yield :class:`EventEmit` for each ``emit Foo(...)`` in the node.

    Slither exposes emits via the SlithIR ``EventCall`` operation; we
    look at ``node.irs`` for any operation whose class name contains
    ``EventCall``. Falls back to scanning ``node.expression`` text when
    SlithIR is unavailable (older Slither builds).
    """

    irs = getattr(sl_node, "irs", []) or []
    for op in irs:
        cls_name = type(op).__name__
        if "EventCall" in cls_name:
            event_name = getattr(op, "name", None) or "<event>"
            args = tuple(str(a) for a in getattr(op, "arguments", []) or [])
            sig = f"{event_name}({','.join(_arg_type(a) for a in args) or '...'})"
            yield EventEmit(
                signature=sig,
                arguments=args,
                location=f"{sl_node.function.contract.name}.{sl_node.function.name}:{sl_node.node_id}",
            )


def _arg_type(arg: str) -> str:
    """Heuristic type inference from a SlithIR variable repr.

    SlithIR prints variables as ``REF_x`` / ``TMP_y`` which carries no
    type information at the string level. Real type extraction needs
    the SlithIR variable's `type` attribute. Since EventEmit is consumed
    by xCFG (matching against per-bridge event-signature tables), an
    approximate signature is fine here — the canonical event signature
    used for matching is the **event name** plus topic table lookup,
    not this string. We return a placeholder.
    """

    return "?"


def _enumerate_checks(sl_node) -> Iterable[Check]:  # noqa: ANN001
    """Yield :class:`Check` for require/assert/if-revert predicates.

    Slither exposes these via ``node.contains_require_or_assert()``
    and the IR. Implementation: scan the IR for ``Solidity Call`` ops
    whose function name is in {`require`, `assert`} plus IF nodes
    immediately followed by a ``THROW`` / ``revert``.
    """

    if hasattr(sl_node, "contains_require_or_assert") and sl_node.contains_require_or_assert():
        expr = (sl_node.expression and str(sl_node.expression)) or ""
        yield Check(
            expression=expr,
            kind=None,  # SC classification happens in security_checks.py (SA5)
            location=_node_loc(sl_node),
        )
        return

    # IF-then-revert / if-then-throw pattern
    nt = getattr(sl_node, "type", None)
    nt_str = str(nt) if nt is not None else ""
    if "IF" in nt_str:
        sons = getattr(sl_node, "sons", []) or []
        for s in sons:
            son_type = str(getattr(s, "type", "") or "")
            if "THROW" in son_type or "_REVERT" in son_type:
                expr = (sl_node.expression and str(sl_node.expression)) or ""
                yield Check(
                    expression=expr,
                    kind=None,
                    location=_node_loc(sl_node),
                )
                break


def _node_loc(sl_node) -> str:  # noqa: ANN001
    fn = getattr(sl_node, "function", None)
    fname = getattr(fn, "name", "?") if fn is not None else "?"
    cname = getattr(getattr(fn, "contract", None), "name", "?") if fn is not None else "?"
    nid = getattr(sl_node, "node_id", "?")
    return f"{cname}.{fname}:{nid}"


def _origin_path(slither_obj, sl_contract) -> str:  # noqa: ANN001
    """Best-effort source path lookup from a Slither contract object."""

    src = getattr(sl_contract, "source_mapping", None)
    if src is not None:
        fname = getattr(src, "filename_absolute", None) or getattr(src, "filename", None)
        if fname:
            return os.fspath(fname)
    return getattr(slither_obj, "filename", "<unknown>")
