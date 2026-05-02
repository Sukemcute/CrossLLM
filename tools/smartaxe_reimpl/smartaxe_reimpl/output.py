"""SA5/SA7 — JSON writer matching ``baselines/_cited_results/smartaxe.json``.

Writes one ``run_NNN.json`` per ``(bridge, run)`` pair with:

* ``bridge_id`` — folder name under ``benchmarks/``
* ``run_id`` — caller-provided run number
* ``analysis_seconds`` — wall-clock of cfg + xcfg + xdfg + detect_ccv
* ``contracts_parsed`` — count + list of contract names
* ``violations`` — per-finding dict (kind / sc_id / location / score)
* ``summary`` — per-bridge ``detected`` + ``predicted_sc`` flags so the
  X6-style aggregator can roll a ``baselines/_cited_results/smartaxe_self_run.json``
  on top.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict
from pathlib import Path
from typing import Iterable, Optional

from .detector import Violation
from .models import ContractCfg

log = logging.getLogger(__name__)


def write_run(
    output_path: str | Path,
    bridge_id: str,
    run_id: int,
    analysis_seconds: float,
    contracts: Iterable[ContractCfg],
    violations: Iterable[Violation],
    expected_sc: Optional[list[str]] = None,
) -> Path:
    """Serialize one analysis run to *output_path* (parent dirs auto-created)."""

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    contracts = list(contracts)
    violations = list(violations)
    fired_sc = sorted({v.sc_id for v in violations if v.sc_id})

    summary = {
        "detected": bool(violations),
        "n_violations": len(violations),
        "fired_sc": fired_sc,
        "expected_sc": sorted(expected_sc) if expected_sc else [],
        "predicate_match": (
            bool(set(fired_sc) & set(expected_sc)) if expected_sc else None
        ),
    }

    payload = {
        "tool": "smartaxe-reimpl",
        "schema_version": 1,
        "bridge_id": bridge_id,
        "run_id": run_id,
        "analysis_seconds": round(analysis_seconds, 3),
        "contracts_parsed": len(contracts),
        "contract_names": sorted({c.contract_name for c in contracts}),
        "summary": summary,
        "violations": [asdict(v) for v in violations],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")
    log.info("wrote %s (violations=%d)", output_path, len(violations))
    return output_path
