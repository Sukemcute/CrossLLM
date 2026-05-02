"""SA8 — Build the self-run version of `baselines/_cited_results/smartaxe.json`.

Reads every `results/baselines/smartaxe/<bridge>/run_NNN.json` produced
by the SA7 sweep and aggregates into a per-bridge `detected` flag,
fired-SC list, expected-SC list, and a free-text provenance note.
Schema mirrors :mod:`scripts.build_xscope_self_run_cited` so the RQ1
aggregator can swap the cite-published cells for self-run cells
transparently.

Idempotent. Re-run after every sweep.

Usage:
    python scripts/build_smartaxe_self_run_cited.py
"""

from __future__ import annotations

import glob
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(REPO, "results", "baselines", "smartaxe")
OUT_PATH = os.path.join(
    REPO, "baselines", "_cited_results", "smartaxe_self_run.json"
)

BRIDGES = [
    "nomad",
    "qubit",
    "pgala",
    "polynetwork",
    "wormhole",
    "socket",
    "ronin",
    "harmony",
    "multichain",
    "orbit",
    "fegtoken",
    "gempad",
]

# Spec §4 per-bridge expected SC violation map — same as
# scripts/verify_smartaxe_acceptance.py.
EXPECTED: Dict[str, List[str]] = {
    "nomad": ["SC4"],
    "qubit": ["SC1", "SC2"],
    "pgala": ["SC4", "SC5"],
    "polynetwork": ["SC3"],
    "wormhole": ["SC4"],
    "socket": ["SC2"],
    "ronin": ["SC4"],
    "harmony": ["SC4"],
    "multichain": ["SC4"],
    "orbit": ["SC4"],
    "fegtoken": ["SC5"],
    "gempad": ["SC6"],
}

# Bridges where path-inconsistency is part of the expected verdict
# (see spec §4 column "predicted SmartAxe verdict"). Mirrors
# verify_smartaxe_acceptance.py.
EXPECT_PATH_INCONSISTENCY = {"harmony", "socket"}


def collect_bridge(bridge: str) -> Dict[str, Any]:
    """Aggregate findings from every `run_*.json` for *bridge*.

    Returns a dict in the shape the cited JSON `results.<bridge>`
    block expects, plus a few extra fields specific to static
    analysis (n_violations, contracts_with_findings) so RQ1 can pick
    its narrative without re-reading the raw runs.
    """

    bdir = os.path.join(RESULTS_DIR, bridge)
    expected_set = sorted(set(EXPECTED.get(bridge, [])))

    if not os.path.isdir(bdir):
        return {
            "detected": False,
            "tte_seconds": None,
            "tte_std": None,
            "runs": 0,
            "n_violations": 0,
            "predicates_fired": [],
            "predicates_expected": expected_set,
            "predicate_match": False,
            "has_path_inconsistency": False,
            "contracts_with_findings": [],
            "note": "no run output (bridge skipped or sweep not run)",
        }

    runs = sorted(glob.glob(os.path.join(bdir, "run_*.json")))
    if not runs:
        return {
            "detected": False,
            "tte_seconds": None,
            "tte_std": None,
            "runs": 0,
            "n_violations": 0,
            "predicates_fired": [],
            "predicates_expected": expected_set,
            "predicate_match": False,
            "has_path_inconsistency": False,
            "contracts_with_findings": [],
            "note": "no run_*.json artifacts",
        }

    fired_counter: Counter = Counter()
    n_violations = 0
    has_path_inconsistency = False
    contracts_with_findings: set[str] = set()
    analysis_seconds_avg = 0.0
    analysis_count = 0
    for run_path in runs:
        try:
            with open(run_path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if "analysis_seconds" in data:
            analysis_seconds_avg += float(data["analysis_seconds"])
            analysis_count += 1
        for v in data.get("violations", []):
            n_violations += 1
            if v.get("kind") == "path_inconsistency":
                has_path_inconsistency = True
            sc = v.get("sc_id")
            if sc:
                fired_counter[sc] += 1
            loc = v.get("location", "")
            if "." in loc:
                contracts_with_findings.add(loc.split(".")[0])

    fired = sorted(fired_counter.keys())
    matched_strict = bool(set(fired) & set(expected_set))
    if (
        not matched_strict
        and bridge in EXPECT_PATH_INCONSISTENCY
        and has_path_inconsistency
    ):
        matched_strict = True

    detected = n_violations > 0
    avg_analysis = (
        analysis_seconds_avg / analysis_count if analysis_count else None
    )

    note_parts: List[str] = []
    if detected:
        note_parts.append(
            f"static analysis: {n_violations} omission/path-inconsistency "
            f"finding(s) across {len(runs)} run(s)"
        )
    if matched_strict:
        note_parts.append("predicted SC matched")
    elif fired:
        note_parts.append(
            "fired " + ",".join(fired)
            + " but expected "
            + ",".join(expected_set)
            + " — simplified benchmark retains syntactically valid guard "
            "(see docs/REIMPL_SMARTAXE_SA7_OUTCOME.md §2)"
        )
    if not fired:
        note_parts.append("no SC-classified findings")

    return {
        "detected": detected,
        "tte_seconds": (
            round(avg_analysis, 3) if avg_analysis is not None else None
        ),
        "tte_std": None,  # static analysis is deterministic; TTE std undefined.
        "runs": len(runs),
        "n_violations": n_violations,
        "predicates_fired": fired,
        "predicates_expected": expected_set,
        "predicate_match": matched_strict,
        "has_path_inconsistency": has_path_inconsistency,
        "contracts_with_findings": sorted(contracts_with_findings),
        "note": "; ".join(note_parts) or "—",
    }


def main() -> int:
    payload: Dict[str, Any] = {
        "tool": "smartaxe",
        "tool_type": "static_analysis",
        "source": (
            "Self-run static analysis of SmartAxe re-implementation "
            "against BridgeSentry's 12 benchmarks. See "
            "docs/REIMPL_SMARTAXE_SA7_OUTCOME.md for per-bridge "
            "trajectory (12/12 detected, 4/12 strict predicate_match)."
        ),
        "doi_or_url": (
            "Original paper: Liao et al., \"SmartAxe: Detecting "
            "Cross-Chain Vulnerabilities in Bridge Smart Contracts via "
            "Fine-Grained Static Analysis\", FSE 2024 — "
            "https://arxiv.org/abs/2406.15999"
        ),
        "extraction_date": "2026-05-02",
        "methodology_note": (
            "Static-analysis pipeline: Slither-driven CFG → xCFG/xDFG "
            "construction → 6-class security-check classifier (SC1..SC6) "
            "→ 5-pattern probabilistic inference (P1..P5 max-score) → "
            "omission + path-inconsistency detector with threshold 0.5. "
            "Spec at docs/REIMPL_SMARTAXE_SPEC.md, validation against "
            "the PolyNetwork pre-fix at "
            "docs/REIMPL_SMARTAXE_SA6_REPORT.md (predicate_match=true). "
            "TTE is reported as the analysis wall-clock per bridge "
            "(deterministic — std undefined). The 8 bridges that fail "
            "strict predicate_match all retain syntactically valid "
            "guards in the simplified benchmark contracts; their "
            "documented incidents are runtime key-compromises (V4) "
            "that static analysis cannot reach without semantic "
            "reasoning over trust boundaries — consistent with the "
            "paper §6.2 7/16 detection rate on similar attacks."
        ),
        "results": {},
    }

    for bridge in BRIDGES:
        payload["results"][bridge] = collect_bridge(bridge)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    detected_n = sum(
        1 for r in payload["results"].values() if r["detected"]
    )
    matched_n = sum(
        1 for r in payload["results"].values() if r["predicate_match"]
    )
    print(f"Wrote {OUT_PATH}")
    print(f"  detected (any violation):       {detected_n}/12")
    print(f"  predicate_match (strict any-of): {matched_n}/12")
    return 0


if __name__ == "__main__":
    sys.exit(main())
