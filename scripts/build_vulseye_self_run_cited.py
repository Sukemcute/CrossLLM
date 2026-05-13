"""Build `baselines/_cited_results/vulseye_self_run.json` from self-run outputs.

Reads every ``results/baselines/vulseye/<bridge>/run_*.json`` file and
aggregates detection, TTE, expected/fired BP predicates, and provenance
notes into the same high-level shape as the cited baseline JSONs.

Usage:
    python scripts/build_vulseye_self_run_cited.py
    python scripts/build_vulseye_self_run_cited.py --input results/baselines/vulseye
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import statistics
import sys
from collections import Counter
from datetime import date
from typing import Any, Dict, List


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(REPO, "results", "baselines", "vulseye")
OUT_PATH = os.path.join(REPO, "baselines", "_cited_results", "vulseye_self_run.json")

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

EXPECTED: Dict[str, List[str]] = {
    "nomad": ["BP2"],
    "qubit": ["BP6", "BP1"],
    "multichain": ["BP5"],
    "ronin": ["BP3"],
    "harmony": ["BP3"],
    "wormhole": ["BP4", "BP5"],
    "polynetwork": ["BP5"],
    "pgala": ["BP3", "BP5"],
    "socket": ["BP5"],
    "orbit": ["BP3"],
    "fegtoken": ["BP1"],
    "gempad": ["BP5"],
}


def collect_bridge(results_dir: str, bridge: str) -> Dict[str, Any]:
    expected = sorted(set(EXPECTED.get(bridge, [])))
    bdir = os.path.join(results_dir, bridge)
    runs = sorted(glob.glob(os.path.join(bdir, "run_*.json")))
    if not runs:
        return {
            "detected": False,
            "tte_seconds": None,
            "tte_std": None,
            "runs": 0,
            "predicates_fired": [],
            "predicates_expected": expected,
            "predicate_match": False,
            "note": "no run output (bridge skipped or sweep not run)",
        }

    fired_counter: Counter[str] = Counter()
    detected_count = 0
    ttes: List[float] = []
    target_sources: Counter[str] = Counter()
    zero_coverage_runs = 0
    for path in runs:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        cov = data.get("coverage", {}) or {}
        bb = int(cov.get("basic_blocks_source", 0) or 0) + int(
            cov.get("basic_blocks_dest", 0) or 0
        )
        if bb <= 0:
            zero_coverage_runs += 1
        violations = data.get("violations", []) or []
        if violations:
            detected_count += 1
            times = [
                float(v["detected_at_s"])
                for v in violations
                if v.get("detected_at_s") is not None
            ]
            if times:
                ttes.append(min(times))
        for v in violations:
            inv_id = v.get("invariant_id", "")
            pred = inv_id.split("/", 1)[0] if "/" in inv_id else inv_id
            sd = v.get("state_diff", {}) or {}
            pred = sd.get("pattern_id", pred)
            if isinstance(pred, str) and pred.startswith("BP"):
                fired_counter[pred] += 1
            src = sd.get("target_source")
            if isinstance(src, str) and src:
                target_sources[src] += 1

    fired = sorted(fired_counter.keys())
    expected_set = set(expected)
    match = bool(expected_set & set(fired))
    detected = detected_count > 0
    note_parts = [
        f"{detected_count}/{len(runs)} runs produced VulSEye BP findings",
    ]
    if target_sources:
        note_parts.append(
            "target_sources=" + ",".join(sorted(target_sources.keys()))
        )
    if zero_coverage_runs:
        note_parts.append(f"WARNING: {zero_coverage_runs} run(s) had zero EVM coverage")
    if not match:
        note_parts.append(
            "expected " + ",".join(expected) + "; fired " + (",".join(fired) or "none")
        )

    return {
        "detected": detected,
        "tte_seconds": statistics.median(ttes) if ttes else None,
        "tte_std": statistics.stdev(ttes) if len(ttes) > 1 else (0.0 if ttes else None),
        "runs": len(runs),
        "predicates_fired": fired,
        "predicates_expected": expected,
        "predicate_match": match,
        "note": "; ".join(note_parts),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--input",
        default=RESULTS_DIR,
        help="Directory containing <bridge>/run_*.json outputs.",
    )
    ap.add_argument(
        "--output",
        default=OUT_PATH,
        help="Path for the cited VulSEye self-run JSON.",
    )
    args = ap.parse_args()

    payload: Dict[str, Any] = {
        "tool": "vulseye",
        "tool_type": "stateful_directed_graybox_fuzzer_reimpl",
        "source": (
            "Self-run BridgeSentry VulSEye re-implementation against the "
            "12 benchmark suite, using bridge-specific BP patterns from "
            "docs/REIMPL_VULSEYE_SPEC.md."
        ),
        "doi_or_url": (
            "Original paper: Liang et al., \"Vulseye: Detect Smart Contract "
            "Vulnerabilities via Stateful Directed Graybox Fuzzing\", IEEE "
            "TIFS 2025 — https://arxiv.org/abs/2408.10116"
        ),
        "extraction_date": date.today().isoformat(),
        "methodology_note": (
            "Self-run mode requires real DualEVM coverage. Code targets are "
            "identified from bytecode opcode patterns; when a known bridge "
            "root-cause target is not found by the heuristic, the run may "
            "emit an explicit metadata_seeded BP finding, recorded in each "
            "cell note via target_sources."
        ),
        "results": {},
    }
    for bridge in BRIDGES:
        payload["results"][bridge] = collect_bridge(args.input, bridge)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    detected_n = sum(1 for r in payload["results"].values() if r["detected"])
    matched_n = sum(1 for r in payload["results"].values() if r["predicate_match"])
    print(f"Wrote {os.path.relpath(args.output, REPO)}")
    print(f"  detected:        {detected_n}/12")
    print(f"  predicate_match: {matched_n}/12")
    return 0


if __name__ == "__main__":
    sys.exit(main())
