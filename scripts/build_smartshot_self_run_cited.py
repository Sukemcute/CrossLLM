"""Build baselines/_cited_results/smartshot_self_run.json from run outputs."""

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
DEFAULT_INPUT = os.path.join(REPO, "results", "baselines", "smartshot")
DEFAULT_OUTPUT = os.path.join(
    REPO, "baselines", "_cited_results", "smartshot_self_run.json"
)

EXPECTED: Dict[str, List[str]] = {
    "nomad": ["MS1"],
    "qubit": ["MS2"],
    "multichain": ["MS1"],
    "ronin": ["MS1"],
    "harmony": ["MS1"],
    "wormhole": ["MS1"],
    "polynetwork": ["MS1"],
    "pgala": ["MS1"],
    "socket": ["MS1", "MS2"],
    "orbit": ["MS1"],
    "fegtoken": ["MS1"],
    "gempad": ["MS1"],
}


def collect_bridge(results_dir: str, bridge: str) -> Dict[str, Any]:
    expected = sorted(EXPECTED[bridge])
    paths = sorted(glob.glob(os.path.join(results_dir, bridge, "run_*.json")))
    if not paths:
        return {
            "detected": False,
            "runs": 0,
            "tte_seconds": None,
            "tte_std": None,
            "mutations_fired": [],
            "mutations_expected": expected,
            "predicate_match": False,
            "note": "no run output",
        }

    fired_counter: Counter[str] = Counter()
    ttes: List[float] = []
    detected_count = 0
    sources: Counter[str] = Counter()
    validation: Counter[str] = Counter()
    zero_cov = 0

    for path in paths:
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
            zero_cov += 1
        violations = data.get("violations", []) or []
        if violations:
            detected_count += 1
        for v in violations:
            sd = v.get("state_diff", {}) or {}
            op = sd.get("mutation_operator")
            if isinstance(op, str) and op.startswith("MS"):
                fired_counter[op] += 1
            if v.get("detected_at_s") is not None:
                ttes.append(float(v["detected_at_s"]))
            src = sd.get("taint_source")
            if isinstance(src, str) and src:
                sources[src] += 1
            dv = sd.get("double_validation")
            if isinstance(dv, str) and dv:
                validation[dv] += 1

    fired = sorted(fired_counter)
    match = bool(set(expected) & set(fired))
    note = [f"{detected_count}/{len(paths)} runs produced SmartShot findings"]
    if sources:
        note.append("taint_sources=" + ",".join(sorted(sources)))
    if validation:
        note.append("double_validation=" + ",".join(sorted(validation)))
    if zero_cov:
        note.append(f"WARNING: {zero_cov} run(s) had zero EVM coverage")
    if not match:
        note.append(
            "expected " + ",".join(expected) + "; fired " + (",".join(fired) or "none")
        )

    return {
        "detected": detected_count > 0,
        "runs": len(paths),
        "tte_seconds": statistics.median(ttes) if ttes else None,
        "tte_std": statistics.stdev(ttes) if len(ttes) > 1 else (0.0 if ttes else None),
        "mutations_fired": fired,
        "mutations_expected": expected,
        "predicate_match": match,
        "note": "; ".join(note),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", default=DEFAULT_INPUT)
    ap.add_argument("--output", default=DEFAULT_OUTPUT)
    args = ap.parse_args()

    payload: Dict[str, Any] = {
        "tool": "smartshot",
        "tool_type": "mutable_snapshot_fuzzer_reimpl",
        "source": (
            "Self-run BridgeSentry SmartShot re-implementation against the "
            "12 benchmark suite, using mutable snapshot operators from "
            "docs/REIMPL_SMARTSHOT_SPEC.md."
        ),
        "doi_or_url": "Liu et al., SmartShot, FSE 2025, DOI 10.1145/3715714",
        "extraction_date": date.today().isoformat(),
        "methodology_note": (
            "Self-run mode requires real DualEVM coverage. When SLOAD taint "
            "is unavailable, the reimplementation uses metadata_seeded "
            "bridge root-cause slots and records that provenance per finding."
        ),
        "results": {},
    }
    for bridge in EXPECTED:
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
