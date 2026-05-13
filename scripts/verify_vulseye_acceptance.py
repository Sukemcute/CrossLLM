"""Acceptance verifier for the VulSEye re-implementation.

Reads ``results/baselines/vulseye/<bridge>/run_smoke.json`` (or
``run_*.json`` when smoke output is absent) and checks that each bridge
hits at least one bridge-specific BP pattern predicted by
``docs/REIMPL_VULSEYE_SPEC.md``.

Usage:
    python scripts/verify_vulseye_acceptance.py results/baselines/vulseye
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Set


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


def run_files_for(bridge_dir: str) -> List[str]:
    smoke = os.path.join(bridge_dir, "run_smoke.json")
    if os.path.exists(smoke):
        return [smoke]
    return sorted(glob.glob(os.path.join(bridge_dir, "run_*.json")))


def collect_patterns(paths: List[str]) -> tuple[Set[str], int, List[str]]:
    fired: Set[str] = set()
    total_bb = 0
    sources: Set[str] = set()
    for path in paths:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        cov = data.get("coverage", {}) or {}
        total_bb += int(cov.get("basic_blocks_source", 0) or 0)
        total_bb += int(cov.get("basic_blocks_dest", 0) or 0)
        for v in data.get("violations", []) or []:
            inv_id = v.get("invariant_id", "")
            pred = inv_id.split("/", 1)[0] if "/" in inv_id else inv_id
            if pred.startswith("BP"):
                fired.add(pred)
            sd = v.get("state_diff", {}) or {}
            p = sd.get("pattern_id")
            if isinstance(p, str) and p.startswith("BP"):
                fired.add(p)
            src = sd.get("target_source")
            if isinstance(src, str) and src:
                sources.add(src)
    return fired, total_bb, sorted(sources)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("outdir", help="results dir containing <bridge>/run_smoke.json")
    ap.add_argument("--bar", type=int, default=11, help="passing bridges required")
    ap.add_argument(
        "--summary",
        default=str(
            Path("docs")
            / "baseline_vulseye_artifacts"
            / "vulseye_smoke_acceptance.json"
        ),
        help="summary JSON path",
    )
    args = ap.parse_args()

    rows = []
    passing = 0
    for bridge, expected in EXPECTED.items():
        paths = run_files_for(os.path.join(args.outdir, bridge))
        fired, total_bb, sources = collect_patterns(paths)
        expected_set = set(expected)
        matched = sorted(fired & expected_set)
        passed = bool(matched) and total_bb > 0
        if passed:
            passing += 1
        rows.append(
            {
                "bridge": bridge,
                "expected": sorted(expected_set),
                "fired": sorted(fired),
                "matched": matched,
                "missed": sorted(expected_set - fired),
                "basic_blocks_total": total_bb,
                "target_sources": sources,
                "runs": len(paths),
                "passed": passed,
            }
        )

    print(f"{'bridge':12} {'expected':12} {'fired':18} {'bb':>7} {'sources':28} verdict")
    print("-" * 92)
    for r in rows:
        print(
            f"{r['bridge']:12} {','.join(r['expected']):12} "
            f"{','.join(r['fired']) or '-':18} {r['basic_blocks_total']:7} "
            f"{','.join(r['target_sources'])[:28]:28} "
            f"{'PASS' if r['passed'] else 'FAIL'}"
        )

    overall = passing >= args.bar
    payload = {
        "bar": args.bar,
        "passing": passing,
        "total": len(rows),
        "overall_pass": overall,
        "rows": rows,
    }
    summary_path = Path(args.summary)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    print()
    print(f"Bridges passing: {passing}/{len(rows)}  (acceptance bar: {args.bar}/{len(rows)})")
    print(f"Summary written to {summary_path}")
    print("VULSEYE ACCEPTANCE: " + ("PASS" if overall else "FAIL"))
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
