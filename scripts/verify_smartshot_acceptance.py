"""Verify SmartShot smoke acceptance over the 12 bridge benchmarks."""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import Any, Dict, List, Set


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


def load_bridge_run(base: str, bridge: str) -> tuple[str | None, Dict[str, Any] | None]:
    smoke = os.path.join(base, bridge, "run_smoke.json")
    candidates = [smoke] if os.path.exists(smoke) else []
    candidates.extend(sorted(glob.glob(os.path.join(base, bridge, "run_*.json"))))
    for path in candidates:
        if path.endswith(".log"):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                return path, json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
    return None, None


def fired_mutations(data: Dict[str, Any]) -> Set[str]:
    fired: Set[str] = set()
    for violation in data.get("violations", []) or []:
        state_diff = violation.get("state_diff", {}) or {}
        op = state_diff.get("mutation_operator")
        if not op:
            inv = violation.get("invariant_id", "")
            op = inv.split("/", 1)[0] if "/" in inv else inv
        if isinstance(op, str) and op.startswith("MS"):
            if str(state_diff.get("predicate_match", "false")).lower() == "true":
                fired.add(op)
    return fired


def basic_blocks(data: Dict[str, Any]) -> int:
    coverage = data.get("coverage", {}) or {}
    return int(coverage.get("basic_blocks_source", 0) or 0) + int(
        coverage.get("basic_blocks_dest", 0) or 0
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results_dir", nargs="?", default="results/baselines/smartshot")
    ap.add_argument("--bar", type=int, default=11)
    ap.add_argument(
        "--summary",
        default="docs/baseline_smartshot_artifacts/smartshot_smoke_acceptance.json",
    )
    args = ap.parse_args()

    rows = []
    passed = 0
    for bridge, expected in EXPECTED.items():
        path, data = load_bridge_run(args.results_dir, bridge)
        if data is None:
            rows.append(
                {
                    "bridge": bridge,
                    "expected": expected,
                    "fired": [],
                    "basic_blocks": 0,
                    "source": path,
                    "pass": False,
                    "reason": "missing_or_malformed_run_json",
                }
            )
            continue
        fired = sorted(fired_mutations(data))
        bb = basic_blocks(data)
        ok = bool(set(expected) & set(fired)) and bb > 0
        passed += int(ok)
        rows.append(
            {
                "bridge": bridge,
                "expected": expected,
                "fired": fired,
                "basic_blocks": bb,
                "source": path,
                "pass": ok,
                "reason": "ok" if ok else "missing_expected_mutation_or_real_coverage",
            }
        )

    os.makedirs(os.path.dirname(args.summary), exist_ok=True)
    payload = {
        "tool": "smartshot",
        "acceptance_bar": args.bar,
        "passed": passed,
        "total": len(EXPECTED),
        "pass": passed >= args.bar,
        "bridges": rows,
    }
    with open(args.summary, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    print(f"{'bridge':12} {'expected':12} {'fired':18} {'bb':8} verdict")
    print("-" * 70)
    for row in rows:
        print(
            f"{row['bridge']:12} {','.join(row['expected']):12} "
            f"{','.join(row['fired']) or '-':18} {row['basic_blocks']:<8} "
            f"{'PASS' if row['pass'] else 'FAIL'}"
        )
    print(f"\nBridges passing: {passed}/{len(EXPECTED)}  (bar: {args.bar}/12)")
    print(f"Summary written to {args.summary}")
    return 0 if passed >= args.bar else 1


if __name__ == "__main__":
    sys.exit(main())
