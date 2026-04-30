"""Acceptance verifier for the XScope re-implementation (X4).

Reads a directory of `<outdir>/<bridge>/run_*.json` files produced by
running ``bridgesentry-fuzzer --baseline-mode xscope`` on each of our
12 benchmarks, then matches the predicates that fired against the
per-bridge expected map in
``docs/REIMPL_XSCOPE_SPEC.md`` §4. Acceptance bar (per spec): ≥ 11/12
bridges must hit at least one of their predicted predicates.

Usage:
    python3 scripts/verify_xscope_acceptance.py <outdir>
        [--strict]    # require *all* predicted predicates per bridge,
                       # not just at least one (default: any-of).

The expected map below is a verbatim transcription of the spec §4
table; any change to the spec must be reflected here so the verifier
remains the source of truth for X4 acceptance.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Set


# Per-bridge predicted predicate(s). At least one must fire for the
# bridge to count as "hit" in any-of mode (default). In strict mode,
# **all** listed predicates must fire.
EXPECTED_PREDICATES: Dict[str, List[str]] = {
    "nomad": ["I-6"],                       # zero-root acceptance
    "qubit": ["I-2"],                       # recipient zero (or I-1 mint without lock)
    "multichain": ["I-5"],                  # MPC compromise -> no source ancestor
    "ronin": ["I-6"],                       # multisig under threshold
    "harmony": ["I-6"],                     # multisig leaked
    "wormhole": ["I-5", "I-6"],             # signature replay on forged VAA
    "polynetwork": ["I-5", "I-6"],          # keeper rotation -> arbitrary unlock
    "pgala": ["I-3", "I-4", "I-6"],         # validator re-registration
    "socket": ["I-1", "I-5"],               # unauth transferFrom
    "orbit": ["I-6"],                       # MPC threshold
    "fegtoken": ["I-1", "I-5"],             # migrator mint without lock
    "gempad": ["I-5"],                      # transferLockOwnership drain
}


def collect_predicates(run_files: List[str]) -> Set[str]:
    """Read all run_*.json for one bridge and return the set of
    predicate ids ('I-1' .. 'I-6') that fired across them."""
    fired: Set[str] = set()
    for path in run_files:
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        for v in data.get("violations", []):
            inv_id = v.get("invariant_id", "")
            # Format from run_xscope (X3): "<I-N>/<C-class>"
            if "/" in inv_id:
                pred = inv_id.split("/", 1)[0]
            else:
                pred = inv_id
            if pred.startswith("I-"):
                fired.add(pred)
    return fired


def verify_bridge(
    bridge: str, fired: Set[str], expected: List[str], strict: bool
) -> Dict[str, object]:
    """One row of the verification table."""
    expected_set = set(expected)
    matched = fired & expected_set
    if strict:
        passed = expected_set.issubset(fired)
        rule = "strict (all predicted)"
    else:
        passed = bool(matched)
        rule = "any-of"
    return {
        "bridge": bridge,
        "expected": sorted(expected_set),
        "fired": sorted(fired),
        "matched": sorted(matched),
        "missed": sorted(expected_set - fired),
        "extra": sorted(fired - expected_set),
        "passed": passed,
        "rule": rule,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("outdir", help="results dir containing <bridge>/run_*.json")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="require ALL predicted predicates per bridge, not just any-of",
    )
    ap.add_argument(
        "--bar",
        type=int,
        default=11,
        help="number of bridges that must pass (default 11/12 per spec §4)",
    )
    args = ap.parse_args()

    rows: List[Dict[str, object]] = []
    for bridge, expected in EXPECTED_PREDICATES.items():
        bridge_dir = os.path.join(args.outdir, bridge)
        run_files = sorted(glob.glob(os.path.join(bridge_dir, "run_*.json")))
        if not run_files:
            rows.append(
                {
                    "bridge": bridge,
                    "expected": expected,
                    "fired": [],
                    "matched": [],
                    "missed": expected,
                    "extra": [],
                    "passed": False,
                    "rule": "missing-results",
                }
            )
            continue
        fired = collect_predicates(run_files)
        rows.append(verify_bridge(bridge, fired, expected, args.strict))

    # ----- Print per-bridge table -----
    print(
        f"{'bridge':12} {'expected':18} {'fired':22} {'matched':14} "
        f"{'missed':14} {'rule':18} verdict"
    )
    print("-" * 110)
    pass_count = 0
    for r in rows:
        verdict = "PASS" if r["passed"] else "FAIL"
        if r["passed"]:
            pass_count += 1
        print(
            f"{r['bridge']:12} {','.join(r['expected']):18} "
            f"{','.join(r['fired']) or '—':22} "
            f"{','.join(r['matched']) or '—':14} "
            f"{','.join(r['missed']) or '—':14} "
            f"{r['rule']:18} {verdict}"
        )

    total = len(rows)
    print()
    print(f"Bridges passing: {pass_count}/{total}  (acceptance bar: {args.bar}/{total})")
    overall_pass = pass_count >= args.bar

    # ----- JSON summary written next to outdir for the LaTeX pipeline -----
    summary_path = os.path.join(args.outdir, "_x4_verification.json")
    try:
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "rule": "strict" if args.strict else "any-of",
                    "bar": args.bar,
                    "passing": pass_count,
                    "total": total,
                    "overall_pass": overall_pass,
                    "rows": rows,
                },
                f,
                indent=2,
            )
        print(f"Summary written to {summary_path}")
    except OSError as exc:
        print(f"WARNING: could not write summary JSON: {exc}", file=sys.stderr)

    print()
    print("X4 ACCEPTANCE: " + ("PASS" if overall_pass else "FAIL"))
    return 0 if overall_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
