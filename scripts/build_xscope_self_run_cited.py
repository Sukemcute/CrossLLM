"""X6 — Build the self-run version of `baselines/_cited_results/xscope.json`.

Reads every `results/baselines/xscope/<bridge>/run_NNN.json` produced by
the X5 sweep and aggregates them into a per-bridge `detected` flag +
predicate list + run statistics. Schema mirrors the cited version so
the RQ1 aggregator can swap them transparently.

Idempotent. Re-run after every sweep to pick up new runs.

Usage:
    python scripts/build_xscope_self_run_cited.py
"""

from __future__ import annotations

import glob
import json
import os
import sys
from collections import Counter
from typing import Any, Dict, List

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(REPO, "results", "baselines", "xscope")
OUT_PATH = os.path.join(
    REPO, "baselines", "_cited_results", "xscope_self_run.json"
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

# Spec §4 expected predicate map — same as verify_xscope_acceptance.py
EXPECTED: Dict[str, List[str]] = {
    "nomad": ["I-6"],
    "ronin": ["I-6"],
    "harmony": ["I-6"],
    "wormhole": ["I-5", "I-6"],
    "polynetwork": ["I-5", "I-6"],
    "pgala": ["I-3", "I-4", "I-6"],
    "socket": ["I-1", "I-5"],
    "orbit": ["I-6"],
    "multichain": ["I-5"],
    "gempad": ["I-5"],
    "fegtoken": ["I-1", "I-5"],
    "qubit": ["I-2"],
}


def collect_bridge(bridge: str) -> Dict[str, Any]:
    bdir = os.path.join(RESULTS_DIR, bridge)
    if not os.path.isdir(bdir):
        return {
            "detected": False,
            "tte_seconds": None,
            "tte_std": None,
            "runs": 0,
            "predicates_fired": [],
            "predicates_expected": EXPECTED.get(bridge, []),
            "predicate_match": False,
            "note": "no run output (bridge skipped or sweep not run)",
        }

    runs = sorted(glob.glob(os.path.join(bdir, "run_*.json")))
    if not runs:
        return {
            "detected": False,
            "tte_seconds": None,
            "tte_std": None,
            "runs": 0,
            "predicates_fired": [],
            "predicates_expected": EXPECTED.get(bridge, []),
            "predicate_match": False,
            "note": "no run_*.json artifacts",
        }

    fired_counter: Counter = Counter()
    detected_count = 0
    for run_path in runs:
        try:
            with open(run_path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        violations = data.get("violations", [])
        if violations:
            detected_count += 1
        for v in violations:
            inv_id = v.get("invariant_id", "")
            pred = inv_id.split("/", 1)[0] if "/" in inv_id else inv_id
            if pred.startswith("I-"):
                fired_counter[pred] += 1

    n = len(runs)
    fired_set = sorted(fired_counter.keys())
    expected_set = set(EXPECTED.get(bridge, []))
    match = bool(expected_set & set(fired_set))  # any-of rule

    detected = detected_count > 0
    note_parts: List[str] = []
    if detected:
        note_parts.append(
            f"replay-mode: {detected_count}/{n} runs flagged "
            f"(deterministic — same input each run)"
        )
    if not match and fired_set:
        note_parts.append(
            f"fired {','.join(fired_set)} but expected "
            f"{','.join(EXPECTED.get(bridge, []))} — "
            "predicate-class mismatch (see X4 outcome doc)"
        )
    if not fired_set:
        note_parts.append("no predicate fired (replay-side empty / SKIP)")

    return {
        "detected": detected,
        "tte_seconds": None,  # XScope is a per-tx classifier, not a fuzzer
        "tte_std": None,
        "runs": n,
        "predicates_fired": fired_set,
        "predicates_expected": sorted(expected_set),
        "predicate_match": match,
        "note": "; ".join(note_parts) or "—",
    }


def main() -> int:
    payload: Dict[str, Any] = {
        "tool": "xscope",
        "tool_type": "rule_based_detector",
        "source": (
            "Self-run replay of XScope re-implementation against "
            "BridgeSentry's 12 benchmarks. See "
            "docs/REIMPL_XSCOPE_X4_OUTCOME.md for per-bridge "
            "trajectory (0/12 → 10/12 PASS via 5 X3-polish phases)."
        ),
        "doi_or_url": (
            "Original paper: Zhang et al., \"Xscope: Hunting for "
            "Cross-Chain Bridge Attacks\", ASE 2022 — "
            "https://arxiv.org/abs/2208.07119"
        ),
        "extraction_date": "2026-05-01",
        "methodology_note": (
            "Replay-mode: cached on-chain exploit transactions are "
            "dispatched through revm against a fork at "
            "(exploit_block - 1). XScope's six predicates I-1..I-6 "
            "evaluate against the resulting view. The acceptance rule "
            "is any-of: a bridge passes if at least one predicate "
            "from its spec §4 expected set fires. TTE is undefined "
            "for replay-mode XScope (it's a deterministic per-tx "
            "classifier, not a fuzz loop with time-to-find). The 11 "
            "ETH/BSC bridges run end-to-end; Wormhole is "
            "cite-published because its source side is Solana."
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
    print(f"  detected (any predicate fired): {detected_n}/12")
    print(f"  matched (any-of expected):       {matched_n}/12")
    return 0


if __name__ == "__main__":
    sys.exit(main())
