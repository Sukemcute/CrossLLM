#!/usr/bin/env python3
"""Aggregate GPTScan self-run results into the cited-style JSON for RQ1.

Reads `results/baselines/gptscan/<bridge>/run_NNN.json` produced by
`baselines/gptscan/adapter.sh`, computes per-bridge detection rate +
top violation IDs, and writes `baselines/_cited_results/gptscan_self_run.json`.
"""
from __future__ import annotations

import glob
import json
import os
import statistics
import sys
from collections import Counter
from pathlib import Path

BRIDGES = [
    "nomad", "qubit", "pgala", "polynetwork", "wormhole", "socket",
    "ronin", "harmony", "multichain", "orbit", "fegtoken", "gempad",
]

REPO_ROOT = Path(__file__).resolve().parent.parent


def build(results_dir: Path, out_path: Path) -> dict:
    per_bridge: dict[str, dict] = {}
    detected_bridges = 0

    for bridge in BRIDGES:
        files = sorted((results_dir / bridge).glob("run_[0-9][0-9][0-9].json"))
        detected_runs = 0
        violations_counter: Counter[str] = Counter()
        ttes: list[float] = []

        for f in files:
            try:
                doc = json.loads(f.read_text())
            except json.JSONDecodeError:
                continue
            if doc.get("detected"):
                detected_runs += 1
                ttes.append(float(doc.get("tte_seconds") or 0))
                for v in doc.get("violations", []):
                    violations_counter[v.get("id", "unknown")] += 1

        per_bridge[bridge] = {
            "detected": detected_runs > 0,
            "runs": len(files),
            "detected_runs": detected_runs,
            "detection_rate": f"{detected_runs}/{len(files)}" if files else "0/0",
            "tte_seconds": statistics.mean(ttes) if ttes else 0.0,
            "violations_top": dict(violations_counter.most_common(5)),
            "note": (
                f"GPTScan 10 DeFi rules on {len(files)} runs; "
                f"{detected_runs} runs flagged"
            ),
        }
        if detected_runs > 0:
            detected_bridges += 1

    summary = {
        "tool": "gptscan",
        "tool_type": "llm_static_reimpl",
        "source": (
            "Self-run BridgeSentry GPTScan adapter against the 12 benchmark "
            "suite via NVIDIA NIM gpt-oss-120b."
        ),
        "doi_or_url": (
            "Sun et al., GPTScan: Detecting Logic Vulnerabilities in Smart "
            "Contracts by Combining GPT with Program Analysis, ICSE 2024"
        ),
        "extraction_date": os.environ.get("EXTRACTION_DATE", "2026-06-06"),
        "methodology_note": (
            "GPTScan 10 DeFi rules (Flashloan_*, Slippage, ApprovalNotClear, "
            "FrontRun, UnauthorizedTransfer, WrongOrder_*, FirstDeposit) "
            "applied per .sol file via adapter loop. Detected if any rule "
            "fires on any contract. Model: openai/gpt-oss-120b via NVIDIA NIM "
            "(OpenAI-compatible endpoint)."
        ),
        "detection_summary": {
            "detected_bridges": detected_bridges,
            "total_bridges": len(BRIDGES),
        },
        "results": per_bridge,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))
    return summary


def main() -> int:
    results_dir = REPO_ROOT / "results" / "baselines" / "gptscan"
    out_path = REPO_ROOT / "baselines" / "_cited_results" / "gptscan_self_run.json"
    if len(sys.argv) > 1:
        results_dir = Path(sys.argv[1])

    summary = build(results_dir, out_path)
    print(f"Wrote {out_path}")
    print(f"  detected_bridges: {summary['detection_summary']['detected_bridges']}/12")
    for bridge, r in summary["results"].items():
        verdict = "DETECTED" if r["detected"] else "clean"
        print(f"  {bridge:12s}  {r['detection_rate']:7s}  {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
