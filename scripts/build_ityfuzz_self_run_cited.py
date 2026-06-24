#!/usr/bin/env python3
"""Aggregate ItyFuzz self-run results into the cited-style JSON for RQ1.

Reads `results/baselines/ityfuzz/<bridge>/run_NNN.json` produced by
`baselines/ityfuzz/adapter.sh`, computes per-bridge detection rate +
instruction/branch coverage extracted from raw fuzzer logs, and writes
`baselines/_cited_results/ityfuzz_self_run.json`.

Defensive against:
- JSON files with embedded ANSI escape codes in stderr_excerpt (pre-patch
  adapter runs) — uses tolerant parsing that strips control chars.
- Missing raw_output_path — falls back to JSON-only stats.
"""
from __future__ import annotations

import glob
import json
import os
import re
import statistics
import sys
from collections import Counter
from pathlib import Path

BRIDGES = [
    "nomad", "qubit", "pgala", "polynetwork", "wormhole", "socket",
    "ronin", "harmony", "multichain", "orbit", "fegtoken", "gempad",
]

REPO_ROOT = Path(__file__).resolve().parent.parent

ANSI_RE = re.compile(rb"\x1b\[[0-9;]*[a-zA-Z]")
CTRL_RE = re.compile(rb"[\x00-\x08\x0b\x0c\x0e-\x1f]")
COV_LINE_RE = re.compile(
    r"(0x[0-9a-fA-F]{40}): ([\d.]+)% Instruction Covered, ([\d.]+)% Branch Covered"
)


def load_json_tolerant(path: Path) -> dict | None:
    """Load JSON, stripping ANSI + control chars if needed (pre-patch runs)."""
    try:
        return json.loads(path.read_text())
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    raw = path.read_bytes()
    cleaned = CTRL_RE.sub(b"?", ANSI_RE.sub(b"", raw))
    try:
        return json.loads(cleaned.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        print(f"  WARN: {path}: {e}", file=sys.stderr)
        return None


def parse_coverage_from_raw(raw_path: Path) -> dict[str, dict]:
    """Extract last `Coverage Summary` block per address from raw fuzz log."""
    coverage: dict[str, dict] = {}
    try:
        text = raw_path.read_text(errors="replace")
    except FileNotFoundError:
        return coverage
    for m in COV_LINE_RE.finditer(text):
        addr, inst, branch = m.group(1).lower(), float(m.group(2)), float(m.group(3))
        coverage[addr] = {"instruction_pct": inst, "branch_pct": branch}
    return coverage


def build(results_dir: Path, out_path: Path) -> dict:
    per_bridge: dict[str, dict] = {}
    detected_bridges = 0

    for bridge in BRIDGES:
        files = sorted((results_dir / bridge).glob("run_[0-9][0-9][0-9].json"))
        detected_runs = 0
        ttes: list[float] = []
        wall_clocks: list[float] = []
        objective_ids: Counter[str] = Counter()
        cov_inst_all: list[float] = []
        cov_branch_all: list[float] = []

        for f in files:
            doc = load_json_tolerant(f)
            if doc is None:
                continue
            if doc.get("detected"):
                detected_runs += 1
                if doc.get("tte_seconds") is not None:
                    ttes.append(float(doc["tte_seconds"]))
                for v in doc.get("violations", []):
                    objective_ids[v.get("id", "unknown")] += 1
            stats = doc.get("stats") or {}
            if stats.get("wall_clock_s") is not None:
                wall_clocks.append(float(stats["wall_clock_s"]))
            # Pull coverage from co-located raw log
            raw = f.with_name(f"{f.stem}.raw.txt")
            cov = parse_coverage_from_raw(raw)
            for addr_data in cov.values():
                cov_inst_all.append(addr_data["instruction_pct"])
                cov_branch_all.append(addr_data["branch_pct"])

        per_bridge[bridge] = {
            "detected": detected_runs > 0,
            "runs": len(files),
            "detected_runs": detected_runs,
            "detection_rate": f"{detected_runs}/{len(files)}" if files else "0/0",
            "tte_seconds": statistics.mean(ttes) if ttes else None,
            "wall_clock_s_mean": statistics.mean(wall_clocks) if wall_clocks else None,
            "mean_instruction_cov_pct": (
                statistics.mean(cov_inst_all) if cov_inst_all else None
            ),
            "mean_branch_cov_pct": (
                statistics.mean(cov_branch_all) if cov_branch_all else None
            ),
            "objectives_top": dict(objective_ids.most_common(5)),
            "note": (
                f"ItyFuzz onchain mode on {len(files)} runs × 660s budget; "
                f"{detected_runs} runs triggered oracle"
            ),
        }
        if detected_runs > 0:
            detected_bridges += 1

    summary = {
        "tool": "ityfuzz",
        "tool_type": "stateful_evm_fuzzer_self_run",
        "source": (
            "Self-run ItyFuzz (fuzzland/ityfuzz, commit 80e3b44170...) against "
            "the 12 benchmark suite via baselines/ityfuzz/adapter.sh onchain mode."
        ),
        "doi_or_url": "Shou et al., ItyFuzz, ISSTA 2023 — arxiv 2306.17135",
        "extraction_date": os.environ.get("EXTRACTION_DATE", "2026-06-08"),
        "methodology_note": (
            "Onchain mode: forks at metadata fork_block_number, fetches ABI "
            "via Etherscan. Default detectors = high_confidence. Budget 660s "
            "per run (paper convention). Detected if any oracle/objective "
            "triggered (grep heuristic on fuzzer log)."
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
    results_dir = REPO_ROOT / "results" / "baselines" / "ityfuzz"
    out_path = REPO_ROOT / "baselines" / "_cited_results" / "ityfuzz_self_run.json"
    if len(sys.argv) > 1:
        results_dir = Path(sys.argv[1])

    summary = build(results_dir, out_path)
    print(f"Wrote {out_path}")
    print(f"  detected_bridges: {summary['detection_summary']['detected_bridges']}/12")
    print(f"  bridge           runs  detect   mean_inst_cov  mean_branch_cov")
    print(f"  ------           ----  ------   -------------  ---------------")
    for bridge, r in summary["results"].items():
        inst = f"{r['mean_instruction_cov_pct']:.2f}%" if r["mean_instruction_cov_pct"] else "n/a"
        branch = f"{r['mean_branch_cov_pct']:.2f}%" if r["mean_branch_cov_pct"] else "n/a"
        verdict = "DETECTED" if r["detected"] else "clean"
        print(
            f"  {bridge:15s}  {r['runs']:4d}  {verdict:9s} {inst:>13s}  {branch:>15s}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
