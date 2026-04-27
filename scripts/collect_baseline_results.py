"""
BridgeSentry — Baseline Comparison Aggregator (Phase D2 of paper experiments)

Merges:
- BridgeSentry results from results/<bridge>/run_*.json (Phase D1)
- Self-run baseline results from results/baselines/<tool>/<bridge>/run_*.json
- Cited published results from baselines/_cited_results/<tool>.json

Outputs an RQ1 comparison table matching paper §5.3 format:

    Sự cố       BridgeSentry  ItyFuzz  SmartShot  VulSEye  SmartAxe  GPTScan  XScope
    PolyNetwork ✓ (36±8s)     ✗        ✓ (41±12s) ✓(55±18s) ✓        ✓        ✓
    ...

Usage:
    python scripts/collect_baseline_results.py                    # console table
    python scripts/collect_baseline_results.py --format latex     # LaTeX table for paper
    python scripts/collect_baseline_results.py --format csv > rq1.csv
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path

BENCHMARKS = [
    "polynetwork",
    "wormhole",
    "ronin",
    "nomad",
    "harmony",
    "multichain",
    "socket",
    "orbit",
    "gempad",
    "fegtoken",
    "pgala",
    "qubit",
]

BASELINE_TOOLS = [
    "ityfuzz",
    "smartshot",
    "vulseye",
    "smartaxe",
    "gptscan",
    "xscope",
]


def load_runs(d: Path) -> list[dict]:
    """Load all run_*.json files from a directory."""
    if not d.is_dir():
        return []
    runs = []
    for f in sorted(d.glob("run_*.json")):
        try:
            with open(f) as fp:
                runs.append(json.load(fp))
        except Exception as exc:
            print(f"WARN: failed to parse {f}: {exc}")
    return runs


def aggregate_runs(runs: list[dict]) -> dict:
    """Compute DR + TTE (median ± std) from a list of run dicts."""
    if not runs:
        return {"detected": None, "n_runs": 0, "tte_median": None, "tte_std": None,
                "source": "no_data"}
    n = len(runs)
    detections = [r for r in runs if r.get("detected") is True]
    detection_rate = len(detections) / n if n else 0.0

    ttes = [r.get("tte_seconds") for r in detections if r.get("tte_seconds") not in (None, "null")]
    ttes = [float(t) for t in ttes if t is not None]
    if ttes:
        tte_median = statistics.median(ttes)
        tte_std = statistics.stdev(ttes) if len(ttes) > 1 else 0.0
    else:
        tte_median = None
        tte_std = None

    return {
        "detected": detection_rate >= 0.5,  # majority rule
        "detection_rate": detection_rate,
        "n_runs": n,
        "n_detections": len(detections),
        "tte_median": tte_median,
        "tte_std": tte_std,
        "source": "self_run",
    }


def load_cited(tool: str, project_root: Path) -> dict:
    """Load cited results JSON; returns {bridge: cell_dict}."""
    f = project_root / "baselines" / "_cited_results" / f"{tool}.json"
    if not f.exists():
        return {}
    try:
        with open(f) as fp:
            data = json.load(fp)
        return data.get("results", {}) or {}
    except Exception as exc:
        print(f"WARN: failed to parse cited {f}: {exc}")
        return {}


def cell_for(tool: str, bridge: str, project_root: Path) -> dict:
    """Resolve a single cell of the RQ1 table for (tool, bridge).

    Priority: self-run results > cited published > unknown.
    """
    self_run_dir = project_root / "results" / "baselines" / tool / bridge
    runs = load_runs(self_run_dir)
    if runs:
        agg = aggregate_runs(runs)
        agg["tool"] = tool
        agg["bridge"] = bridge
        return agg

    cited = load_cited(tool, project_root)
    if bridge in cited and cited[bridge].get("detected") is not None:
        c = cited[bridge]
        return {
            "tool": tool,
            "bridge": bridge,
            "detected": c.get("detected"),
            "detection_rate": 1.0 if c.get("detected") else 0.0,
            "tte_median": c.get("tte_seconds"),
            "tte_std": c.get("tte_std"),
            "n_runs": 1,
            "source": "cited",
            "note": c.get("note", ""),
        }

    return {
        "tool": tool,
        "bridge": bridge,
        "detected": None,
        "tte_median": None,
        "source": "unknown",
    }


def bridgesentry_cell(bridge: str, project_root: Path) -> dict:
    """Aggregate BridgeSentry results from results/<bridge>/run_*.json.

    BridgeSentry's schema differs from the baseline schema: detection
    is implicit in the `violations` array (non-empty = detected), and
    TTE comes from the earliest `detected_at_s` across that array.
    """
    runs_dir = project_root / "results" / bridge
    runs = load_runs(runs_dir)
    if not runs:
        return {"tool": "bridgesentry", "bridge": bridge, "detected": None, "source": "no_data"}

    n = len(runs)
    detections = [r for r in runs if (r.get("violations") or [])]
    detection_rate = len(detections) / n if n else 0.0

    ttes = []
    for r in detections:
        viol_times = [
            v.get("detected_at_s")
            for v in (r.get("violations") or [])
            if v.get("detected_at_s") is not None
        ]
        if viol_times:
            ttes.append(min(viol_times))

    if ttes:
        tte_median = statistics.median(ttes)
        tte_std = statistics.stdev(ttes) if len(ttes) > 1 else 0.0
    else:
        tte_median = None
        tte_std = None

    return {
        "tool": "bridgesentry",
        "bridge": bridge,
        "detected": detection_rate >= 0.5,
        "detection_rate": detection_rate,
        "n_runs": n,
        "n_detections": len(detections),
        "tte_median": tte_median,
        "tte_std": tte_std,
        "source": "self_run",
    }


def format_tte(c: dict) -> str:
    if c.get("source") == "no_data":
        return "—"
    if c.get("source") == "unknown":
        return "n/a"
    if c.get("detected") is None:
        return "n/a"
    if c.get("detected") is False:
        return "—"
    med = c.get("tte_median")
    std = c.get("tte_std")
    if med is None:
        return "✓"
    if std is None or std == 0:
        return f"✓ ({med:.1f}s)"
    if med < 1:
        return f"✓ ({med:.4f}±{std:.4f}s)"
    return f"✓ ({med:.0f}±{std:.0f}s)"


def cell_repr(c: dict) -> str:
    """Convert cell to a single-string rendering for table output."""
    detected = c.get("detected")
    if detected is None:
        return "n/a" if c.get("source") == "unknown" else "—"
    if detected is False:
        return "✗"
    return format_tte(c)


def print_table(project_root: Path):
    """Console-friendly table."""
    header = ["Bridge", "BridgeSentry"] + [t.title() for t in BASELINE_TOOLS]
    rows = []
    for b in BENCHMARKS:
        row = [b]
        row.append(cell_repr(bridgesentry_cell(b, project_root)))
        for t in BASELINE_TOOLS:
            row.append(cell_repr(cell_for(t, b, project_root)))
        rows.append(row)

    widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
    sep = "  ".join("-" * w for w in widths)

    def fmt_row(r):
        return "  ".join(f"{str(r[i]):<{widths[i]}}" for i in range(len(r)))

    print()
    print("=" * (sum(widths) + 2 * (len(widths) - 1)))
    print("  RQ1 Comparison — paper §5.3")
    print("=" * (sum(widths) + 2 * (len(widths) - 1)))
    print(fmt_row(header))
    print(sep)
    for row in rows:
        print(fmt_row(row))
    print(sep)


def print_latex(project_root: Path):
    """LaTeX table — paste into paper.tex."""
    print(r"% Auto-generated by scripts/collect_baseline_results.py")
    print(r"\begin{table}[t]")
    print(r"\caption{RQ1 — Detection rate and time-to-exploit across bridge benchmarks.}")
    print(r"\label{tab:rq1}")
    cols = "l" + "c" * (len(BASELINE_TOOLS) + 1)
    print(r"\begin{tabular}{" + cols + r"}")
    print(r"\toprule")
    headers = ["Bridge", "BridgeSentry"] + [t.title() for t in BASELINE_TOOLS]
    print(" & ".join(headers) + r" \\")
    print(r"\midrule")
    for b in BENCHMARKS:
        cells = [b.replace("_", r"\_")]
        cells.append(cell_repr(bridgesentry_cell(b, project_root)).replace("✓", r"$\checkmark$").replace("✗", r"$\times$"))
        for t in BASELINE_TOOLS:
            cells.append(cell_repr(cell_for(t, b, project_root)).replace("✓", r"$\checkmark$").replace("✗", r"$\times$"))
        print(" & ".join(cells) + r" \\")
    print(r"\bottomrule")
    print(r"\end{tabular}")
    print(r"\end{table}")


def print_csv(project_root: Path):
    import csv, sys
    w = csv.writer(sys.stdout)
    w.writerow(["bridge", "bridgesentry"] + BASELINE_TOOLS)
    for b in BENCHMARKS:
        row = [b, cell_repr(bridgesentry_cell(b, project_root))]
        for t in BASELINE_TOOLS:
            row.append(cell_repr(cell_for(t, b, project_root)))
        w.writerow(row)


def print_json(project_root: Path):
    import sys
    out = {"benchmarks": {}, "tools": ["bridgesentry"] + BASELINE_TOOLS}
    for b in BENCHMARKS:
        cell = {"bridgesentry": bridgesentry_cell(b, project_root)}
        for t in BASELINE_TOOLS:
            cell[t] = cell_for(t, b, project_root)
        out["benchmarks"][b] = cell
    json.dump(out, sys.stdout, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(description="Collect RQ1 baseline comparison")
    parser.add_argument("--format", choices=["table", "latex", "csv", "json"],
                        default="table", help="Output format")
    parser.add_argument("--project-root", type=str,
                        default=str(Path(__file__).resolve().parent.parent),
                        help="Repository root (for results/ and baselines/ paths)")
    args = parser.parse_args()

    project_root = Path(args.project_root)
    if args.format == "table":
        print_table(project_root)
    elif args.format == "latex":
        print_latex(project_root)
    elif args.format == "csv":
        print_csv(project_root)
    elif args.format == "json":
        print_json(project_root)


if __name__ == "__main__":
    main()
