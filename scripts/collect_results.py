"""
BridgeSentry — Experiment Metrics Collector
Follows experiment_guide.html Section 8.3 + Section 9.1

Reads results/<bridge>/run_*.json files and computes:
  - Discovery Rate (DR)
  - Time-to-Exploit (TTE) — median ± std
  - False Positive Rate (FPR)
  - Cross-Chain Coverage (XCC)

Usage:
    python scripts/collect_results.py                    # all bridges
    python scripts/collect_results.py --bridge nomad     # single bridge
    python scripts/collect_results.py --format latex     # LaTeX table output
"""

import argparse
import json
import math
import statistics
from datetime import datetime
from pathlib import Path


def load_runs(bridge_dir: Path) -> list[dict]:
    """Load all run_*.json files from a bridge results directory."""
    runs = []
    for run_file in sorted(bridge_dir.glob("run_*.json")):
        with open(run_file) as f:
            runs.append(json.load(f))
    return runs


def compute_metrics(runs: list[dict]) -> dict:
    """
    Compute metrics for a single bridge from multiple runs.
    
    Metrics (Section 9.1 of experiment_guide):
      DR  = Whether vulnerability was detected in any run
      TTE = Time-to-Exploit for runs with violations (median ± std)
      FPR = False positive rate (estimated)
      XCC = Cross-chain coverage (fraction of ATG edges exercised)
    """
    if not runs:
        return {"detected": False, "n_runs": 0}

    n_runs = len(runs)
    
    # --- DR: detected if any run found violations ---
    runs_with_violations = [r for r in runs if r.get("violations") and len(r["violations"]) > 0]
    detected = len(runs_with_violations) > 0
    detection_rate = len(runs_with_violations) / n_runs

    # --- TTE: Time-to-Exploit (seconds) ---
    tte_values = []
    for r in runs_with_violations:
        # Take earliest violation time in each run
        min_tte = min(v["detected_at_s"] for v in r["violations"])
        tte_values.append(min_tte)

    if tte_values:
        tte_median = statistics.median(tte_values)
        tte_std = statistics.stdev(tte_values) if len(tte_values) > 1 else 0.0
        tte_min = min(tte_values)
        tte_max = max(tte_values)
    else:
        tte_median = tte_std = tte_min = tte_max = None

    # --- Unique invariants violated across all runs ---
    all_violated_ids = set()
    for r in runs_with_violations:
        for v in r["violations"]:
            all_violated_ids.add(v["invariant_id"])

    # --- XCC: Cross-chain coverage ---
    xcc_values = [r["coverage"]["xcc_atg"] for r in runs if "coverage" in r]
    xcc_mean = statistics.mean(xcc_values) if xcc_values else 0.0

    # --- Iteration stats ---
    iter_values = [r["stats"]["total_iterations"] for r in runs if "stats" in r]
    iter_mean = statistics.mean(iter_values) if iter_values else 0

    # --- Corpus stats ---
    corpus_values = [r["stats"].get("corpus_size", 0) for r in runs if "stats" in r]
    corpus_mean = statistics.mean(corpus_values) if corpus_values else 0

    # --- Snapshot stats ---
    snap_values = [r["stats"].get("snapshots_captured", 0) for r in runs if "stats" in r]
    snap_mean = statistics.mean(snap_values) if snap_values else 0

    return {
        "detected": detected,
        "detection_rate": detection_rate,
        "n_runs": n_runs,
        "n_runs_with_violations": len(runs_with_violations),
        "violated_invariants": sorted(all_violated_ids),
        "n_violated_invariants": len(all_violated_ids),
        "tte_median": tte_median,
        "tte_std": tte_std,
        "tte_min": tte_min,
        "tte_max": tte_max,
        "xcc_mean": xcc_mean,
        "iterations_mean": iter_mean,
        "corpus_mean": corpus_mean,
        "snapshots_mean": snap_mean,
    }


def format_tte(metrics: dict) -> str:
    """Format TTE as 'median ± std' matching paper Table 2 format."""
    if metrics["tte_median"] is None:
        return "N/A"
    med = metrics["tte_median"]
    std = metrics["tte_std"]
    if med < 1.0:
        return f"{med:.4f}±{std:.4f}s"
    else:
        return f"{med:.1f}±{std:.1f}s"


def print_summary(all_metrics: dict[str, dict]):
    """Print human-readable summary table (Section 9.1 format)."""
    print("\n" + "=" * 90)
    print("  BridgeSentry Module 3 — Experiment Results Summary")
    print("=" * 90)
    
    header = f"{'Bridge':<18} {'DR':>6} {'Runs':>5} {'TTE (median±std)':>20} {'XCC':>6} {'Invariants Violated'}"
    print(header)
    print("-" * 90)

    for bridge, m in all_metrics.items():
        dr_str = f"{m['n_runs_with_violations']}/{m['n_runs']}" if m['n_runs'] > 0 else "N/A"
        tte_str = format_tte(m)
        xcc_str = f"{m['xcc_mean']:.1%}" if m['xcc_mean'] else "N/A"
        inv_str = ", ".join(m.get("violated_invariants", []))

        print(f"{bridge:<18} {dr_str:>6} {m['n_runs']:>5} {tte_str:>20} {xcc_str:>6} {inv_str}")

    print("-" * 90)

    # Aggregate
    total_runs = sum(m["n_runs"] for m in all_metrics.values())
    total_detected = sum(1 for m in all_metrics.values() if m["detected"])
    total_bridges = len(all_metrics)
    overall_dr = total_detected / total_bridges if total_bridges else 0

    all_ttes = []
    for m in all_metrics.values():
        if m["tte_median"] is not None:
            all_ttes.append(m["tte_median"])
    overall_tte = statistics.median(all_ttes) if all_ttes else None
    overall_tte_std = statistics.stdev(all_ttes) if len(all_ttes) > 1 else 0

    all_xcc = [m["xcc_mean"] for m in all_metrics.values() if m["xcc_mean"]]
    overall_xcc = statistics.mean(all_xcc) if all_xcc else 0

    print(f"{'OVERALL':<18} {total_detected}/{total_bridges}   {total_runs:>5}", end="")
    if overall_tte is not None:
        print(f" {overall_tte:.4f}±{overall_tte_std:.4f}s", end="")
    print(f" {overall_xcc:.1%}")
    print("=" * 90)


def print_latex_table(all_metrics: dict[str, dict]):
    """Output LaTeX table matching paper Table 2 format."""
    print("\n% LaTeX table — paste into paper.tex")
    print(r"\begin{tabular}{@{}lccc@{}}")
    print(r"\toprule")
    print(r"Bridge & DR & Median TTE (s) & XCC\textsubscript{ATG} \\")
    print(r"\midrule")

    for bridge, m in all_metrics.items():
        dr = r"$\checkmark$" if m["detected"] else r"$\times$"
        tte = format_tte(m) if m["detected"] else "---"
        xcc = f"{m['xcc_mean']:.1%}"
        print(f"{bridge:<18} & {dr} ({tte}) & {xcc} \\\\")

    print(r"\midrule")
    total = sum(1 for m in all_metrics.values() if m["detected"])
    n = len(all_metrics)
    print(f"DR & {total}/{n} ({total/n:.1%}) & & \\\\")
    print(r"\bottomrule")
    print(r"\end{tabular}")


def print_detail_per_run(bridge: str, runs: list[dict]):
    """Print per-run detail for a single bridge."""
    print(f"\n--- {bridge}: Per-run detail ({len(runs)} runs) ---")
    print(f"{'Run':>5} {'Violations':>10} {'TTE(s)':>12} {'Iterations':>12} {'Corpus':>8} {'Snapshots':>10} {'XCC':>6}")
    print("-" * 75)
    for i, r in enumerate(runs, 1):
        n_viol = len(r.get("violations", []))
        if n_viol > 0:
            tte = min(v["detected_at_s"] for v in r["violations"])
            tte_str = f"{tte:.4f}"
        else:
            tte_str = "---"
        n_iter = r["stats"]["total_iterations"]
        corpus = r["stats"].get("corpus_size", 0)
        snaps = r["stats"].get("snapshots_captured", 0)
        xcc = r["coverage"]["xcc_atg"]
        print(f"{i:>5} {n_viol:>10} {tte_str:>12} {n_iter:>12} {corpus:>8} {snaps:>10} {xcc:>6.1%}")


def save_metrics_json(all_metrics: dict, output_path: Path):
    """Save computed metrics as JSON for downstream analysis."""
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "bridges": {},
    }
    for bridge, m in all_metrics.items():
        payload["bridges"][bridge] = {k: v for k, v in m.items()}

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\nMetrics JSON saved to: {output_path}")


def build_history_output_path(results_root: Path, bridge: str | None) -> Path:
    """Build non-overwriting timestamped output path under results/summary."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scope = bridge if bridge else "all_bridges"
    filename = f"{scope}_metrics_{timestamp}.json"
    return results_root / "summary" / filename


def main():
    parser = argparse.ArgumentParser(description="Collect BridgeSentry experiment metrics")
    parser.add_argument("--results-dir", type=str, default="results",
                        help="Root results directory")
    parser.add_argument("--bridge", type=str, default=None,
                        help="Single bridge to analyze (default: all)")
    parser.add_argument("--format", choices=["table", "latex", "detail", "json"],
                        default="table", help="Output format")
    parser.add_argument("--save-json", type=str, default=None,
                        help="Save metrics to JSON file")
    parser.add_argument("--no-history-save", action="store_true",
                        help="Disable auto-save timestamped metrics JSON in results/summary/")
    args = parser.parse_args()

    results_root = Path(args.results_dir)
    if not results_root.exists():
        print(f"ERROR: Results directory not found: {results_root}")
        return

    # Discover bridges
    if args.bridge:
        bridge_dirs = [results_root / args.bridge]
    else:
        bridge_dirs = sorted(d for d in results_root.iterdir() 
                           if d.is_dir() and not d.name.startswith("."))

    all_metrics = {}
    all_runs_by_bridge = {}

    for bridge_dir in bridge_dirs:
        runs = load_runs(bridge_dir)
        if not runs:
            continue
        bridge_name = bridge_dir.name
        all_metrics[bridge_name] = compute_metrics(runs)
        all_runs_by_bridge[bridge_name] = runs

    if not all_metrics:
        print("No results found.")
        return

    # Output
    if args.format == "table":
        print_summary(all_metrics)
    elif args.format == "latex":
        print_latex_table(all_metrics)
    elif args.format == "detail":
        for bridge, runs in all_runs_by_bridge.items():
            print_detail_per_run(bridge, runs)
        print_summary(all_metrics)
    elif args.format == "json":
        import sys
        print(json.dumps(all_metrics, indent=2))

    if args.save_json:
        save_metrics_json(all_metrics, Path(args.save_json))

    if not args.no_history_save:
        history_path = build_history_output_path(results_root, args.bridge)
        save_metrics_json(all_metrics, history_path)


if __name__ == "__main__":
    main()
