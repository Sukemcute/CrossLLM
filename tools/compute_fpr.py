#!/usr/bin/env python3
"""Compute FPR + Cohen's kappa from the filled FPR labeling sheet.

Reads docs/FPR_LABELING_SHEET.csv after both reviewers fill R1_TP_or_FP and
R2_TP_or_FP with TP/FP. Prints per-reviewer FPR, consensus FPR, Cohen's kappa,
per-bridge FPR, and the list of disagreements to resolve.

Usage: python tools/compute_fpr.py
"""
from __future__ import annotations
import csv, sys
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
SHEET = ROOT/"docs/FPR_LABELING_SHEET.csv"


def norm(x):
    x = (x or "").strip().upper()
    return x if x in ("TP", "FP") else ""


def cohen_kappa(pairs):
    """pairs: list of (r1, r2) labels in {TP,FP}. Returns kappa or None."""
    n = len(pairs)
    if n == 0:
        return None
    po = sum(1 for a, b in pairs if a == b) / n
    # marginal probabilities
    labels = ("TP", "FP")
    p1 = {l: sum(1 for a, _ in pairs if a == l)/n for l in labels}
    p2 = {l: sum(1 for _, b in pairs if b == l)/n for l in labels}
    pe = sum(p1[l]*p2[l] for l in labels)
    if pe == 1:
        return 1.0
    return (po - pe) / (1 - pe)


def main():
    if not SHEET.exists():
        sys.exit(f"missing {SHEET}")
    rows = list(csv.DictReader(open(SHEET, encoding="utf-8-sig")))
    filled = [(r, norm(r["R1_TP_or_FP"]), norm(r["R2_TP_or_FP"])) for r in rows]
    both = [(r, a, b) for r, a, b in filled if a and b]
    if not both:
        sys.exit("No rows have BOTH R1 and R2 filled yet. Fill the sheet first.")

    n_total = len(rows)
    n_filled = len(both)
    r1_fp = sum(1 for _, a, _ in both if a == "FP")
    r2_fp = sum(1 for _, _, b in both if b == "FP")
    agree = [(r, a) for r, a, b in both if a == b]
    consensus_fp = sum(1 for _, a in agree if a == "FP")

    print(f"=== FPR / Cohen's kappa (from {n_filled}/{n_total} fully-labeled rows) ===\n")
    print(f"Reviewer 1 FPR : {r1_fp}/{n_filled} = {r1_fp/n_filled*100:.1f}%")
    print(f"Reviewer 2 FPR : {r2_fp}/{n_filled} = {r2_fp/n_filled*100:.1f}%")
    print(f"Agreement      : {len(agree)}/{n_filled} = {len(agree)/n_filled*100:.1f}%")
    if agree:
        print(f"Consensus FPR  : {consensus_fp}/{len(agree)} = {consensus_fp/len(agree)*100:.1f}%  (report this)")
    k = cohen_kappa([(a, b) for _, a, b in both])
    print(f"Cohen's kappa  : {k:.3f}  ({'near-perfect' if k>0.8 else 'substantial' if k>0.6 else 'moderate' if k>0.4 else 'weak'})")

    print("\n=== Per-bridge consensus FPR ===")
    per = defaultdict(lambda: [0, 0])  # bridge -> [fp, agreed]
    for r, a in agree:
        per[r["bridge"]][1] += 1
        if a == "FP":
            per[r["bridge"]][0] += 1
    for b, (fp, ag) in per.items():
        print(f"  {b:<12} {fp}/{ag} = {fp/ag*100:.0f}%" if ag else f"  {b:<12} n/a")

    dis = [(r, a, b) for r, a, b in both if a != b]
    print(f"\n=== Disagreements to resolve: {len(dis)} ===")
    for r, a, b in dis[:50]:
        print(f"  {r['bridge']:<12} {r['invariant_id']:<40} R1={a} R2={b}")


if __name__ == "__main__":
    main()
