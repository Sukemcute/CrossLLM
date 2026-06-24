#!/usr/bin/env python3
"""Build the FPR labeling workbook from extracted violations.

Inputs:
  results/fpr_violations_raw.json   (distinct bridge x invariant violations)
  benchmarks/<b>/llm_outputs/atg.json   (invariant predicates)
  benchmarks/<b>/metadata.json          (documented root cause = ground-truth context)

Outputs:
  docs/FPR_LABELING_SHEET.csv    one row per (bridge, invariant); 2 empty reviewer cols
  docs/FPR_LABELING_GUIDE.md     criteria + how to fill + how FPR/kappa are computed

Two reviewers independently fill R1/R2 with TP or FP, then run
tools/compute_fpr.py to get FPR + Cohen's kappa.
"""
from __future__ import annotations
import json, csv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BR = "nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad".split()


def predicate_map(b):
    try:
        atg = json.loads((ROOT/f"benchmarks/{b}/llm_outputs/atg.json").read_text(encoding="utf-8"))
        return {i.get("invariant_id"): (i.get("predicate") or i.get("description") or "")
                for i in atg.get("invariants", [])}
    except Exception:
        return {}


def root_cause(b):
    try:
        m = json.loads((ROOT/f"benchmarks/{b}/metadata.json").read_text(encoding="utf-8"))
    except Exception:
        return ""
    for k in ("root_cause_summary", "root_cause", "vulnerability"):
        v = m.get(k)
        if isinstance(v, dict):
            return v.get("notes") or v.get("summary") or json.dumps(v, ensure_ascii=False)[:300]
        if isinstance(v, str):
            return v
    return ""


def main():
    raw = json.loads((ROOT/"results/fpr_violations_raw.json").read_text(encoding="utf-8"))
    rows = []
    for b in BR:
        preds = predicate_map(b)
        rc = root_cause(b)
        for v in raw.get(b, []):
            iid = v["invariant_id"]
            trace = v.get("trace", [])
            rows.append({
                "bridge": b,
                "documented_root_cause": rc[:200],
                "invariant_id": iid,
                "category": v.get("category", ""),
                "predicate": preds.get(iid, "")[:200],
                "trigger_scenario": v.get("trigger_scenario", "")[:80],
                # strongest-evidence instance across the 20 runs (max state-diff)
                "representative_trace": " | ".join(trace) if isinstance(trace, list) else str(trace),
                "state_diff": json.dumps(v.get("state_diff", {}), ensure_ascii=False)[:120],
                "max_state_diff_wei": v.get("max_diff", 0),
                "has_successful_exec_step": v.get("has_success_step", False),
                "R1_TP_or_FP": "",
                "R2_TP_or_FP": "",
                "notes": "",
            })
    cols = list(rows[0].keys())
    out_csv = ROOT/"docs/FPR_LABELING_SHEET.csv"
    with open(out_csv, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {out_csv} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
