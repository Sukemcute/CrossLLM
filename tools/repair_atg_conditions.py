#!/usr/bin/env python3
"""One-shot repair for char-exploded ``conditions`` in already-generated atg.json.

Edges produced before the set_conditions string-coercion fix have a
``conditions`` list where every element is a single character (the LLM returned
a bare string and the old code iterated it char-by-char). This rejoins them and
rebuilds ``condition_objects`` using the corrected logic. Idempotent.

Usage: python tools/repair_atg_conditions.py
"""
from __future__ import annotations
import json, glob
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.module1_semantic.atg_builder import ATGEdge  # noqa: E402


def is_exploded(c) -> bool:
    return isinstance(c, list) and len(c) > 1 and all(isinstance(x, str) and len(x) <= 1 for x in c)


def repair_file(p: Path) -> int:
    atg = json.loads(p.read_text(encoding="utf-8"))
    fixed = 0
    for e in atg.get("edges", []):
        if is_exploded(e.get("conditions")):
            joined = "".join(e["conditions"])
            tmp = ATGEdge(src=e.get("src", ""), dst=e.get("dst", ""), label=e.get("label", ""))
            tmp.set_conditions(joined)  # corrected: scalar string -> single condition
            e["conditions"] = tmp.conditions
            e["condition_objects"] = [c.to_dict() for c in tmp.condition_objects]
            fixed += 1
    if fixed:
        p.write_text(json.dumps(atg, ensure_ascii=False, indent=2), encoding="utf-8")
    return fixed


def main():
    patterns = ["benchmarks/*/llm_outputs/atg.json", "results/*_llm/atg.json"]
    total_files = total_edges = 0
    for pat in patterns:
        for fp in glob.glob(str(ROOT / pat)):
            n = repair_file(Path(fp))
            if n:
                total_files += 1
                total_edges += n
                rel = Path(fp).relative_to(ROOT)
                print(f"  fixed {n} edge(s): {rel}")
    print(f"\nRepaired {total_edges} edge(s) across {total_files} file(s).")


if __name__ == "__main__":
    main()
