#!/usr/bin/env python3
"""RQ3 k-sensitivity: regenerate ONLY Module 2 scenarios with varying RAG top_k,
holding the (real LLM) ATG fixed, to isolate the effect of k.

For each bridge, loads the existing real atg.json (its invariants), then runs the
RAG scenario generator with top_k in {1,5,10} and writes
benchmarks/<bridge>/llm_outputs/hypotheses_k{N}.json.
(k=3 is the existing canonical hypotheses.json — reused, not regenerated.)

Requires NVIDIA_API_KEY in env (uses the real LLM RAG path). Run:
    set -a; source <(tr -d '\r' < .env); set +a
    python tools/rq3_gen_k_hypotheses.py
"""
from __future__ import annotations
import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from src.module2_rag.scenario_gen import AttackScenarioGenerator  # noqa: E402

BRIDGES = ["nomad", "qubit", "pgala", "polynetwork", "wormhole", "socket",
           "ronin", "harmony", "multichain", "orbit", "fegtoken", "gempad"]
K_VALUES = [1, 5, 10]  # k=3 is the canonical existing run


def main():
    for b in BRIDGES:
        atg_path = ROOT / "benchmarks" / b / "llm_outputs" / "atg.json"
        if not atg_path.exists():
            print(f"  SKIP {b}: no atg.json"); continue
        atg = json.loads(atg_path.read_text(encoding="utf-8"))
        invs = atg.get("invariants", [])
        for k in K_VALUES:
            gen = AttackScenarioGenerator(top_k=k)
            scenarios = gen.generate(atg, invs)
            out = {"bridge_name": b, "scenarios": scenarios}
            outp = ROOT / "benchmarks" / b / "llm_outputs" / f"hypotheses_k{k}.json"
            outp.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"  {b} k={k}: {len(scenarios)} scenarios -> {outp.name}")


if __name__ == "__main__":
    main()
