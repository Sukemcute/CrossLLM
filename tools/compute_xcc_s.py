#!/usr/bin/env python3
"""Compute XCC_S: an INDEPENDENT cross-chain coverage metric from Slither's
call graph (not BridgeSentry's own ATG), to counter the XCC circularity critique.

Runs on the LAB (needs slither + solc-select 0.8.20). For each benchmark:
  1. slither --print call-graph on benchmarks/<b>/contracts/ → *.dot
  2. parse + union all `*.all_contracts.call-graph.dot` → user functions + call edges
  3. entry functions = bare-op names of the executed scenario actions (hypotheses.json)
  4. XCC_S = |functions forward-reachable from entries| / |total user functions|
     (entries are DYNAMIC = what the fuzzer drove; reachability is STATIC = Slither graph)
  Also reports total functions and cross-contract edges (the cross-chain-relevant subset).

Output: /tmp/xcc_s_result.json
Usage (on lab):  python3 tools/compute_xcc_s.py
"""
from __future__ import annotations
import json, re, subprocess, glob, os
from collections import defaultdict

ROOT = os.path.expanduser("~/sukem/CrossLLM")
SLITHER = os.path.expanduser("~/baselines/gptscan/.venv/bin/slither")
SOLC_SELECT = os.path.expanduser("~/.local/bin/solc-select")
BR = "nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad".split()

NODE_RE = re.compile(r'"([^"]+)"\s*\[label="([^"]+)"\]')
EDGE_RE = re.compile(r'"([^"]+)"\s*->\s*"([^"]+)"')


def bare(sig: str) -> str:
    return re.split(r"[\s(]", (sig or "").strip(), 1)[0].lower()


def parse_dots(contracts_dir):
    """Union all all_contracts dot files → (funcs: id->bare_name, edges: set, contract_of: id->cid)."""
    funcs, contract_of, edges = {}, {}, set()
    for dot in glob.glob(f"{contracts_dir}/*.all_contracts.call-graph.dot"):
        txt = open(dot, encoding="utf-8", errors="ignore").read()
        for nid, label in NODE_RE.findall(txt):
            if nid.startswith('"'):
                continue
            # user-contract nodes look like "CID_func"; builtins have no CID prefix
            m = re.match(r"^(\d+)_", nid)
            if m:
                funcs[nid] = label.lower()
                contract_of[nid] = m.group(1)
        for a, b in EDGE_RE.findall(txt):
            edges.add((a, b))
    return funcs, contract_of, edges


def reachable(entries, edges_by_src):
    seen, stack = set(entries), list(entries)
    while stack:
        n = stack.pop()
        for m in edges_by_src.get(n, ()):  # forward calls
            if m not in seen:
                seen.add(m)
                stack.append(m)
    return seen


def main():
    out = {}
    for b in BR:
        cdir = f"{ROOT}/benchmarks/{b}/contracts"
        # clean old dots, run slither. Run from benchmarks/ with target
        # <bridge>/contracts so that base-path covers both the local ./ imports
        # and the ../../_shared/ imports used by the off-chain multi-sig bridges.
        subprocess.run(f"rm -f {cdir}/*.dot", shell=True)
        subprocess.run(f"{SOLC_SELECT} use 0.8.20", shell=True,
                       capture_output=True)
        subprocess.run(f"cd {ROOT}/benchmarks && {SLITHER} {b}/contracts --print call-graph",
                       shell=True, capture_output=True, timeout=180)
        funcs, contract_of, edges = parse_dots(cdir)
        if not funcs:
            out[b] = {"error": "no call graph parsed"}
            continue
        # entry functions from executed scenarios
        hyp = json.load(open(f"{ROOT}/benchmarks/{b}/llm_outputs/hypotheses.json", encoding="utf-8"))
        scen = hyp.get("scenarios", hyp) if isinstance(hyp, dict) else hyp
        entry_names = set()
        for s in scen:
            for a in s.get("actions", []):
                op = bare(a.get("function") or a.get("op") or a.get("function_signature") or "")
                if op:
                    entry_names.add(op)
        # map entry names → node ids
        entries = [nid for nid, nm in funcs.items() if nm in entry_names]
        edges_by_src = defaultdict(list)
        user_ids = set(funcs)
        cross_edges = 0
        for a, c in edges:
            if a in user_ids and c in user_ids:
                edges_by_src[a].append(c)
                if contract_of.get(a) != contract_of.get(c):
                    cross_edges += 1
        reached = reachable(entries, edges_by_src) & user_ids
        n_func = len(user_ids)
        out[b] = {
            "total_functions": n_func,
            "total_contracts": len(set(contract_of.values())),
            "cross_contract_edges": cross_edges,
            "entry_functions_matched": len(entries),
            "functions_reached": len(reached),
            "xcc_s_pct": round(len(reached) / n_func * 100, 1) if n_func else None,
        }
        print(f"{b:<12} funcs={n_func} cross_edges={cross_edges} entries={len(entries)} reached={len(reached)} XCC_S={out[b]['xcc_s_pct']}%", flush=True)
    json.dump(out, open("/tmp/xcc_s_result.json", "w"), indent=2)
    vals = [v["xcc_s_pct"] for v in out.values() if isinstance(v.get("xcc_s_pct"), (int, float))]
    if vals:
        print(f"\nmean XCC_S = {sum(vals)/len(vals):.1f}%  over {len(vals)} bridges")


if __name__ == "__main__":
    main()
