#!/usr/bin/env python3
"""ATG visualizer — convert atg.json into an interactive HTML graph + Mermaid.

Usage:
    python tools/atg_viz.py                 # all 12 bridges -> tools/atg_viz_out/
    python tools/atg_viz.py qubit           # single bridge
    python tools/atg_viz.py path/to/atg.json --out out_dir

Outputs per bridge:
    <out>/<bridge>.html   interactive (vis-network, drag/zoom) — open in a browser
    <out>/<bridge>.mmd    Mermaid flowchart (paste into mermaid.live / VSCode preview)
    <out>/index.html      links to every bridge graph
"""
from __future__ import annotations
import json, sys, html, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRIDGES = ["nomad", "qubit", "pgala", "polynetwork", "wormhole", "socket",
           "ronin", "harmony", "multichain", "orbit", "fegtoken", "gempad"]

# node_type -> colour
NODE_COLORS = {
    "contract": "#4f86c6", "user": "#e8a33d", "eoa": "#e8a33d",
    "relay": "#7d5ba6", "token": "#3aa66f", "governance": "#c64f6d",
}
# edge label -> colour (asset/relay semantics)
EDGE_COLORS = {
    "lock": "#2e7d32", "mint": "#1565c0", "unlock": "#2e7d32", "burn": "#b71c1c",
    "withdraw": "#b71c1c", "relay": "#6a1b9a", "verify": "#5d4037",
    "deposit": "#2e7d32", "transfer": "#455a64",
}


def _clean_conditions(cond) -> str:
    """conditions may be a proper string, a list of strings, or a char-exploded list."""
    if cond is None:
        return ""
    if isinstance(cond, str):
        return cond
    if isinstance(cond, list):
        # char-explosion bug: every element is a single character -> join
        if cond and all(isinstance(c, str) and len(c) <= 1 for c in cond):
            return "".join(cond)
        return " ; ".join(str(c) for c in cond)
    return str(cond)


def _node_id(n: dict) -> str:
    return n.get("node_id") or n.get("id") or n.get("name") or "?"


def _edge_ends(e: dict):
    s = e.get("src") or e.get("source") or e.get("from")
    d = e.get("dst") or e.get("target") or e.get("to")
    return s, d


def load_atg(p: Path) -> dict:
    atg = json.loads(p.read_text(encoding="utf-8"))
    # Render the cleaned graph (dedup + canonical actors) without mutating the
    # canonical artifact on disk.
    try:
        import sys
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from src.module1_semantic.atg_builder import normalize_atg_dict
        atg = normalize_atg_dict(atg)
    except Exception:
        pass  # fall back to raw graph if the normalizer is unavailable
    return atg


def to_vis(atg: dict):
    """Return (nodes, edges) lists for vis-network."""
    seen, nodes = set(), []
    # nodes declared explicitly
    for n in atg.get("nodes", []):
        nid = _node_id(n)
        if nid in seen:
            continue
        seen.add(nid)
        ntype = (n.get("node_type") or n.get("type") or "contract").lower()
        chain = n.get("chain") or ""
        title = f"{nid}\\ntype: {ntype}" + (f"\\nchain: {chain}" if chain else "")
        nodes.append({
            "id": nid, "label": nid,
            "group": chain or ntype,
            "color": NODE_COLORS.get(ntype, "#90a4ae"),
            "title": title,
        })
    edges = []
    for e in atg.get("edges", []):
        s, d = _edge_ends(e)
        for endpoint in (s, d):
            if endpoint and endpoint not in seen:
                seen.add(endpoint)
                nodes.append({"id": endpoint, "label": endpoint,
                              "group": "implicit", "color": "#cfd8dc",
                              "title": f"{endpoint}\\n(referenced by edge)"})
        label = e.get("label") or e.get("action") or ""
        sig = e.get("function_signature") or ""
        tok = e.get("token") or ""
        cond = _clean_conditions(e.get("conditions"))
        title = "\\n".join(filter(None, [
            f"label: {label}", f"fn: {sig}" if sig else "",
            f"token: {tok}" if tok else "",
            f"guard: {cond[:160]}" if cond else ""]))
        edges.append({
            "from": s, "to": d,
            "label": label,
            "color": EDGE_COLORS.get(label.lower(), "#78909c"),
            "title": title, "arrows": "to",
        })
    return nodes, edges


HTML_TMPL = """<!DOCTYPE html>
<html lang="vi"><head><meta charset="utf-8"><title>ATG — {bridge}</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
 body{{font-family:system-ui,Segoe UI,Arial;margin:0;background:#fafafa}}
 #hdr{{padding:10px 16px;background:#263238;color:#fff}}
 #hdr b{{font-size:18px}} #hdr span{{opacity:.8;font-size:13px;margin-left:10px}}
 #net{{width:100vw;height:calc(100vh - 110px);border-top:1px solid #ccc}}
 #legend{{padding:6px 16px;font-size:12px;background:#eceff1}}
 .chip{{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;margin-right:6px}}
</style></head><body>
<div id="hdr"><b>ATG — {bridge}</b>
 <span>{nnodes} nodes · {nedges} edges · {ninv} invariants — kéo để di chuyển, lăn chuột để zoom, rê chuột vào cạnh để xem guard</span></div>
<div id="legend">
 <span class="chip" style="background:#4f86c6">contract</span>
 <span class="chip" style="background:#e8a33d">user/eoa</span>
 <span class="chip" style="background:#7d5ba6">relay</span>
 <span class="chip" style="background:#3aa66f">token</span>
 <span class="chip" style="background:#2e7d32">lock/mint</span>
 <span class="chip" style="background:#b71c1c">withdraw/burn</span>
</div>
<div id="net"></div>
<script>
 const nodes=new vis.DataSet({nodes});
 const edges=new vis.DataSet({edges});
 new vis.Network(document.getElementById('net'),{{nodes,edges}},{{
   nodes:{{shape:'box',font:{{color:'#fff',size:14}},margin:8,borderWidth:0}},
   edges:{{font:{{size:12,align:'middle',background:'#fff'}},smooth:{{type:'cubicBezier'}}}},
   physics:{{stabilization:true,barnesHut:{{springLength:160}}}},
   layout:{{improvedLayout:true}}
 }});
</script></body></html>"""


def mermaid(atg: dict, bridge: str) -> str:
    def mid(s): return "n_" + re.sub(r"[^0-9A-Za-z_]", "_", s or "x")
    lines = [f"%% ATG {bridge}", "flowchart LR"]
    declared = set()
    for n in atg.get("nodes", []):
        nid = _node_id(n)
        if nid in declared:
            continue
        declared.add(nid)
        lines.append(f'  {mid(nid)}["{nid}"]')
    for e in atg.get("edges", []):
        s, d = _edge_ends(e)
        lbl = (e.get("label") or "").replace('"', "'")
        lines.append(f'  {mid(s)} -- "{lbl}" --> {mid(d)}')
    return "\n".join(lines)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    out = ROOT / "tools" / "atg_viz_out"
    if "--out" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--out") + 1])
    out.mkdir(parents=True, exist_ok=True)

    targets = []  # (bridge_name, atg_path)
    if not args:
        for b in BRIDGES:
            p = ROOT / "benchmarks" / b / "llm_outputs" / "atg.json"
            if p.exists():
                targets.append((b, p))
    else:
        for a in args:
            p = Path(a)
            if p.suffix == ".json":
                targets.append((p.stem, p))
            else:
                targets.append((a, ROOT / "benchmarks" / a / "llm_outputs" / "atg.json"))

    done = []
    for bridge, p in targets:
        if not p.exists():
            print(f"  SKIP {bridge}: {p} not found"); continue
        atg = load_atg(p)
        nodes, edges = to_vis(atg)
        ninv = len(atg.get("invariants", []))
        html_doc = HTML_TMPL.format(
            bridge=html.escape(bridge), nnodes=len(nodes), nedges=len(edges), ninv=ninv,
            nodes=json.dumps(nodes, ensure_ascii=False), edges=json.dumps(edges, ensure_ascii=False))
        (out / f"{bridge}.html").write_text(html_doc, encoding="utf-8")
        (out / f"{bridge}.mmd").write_text(mermaid(atg, bridge), encoding="utf-8")
        done.append((bridge, len(nodes), len(edges), ninv))
        print(f"  OK {bridge}: {len(nodes)} nodes, {len(edges)} edges -> {bridge}.html / .mmd")

    # index
    rows = "\n".join(
        f'<li><a href="{b}.html">{b}</a> — {n} nodes, {e} edges, {i} invariants</li>'
        for b, n, e, i in done)
    (out / "index.html").write_text(
        f"<!DOCTYPE html><meta charset=utf-8><title>ATG graphs</title>"
        f"<h2>BridgeSentry — ATG visualizations</h2><ul>{rows}</ul>", encoding="utf-8")
    print(f"\nDone. Open: {out / 'index.html'}")


if __name__ == "__main__":
    main()
