# SmartAxe — cite-published path (B4)

> SmartAxe — cross-contract vulnerability detector. Originally
> published as paper artifact; **the public repository at
> https://github.com/CGCL-codes/SmartAxe (and several capitalisation
> variants) returns 404 as of 2026-04-27**. Likely the artifact is
> only available on Zenodo / paper supplementary material, or has
> been taken down.

## Status (2026-04-27)

- **Public repo found**: NO (404 on canonical URL + 4 alternative
  spellings tried — see `baselines/README.md` audit).
- **Approach**: cite published results path (B4) — extract numbers
  from SmartAxe paper Tables. Same pattern as SmartShot / VulSEye /
  XScope.
- **Adapter retained**: [`adapter.sh`](adapter.sh) is left in place
  for future use if the artifact becomes available; it expects a
  Python module `smartaxe` to be importable. Currently it will fail
  with "ERROR: SmartAxe not installed" if invoked.

## Cite published values

Same procedure as `smartshot`:

1. Locate the SmartAxe paper:
   - Likely IEEE / ACM / arXiv. Search `"SmartAxe" cross-chain`.
2. Find Table N reporting per-bridge detection.
3. Populate
   [`baselines/_cited_results/smartaxe.json`](../_cited_results/smartaxe.json)
   (template — created same time as this doc).
4. `scripts/collect_baseline_results.py` will merge automatically.

## Methodology note for paper

In §5.3 / RQ1 results table, mark column header for SmartAxe as
*static* tool type. TTE column = analysis wall-clock from paper
(typically 1-30 seconds for static analyzers). Cells where SmartAxe
paper didn't test a benchmark → `"detected": null, "note": "not
tested in original paper"` → renders as `n/a` in our table.

## If artifact becomes available

Update this file, document install steps, populate `version.txt` with
commit hash, and run via the existing
[`adapter.sh`](adapter.sh) — no other changes needed in the
aggregator pipeline.
