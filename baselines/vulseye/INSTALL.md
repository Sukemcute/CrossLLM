# VulSEye — cite published results (B4 approach)

> VulSEye combines symbolic execution with ML for cross-chain bridge
> vulnerability detection. Same B4 pattern as SmartShot — artifact may
> not be runnable, cite paper.

## Status

- **Public artifact**: typically academic — verify availability with
  paper authors. Some VulSEye forks exist on GitHub but not officially
  released.
- **Approach**: cite published results
- **Output template**: `baselines/_cited_results/vulseye.json`

## Cite published values

Same procedure as SmartShot:

1. Locate VulSEye paper.
2. Table reporting per-bridge detection + TTE.
3. Populate `baselines/_cited_results/vulseye.json` (template same as
   `smartshot.json`).

## Notes

- VulSEye's symbolic engine is computationally expensive — paper TTE
  values typically 10-60s per benchmark. Mark realistic in cited table.
- Cells where original paper didn't test a benchmark → `"detected":
  null, "note": "not tested in original paper"`.
