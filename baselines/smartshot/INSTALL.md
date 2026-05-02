# SmartShot — cite published results (B4 approach)

> SmartShot is a hybrid (rule-based + LLM) detector. At time of writing
> the artifact is not publicly released as runnable code, only as a
> paper: "SmartShot: Discovering Vulnerabilities in Smart Contracts via
> Multi-stage Rule-LLM Analysis" (or similar; verify exact title).

## Status

- **Public binary**: NOT available
- **Approach**: cite published numbers from the paper instead of self-run
- **Output template**: `baselines/_cited_results/smartshot.json`

## How to cite published results

Follow B4 path in `docs/PLAN_PAPER_EXPERIMENTS.md`:

1. Locate the SmartShot paper (typically arXiv / IEEE / ACM).
2. Identify Table N (RQ1 baseline comparison) showing per-bridge
   detection ratios + TTE.
3. Extract values for the benchmarks that overlap with our 12-bridge
   dataset (Nomad / Wormhole / etc.).
4. Populate `baselines/_cited_results/smartshot.json` with:

```json
{
  "tool": "smartshot",
  "source": "PaperLastNameYearVenue, Table N",
  "doi_or_url": "https://...",
  "results": {
    "polynetwork": {"detected": true,  "tte_seconds": 41,  "tte_std": 12, "note": "from paper Table 5"},
    "wormhole":    {"detected": true,  "tte_seconds": 74,  "tte_std": 21},
    "ronin":       {"detected": false, "tte_seconds": null, "note": "not tested in original paper"},
    "nomad":       {"detected": null,  "tte_seconds": null, "note": "not tested"}
  }
}
```

5. `scripts/collect_baseline_results.py` (Phase D2) sẽ merge cited
   results với self-run results, distinguish bằng `source` field.

## Reviewer-facing note

Trong methodology của paper, ghi rõ:

> *"For SmartShot, we cite results from [original paper, Table N]
> rather than self-running because the artifact is not publicly
> available. Cells marked 'n/a' indicate benchmarks not covered by the
> original paper."*

## Effort

- ~1-2 giờ đọc paper + extract numbers per benchmark.
- ~30 phút write JSON.
