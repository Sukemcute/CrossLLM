# XScope — cite published results (B4 approach)

> XScope is a cross-chain bridge security analyzer (academic artifact).
> Used by build_exploit_kb.py as part of our 48-record KB but the
> standalone tool isn't released. Same B4 pattern — cite paper.

## Status

- **Public binary**: NOT available
- **Output template**: `baselines/_cited_results/xscope.json`

## Cite published values

Same procedure as SmartShot / VulSEye. Template:

```json
{
  "tool": "xscope",
  "source": "Zhang et al., XScope: ...",
  "doi_or_url": "https://...",
  "results": {
    "polynetwork": {"detected": true,  "tte_seconds": null, "note": "static analysis — no TTE"},
    "wormhole":    {"detected": true,  "tte_seconds": null},
    ...
  }
}
```

XScope is static analysis — TTE is N/A. Report `tte_seconds: null` and
note in column header that "static" tools don't have a meaningful TTE.

## Methodology note for paper

Distinguish in RQ1 table:

| Tool | Type | TTE column meaning |
|---|---|---|
| BridgeSentry | Fuzzer | wall-clock to first violation |
| ItyFuzz | Fuzzer | same as BridgeSentry |
| SmartShot | Hybrid | analysis wall-clock |
| VulSEye | Symbolic + ML | analysis wall-clock |
| **SmartAxe** | Static | N/A (instant) |
| **GPTScan** | LLM | LLM latency |
| **XScope** | Static | N/A |

Report `--` for static tools' TTE; reviewer-friendly.
