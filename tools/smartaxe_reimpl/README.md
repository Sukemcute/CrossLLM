# smartaxe-reimpl — SmartAxe re-implementation for BridgeSentry RQ1

Python static analyzer that re-implements the SmartAxe (Liao et al.,
FSE 2024) cross-chain vulnerability pipeline against the 12 BridgeSentry
benchmarks. Output is a per-bridge JSON whose schema mirrors
`baselines/_cited_results/smartaxe.json` so the RQ1 aggregator can
swap the cite-published cells for self-run cells.

See [`docs/REIMPL_SMARTAXE_SPEC.md`](../../docs/REIMPL_SMARTAXE_SPEC.md)
for the algorithm spec and the per-bridge expected SC violation map.

## Quick start

```bash
cd tools/smartaxe_reimpl
python3 -m venv .venv
. .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -e ".[dev]"

# Unit tests (CFG/DFG construction + pattern inference)
pytest -v tests/

# Run on a single benchmark
smartaxe-reimpl run \
    --contracts ../../benchmarks/nomad/contracts/ \
    --metadata  ../../benchmarks/nomad/metadata.json \
    --output    ../../results/baselines/smartaxe/nomad/run_001.json

# Run all 12 benchmarks
bash ../../scripts/run_smartaxe_sweep.sh   # SA7
```

## Module map

| File | SA sub-task | Spec section |
|---|---|---|
| [`smartaxe_reimpl/cfg_builder.py`](smartaxe_reimpl/cfg_builder.py) | SA3 | §2.1 single-chain CFG (`CfgNode` dataclass) |
| [`smartaxe_reimpl/xcfg_builder.py`](smartaxe_reimpl/xcfg_builder.py) | SA4 | §2.2 emitting + informing edges |
| [`smartaxe_reimpl/xdfg_builder.py`](smartaxe_reimpl/xdfg_builder.py) | SA4 | §2.3 propagation rules |
| [`smartaxe_reimpl/security_checks.py`](smartaxe_reimpl/security_checks.py) | SA5 | §2.4 Table 1 (SC1..SC6 + R1..R4) |
| [`smartaxe_reimpl/pattern_inference.py`](smartaxe_reimpl/pattern_inference.py) | SA5 | §2.5 Table 2 (P1..P5 max-score) |
| [`smartaxe_reimpl/detector.py`](smartaxe_reimpl/detector.py) | SA5 | §2.6 detect_ccv() |
| [`smartaxe_reimpl/output.py`](smartaxe_reimpl/output.py) | SA5 | §3 output schema |

## Out of scope

Per [spec §5](../../docs/REIMPL_SMARTAXE_SPEC.md#5-out-of-scope-deliberately-not-ported):

- SmartDagger cross-function CFG enrichment (use Slither's standard inter-procedural analysis).
- SmartState taint analysis (Slither `data_dependency` covers our cases).
- Wild-scan corpus (only 12 benchmarks).
- 88-CCV ground truth (we use `metadata.json::root_cause_summary`).
- PDF report generation; JSON only.

## Status

| Sub-task | Status |
|---|---|
| SA1 spec | ✅ done — `docs/REIMPL_SMARTAXE_SPEC.md` |
| SA2 project skeleton | ✅ done |
| SA3 cfg_builder | ✅ done |
| SA4 xCFG / xDFG | ✅ done — 39/39 tests; Nomad e2e |
| SA5 security checks + inference | ✅ done — 64/64 tests; Nomad e2e: 2 omissions |
| SA6 PolyNetwork validation | ✅ done — `predicate_match=true`; 70/70 tests |
| SA7 12-benchmark sweep | ⏳ |
| SA8 self-run cited JSON | ⏳ |
