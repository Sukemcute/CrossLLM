# JSON Schemas — Giao tiếp giữa các module

> **FROZEN** sau Phase 0. Thay đổi chỉ khi **cả hai** thành viên đồng ý (sau khi Member B định nghĩa bản nháp và Member A đồng bộ pipeline Python).

## Files (JSON Schema Draft 2020-12)

| File | Producer | Consumer | Ghi chú |
|------|----------|----------|---------|
| `invariants.schema.json` | Module 1 (invariant synth / ATG) | ATG + Module 2 + 3 | Một object invariant; **phải đồng bộ** với `$defs.invariant` trong `atg.schema.json`. |
| `atg.schema.json` | Module 1 | Module 2 + 3 | ATG đầy đủ: `bridge_name`, `version`, `nodes`, `edges`, `invariants`. |
| `hypotheses.schema.json` | Module 2 | Module 3 | Kịch bản tấn công + waypoints. |
| `results.schema.json` | **Module 3 (Rust)** | Orchestrator | **Do Member B dẫn** — khớp `types::FuzzingResults`. |

## Khớp code (Module 3)

- `atg.json` / `hypotheses.json` ↔ `src/module3_fuzzing/src/types.rs` (`AtgGraph`, `HypothesesFile`, …).
- `results.json` ↔ `FuzzingResults`, `Violation`, `Coverage`, `FuzzingStats`.

## Validate nhanh (tùy chọn)

```bash
# ví dụ với Python jsonschema
pip install jsonschema
python -c "import json, jsonschema; jsonschema.validate(json.load(open('tests/fixtures/atg_mock.json')), json.load(open('schemas/atg.schema.json')))"
```

## Mock fixtures

- `tests/fixtures/atg_mock.json`
- `tests/fixtures/hypotheses_mock.json`

Cần đạt validation khi schema đã thống nhất với Member A.
