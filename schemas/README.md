# JSON Schemas — Giao diện Giao tiếp giữa các Module

> **FROZEN** sau Phase 0. Thay doi chi khi CA HAI thanh vien dong y.

## Files

| Schema | Producer | Consumer | Mo ta |
|--------|----------|----------|-------|
| `atg.json` | Module 1 | Module 2 + 3 | ATG graph + invariants |
| `hypotheses.json` | Module 2 | Module 3 | Attack scenarios + waypoints |
| `results.json` | Module 3 | Orchestrator | Violation reports + coverage |

## Mock Fixtures

De dev song song ma khong cho doi nhau, dung mock fixtures:
- `tests/fixtures/atg_mock.json` — ATG mau cho Nomad bridge
- `tests/fixtures/hypotheses_mock.json` — Kich ban tan cong mau cho Nomad
