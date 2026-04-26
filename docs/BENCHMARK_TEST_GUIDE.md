# Hướng dẫn Test 1 Benchmark — End-to-end

> Áp dụng cho mọi benchmark trong `benchmarks/` (Nomad, Qubit, pGALA, PolyNetwork, Wormhole, ...).
> Lấy ví dụ minh hoạ là **Qubit** (đã có sẵn).

---

## Tổng quan: 4 cấp test

| Tier | Mục đích | Thời gian | Cần gì |
|------|----------|-----------|--------|
| **0** | `verify_benchmark.py` — schema + addresses + RPC | ~10s | RPC keys |
| **1** | Pipeline offline — fallback (no LLM) | ~10s | Không cần API |
| **2** | Pipeline LLM — NVIDIA NIM | ~60-90s | NVIDIA_API_KEY |
| **3** | Manual quality check | ~10 phút | Đọc atg.json + hypotheses.json |

---

## Pre-requisites (1 lần)

### Sync code mới nhất từ Windows sang WSL

```bash
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/src/      ~/CrossLLM/src/
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/scripts/  ~/CrossLLM/scripts/
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/schemas/  ~/CrossLLM/schemas/
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/benchmarks/ ~/CrossLLM/benchmarks/
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/.env       ~/CrossLLM/.env
```

### Activate venv + load `.env`

```bash
cd ~/CrossLLM
source .crossllm/bin/activate
set -a && source .env && set +a
```

> **Quan trọng:** phải `source .crossllm/bin/activate` để Slither tìm thấy `solc`.

---

## Tier 0 — Verify benchmark structure

```bash
python scripts/verify_benchmark.py benchmarks/qubit/
```

**Kết quả mong đợi:**

```
=== Verifying qubit ===
[schema] OK
[contracts] 3 .sol file(s): MockToken.sol, QBridgeBSC.sol, QBridgeETH.sol
[rpc ethereum] connected, latest block 24956471
[rpc bsc] connected, latest block 94581233
[fork] block 14180000 exists, ts=1644518643
[code] exploit_minted_token 0xc78248D676DeBB4597e88071D3d889eCA70E5469 -> contract (latest (archive unavailable))
[ref] https://medium.com/@QubitFin/protocol-exploit-report-305c34540fa3 -> 403 [warn]
[ref] https://rekt.news/qubit-rekt/ -> 200
[ref] https://bscscan.com/address/0xF734985f7d40Bcc0B2E3FA5d0cb2A86C12BDF7eb -> 403 [warn]

ALL CHECKS PASSED
```

**Tốt nếu thấy:**
- `[schema] OK` — metadata.json hợp lệ
- `[contracts] N .sol file(s)` — có ít nhất 1 file
- `[rpc <chain>] connected` — RPC keys hoạt động
- `[fork] block N exists` — fork block có thật
- `[code] <name> -> contract` — addresses là contract (`-> EOA` chỉ OK khi có `is_eoa: true`)
- `ALL CHECKS PASSED`

**Cảnh báo có thể bỏ qua:**
- `[ref] ... -> 403 [warn]` — Medium/Etherscan chặn HEAD request, link vẫn hoạt động trong browser
- `[code] ... -> contract (latest (archive unavailable))` — BSC public RPC không có archive, fallback latest

---

## Tier 1 — Pipeline offline (fallback path)

Chạy không có API key — kiểm tra fallback determinitic.

```bash
unset NVIDIA_API_KEY OPENAI_API_KEY
bash benchmarks/qubit/repro.sh
```

Hoặc trực tiếp:

```bash
python -m src.orchestrator \
    --benchmark benchmarks/qubit/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/qubit_smoke/
```

**Output mong đợi:**

```
  Module 1: Extracting semantics    ━━━━━━━━━━━━━━━━━━━━━━━━ 0:00:01
  Module 1: ATG + invariants        ━━━━━━━━━━━━━━━━━━━━━━━━ 0:00:00
  Module 2: RAG scenario generation ━━━━━━━━━━━━━━━━━━━━━━━━ 0:00:13
⠸ Module 3: skipped (--skip-fuzzer)                          0:00:00
[Output] Saved report to results/qubit_smoke/report.json
```

**Kiểm tra report:**

```bash
cat results/qubit_smoke/report.json
```

**Tiêu chí "tốt":**

| Field | Mong đợi | Ý nghĩa |
|-------|----------|---------|
| `module1.contracts_processed` | 3 | Đã parse hết .sol |
| `module1.entities` | ≥ 3 | Có user + ≥2 contract |
| `module1.edges` | ≥ 2 | Có flow lock + mint (hoặc verify) |
| `module1.invariants` | 4 | 4 invariants fallback (asset/auth/uniq/time) |
| `module2.scenarios` | 4 | 1 scenario per invariant (template fallback) |

---

## Tier 2 — Pipeline với LLM thật (NVIDIA NIM)

Reload env (nếu vừa unset trên):

```bash
set -a && source .env && set +a
echo "NVIDIA_API_KEY: ${NVIDIA_API_KEY:0:15}..."
echo "NVIDIA_MODEL:   $NVIDIA_MODEL"
```

Phải in ra `nvapi-...` và `openai/gpt-oss-120b`.

```bash
rm -rf results/qubit_llm .llm_cache  # clean cache for fair test (optional)
python -m src.orchestrator \
    --benchmark benchmarks/qubit/ \
    --time-budget 5 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/qubit_llm/
```

**Thời gian:** 60-120s với gpt-oss-120b (reasoning model chậm).

**Tiêu chí "tốt":**

```bash
cat results/qubit_llm/report.json
```

| Field | Offline fallback | **LLM mong đợi** |
|-------|-----------------|------------------|
| `module1.invariants` | 4 | **≥ 10** (paper target ~12) |
| `module2.scenarios` | 4 | **≥ 10** |

**Ví dụ kết quả Qubit thực tế (đã test):**

```json
{
  "module1": { "contracts_processed": 3, "entities": 4, "edges": 4, "invariants": 20 },
  "module2": { "scenarios": 20 }
}
```

20 invariants + 20 scenarios — vượt paper target.

---

## Tier 3 — Manual quality check

Đây là phần thầy/reviewer kiểm tra. Dùng script kiểm tra nhanh:

```bash
python <<'PY'
import json
from pathlib import Path

run = Path("results/qubit_llm")  # or qubit_smoke for offline
atg = json.load(open(run / "atg.json"))
hyp = json.load(open(run / "hypotheses.json"))

# Invariants
print(f"=== Invariants ({len(atg['invariants'])}) ===")
cats: dict[str, int] = {}
for inv in atg["invariants"]:
    cats[inv["category"]] = cats.get(inv["category"], 0) + 1
for cat, n in sorted(cats.items()):
    print(f"  {cat}: {n}")

# Show 3 invariant samples
print("\n=== Sample invariants ===")
for inv in atg["invariants"][:3]:
    print(f"  [{inv['category']}] {inv['invariant_id']}")
    print(f"    desc: {inv['description'][:80]}")
    print(f"    solidity: {inv['solidity_assertion'][:90]}")

# Scenarios
print(f"\n=== Scenarios ({len(hyp['scenarios'])}) ===")
classes = sorted({s["vulnerability_class"] for s in hyp["scenarios"]})
print(f"Vuln classes ({len(classes)}): {classes[:6]}{' ...' if len(classes) > 6 else ''}")

# Action stats
action_counts = [len(s["actions"]) for s in hyp["scenarios"]]
print(f"Actions per scenario: min={min(action_counts)}, max={max(action_counts)}, avg={sum(action_counts)/len(action_counts):.1f}")

# First scenario detail
s0 = hyp["scenarios"][0]
print(f"\n=== First scenario: {s0['scenario_id']} ===")
print(f"  target: {s0['target_invariant']}, class={s0['vulnerability_class']}, conf={s0['confidence']}")
for a in s0["actions"][:3]:
    op = a.get("function") or a.get("action") or "?"
    print(f"    {a['step']}. [{a['chain']}] {op} {dict(list(a.get('params', {}).items())[:2])}")

print(f"\n=== Waypoints (first scenario) ===")
for w in s0["waypoints"][:3]:
    print(f"  {w['waypoint_id']}: {w['predicate']}")
PY
```

**Đọc và đánh giá:**

| Aspect | TỐT | XẤU |
|--------|-----|-----|
| Invariant categories | Có cả 4 (asset_conservation, authorization, uniqueness, timeliness) | Chỉ 1-2 categories |
| Invariant description | Mô tả tiếng Anh rõ ràng, có ngữ cảnh bridge | Trùng nhau, hoặc generic kiểu "invariant should hold" |
| Solidity assertion | `require(...)` hoặc `assert(...)` parseable | Rỗng, hoặc chỉ `true`/`false` |
| Vuln class diversity | ≥4 unique classes | Tất cả là cùng 1 class |
| Action chain | Đa dạng `source` / `destination` / `relay` | Chỉ 1 chain |
| Waypoint predicate | State predicate kiểu `sourceRouter.totalLocked() >= X` | Generic kiểu `step_2_executed` |
| Confidence | Phân bổ 0.5–0.9 | Tất cả 0.5 |

---

## So sánh kết quả

```bash
python <<'PY'
import json
from pathlib import Path

off = json.load(open("results/qubit_smoke/report.json"))
llm = json.load(open("results/qubit_llm/report.json"))
print(f"{'Metric':<25}{'Offline':<12}{'LLM (NVIDIA)':<12}")
print("-" * 49)
print(f"{'Invariants':<25}{off['module1']['invariants']:<12}{llm['module1']['invariants']:<12}")
print(f"{'Scenarios':<25}{off['module2']['scenarios']:<12}{llm['module2']['scenarios']:<12}")

oh = json.load(open("results/qubit_smoke/hypotheses.json"))
lh = json.load(open("results/qubit_llm/hypotheses.json"))
print(f"{'Vuln classes':<25}{len({s['vulnerability_class'] for s in oh['scenarios']}):<12}{len({s['vulnerability_class'] for s in lh['scenarios']}):<12}")
PY
```

**Kết quả Qubit thực tế:**

| Metric | Offline | **LLM (NVIDIA)** |
|--------|---------|------------------|
| Invariants | 4 | **20** (5×) |
| Scenarios | 4 | **20** (5×) |
| Vuln classes | 4 | **15+** |

---

## Acceptance checklist (per benchmark)

Khi mỗi benchmark mới hoàn thành (Q/P/N/W/...):

- [ ] **Tier 0:** `verify_benchmark.py` → `ALL CHECKS PASSED`
- [ ] **Tier 1:** Pipeline offline chạy, `report.json` valid
- [ ] **Tier 2:** Pipeline LLM chạy, `module1.invariants ≥ 10`
- [ ] **Tier 3:** 4 invariant categories present, scenarios diverse
- [ ] **Pytest:** `python -m pytest tests/ -q` → all pass
- [ ] Sync results về Windows: `rsync -a ~/CrossLLM/results/<benchmark>* /mnt/c/.../CrossLLM/results/`

---

## Troubleshooting

### `verify_benchmark.py` báo `address has no bytecode`

→ Address sai, hoặc cố ý là EOA. Nếu cố ý → thêm `"is_eoa": true` vào entry trong `metadata.json`.

### `ERROR: [schema:atg] ... is not of type 'string'`

LLM trả `null` hoặc object thay vì string. **Bug pipeline, KHÔNG sửa data.** Báo cho người maintain `atg_builder.py` / `scenario_gen.py` để bổ sung normalize.

### `[Slither] Failed to compile ... 'solc'`

Venv chưa activate. Chạy:
```bash
source ~/CrossLLM/.crossllm/bin/activate
solc-select use 0.8.20
```

### LLM call rất chậm (>2 phút)

`gpt-oss-120b` là reasoning model, mỗi call ~30s. Đổi sang model nhanh hơn:
```bash
export NVIDIA_MODEL=meta/llama-3.3-70b-instruct
```

Hoặc giảm số invariants candidate (sửa `_USER_PROMPT_TEMPLATE` trong `invariant_synth.py` từ "15-20" xuống "8-10").

### `BSC RPC error: missing trie node`

Public BSC RPC không có archive. `verify_benchmark.py` đã auto-fallback sang `latest` block — chỉ là warning, không phải lỗi.

---

## Shared benchmark utilities (`benchmarks/_shared/`)

Một số benchmark (Ronin, Harmony, Orbit, Multichain trong
`PLAN_POPULATE_OFFCHAIN.md`) chia sẻ cùng K-of-N multi-sig pattern.
Phần code dùng chung sống ở `benchmarks/_shared/`:

| File | Purpose |
|------|---------|
| `benchmarks/_shared/MockMultisig.sol` | K-of-N ECDSA threshold harness (constructor: `address[] signers_, uint256 threshold_`) |
| `benchmarks/_shared/README.md` | Note dùng chung — không có `metadata.json` nên `verify_benchmark.py` không chạy ở đây |

**Cách import từ benchmark:**

```solidity
// benchmarks/<bridge>/contracts/SomeBridge.sol
import "../../_shared/MockMultisig.sol";

contract RoninBridgeManager is MockMultisig {
    constructor(address[] memory signers_) MockMultisig(signers_, 5) {}
}
```

**Lưu ý cho rsync sang WSL:** thư mục `_shared/` là sibling của các
benchmark folder, nên lệnh rsync `benchmarks/` ở Pre-requisites đã đồng
bộ luôn. Không cần lệnh riêng.

**Lưu ý cho `verify_benchmark.py`:** không pass `benchmarks/_shared/`
làm argument — script sẽ báo `missing metadata.json` (đúng, vì đây là
helper chứ không phải benchmark). Convention: thư mục con của
`benchmarks/` bắt đầu bằng `_` là private/library.

---

## Reference: Qubit smoke test đã chạy thành công

| Tier | Command | Output |
|------|---------|--------|
| 0 | `python scripts/verify_benchmark.py benchmarks/qubit/` | ALL CHECKS PASSED |
| 1 | `bash benchmarks/qubit/repro.sh` (no API key) | 4 invariants, 4 scenarios |
| 2 | LLM run | **20 invariants, 20 scenarios** |
| Tests | `python -m pytest tests/ -q` | **80 passed** |

Khi populate benchmark mới (pGALA, PolyNetwork, Wormhole) — chạy đúng 4 tier này, kết quả tương tự là pass.
