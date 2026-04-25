# Hướng dẫn Test Sprint 1 (Module 1 + Module 2)

> Hướng dẫn từng bước để chạy Sprint 1 test (unit tests, offline smoke test, LLM end-to-end).
> Môi trường: WSL2 Ubuntu 22.04, Python 3.11 trong venv `.crossllm`.

---

## 0. Chuẩn bị (một lần)

### 0.1. Đảm bảo working copy ở `~/CrossLLM` (ổ Linux)

Venv không hoạt động trên `/mnt/c/`, luôn làm việc trong `~/CrossLLM`:

```bash
# Trong WSL terminal:
ls ~/CrossLLM/.crossllm/bin/python  # phải tồn tại
```

Nếu chưa có, tạo venv:

```bash
cd ~
python3.11 -m venv CrossLLM/.crossllm
source ~/CrossLLM/.crossllm/bin/activate
cd ~/CrossLLM
pip install --upgrade pip
pip install -r requirements.txt
```

### 0.2. Sync code từ Windows sang WSL

Khi bạn chỉnh code trên Windows (Cursor), sync sang WSL trước khi test:

```bash
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/src/ \
        ~/CrossLLM/src/

rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/tests/ \
        ~/CrossLLM/tests/

rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/benchmarks/ \
        ~/CrossLLM/benchmarks/

rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/schemas/ \
        ~/CrossLLM/schemas/

rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/.env \
        ~/CrossLLM/.env
```

> **Mẹo:** Có thể dán block trên thành alias `alias sync-crossllm='...'` trong `~/.bashrc`.

### 0.3. Load biến môi trường `.env`

```bash
cd ~/CrossLLM
set -a
source .env
set +a

# Xác nhận:
echo "${NVIDIA_API_KEY:0:15}..."   # phải ra "nvapi-96YkCMO..."
echo "$NVIDIA_MODEL"                # phải ra "openai/gpt-oss-120b"
```

> `set -a ... set +a` tự động export mọi biến trong `.env`. Nếu dùng `export $(grep -v "^#" .env | xargs)` có thể fail vì URL chứa `=`.

---

## 1. Unit Tests (offline — không gọi API)

**Mục đích:** Verify logic code, chạy nhanh, không tốn API credit.

```bash
cd ~/CrossLLM
source .crossllm/bin/activate

# Chạy toàn bộ test suite
python -m pytest tests/ -v
```

**Kết quả mong đợi:**

```
tests/test_atg_builder.py::test_atg_node_creation PASSED
tests/test_atg_builder.py::test_atg_edge_creation PASSED
tests/test_atg_builder.py::test_atg_structure PASSED
tests/test_common_llm_client.py::test_get_llm_client_returns_none_without_credentials PASSED
tests/test_common_llm_client.py::test_get_llm_client_skips_placeholder_keys PASSED
tests/test_common_llm_client.py::test_get_llm_client_picks_openai_when_only_openai_set PASSED
tests/test_common_llm_client.py::test_get_llm_client_prefers_nvidia_auto PASSED
tests/test_common_llm_client.py::test_get_llm_client_prefer_override PASSED
tests/test_common_llm_client.py::test_with_retry_passes_through_on_success PASSED
tests/test_common_llm_client.py::test_with_retry_raises_non_retryable PASSED
tests/test_common_llm_client.py::test_with_retry_recovers_after_transient PASSED
tests/test_module1_semantic.py::test_extractor_builds_semantics PASSED
tests/test_module1_semantic.py::test_atg_builder_outputs_edges PASSED
tests/test_module1_semantic.py::test_invariant_synthesizer_outputs_core_categories PASSED
tests/test_module1_semantic.py::test_invariant_synth_fallback_without_api PASSED
tests/test_module1_semantic.py::test_invariant_synth_consistency_drops_duplicates PASSED
tests/test_module1_semantic.py::test_invariant_synth_parses_wrapped_json_response PASSED
tests/test_module1_semantic.py::test_invariant_synth_rejects_missing_fields PASSED
tests/test_module2_rag.py::test_knowledge_base_load_and_filter PASSED
tests/test_module2_rag.py::test_embedder_search_returns_results PASSED
tests/test_module2_rag.py::test_scenario_generator_fallback_shape PASSED
tests/test_module2_rag.py::test_fallback_templates_differ_by_vuln_class PASSED
tests/test_module2_rag.py::test_state_based_waypoints_use_predicates PASSED
tests/test_module2_rag.py::test_zero_root_predicate_triggered_for_nomad_style_action PASSED
tests/test_module2_rag.py::test_template_registry_covers_primary_vuln_classes PASSED
tests/test_module2_rag.py::test_instantiate_template_substitutes_contract_and_defaults PASSED

======================= 26 passed in ~48s =======================
```

> Lần đầu chạy sẽ download `sentence-transformers/all-MiniLM-L6-v2` (~90MB) mất ~30s. Các lần sau cache sẵn chỉ ~15s.

### Chạy 1 file test cụ thể

```bash
# Ví dụ: chỉ test Module 2
python -m pytest tests/test_module2_rag.py -v

# Chỉ 1 test
python -m pytest tests/test_module2_rag.py::test_fallback_templates_differ_by_vuln_class -v
```

### Dừng khi có test đầu tiên fail (`-x`)

```bash
python -m pytest tests/ -x -v
```

---

## 2. Offline Smoke Test (không cần API key)

**Mục đích:** Verify pipeline end-to-end (Module 1 → Module 2) chạy được mà không cần LLM.
Sẽ dùng fallback deterministic (4 invariants + 7 templates).

```bash
cd ~/CrossLLM
source .crossllm/bin/activate

# KHÔNG load .env — để fallback
unset NVIDIA_API_KEY OPENAI_API_KEY

python -m src.orchestrator \
    --benchmark benchmarks/nomad/ \
    --time-budget 10 \
    --runs 1 \
    --rag-k 2 \
    --skip-fuzzer \
    --output results/smoke_offline/
```

**Kết quả mong đợi:**

```
[Module 1] Extracting semantics from benchmarks/nomad/...
[Module 2] Generating attack scenarios via RAG...
[Module 3] Skipped by --skip-fuzzer
[Output] Aggregating results...
[Output] Saved report to results/smoke_offline/report.json
```

**Output files:**

```bash
cat results/smoke_offline/report.json
# {
#   "module1": {"invariants": 4, ...},
#   "module2": {"scenarios": 4}
# }
```

---

## 3. LLM End-to-End Test (với NVIDIA NIM)

**Mục đích:** Verify Module 1 LLM sinh 15-20 invariants + Module 2 sinh 15-20 scenarios đa dạng.

**Thời gian:** ~60-120 giây (tuỳ latency NVIDIA NIM + số invariants).

### 3.1. Chuẩn bị

```bash
cd ~/CrossLLM
source .crossllm/bin/activate

# Load .env
set -a && source .env && set +a

# Verify key hoạt động
python -c "
from src.common.llm_client import get_llm_client
p = get_llm_client()
print('Provider:', p.provider_name, p.model)
"
# Expected: Provider: nvidia openai/gpt-oss-120b
```

### 3.2. Chạy orchestrator

```bash
# Xoá result cũ (nếu có)
rm -rf results/sprint1_final

python -m src.orchestrator \
    --benchmark benchmarks/nomad/ \
    --time-budget 10 \
    --runs 1 \
    --rag-k 2 \
    --skip-fuzzer \
    --output results/sprint1_final/
```

**Output mong đợi:**

```
[Module 1] Extracting semantics from benchmarks/nomad/...
[Module 2] Generating attack scenarios via RAG...
[Module 3] Skipped by --skip-fuzzer
[Output] Saved report to results/sprint1_final/report.json
```

### 3.3. Kiểm tra output

```bash
cat results/sprint1_final/report.json
```

**Kết quả thực tế (đã chạy):**

```json
{
  "benchmark": "nomad",
  "artifacts": {
    "atg": "results/sprint1_final/atg.json",
    "hypotheses": "results/sprint1_final/hypotheses.json"
  },
  "module1": {
    "contracts_processed": 4,
    "entities": 6,
    "edges": 3,
    "invariants": 21
  },
  "module2": {
    "scenarios": 21
  },
  "module3": {
    "runs_attempted": 0,
    "runs_completed": 0,
    "violations_total": 0
  }
}
```

> **Paper target:** "18.3 candidates, 12.1 final" — thực tế đạt **21 invariants** ✓

### 3.4. Xem chi tiết invariants

```bash
python - <<'PY'
import json
d = json.load(open("results/sprint1_final/atg.json"))
print("Total invariants:", len(d["invariants"]))
print()

# Group by category
by_cat = {}
for inv in d["invariants"]:
    by_cat.setdefault(inv["category"], []).append(inv)

for cat, invs in sorted(by_cat.items()):
    print(f"== {cat} ({len(invs)}) ==")
    for i in invs:
        print(f"  - {i['invariant_id']}: {i['description'][:80]}")
    print()
PY
```

### 3.5. Xem chi tiết scenarios

```bash
python - <<'PY'
import json
h = json.load(open("results/sprint1_final/hypotheses.json"))
print("Total scenarios:", len(h["scenarios"]))
print()

for s in h["scenarios"]:
    print(f"  {s['scenario_id']}")
    print(f"    target_invariant: {s['target_invariant']}")
    print(f"    vulnerability_class: {s['vulnerability_class']}")
    print(f"    confidence: {s.get('confidence')}")
    print(f"    actions: {len(s['actions'])}, waypoints: {len(s['waypoints'])}")
    # First action
    if s["actions"]:
        a = s["actions"][0]
        op = a.get("function") or a.get("action") or "?"
        print(f"    first_action: step {a['step']} [{a['chain']}] {op}")
    print()
PY
```

### 3.6. Xem 1 scenario cụ thể với actions đầy đủ

```bash
python - <<'PY'
import json
h = json.load(open("results/sprint1_final/hypotheses.json"))

# Pick first replay-like scenario
target = next((s for s in h["scenarios"] if "replay" in s["vulnerability_class"].lower()), h["scenarios"][0])
print(json.dumps(target, indent=2, ensure_ascii=False))
PY
```

---

## 4. So sánh offline vs LLM

```bash
# Giả sử đã chạy cả hai: results/smoke_offline + results/sprint1_final

python - <<'PY'
import json
off = json.load(open("results/smoke_offline/report.json"))
llm = json.load(open("results/sprint1_final/report.json"))

print(f"{'Metric':<20}{'Offline':<15}{'LLM (NVIDIA)':<15}")
print("-" * 50)
print(f"{'Invariants':<20}{off['module1']['invariants']:<15}{llm['module1']['invariants']:<15}")
print(f"{'Scenarios':<20}{off['module2']['scenarios']:<15}{llm['module2']['scenarios']:<15}")

print("\n=== Offline vulnerability classes ===")
oh = json.load(open("results/smoke_offline/hypotheses.json"))
classes_off = {s['vulnerability_class'] for s in oh['scenarios']}
print(f"  {len(classes_off)} classes: {classes_off}")

print("\n=== LLM vulnerability classes ===")
lh = json.load(open("results/sprint1_final/hypotheses.json"))
classes_llm = {s['vulnerability_class'] for s in lh['scenarios']}
print(f"  {len(classes_llm)} classes (showing first 10):")
for c in list(classes_llm)[:10]:
    print(f"    - {c}")
PY
```

**Ví dụ output:**

```
Metric              Offline        LLM (NVIDIA)
--------------------------------------------------
Invariants          4              21
Scenarios           4              21

=== Offline vulnerability classes ===
  4 classes: {'signature_forgery', 'replay_attack', 'timeout_manipulation', 'state_desync'}

=== LLM vulnerability classes ===
  20 classes (showing first 10):
    - root_replay_tampering
    - calldata_tampering
    - integer_overflow_truncation
    - storage_collision_via_ERC777_hook
    - fee_recipient_parameter_tampering
    - batch_root_tampering_nonce_reuse
    - timestamp_tampering
    - relay_root_forgery
    - upgradable_replica_state_reset
    - root_acceptance_tampering
```

LLM sinh ra vulnerability classes **rất cụ thể cho Nomad bridge** (dùng RAG retrieval + contextual reasoning), thay vì fallback dùng template chung.

---

## 5. Kéo kết quả từ WSL về Windows

```bash
rsync -a ~/CrossLLM/results/ \
        /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/results/
```

Sau đó mở trên Windows để xem trong Cursor:
```
c:\Users\INNOTECH\Documents\Blockchain\Blockchain\CrossLLM\results\sprint1_final\
  atg.json          (300 lines — LLM invariants)
  hypotheses.json   (1915 lines — LLM scenarios)
  report.json       (summary)
```

---

## 6. Troubleshooting

### Lỗi: `ModuleNotFoundError: No module named 'src'`

Đang chạy từ sai thư mục. Phải chạy từ `~/CrossLLM`:

```bash
cd ~/CrossLLM
python -m src.orchestrator ...
# KHÔNG: python src/orchestrator.py
```

### Lỗi: `FileNotFoundError: No Solidity contracts found in benchmarks/nomad/contracts`

`benchmarks/` chưa sync sang WSL. Chạy lại sync ở bước 0.2.

### Lỗi: `.env` không load

Không dùng `export $(grep -v "^#" .env | xargs)` vì URL chứa ký tự đặc biệt. Dùng:

```bash
set -a && source .env && set +a
```

### LLM call timeout / chậm

gpt-oss-120b là reasoning model, mỗi call có thể mất 30-60s. Với 20+ invariants ≈ 60-120s tổng. Cách khắc phục:

```bash
# Đổi sang model nhanh hơn (non-reasoning)
export NVIDIA_MODEL=meta/llama-3.3-70b-instruct
python -m src.orchestrator ...
```

### Test fail: `test_knowledge_base_load_and_filter`

`src/module2_rag/data/` phải chứa ít nhất 2 JSON records. Verify:

```bash
ls ~/CrossLLM/src/module2_rag/data/
# Phải có: sample_exploits.json (ít nhất)
```

### Test quá chậm (> 2 phút)

`sentence-transformers` đang download model lần đầu. Sau lần đầu cache sẽ ở `~/.cache/huggingface/`, các lần sau nhanh hơn.

### Memory issues

WSL mặc định chỉ có 8GB. `sentence-transformers` + fuzzer có thể dùng nhiều. Tăng WSL memory:

```powershell
# Trên Windows PowerShell (Admin)
notepad $env:USERPROFILE\.wslconfig
```

Thêm:
```ini
[wsl2]
memory=16GB
processors=8
```

Rồi `wsl --shutdown` và mở lại.

---

## 7. Quick Commands Cheat Sheet

| Mục đích | Lệnh |
|----------|------|
| Sync code từ Windows | `rsync -a /mnt/c/Users/.../CrossLLM/src/ ~/CrossLLM/src/` |
| Activate venv | `source ~/CrossLLM/.crossllm/bin/activate` |
| Load .env | `cd ~/CrossLLM && set -a && source .env && set +a` |
| Chạy test suite | `python -m pytest tests/ -v` |
| Chạy 1 test file | `python -m pytest tests/test_module2_rag.py -v` |
| Smoke test offline | `unset NVIDIA_API_KEY && python -m src.orchestrator --benchmark benchmarks/nomad/ --time-budget 10 --skip-fuzzer --output results/offline/` |
| Full LLM test | `python -m src.orchestrator --benchmark benchmarks/nomad/ --time-budget 10 --skip-fuzzer --output results/llm/` |
| Sync results về Windows | `rsync -a ~/CrossLLM/results/ /mnt/c/.../CrossLLM/results/` |

---

## 8. Metric Summary (Sprint 1 achievements)

| Metric | Before Sprint 1 | After Sprint 1 (NVIDIA NIM) |
|--------|-----------------|----------------------------|
| Invariants per bridge | 4 hardcoded | **~21 dynamic** |
| Invariant categories | 4 fixed | 4 categories, many IDs each |
| Scenario vulnerability classes | 4 templates | **~20 unique classes** |
| Scenarios per bridge | 4 | **~21** (paper target: 18.3) |
| LLM integration | Partial | Full (Module 1 + 2) |
| Retry / backoff | None | Exponential (30s for rate limit) |
| Offline fallback | Missing or naive | Deterministic + template-based |
| Test coverage | 6 tests | **26 tests** (all pass) |

---

*File này đi kèm với [`PLAN_IMPROVE_MEMBER_A.md`](PLAN_IMPROVE_MEMBER_A.md) (kế hoạch chi tiết) và [`PLAN_IMPLEMENTATION.md`](PLAN_IMPLEMENTATION.md) (kế hoạch tổng).*
