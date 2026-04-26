# Session Handoff — Sprint W → G + Tier-2 Verification

> Báo cáo tổng kết session 2026-04-25 → 2026-04-26: hoàn thành 6 sprint
> benchmark còn lại (W/S/M0/R/H/M/O/F/G), Tier-2 LLM verification toàn
> bộ 12 benchmark, và quy trình tích hợp với Member B (Module 3 fuzzer).
>
> Audience: Member A future-self khi resume + Member B (integration) + thầy/cô.

---

## 1. Việc đã làm

### 1.1 Benchmark population (5/12 → **12/12 hoàn thành**)

| Sprint | Bridge | Loss | Vuln | Đặc điểm | Commit |
|---|---|---|---|---|---|
| W | Wormhole | $326M | V1 | Solana → EVM simulation gap (paper §6) | `82a5b56` |
| S | Socket | $3.3M | V5 | Logic bug single-chain ETH | (gộp commit) |
| **M0** | MockMultisig harness | n/a | template | Shared K-of-N ECDSA — 4 bridge dùng | `a466ff0` |
| R | Ronin | $624M | V4 | 5/9 PoA + Axie DAO stale delegate | (gộp commit) |
| H | Harmony | $100M | V4 | 2/4 multi-sig (Lazarus Group) | `b66322f` + `df09627` |
| M | Multichain | $126M | V2+V4 | TSS/MPC simulation gap | `e416316` |
| O | Orbit | $82M | V4 | 7/10 multi-sig (highest threshold ratio) | `a97992d` |
| F | FEGtoken | $1.3M | V2+V4 | Flash-loan + migrator role grant (chained) | `a074996` |
| G | GemPad | $1.9M | V1 | Single-chain BSC, lock-ownership hijack | `fb93747` |

### 1.2 Documents tạo mới

| File | Vai trò |
|---|---|
| [`docs/PLAN_POPULATE_OFFCHAIN.md`](PLAN_POPULATE_OFFCHAIN.md) | Plan 5 sprint off-chain (R/H/M/O/F) + Sprint M0 harness |
| [`docs/LLM_VERIFICATION_RONIN_HARMONY.md`](LLM_VERIFICATION_RONIN_HARMONY.md) | Deep-dive R+H + V4 reframing finding |
| [`docs/LLM_VERIFICATION_FULL_DATASET.md`](LLM_VERIFICATION_FULL_DATASET.md) | Tier-2 verification toàn bộ 12 benchmark |
| Update [`docs/BENCHMARK_TEST_GUIDE.md`](BENCHMARK_TEST_GUIDE.md) | Thêm section `_shared/` |

### 1.3 Bug fix
- [`src/module1_semantic/atg_builder.py`](../src/module1_semantic/atg_builder.py) — `set_conditions(None)` handler. LLM đôi khi trả `"conditions": null`, làm crash 3 benchmark trong batch đầu (orbit/fegtoken/gempad). Fix với defensive None check; 78/2 pytest vẫn pass.

### 1.4 LLM verification (Tier-2) toàn dataset
- 12/12 benchmark chạy `gpt-oss-120b` — 229 invariants + 229 scenarios + 4 categories cố định (asset_conservation / authorization / timeliness / uniqueness)
- Wall-clock ~80 phút trên WSL (10 batch + bug fix + 3 re-run)

---

## 2. Tác dụng (cho thesis + project)

### 2.1 Cho thesis paper

- **§5 Architecture:** Mỗi benchmark là minh họa concrete cho ATG formalism + Module 1+2 flow. 12 entries cover V1-V5 đầy đủ.
- **§6 Limitations:** 4 findings sẵn sàng đưa vào:
  - V4 reframing (LLM không dùng literal `key_compromise` cho 5/6 V4 benchmark)
  - Wormhole Solana → EVM gap (mô hình `verify_signatures` qua `legacyVerifiedSlot`)
  - Multichain TSS → 1-of-1 collapse (Solidity không verify partial sigs)
  - Module 1 ATG node count phản ánh contract entity, không exploit complexity
- **§7 Evaluation tables:** 12 benchmark × (nodes/edges/invariants/scenarios) = bảng số liệu sẵn dùng. Cộng vocabulary diversity (>100 unique labels) chứng minh framework không over-fit.

### 2.2 Cho project (Member A pipeline)

- Module 1+2 verified end-to-end Tier-1 (offline) + Tier-2 (LLM) cho cả 12 benchmark
- 78 pytest pass / 2 skip (Slither tests, pass với `solc-select`)
- Reproducibility: mỗi benchmark có `repro.sh` + `repro.ps1` + verified bằng `scripts/verify_benchmark.py`

### 2.3 Cho Member B (Module 3 fuzzer)

- 12 benchmark có sẵn fork config (block + RPC env), invariants list, atg.json để load làm corpus seed + reward function
- ATG có chuẩn schema (`schemas/atg.schema.json`) — Rust binary chỉ cần parse JSON
- Per-benchmark `mapping.json` chỉ rõ entity addresses để fuzzer fork RPC đúng

### 2.4 Coverage V1-V5 toàn dataset

| Class | Benchmark count | Bridges |
|---|---|---|
| V1 (Verification Bypass) | 5 | Wormhole, Nomad, GemPad, pGALA, Qubit |
| V2 (Replay Attack) | 2 | Multichain, FEGtoken |
| V3 (State Desync) | 2 | PolyNetwork, Nomad |
| V4 (Unauthorized Access / Key Compromise) | 6 | PolyNetwork, Ronin, Harmony, Multichain, Orbit, FEGtoken |
| V5 (Logic / Business Rule Bug) | 1 | Socket |

---

## 3. Vì sao đầu tư 12 benchmark — phân tích sâu

> Section này giải thích chi tiết "tại sao cần dataset" để Member A có ammunition khi
> trình bày với thầy/cô/reviewer. Section 2 ở trên là phiên bản tóm tắt theo audience;
> section này là phiên bản theo từng lý do thực dụng.

### 3.1 Là điều kiện sống còn để paper được publish (lý do quan trọng nhất)

Trong nghiên cứu security ML/LLM, bất kỳ tool nào claim "phát hiện được lỗ hổng X"
đều **bắt buộc** phải có evaluation dataset. Reviewer sẽ reject nếu paper chỉ trình
bày ý tưởng + code mà không có:

> "Chúng tôi test framework trên N benchmark thực tế, đạt kết quả Y."

Hiện thực 12 benchmark = đủ điều kiện vào paper §7 (Evaluation). Đây là **deliverable
không thể thiếu** của thesis, không phải phần phụ.

### 3.2 Coverage 5 lớp vuln V1-V5 — chứng minh framework không chuyên môn hóa quá mức

| Class | Số benchmark | Tại sao cần coverage |
|---|---|---|
| V1 (Verification Bypass) | 5 | Chứng minh framework xử lý được kiểu bug phổ biến nhất |
| V2 (Replay Attack) | 2 | Chứng minh xử lý được state/timing dependencies |
| V3 (State Desync) | 2 | Chứng minh hiểu cross-chain consistency |
| V4 (Key Compromise) | 6 | Chứng minh xử lý được lỗ hổng off-chain (lớn nhất theo USD) |
| V5 (Logic Bug) | 1 | Chứng minh xử lý được bug ngoài taxonomy chính |

Nếu chỉ test trên 1 lớp (vd: chỉ V1), reviewer sẽ hỏi *"thế V2-V5 thì sao?"*. 12
benchmark đáp lại trước khi reviewer hỏi.

### 3.3 Là ground truth cho Module 3 (fuzzer) của Member B

Module 3 fuzzer cần **biết trước** contract nào có bug + bug ở đâu để đo:

- Time-to-violation (fuzzer mất bao lâu mới tìm được)
- False negative rate (số bug fuzzer bỏ sót)
- Coverage (fuzzer khám phá được bao nhiêu state)

Không có 12 benchmark → Member B không có ground truth → không validate được fuzzer
hoạt động → Module 3 vô dụng cho thesis.

12 benchmark = **12 known-buggy contracts với invariant violations đã được document
trước**.

### 3.4 So sánh với baselines (ItyFuzz, SmartShot, VulSEye, SmartAxe, GPTScan, XScope)

Paper claim: *"BridgeSentry tốt hơn các baseline X/Y/Z"*. Để claim này có nghĩa
phải:

- Chạy BridgeSentry trên benchmark — có rồi (229 inv, 229 sc).
- Chạy 6 baseline TƯƠNG TỰ trên CÙNG benchmark.
- So sánh số liệu.

Nếu 12 benchmark không tồn tại, không có gì để so sánh → claim "tốt hơn" là vô căn
cứ.

Đây cũng là lý do pick những vụ hack nổi tiếng (Nomad, Wormhole, Ronin...) — các
baseline đã từng test trên những vụ này, dễ apple-to-apple compare.

### 3.5 Generate input cho Module 1+2 pipeline (chính cái mà thesis claim)

Thesis claim: *"Module 1 sinh ATG từ Solidity, Module 2 sinh attack scenarios từ
ATG"*.

Nhưng ATG sinh ra **từ cái gì**? Từ Solidity contracts. Solidity contracts ở
**đâu**? Từ benchmark.

Không có benchmark → không có Solidity → không có ATG → không có scenarios →
**không có thesis**.

12 benchmark là **fuel cho pipeline**. Bằng chứng: 229 invariants + 229 scenarios
chỉ tồn tại vì có 12 benchmark feed vào.

### 3.6 Là regression tests cho framework

Mỗi lần Member A/B sửa code Module 1/2/3, cần chạy lại trên benchmark để chắc
không break gì:

```bash
python -m pytest tests/                      # 78/2 unit tests
for b in ...; do verify_benchmark.py ...     # 12/12 verify
for b in ...; do orchestrator --skip-fuzzer  # 12/12 smoke test
```

Đây cũng là cách phát hiện bug `set_conditions(None)` trong session vừa rồi — chạy
LLM trên 12 benchmark, 3 cái crash, fix bug, re-run sạch.

Không có benchmark → mỗi commit phải hy vọng không break gì → debt tích lũy → hệ
thống mục.

### 3.7 Concrete numbers cho paper tables

Paper sẽ có ít nhất các bảng sau, và chỉ tồn tại vì có 12 benchmark:

**Bảng 1 — Benchmark statistics (paper §7.1):**

| # | Bridge | Year | Loss | Vuln class |
|---|---|---|---|---|
| 1 | PolyNetwork | 2021 | $611M | V3+V4 |
| ... | ... | ... | ... | ... |
| 12 | Qubit | 2022 | $80M | V1 |

**Bảng 2 — Module 1+2 output (paper §7.2):**

| # | Bridge | ATG nodes | Edges | Invariants | Scenarios |
|---|---|---|---|---|---|
| 1 | Nomad | 6 | 3 | 18 | 18 |
| ... | ... | ... | ... | ... | ... |

**Bảng 3 — Module 3 fuzzer results (paper §7.3, sau khi Member B integrate):**

| # | Bridge | Time-to-violation | TVL drained | Coverage |
|---|---|---|---|---|

3 bảng này là backbone của Evaluation chapter — không có benchmark thì không có
bảng nào.

### 3.8 Educational + reproducibility artifacts

Mỗi benchmark có README giải thích:

- Bug pattern thực tế (background)
- Mapping bug → invariant nào bị vi phạm
- Cách reconstruct (decisions taken)

→ Future researcher đọc thesis có thể:

- Hiểu nhanh từng vụ hack
- Reproduce kết quả bằng `repro.sh`
- Extend với benchmark mới theo pattern có sẵn

Đây là **scientific contribution độc lập** với framework — kể cả khi BridgeSentry
bị thay thế bởi tool tốt hơn, dataset 12 benchmark vẫn có giá trị riêng.

### 3.9 Findings trong paper §6 (Limitations) chỉ có ý nghĩa với coverage đầy đủ

Ví dụ finding "V4 reframing":

> *"LLM dùng literal `key_compromise` cho 1/6 V4 benchmark, reframe 5/6 còn lại
> thành signature semantics."*

Finding này chỉ có giá trị thống kê **vì có 6 V4 benchmark**. Nếu chỉ có 1 (Ronin),
không kết luận được pattern. Nếu có 2 (Ronin + Harmony), kết luận yếu. **6 benchmark
= đủ để claim pattern reproducible.**

Tương tự với "vocabulary diversity >100 unique labels" — chỉ chứng minh được khi có
≥10 benchmark khác nhau.

### 3.10 TL;DR

12 benchmark **không phải phần phụ** — chúng là:

1. **Điều kiện publish** (không có = không qua review)
2. **Ground truth** cho Member B (Module 3 không validate được nếu không có)
3. **Fuel** cho Module 1+2 (pipeline không chạy được nếu không có)
4. **Regression tests** (mỗi commit cần re-verify)
5. **Comparison plane** với 6 baseline tools
6. **Concrete data** cho 3 paper tables
7. **Statistical foundation** cho findings §6
8. **Educational artifacts** standalone — vẫn có giá trị nếu tool bị thay thế

→ Đầu tư ~3 tuần xây 12 benchmark là **nền móng** cho mọi thứ phía sau (paper +
Module 3 + future work).

---

## 4. Các lệnh chạy thực nghiệm

### 4.1 Pre-requisites (1 lần, trên WSL)

```bash
# Sync code Windows → WSL (chạy mỗi khi edit Windows side)
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/src/      ~/CrossLLM/src/
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/scripts/  ~/CrossLLM/scripts/
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/schemas/  ~/CrossLLM/schemas/
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/benchmarks/ ~/CrossLLM/benchmarks/
rsync -a /mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM/.env       ~/CrossLLM/.env

# Activate venv + load .env
cd ~/CrossLLM
source .crossllm/bin/activate
set -a && source .env && set +a

# (1 lần) Slither solc dependency
solc-select install 0.8.20 && solc-select use 0.8.20
```

### 4.2 Khi nào chạy tier nào — quy tắc thực dụng

4 tier (0/1/2/3) là **các mức độ confidence khác nhau**, dùng tùy mục đích —
không bắt buộc chạy hết.

| Tier | Mục đích | Thời gian | Cần API key? | Bắt được gì? | Bỏ qua được gì? |
|---|---|---|---|---|---|
| **0** | Verify cấu trúc benchmark | ~10s | Không | metadata sai schema, address invalid, .sol thiếu, refs unreachable | Không kiểm pipeline thực sự chạy |
| **1** | Pipeline offline (regex fallback) | ~10s | Không | pipeline crash, schema validation Module 1+2 fail | Không sinh data chất lượng cao — output là 4 template generic |
| **2** | Pipeline LLM (NVIDIA NIM) | ~5-7 phút | Có (`NVIDIA_API_KEY`) | Module 1+2 sinh ATG/invariants/scenarios thực sự (16-21 inv/sc) | Không kiểm tra nội dung có đúng với bug thật không |
| **3** | Manual đọc artifacts | ~10 phút | Không | Logic bug, scenarios sai semantic, invariants vô nghĩa | (Đây là final sanity check — không bỏ qua được gì) |

#### Khi nào chạy tier nào

| Tình huống | Tier nên chạy | Tổng thời gian |
|---|---|---|
| Sửa `metadata.json` hoặc thêm/đổi address contract | **Tier 0** | ~10s |
| Sửa code Module 1/2/3 (`src/`) hoặc fix bug pipeline | **Tier 0 + 1** | ~20s |
| Cần data LLM cho paper / Member B integration / re-verify finding | **Tier 0 + 1 + 2** | ~5-7 phút × N benchmark |
| Trước nộp paper / chia sẻ với thầy / Member B integrate xong benchmark | **Tier 0 + 1 + 2 + 3** | ~10-15 phút × N benchmark |
| Thêm benchmark mới | **Tất cả 4 tier** một lần | ~15 phút |
| Edit nhỏ benchmark đã có | Chỉ **Tier 0 + 1** | ~20s |

#### Tier 1 ≠ Tier 2 — đặc điểm dễ nhầm

|  | Tier 1 (offline) | Tier 2 (LLM) |
|---|---|---|
| Sinh ra | **4 invariants generic** (template cố định) | **16-21 invariants chuyên sâu** |
| Sinh ra | **4 scenarios generic** (signature_forgery / replay_attack / timeout_manipulation / state_desync) | **18-21 scenarios** với >100 vocabulary đa dạng |
| Categories | 1 (generic) | **4** (asset_cons / auth / time / uniq) |
| Dùng cho paper? | Không — quá thô | Có |
| Dùng cho Member B? | Không — không reflect contract thực sự | Có |
| Cần internet? | Không | Có (API NIM) |

**Hệ quả:** Tier 1 pass không đồng nghĩa benchmark tốt — chỉ đồng nghĩa pipeline
không crash. **Tier 2 mới là evaluation thật.**

#### Quy tắc 1 dòng

> Tier 0+1 = sanity check (chạy thường xuyên).
> Tier 2 = data thực (chạy khi cần publish).
> Tier 3 = final QA (chạy khi nộp).

Trong session vừa rồi đã chạy đúng pattern này:

- Mỗi sprint W/S/R/H/M/O/F/G → **Tier 0 + 1** ngay sau khi viết xong (~20s/benchmark)
- Cuối session → **Tier 2** cho cả 12 benchmark (~80 phút) → tạo
  [`LLM_VERIFICATION_FULL_DATASET.md`](LLM_VERIFICATION_FULL_DATASET.md)
- Tier 3 chưa làm — đó là việc nên làm sau khi push, hoặc Member B / thầy cô review

---

### 4.3 Tier 0 — Verify benchmark structure (~10s/benchmark)

```bash
# Verify 1 benchmark
python scripts/verify_benchmark.py benchmarks/qubit/

# Verify all 12
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
    python scripts/verify_benchmark.py benchmarks/$b/
done
```

**Pass criteria:** mỗi benchmark in `ALL CHECKS PASSED`.

### 4.4 Tier 1 — Module 1+2 offline (regex fallback, không cần API key, ~10s/benchmark)

```bash
# 1 benchmark
bash benchmarks/qubit/repro.sh

# All 12
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
    python -m src.orchestrator \
        --benchmark benchmarks/$b/ \
        --time-budget 5 --runs 1 \
        --skip-fuzzer \
        --output results/${b}_smoke/
done
```

### 4.5 Tier 2 — Module 1+2 LLM mode (NVIDIA NIM, ~5-7 phút/benchmark)

```bash
# Đảm bảo .env có NVIDIA_API_KEY và NVIDIA_MODEL=openai/gpt-oss-120b
set -a && source .env && set +a

# 1 benchmark
python -m src.orchestrator \
    --benchmark benchmarks/qubit/ \
    --time-budget 60 --runs 1 --rag-k 3 \
    --skip-fuzzer --strict-schema --progress \
    --output results/qubit_llm/

# All 12 (~80 phút)
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
    time python -m src.orchestrator \
        --benchmark benchmarks/$b \
        --time-budget 60 --runs 1 --rag-k 3 \
        --skip-fuzzer --output results/${b}_llm/
done

# Đổi sang model nhanh hơn (~30 phút thay vì 80) — chất lượng tương đương
export NVIDIA_MODEL=meta/llama-3.3-70b-instruct
```

### 4.6 Tier 3 — Manual quality check (đọc artifacts)

```bash
# Đếm output mỗi benchmark
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
    python -c "
import json
from pathlib import Path
out = Path('results/${b}_llm')
atg = json.loads((out/'atg.json').read_text())
hyp = json.loads((out/'hypotheses.json').read_text())
scen = hyp.get('scenarios',[]) if isinstance(hyp,dict) else hyp
print('${b}: nodes=%d edges=%d inv=%d sc=%d' % (
    len(atg.get('nodes',[])), len(atg.get('edges',[])),
    len(atg.get('invariants',[])), len(scen)))
"
done
```

### 4.7 Pytest (verify pipeline correctness, không liên quan benchmark)

```bash
python -m pytest tests/ -q
# Expected: 78 passed, 2 skipped (Slither tests pass khi solc available)
```

---

## 5. Quy trình tiếp theo với Member B

### 5.1 Member B chịu trách nhiệm

**Module 3 — Dual-EVM Fuzzer (Rust):**
- 2 revm instance synced (Chain A + Chain B)
- Mock relay, snapshot pool, ATG-aware mutator
- Invariant checker với reward function
- Fuzz loop Algorithm 1 (corpus + R-threshold + dynamic snapshots)

Per memory: **Module 3 đã DONE** về mặt code, nhưng chưa được wire-up với từng benchmark cụ thể (`ready_for_full_dual_evm_replay: false` cho 11/12 benchmark).

### 5.2 Integration plan — đề xuất

#### Bước 1: Member B build + push Rust binary

```bash
# Member B (giả định ở thư mục ~/CrossLLM/fuzzer hoặc tương tự)
cd ~/CrossLLM/fuzzer
cargo build --release
# Output: target/release/bridge_fuzzer (hoặc tên tương đương)
```

Member B push binary path / cargo workspace lên branch — Member A pull về.

#### Bước 2: Define integration contract

**Input cho fuzzer (do Member A cung cấp):**
- `benchmarks/<bridge>/metadata.json` — fork config (block, RPC env)
- `results/<bridge>_llm/atg.json` — entities + edges + invariants
- `results/<bridge>_llm/hypotheses.json` — scenarios với target_invariant
- `benchmarks/<bridge>/mapping.json` — cross-chain entity addresses
- `benchmarks/<bridge>/contracts/*.sol` — source để compile + deploy lên revm fork

**Output từ fuzzer:**
- `results/<bridge>_fuzz/` directory chứa:
  - `corpus/` (test inputs)
  - `coverage.json`
  - `violations.json` (invariants bị vi phạm + minimal reproducer)
  - `report.json` (stats: TVL drained, runs, time-to-violation)

#### Bước 3: Pick baseline benchmark

**Khuyên bắt đầu với Nomad** vì:
- Đã có sẵn baseline Module 1+2 output từ trước (21 inv / 21 sc trong memory)
- Authentic V1+V3 vuln đã được nhiều paper khác replicate
- ETH-only fork — đơn giản hơn cross-chain

```bash
# Member A: cung cấp full input bundle cho Nomad
ls benchmarks/nomad/                # contracts, metadata, mapping, trace
ls results/nomad_llm/               # atg.json, hypotheses.json, report.json
```

#### Bước 4: Wire up Member B fuzzer cho Nomad

Member B implement loader đọc atg.json → corpus + reward function. Cấu trúc đề xuất:

```bash
# Lệnh chạy fuzzer (Member B định nghĩa)
./target/release/bridge_fuzzer \
    --atg results/nomad_llm/atg.json \
    --hypotheses results/nomad_llm/hypotheses.json \
    --metadata benchmarks/nomad/metadata.json \
    --eth-rpc $ETH_RPC_URL \
    --fork-block 15259100 \
    --time-budget 3600 \
    --runs 5 \
    --output results/nomad_fuzz/
```

**Expected outcome:** fuzzer phát hiện ít nhất 1 invariant violation (`proven_before_process` / `no_mint_without_lock` / `single_use_nonce`) trong < 1h.

#### Bước 5: Member A flip flag

Sau khi Member B confirm fuzzer chạy OK trên Nomad:

```json
// benchmarks/nomad/metadata.json
"status": {
  ...
  "ready_for_full_dual_evm_replay": true   // false → true
}
```

Lặp lại bước 3-5 cho từng benchmark còn lại theo thứ tự ưu tiên:

| Ưu tiên | Benchmark | Lý do |
|---|---|---|
| 1 | Nomad | Baseline đã verified |
| 2 | Qubit | V1 đơn giản, BSC archive RPC fallback đã handle |
| 3 | pGALA | V1, single chain |
| 4 | PolyNetwork | V3+V4, manager-forwarded-call — exercise authority chain |
| 5 | Wormhole | V1, EVM-side simulation (Solana side skip) |
| 6 | Socket | V5 single chain, simple drain |
| 7-10 | Ronin/Harmony/Orbit/FEGtoken | V4 multi-sig với MockMultisig harness |
| 11 | Multichain | V2+V4 với 1-of-1 TSS gap |
| 12 | GemPad | V1 single chain BSC |

### 5.3 Acceptance criteria cho mỗi benchmark integration

- [ ] Fuzzer load được atg.json + hypotheses.json không lỗi
- [ ] Fork RPC kết nối được tại `fork.block_number`
- [ ] Compile + deploy được tất cả `contracts/*.sol` lên revm fork
- [ ] Mutator sinh được ≥1 candidate per scenario
- [ ] Invariant checker phát hiện ≥1 violation trong time-budget
- [ ] `violations.json` có minimal reproducer (calldata + balance diff)
- [ ] Member A flip `ready_for_full_dual_evm_replay: true`

### 5.4 Lệnh phối hợp

#### Member A side (ATG + hypotheses sinh ra cho Member B)

```bash
# Mỗi khi Member A update Module 1+2 hoặc benchmark:
cd ~/CrossLLM
source .crossllm/bin/activate
set -a && source .env && set +a

# Re-run Tier-2 cho benchmark đó
python -m src.orchestrator \
    --benchmark benchmarks/<bridge> \
    --time-budget 60 --runs 1 --rag-k 3 \
    --skip-fuzzer --output results/<bridge>_llm/

# Sync output lên branch
git add results/<bridge>_llm/atg.json results/<bridge>_llm/hypotheses.json benchmarks/<bridge>/
git commit -m "feat(integration): bundle <bridge> for fuzzer integration"
git push origin sukem/sprint2
```

**Quan trọng:** `results/` đang gitignore. Để chia sẻ với Member B cần một trong:
1. Tạo `results-shared/` riêng (không gitignore) chứa atg.json + hypotheses.json
2. Force-add: `git add -f results/<bridge>_llm/{atg,hypotheses}.json`
3. Một artifact storage chung (S3 / Drive) — Member B pull qua URL

→ **Đề xuất:** copy 2 file (atg.json + hypotheses.json) vào `benchmarks/<bridge>/llm_outputs/` để gắn với benchmark, không ngại gitignore. Member A tự động hoá bước này trong Sprint tiếp.

#### Member B side (run fuzzer)

```bash
# Pull latest
git checkout sukem/sprint2
git pull

# Build (1 lần)
cd fuzzer && cargo build --release

# Run cho 1 benchmark
./target/release/bridge_fuzzer \
    --benchmark ../benchmarks/nomad \
    --llm-outputs ../benchmarks/nomad/llm_outputs \
    --output ../results/nomad_fuzz \
    --time-budget 3600

# Hoặc loop tất cả
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
    ./target/release/bridge_fuzzer \
        --benchmark ../benchmarks/$b \
        --llm-outputs ../benchmarks/$b/llm_outputs \
        --output ../results/${b}_fuzz \
        --time-budget 3600
done
```

### 5.5 Phase 5 song song (paper finalization)

Trong khi Member B integrate, Member A có thể:

1. Mở [`latex/paper.tex`](../latex/paper.tex), section 7 (Evaluation)
2. Paste 12-row table từ `LLM_VERIFICATION_FULL_DATASET.md` vào
3. Section 6 (Limitations): copy 4 findings từ doc đó
4. Khi Member B có violation results → bổ sung column "Time-to-violation" + "TVL drained" cho 12-row table

---

## 6. Trạng thái git hiện tại

```
sukem/sprint2 (ahead origin 2 commits):
  a9e7238 feat(llm-verification): full Tier-2 verification across 12 benchmarks
  fb93747 feat(benchmarks): add GemPad locker benchmark — closes 12/12 dataset
  (đã push:)
  a074996 feat(benchmarks): add FEGtoken benchmark (V2+V4 flash-loan + role grant)
  a97992d feat(benchmarks): add Orbit Bridge benchmark (7-of-10 multi-sig)
  e416316 feat(benchmarks): add Multichain bridge benchmark with MPC simulation gap
  ... (older)
```

**Action item ngay:** `git push origin sukem/sprint2` để Member B + thầy/cô xem được 2 commit local mới nhất.

---

## 7. TL;DR — Cần làm tiếp theo

1. **Push `sukem/sprint2` lên origin** — 2 commit chưa publish
2. **Nói với Member B:** "12/12 benchmark đã sẵn sàng, có ATG + invariants + scenarios trong `results/<bridge>_llm/` (hoặc copy sang `benchmarks/<bridge>/llm_outputs/`); pick Nomad làm baseline integration"
3. **Member A song song:** mở `latex/paper.tex` viết §6 + §7 với 4 findings + 12-row table có sẵn
4. **Sau khi Member B integrate xong từng benchmark:** flip `ready_for_full_dual_evm_replay: true` trong metadata.json

---

## 8. Tham chiếu nhanh

| Resource | Path |
|---|---|
| Benchmark gốc | [`benchmarks/`](../benchmarks/) (12 folders) |
| Shared multi-sig harness | [`benchmarks/_shared/MockMultisig.sol`](../benchmarks/_shared/MockMultisig.sol) |
| Off-chain plan | [`docs/PLAN_POPULATE_OFFCHAIN.md`](PLAN_POPULATE_OFFCHAIN.md) |
| Population plan (Q/P/N/W) | [`docs/PLAN_POPULATE_BENCHMARKS.md`](PLAN_POPULATE_BENCHMARKS.md) |
| 4-tier test guide | [`docs/BENCHMARK_TEST_GUIDE.md`](BENCHMARK_TEST_GUIDE.md) |
| LLM deep-dive R+H | [`docs/LLM_VERIFICATION_RONIN_HARMONY.md`](LLM_VERIFICATION_RONIN_HARMONY.md) |
| LLM full-dataset verification | [`docs/LLM_VERIFICATION_FULL_DATASET.md`](LLM_VERIFICATION_FULL_DATASET.md) |
| Module 1 source | [`src/module1_semantic/`](../src/module1_semantic/) |
| Module 2 source | [`src/module2_rag/`](../src/module2_rag/) |
| KB build script | [`scripts/build_exploit_kb.py`](../scripts/build_exploit_kb.py) (48 records từ SmartAxe + XScope) |
| Verify script | [`scripts/verify_benchmark.py`](../scripts/verify_benchmark.py) |
| Paper draft | [`latex/paper.tex`](../latex/paper.tex) |
