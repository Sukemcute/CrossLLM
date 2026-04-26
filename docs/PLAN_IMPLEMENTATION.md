# BridgeSentry — Kế hoạch Triển khai Chi tiết

> Plan cho 2 thành viên làm việc song song, không conflict code.

---

## Đánh giá Trạng thái Hiện tại

| Thành phần | Trạng thái |
|------------|-----------|
| Tài liệu / Paper | Hoàn chỉnh (paper.tex, docs, guide) |
| Python (Module 1+2) | **Đã triển khai core:** `extractor.py`, `atg_builder.py`, `invariant_synth.py`, `knowledge_base.py`, `embedder.py` (lazy-import `SentenceTransformer` trong `_encode_texts`), `scenario_gen.py`; có test cho Module 1/2 pass. **Còn thiếu:** dữ liệu đủ 51 exploits, benchmark artifacts đủ 12 bridge, và kiểm thử end-to-end với Module 3 trên từng benchmark. |
| Rust (Module 3) | **Đã có:** `types.rs`, `config.rs` + CLI (gồm `--r-threshold`, `--max-corpus`, `--max-snapshots`, `--no-dynamic-snapshots`), `dual_evm.rs` (fork/execute + `capture_snapshot`/`restore_snapshot`), `mock_relay.rs`, `snapshot.rs` (SnapshotPool, shared-prefix `select_for_seed`), `mutator.rs`, `checker.rs` (+ `set_reward_weights` decay), `scenario_sim.rs` (+ `evaluate_waypoints`), `fuzz_loop.rs` (Alg. 1: corpus, chọn seed theo trọng số $R$, pool động), `main.rs` gọi `fuzz_loop::run` → `results.json`. |
| Benchmarks | `benchmarks/README.md` có bảng 12 exploit (fork block, hướng tấn công). **Chưa** có đủ 12 thư mục benchmark đầy đủ; **Nomad** là gói tham chiếu (`metadata` + `schema_version`, `BENCHMARK_METADATA.schema.json`, `repro.sh`/`repro.ps1`, `Message.sol` + luồng `prove`→`process`). |
| JSON schemas giao tiếp | **Đã định nghĩa:** `schemas/*.schema.json` (ATG, hypotheses, invariants, results) + `schemas/README.md`; mock fixtures trong `tests/fixtures/`. Cần **đồng bộ với Member A** (Python) trước khi coi Phase 0 schema là đóng băng. |
| Dữ liệu 51 exploit | Chưa có nội dung record (`src/module2_rag/data/` gần như trống ngoài README) |

**Mục tiêu:** Triển khai đầy đủ ~8.500 dòng Python + ~3.200 dòng Rust, đạt kết quả paper (11/12 DR, median TTE 47s).

---

## Phân chia Công việc — Ai làm gì

### Thành viên A — AI & Logic Modeling (Python)

**Sở hữu hoàn toàn — Member B KHÔNG chạm vào:**

```
src/module1_semantic/          ← TOÀN BỘ thư mục
  extractor.py                 Trích xuất ngữ nghĩa qua LLM
  atg_builder.py               Xây đồ thị ATG
  invariant_synth.py           Tổng hợp bất biến
  prompts/*                    Prompt templates

src/module2_rag/               ← TOÀN BỘ thư mục
  knowledge_base.py            Quản lý 51 exploit records
  embedder.py                  FAISS vector index
  scenario_gen.py              Sinh kịch bản tấn công RAG
  data/*                       51 file JSON exploit

src/orchestrator.py            Điều phối pipeline (A lead, B review)

tests/test_extractor.py
tests/test_atg_builder.py
tests/test_knowledge_base.py
tests/test_embedder.py
tests/test_scenario_gen.py
tests/test_orchestrator.py
```

### Thành viên B — Systems & Fuzzing (Rust)

**Sở hữu hoàn toàn — Member A KHÔNG chạm vào:**

```
src/module3_fuzzing/           ← TOÀN BỘ thư mục
  Cargo.toml                   Dependencies Rust
  src/main.rs                  CLI entry point
  src/dual_evm.rs              Dual-EVM (revm fork 2 chuỗi)
  src/mock_relay.rs            Mock relay (4 chế độ)
  src/snapshot.rs              Synced snapshot management
  src/mutator.rs               ATG-aware mutation
  src/checker.rs               Invariant checker + waypoint reward
  src/types.rs                 Shared Rust types (TẠO MỚI)
  src/config.rs                Config/CLI parsing (TẠO MỚI)

scripts/setup_env.sh
scripts/run_benchmark.sh
scripts/run_all_benchmarks.sh
Dockerfile
```

### Shared — Cả hai cùng đóng góp (qua Pull Request)

```
schemas/                       ← Đóng băng sau Phase 0
  atg.schema.json
  invariants.schema.json
  hypotheses.schema.json
  results.schema.json

benchmarks/*/                  ← A: contracts + exploit_trace, B: mapping + fork config
```

**Quy tắc vàng:** A không bao giờ chạm `src/module3_fuzzing/`. B không bao giờ chạm `src/module1_semantic/` hoặc `src/module2_rag/`.

---

## JSON Schemas — Giao diện Giao tiếp Giữa các Module

> Định nghĩa TRƯỚC khi code. Đóng băng sau Phase 0.

### Schema 1: `atg.json` (Module 1 → Module 2 + Module 3)

```json
{
  "bridge_name": "nomad",
  "version": "1.0",
  "nodes": [
    {
      "node_id": "source_router",
      "node_type": "contract",
      "chain": "source",
      "address": "0x...",
      "functions": ["deposit", "lock", "refund"]
    }
  ],
  "edges": [
    {
      "edge_id": "e1",
      "src": "user",
      "dst": "source_router",
      "label": "lock",
      "token": "WETH",
      "conditions": ["amount > 0", "msg.value == amount"],
      "function_signature": "deposit(address,uint256)"
    }
  ],
  "invariants": [
    {
      "invariant_id": "inv_asset_conservation",
      "category": "asset_conservation",
      "description": "Locked value minus fee equals minted value",
      "predicate": "sum(locked) - fee == sum(minted)",
      "solidity_assertion": "require(sourceRouter.totalLocked() - fee == destRouter.totalMinted())",
      "related_edges": ["e1", "e4"]
    }
  ]
}
```

### Schema 2: `hypotheses.json` (Module 2 → Module 3)

```json
{
  "bridge_name": "nomad",
  "scenarios": [
    {
      "scenario_id": "s1_verification_bypass",
      "target_invariant": "inv_asset_conservation",
      "vulnerability_class": "fake_deposit",
      "confidence": 0.85,
      "actions": [
        {
          "step": 1,
          "chain": "source",
          "contract": "source_router",
          "function": "deposit",
          "params": {"token": "WETH", "amount": "1000000000000000000"},
          "description": "Legitimate deposit"
        },
        {
          "step": 2,
          "chain": "relay",
          "action": "tamper",
          "params": {"field": "amount", "value": "999000000000000000000"},
          "description": "Tamper relay message"
        },
        {
          "step": 3,
          "chain": "destination",
          "contract": "dest_router",
          "function": "process",
          "params": {},
          "description": "Process tampered message"
        }
      ],
      "waypoints": [
        {
          "waypoint_id": "w1",
          "after_step": 1,
          "predicate": "sourceRouter.deposits(nonce) > 0",
          "description": "Deposit recorded on source"
        },
        {
          "waypoint_id": "w2",
          "after_step": 2,
          "predicate": "relay.pendingMessage.amount != sourceRouter.deposits(nonce).amount",
          "description": "Relay message differs from deposit"
        }
      ],
      "retrieved_exploits": ["nomad_2022", "qubit_2022"]
    }
  ]
}
```

### Schema 3: `results.json` (Module 3 → Output)

```json
{
  "bridge_name": "nomad",
  "run_id": 1,
  "time_budget_s": 600,
  "violations": [
    {
      "invariant_id": "inv_asset_conservation",
      "detected_at_s": 11.3,
      "trigger_scenario": "s1_verification_bypass",
      "trigger_trace": ["tx1_hash", "tx2_hash"],
      "state_diff": {
        "source_locked": "1000000000000000000",
        "dest_minted": "999000000000000000000"
      }
    }
  ],
  "coverage": {
    "xcc_atg": 0.78,
    "basic_blocks_source": 1234,
    "basic_blocks_dest": 987
  },
  "stats": {
    "total_iterations": 15234,
    "snapshots_captured": 47,
    "mutations_applied": 14890
  }
}
```

---

## Kế hoạch Theo Phase

> **Ký hiệu (Member B):** ✅ = Member B đã hoàn thành (hoặc phần việc của B trong task **Cả hai**).

### Phase 0: Nền tảng (Tuần 1) — CẢ HAI LÀM CÙNG

> Ngồi cùng nhau hoặc call. Mục tiêu: định nghĩa schemas, tạo benchmark đầu tiên, fixtures.

| Task | Ai | Deliverable |
|------|-----|------------|
| ✅ Tạo `schemas/` với 3 file JSON schema | Cả hai | Schemas committed, đóng băng |
| ✅ Tạo mock fixture JSON (atg_mock.json, hypotheses_mock.json) | Cả hai | Fixtures trong `tests/fixtures/` |
| ✅ Tạo benchmark Nomad hoàn chỉnh | A: contracts + trace, B: mapping + metadata | ✅ `benchmarks/nomad/`: `metadata.json` (kèm `schema_version` + `reporting`), `mapping.json`, `exploit_trace.json`, `contracts/` (`Message.sol`, `Replica`, `BridgeRouter`, `MockToken`), `repro.sh`/`repro.ps1`, `README.md`; `benchmarks/BENCHMARK_METADATA.schema.json` dùng chung |
| Verify Python venv + `pip install` | A | requirements.txt hoạt động |
| ✅ Verify `cargo check` biên dịch | B | Cargo.toml dependencies đúng |
| Tạo `.env` với API keys thật | Cả hai | OpenAI + Alchemy hoạt động |
| ✅ B thử nghiệm revm proof-of-concept | B | Fork ETH mainnet, đọc balance → thành công |

**Milestone:** Schemas đóng băng. Nomad benchmark hoàn chỉnh. Mock fixtures committed. Cả hai build thành công.

---

### Phase 1: Core Data Pipeline (Tuần 2-4) — SONG SONG

#### Member A: Module 1 — Trích xuất Ngữ nghĩa

| Tuần | File | Công việc | Test |
|------|------|-----------|------|
| 2-3 | ✅ `extractor.py` | Tích hợp OpenAI API, prompt engineering, parse JSON output. Dùng `response_format: json_object`. Retry loop 3 lần khi JSON lỗi. | ✅ Test extractor (entities/functions/asset_flows) đã pass |
| 4 | ✅ `atg_builder.py` | Nhận extraction output → xây ATG (nodes, edges, labels). Serialize/deserialize JSON. | ✅ Unit tests + serialize/deserialize đã pass |
| 4 | ✅ `invariant_synth.py` | LLM sinh invariants từ ATG. Pipeline 3 bước: sinh → validate traces → check consistency. | ✅ Test category invariants (4 nhóm chính) đã pass |

**Milestone tuần 4:** Chạy `python -c "from src.module1_semantic.extractor import SemanticExtractor; ..."` trên Nomad → sinh ra `atg.json` hợp lệ.

#### Member B: Module 3 Core — Dual-EVM + Snapshot

| Tuần | File | Công việc | Test |
|------|------|-----------|------|
| 2-3 | ✅ `dual_evm.rs` | Khởi tạo 2 revm instances. Fork ETH mainnet tại block cụ thể. Deploy contract vào EVM. Execute transaction. Thu thập kết quả. | Fork tại block 15259100. Đọc balance Nomad Replica → đúng giá trị |
| 3 | ✅ `types.rs` | Định nghĩa shared types: `GlobalState`, `TransactionResult`, `ChainId` | Compile test |
| 4 | `snapshot.rs` | Capture `GlobalSnapshot = (S_A, S_B, S_R)`. Restore đồng bộ. Differential state images. | Capture → execute tx → restore → assert state reverted |

**Milestone tuần 4:** Dual-EVM fork 2 chains, execute transaction trên mỗi chain, snapshot round-trip hoạt động.

> **CẢNH BÁO:** `dual_evm.rs` là file khó nhất toàn project. revm API phức tạp và thay đổi thường xuyên. Nếu bị stuck >1 tuần, fallback: dùng 2 process Anvil + giao tiếp qua JSON-RPC thay vì revm trực tiếp. Chậm hơn nhưng chắc chắn hoạt động.

---

### Phase 2: Sinh Kịch bản + Logic Fuzzer (Tuần 5-7) — SONG SONG

#### Member A: Module 2 — RAG Pipeline

| Tuần | File | Công việc | Test |
|------|------|-----------|------|
| 5-6 | ✅ `knowledge_base.py` | Load 51 exploit JSON records. Query theo vuln_class, attack_stage. | ✅ Load/filter tests đã pass (hiện có sample records) |
| 5-6 | `data/*.json` | **Thu thập dữ liệu:** viết 51 file JSON exploit (rekt.news, SlowMist, post-mortems). ~30 phút/record → ~25 giờ. Bắt đầu từ tuần 1 làm dần. | Schema validation mỗi file |
| 7 | ✅ `embedder.py` | SentenceTransformer (all-MiniLM-L6-v2) → FAISS index. Build index, search top-k. | ✅ Search/index tests đã pass (có fallback numpy khi thiếu deps) |
| 7 | ✅ `scenario_gen.py` | Xây prompt RAG: ATG + invariant + retrieved exploits → LLM sinh action sequence + waypoints. | ✅ Generator + waypoint extraction tests đã pass |

**Milestone tuần 7:** Chạy `Module 1 → Module 2` trên Nomad → sinh `hypotheses.json` hợp lệ với >=3 kịch bản tấn công.

#### Member B: Module 3 — Relay + Mutator + Checker

| Tuần | File | Công việc | Test |
|------|------|-----------|------|
| 5-6 | ✅ `mock_relay.rs` | 4 chế độ relay: Faithful, Delayed, Tampered, Replayed. Message queue + processed set. | Test mỗi mode riêng |
| 6 | ✅ `config.rs` | Parse CLI args, đọc JSON config (atg.json, hypotheses.json paths, time budget). | Parse example config thành công |
| 7 | ✅ `mutator.rs` | Mutation nhận biết ATG: reorder actions, substitute params (boundary/zero), insert adjacent actions, switch relay mode, advance timestamps. | Mutate seed → output khác nhưng structurally valid |
| 7 | ✅ `checker.rs` | Evaluate invariant assertions. Branch distance heuristic cho boolean invariants. Reward function R(σ) = α·cov + β·waypoints + γ·inv_dist. | Feed violated state → `violated: true`. Feed normal → clean. |

**Milestone tuần 7:** ✅ Fuzzer loop chạy được: đọc JSON → mutate → execute (Dual-EVM khi có RPC + block; không thì mô phỏng trace) → `scenario_sim` tổng hợp state cho oracle → check invariants → ghi `results.json`.

---

### Phase 3: Tích hợp (Tuần 8) — CẢ HAI LÀM CÙNG

| Task | Ai | Chi tiết |
|------|-----|---------|
| Build Rust binary | B | `cargo build --release` → binary sẵn sàng |
| ✅ Orchestrator gọi binary | A | subprocess call: `./bridgesentry-fuzzer --atg atg.json --scenarios hypotheses.json --budget 600 --output results.json` (đã tích hợp; có `--skip-fuzzer`) |
| Test end-to-end Nomad | Cả hai | `python orchestrator.py --benchmark benchmarks/nomad/ --time-budget 60 --runs 1` → phát hiện >=1 violation |
| Fix serialization issues | Cả hai | JSON encoding/decoding giữa Python ↔ Rust |
| Error handling | A: Python side, B: Rust side | Xử lý crash, timeout, invalid input |

**Milestone tuần 8:** Pipeline end-to-end chạy Nomad thành công. **Đây là thời điểm "it works".**

---

### Phase 4: Benchmark + Thực nghiệm (Tuần 9-11)

| Tuần | Member A | Member B |
|------|----------|----------|
| 9 | Populate 4 benchmark ưu tiên cao: Wormhole (block 14268080), PolyNetwork (block 12996658), Qubit (block 14125814), pGALA | Smoke test mỗi benchmark (budget 60s). Debug crash. Tối ưu performance fuzzer. |
| 10 | Populate 7 benchmark còn lại: Ronin, Harmony, Multichain, Socket, Orbit, GemPad, FEGtoken | Chạy mỗi benchmark với budget 600s × 1 run. Ghi nhận DR sơ bộ. |
| 11 | Chạy baseline tools: GPTScan trên từng bridge (A kiểm soát vì dùng LLM). Ghi kết quả. | Chạy baseline tools: ItyFuzz trên từng bridge (B kiểm soát vì dùng Rust fuzzer). Ghi kết quả. |

**Ưu tiên benchmark (dễ → khó):**

| Ưu tiên | Bridge | Lý do |
|---------|--------|-------|
| 1 | Nomad | Fork block rõ, source verified, ItyFuzz 0.3s baseline |
| 2 | Qubit | Fork block rõ, đơn chuỗi BSC |
| 3 | Wormhole | Fork block rõ, source verified |
| 4 | PolyNetwork | Fork block rõ, source trên Etherscan |
| 5 | Socket, pGALA, GemPad | Source trên GitHub/Etherscan |
| 6 | Ronin, Harmony, Multichain, Orbit, FEGtoken | Off-chain attacks → cần Mock Relay phức tạp hơn |

---

### Phase 5: Thống kê + Viết Paper (Tuần 12-13)

| Task | Ai | Chi tiết |
|------|-----|---------|
| Chạy full experiments | Cả hai | 20 seeds × 12 benchmarks × 600s = 240 runs (~40 giờ CPU) |
| Chạy ablation | B | 3 variants × 12 × 20 = 720 runs |
| Chạy parameter sensitivity | B | k ∈ {1,3,5,7,10}, β ∈ {0.1,...,0.7}, T ∈ {60,120,300,600} |
| Phân tích thống kê | A | Mann-Whitney U, Vargha-Delaney A12, Cohen's κ (dùng scipy) |
| Điền bảng kết quả paper | A | Table 1 (benchmark), Table 2 (comparison), Table 3 (ablation) |
| Vẽ biểu đồ | A | Fig 2 (k sensitivity), Fig 3 (time budget), Fig 1 (architecture đã có) |
| Review + polish paper | Cả hai | Submit |

---

## Nơi Chạy Thực nghiệm

| Giai đoạn | Nơi chạy | Lý do |
|-----------|----------|-------|
| Phase 0-3 (dev) | **Laptop cá nhân** | Unit test, debug, budget ngắn (60s) |
| Phase 4 (smoke test) | **Laptop cá nhân** | Mỗi benchmark 1 run × 600s |
| Phase 5 (full experiments) | **Server UIT hoặc Cloud** | 240+ runs, cần multi-core |

**Lựa chọn server thực nghiệm:**

1. **Server trường UIT** (tốt nhất) — hỏi thầy xin access
2. **Google Cloud spot instance** — `n2-standard-32` (32 vCPU, 128GB RAM) ~$1/giờ. Tổng ~$40-50 cho 40 giờ chạy.
3. **Laptop** — nếu có 16GB RAM + 8 core, chạy được nhưng chậm (~100 giờ)

**Không cần GPU** — GPU chỉ dùng cho embedding (sentence-transformers), chạy vài giây. Fuzzer là CPU-bound.

---

## Chi phí Dự kiến

| Khoản | Chi phí |
|-------|---------|
| OpenAI API (dev + experiments) | ~$50-100 |
| Alchemy RPC (free tier) | $0 (300M compute units/tháng) |
| Cloud server (Phase 5) | ~$40-50 |
| **Tổng** | **~$100-150** |

**Tiết kiệm:** Dùng `gpt-4o-mini` (~10x rẻ hơn) khi dev và prompt engineering. Chỉ dùng `gpt-4o` cho experiment runs cuối.

---

## Rủi ro và Biện pháp

| Rủi ro | Xác suất | Biện pháp |
|--------|----------|-----------|
| **revm API quá khó / version không tương thích** | CAO | Fallback: dùng 2 process Anvil + JSON-RPC thay vì revm trực tiếp. Chậm hơn nhưng chắc chắn hoạt động. Thử PoC tuần 1. |
| **GPT-4o output JSON lỗi** | TRUNG BÌNH | Dùng `response_format: json_object`. Retry loop 3 lần. Validate schema sau mỗi call. |
| **Alchemy rate limit khi fork** | TRUNG BÌNH | Cache fork state. Pre-dump state DB. Dùng Alchemy free tier hợp lý. |
| **Thu thập 51 exploit records quá lâu** | CAO | Bắt đầu từ tuần 1, làm 3-5 records/ngày. Ưu tiên 12 bridges trong benchmark trước. |
| **Kết quả không đạt 11/12 DR** | TRUNG BÌNH | Paper đã ghi nhận Qubit miss. Nếu chỉ đạt 9-10/12, cập nhật paper trung thực. |
| **Git conflict** | THẤP | File ownership tách biệt hoàn toàn. Dùng feature branches. |

---

## Checklist Theo Tuần

> **Cột Kiểm tra:** chỉ gắn ✅ khi tiêu chí đó **đã đạt** trong repo hoặc đã xác nhận chạy được; chưa đạt thì ghi tiêu chí **không** có ✅.

| Tuần | Member A | Member B | Kiểm tra |
|------|----------|----------|----------|
| 1 | ✅ Schemas + Nomad contracts + mock fixtures | ✅ Schemas + revm PoC + Cargo fix | ✅ Schemas + mock fixtures đã commit · ✅ benchmark Nomad artifact đầy đủ · ✅ cargo check · revm PoC trong dual_evm (test fork RPC, #[ignore]) |
| 2 | ✅ extractor.py: OpenAI integration (kèm offline heuristic) | ✅ dual_evm.rs: fork 2 chains | ✅ extractor output JSON hợp lệ |
| 3 | ✅ extractor.py: multi-step analysis hoàn chỉnh | ✅ dual_evm.rs: execute tx trên cả 2 chains | ✅ execute tx trên dual-EVM (`dual_evm.rs`) |
| 4 | ✅ atg_builder.py + ✅ invariant_synth.py | ✅ snapshot.rs + dual_evm capture/restore | atg.json cho Nomad: chưa (thiếu benchmark artifacts) · ✅ snapshot round-trip (unit tests + `snapshot_restore_preserves_tracked_balances` #[ignore] RPC) |
| 5 | ✅ knowledge_base.py + bắt đầu 51 records (đã có sample records) | ✅ mock_relay.rs: 4 modes | ✅ KB load/filter tests · relay mode tests |
| 6 | Tiếp tục 51 records + ✅ embedder.py | ✅ config.rs + ✅ types.rs | ✅ Module 3: CLI + deserialize ATG/hypotheses · ✅ FAISS/search test |
| 7 | ✅ scenario_gen.py → hypotheses.json | ✅ mutator.rs + ✅ checker.rs + ✅ fuzz_loop (Alg.1: corpus, R, SnapshotPool) | hypotheses.json cho Nomad: chưa (chưa có benchmark Nomad đầy đủ) · fuzzer loop |
| 8 | ✅ orchestrator.py tích hợp | main.rs CLI + binary build | END-TO-END NOMAD: chưa |
| 9 | 4 benchmarks ưu tiên cao | Smoke test + debug | 5/12 benchmarks chạy |
| 10 | 7 benchmarks còn lại | Benchmark testing | 12/12 benchmarks chạy |
| 11 | Baseline: GPTScan | Baseline: ItyFuzz | Comparison data |
| 12 | Thống kê + bảng paper | Ablation + sensitivity | Tables filled |
| 13 | Review paper | Review paper | SUBMIT |

---

## Git Workflow

```
main                    ← production, luôn chạy được
├── feature/module1     ← Member A
├── feature/module2     ← Member A
├── feature/module3     ← Member B
├── feature/benchmarks  ← cả hai
└── feature/experiments ← cả hai
```

**Quy tắc:**
1. Mỗi người làm trên branch riêng
2. Merge vào `main` qua Pull Request
3. Không push trực tiếp vào `main`
4. `schemas/` chỉ thay đổi khi cả hai đồng ý
5. Commit message format: `[Module X] mô tả ngắn`

---

---

## Source Code Tham khảo từ Các Bài báo

> Danh sách tất cả repo công khai liên quan đến project, phân loại theo mức độ tái sử dụng.

### Nhóm 1: TÁI SỬ DỤNG TRỰC TIẾP — Dependency hoặc đọc code để implement

| # | Tool | GitHub | Ngôn ngữ | Stars | Dùng cho |
|---|------|--------|----------|-------|----------|
| 1 | **ItyFuzz** | https://github.com/fuzzland/ityfuzz | Rust | ~1.100 | **Module 3.** Nền tảng snapshot fuzzing. Đọc kỹ `src/evm/`, `src/state_input.rs`, `src/scheduler.rs`, `src/fuzzer.rs` để hiểu cách quản lý snapshot, waypoint, state corpus. BridgeSentry mở rộng từ kiến trúc này sang Dual-EVM. |
| 2 | **revm** | https://github.com/bluealloy/revm | Rust | ~2.200 | **Module 3.** EVM backend — dependency trực tiếp trong Cargo.toml. Mỗi revm instance = 1 chain giả lập. Đọc `crates/revm/` (core) + `crates/primitives/` (types). |
| 3 | **Slither** | https://github.com/crytic/slither | Python | ~6.200 | **Module 1.** Dùng SlithIR để parse Solidity AST, trích xuất control-flow/data-flow graph. Bổ trợ LLM extraction: parse code trước → gửi cấu trúc cho LLM thay vì raw code. `pip install slither-analyzer` |
| 4 | **GPTScan** | https://github.com/GPTScan/GPTScan | Java/Python | ~100 | **Module 1+2.** Tham khảo prompt engineering: cách chia function → role classification, cách kết hợp LLM + static matching + confirmation. Pipeline rất giống Module 1. |
| 5 | **Foundry** | https://github.com/foundry-rs/foundry | Rust | ~10.300 | **Benchmarks.** anvil fork blockchain, forge compile/test, cast tương tác contract. Dependency cho toàn project. |
| 6 | **FAISS** | https://github.com/facebookresearch/faiss | C++/Python | ~39.700 | **Module 2.** Vector similarity search cho RAG knowledge base. `pip install faiss-cpu` |
| 7 | **sentence-transformers** | https://github.com/UKPLab/sentence-transformers | Python | ~18.500 | **Module 2.** Encode exploit descriptions thành embeddings. Model: `all-MiniLM-L6-v2`. `pip install sentence-transformers` |

### Nhóm 2: THAM KHẢO KIẾN TRÚC — Đọc code để học cách triển khai

| # | Tool | GitHub | Dùng để tham khảo |
|---|------|--------|-------------------|
| 8 | **CTLC Implementation** | https://github.com/hn-rg/CTLC-Implementation | Solidity/JS. **Module 1** — Implementation chính thức của paper ATG. Cách định nghĩa nodes, edges, conditions trong smart contract. Tham khảo cấu trúc đồ thị. |
| 9 | **BridgeShield** | https://github.com/Connector-Tool/BridgeShield | Python. Heterogeneous graph neural network cho cross-chain anomaly detection. Tham khảo cách xây đồ thị hành vi liên chuỗi (xBHG). |
| 10 | **Connector** | https://github.com/Connector-Tool/Connector | Python. Logic match deposit-withdrawal liên chuỗi + multi-chain data crawling (Ethereum, BSC, Polygon). Tham khảo cho benchmark data collection. |
| 11 | **VulSEye** | https://github.com/SCFuzzing/Vulseye | Python. Directed graybox fuzzing — tham khảo code/state distance metrics, vulnerability-directed seed scheduling. Liên quan trực tiếp tới `checker.rs` (invariant distance). |
| 12 | **SmartAxe** (dataset) | https://github.com/InPlusLab/FSE24-SmartAxe | Dataset 88 cross-chain vulnerabilities đã label. **Dùng cho Module 2 knowledge base + benchmark evaluation.** Download dataset CCV. |
| 13 | **XScope** (data) | https://github.com/Xscope-Tool/Cross-Chain-Attacks | Danh mục 16 cuộc tấn công cross-chain có mô tả chi tiết. Dùng bổ sung knowledge base Module 2. |
| 14 | **ALBA Protocol** | https://github.com/ALBA-blockchain/ALBA-Protocol | Solidity. Bridge mẫu LN↔Ethereum. Có thể dùng làm sample bridge đơn giản để test pipeline. |
| 15 | **Verite** (data) | https://github.com/wtdcode/verite | Paper + dataset + slides. Tham khảo profit-oriented oracle design cho reward function. |
| 16 | **CrossGuard** | https://github.com/ghazi1987/CrossGuard | Minimal (dataset). Tham khảo paper: adversarial LLM roles, chain-based prompting cho seed generation. |

### Nhóm 3: KHÔNG CÓ SOURCE — Chỉ đọc paper, tự implement

| # | Tool | Paper Venue | Tham khảo gì |
|---|------|-------------|-------------|
| 17 | **BridgeGuard** | IEEE TDSC 2025 | Symbolic dataflow analysis cho bridge router → tham khảo methodology cho Module 1 |
| 18 | **SmartShot** | FSE 2025 | Mutable snapshot + symbolic taint → tham khảo cho `snapshot.rs` |
| 19 | **Midas** | ISSTA 2024 | Profit-driven fuzzing + differential analysis → tham khảo reward function |
| 20 | **SCVHunter** | ICSE 2024 | GNN trên đồ thị ngữ nghĩa → tham khảo graph construction methodology |

---

## Tái sử dụng Code Cụ thể Cho Từng Module

### Module 1 (Semantic Extraction) — Member A cần đọc

```
PHẢI ĐỌC:
├── GPTScan/GPTScan                   → Prompt templates phân tích Solidity
│     Đọc: prompt files, matching pipeline
│     Học: cách chia function → role, cách format output cho LLM
│
├── crytic/slither                    → Parse Solidity AST
│     Dùng: pip install slither-analyzer
│     Đọc: slither/core/declarations/ (function, variable extraction)
│     Học: cách lấy state variables, function signatures, modifiers
│
└── hn-rg/CTLC-Implementation        → Cấu trúc ATG trong code
      Đọc: contracts/ (Solidity), test/ (JavaScript)
      Học: cách node/edge/condition được encode trong implementation
```

### Module 2 (RAG) — Member A cần đọc

```
PHẢI ĐỌC:
├── InPlusLab/FSE24-SmartAxe          → Dataset 88 CCV
│     Dùng: download → chuyển thành exploit JSON records
│     Đây là nguồn dữ liệu chính cho knowledge base
│
├── Xscope-Tool/Cross-Chain-Attacks   → 16 cuộc tấn công chi tiết
│     Dùng: bổ sung knowledge base
│
NÊN ĐỌC:
├── Connector-Tool/Connector          → Cross-chain tx matching
│     Tham khảo: cách crawl + match deposit↔withdrawal liên chuỗi
│
└── Connector-Tool/BridgeShield       → Graph construction
      Tham khảo: cách xây heterogeneous graph từ tx data
```

### Module 3 (Dual-EVM Fuzzer) — Member B cần đọc

```
PHẢI ĐỌC (1 tuần trước khi code):
├── fuzzland/ityfuzz                  → QUAN TRỌNG NHẤT
│     src/evm/                        → Cách wrap revm, execute tx
│     src/evm/onchain/                → Cách fork on-chain state
│     src/state_input.rs              → State corpus management
│     src/scheduler.rs                → Seed scheduling (power schedule)
│     src/fuzzer.rs                   → Main fuzzing loop
│     src/oracle.rs                   → Cách check invariant violations
│     Học: snapshot cách lưu/restore, waypoint cách dẫn hướng
│
├── bluealloy/revm                    → EVM backend API
│     crates/revm/src/                → Core EVM logic
│     examples/                       → Cách khởi tạo, fork state, execute tx
│     Học: Evm::builder(), Database trait, execute_transaction()
│
NÊN ĐỌC:
├── SCFuzzing/Vulseye                 → Distance metrics
│     Đọc: directed fuzzing logic
│     Học: code distance + state distance cho inv_dist() trong checker.rs
│
└── foundry-rs/foundry
      crates/anvil/                   → Cách fork blockchain state
      Học: cách Anvil dùng revm internally
```

---

## Hành động Cụ thể — Clone Repos Tham khảo

```bash
# Tạo thư mục references (NGOÀI project, không commit)
cd ~ && mkdir -p references && cd references

# === MEMBER B: ĐỌC TRƯỚC KHI CODE (Tuần 1) ===
git clone https://github.com/fuzzland/ityfuzz.git          # 1 tuần đọc Rust code

# === MEMBER A: ĐỌC TRƯỚC KHI CODE (Tuần 1) ===
git clone https://github.com/GPTScan/GPTScan.git           # 2-3 ngày đọc prompts
git clone https://github.com/hn-rg/CTLC-Implementation.git # 1 ngày đọc ATG

# === CẢ HAI: DỮ LIỆU CHO KNOWLEDGE BASE ===
git clone https://github.com/InPlusLab/FSE24-SmartAxe.git  # Dataset 88 CCV
git clone https://github.com/Xscope-Tool/Cross-Chain-Attacks.git  # 16 attacks

# === NÊN ĐỌC KHI CÓ THỜI GIAN ===
git clone https://github.com/Connector-Tool/BridgeShield.git
git clone https://github.com/Connector-Tool/Connector.git
git clone https://github.com/SCFuzzing/Vulseye.git
```

### Thứ tự Ưu tiên Đọc Code

| Ưu tiên | Ai | Repo | Thời gian | Mục đích |
|---------|-----|------|-----------|----------|
| 1 | B | **ItyFuzz** | 5-7 ngày | Hiểu snapshot fuzzing, state corpus, waypoint — nền tảng Module 3 |
| 2 | A | **GPTScan** | 2-3 ngày | Hiểu LLM + static analysis pipeline — nền tảng Module 1 |
| 3 | A | **CTLC-Implementation** | 1 ngày | Hiểu ATG formalism trong code thật |
| 4 | A | **SmartAxe dataset** | 1-2 ngày | Download + chuyển đổi → exploit JSON records |
| 5 | B | **revm examples** | 2-3 ngày | Hiểu API fork + execute |
| 6 | A | **XScope attacks** | 0.5 ngày | Bổ sung knowledge base |
| 7 | B | **VulSEye** | 1 ngày | Tham khảo distance metrics |
| 8 | Cả hai | **BridgeShield + Connector** | 1 ngày mỗi cái | Hiểu cross-chain graph construction |

---

*Kế hoạch này sẽ được cập nhật mỗi tuần trong buổi sync giữa hai thành viên.*
