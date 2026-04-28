# Plan — Paper Experiments (RQ1 / RQ2 / RQ3)

> **Mục đích:** Đóng gap giữa trạng thái hiện tại và bảng so sánh trong
> paper. Bảng số liệu cụ thể trong paper là demo — **methodology** phải
> match (20 runs, real bytecode fuzzing, 6 baseline comparison) chứ
> không phải số chính xác.
>
> **Audience:** Member A (Python — Module 1+2 + benchmarks) + Member B
> (Rust — Module 3 fuzzer).
>
> **Time horizon:** ~4-6 tuần với 2 thành viên làm song song.

---

## 0. Gap analysis — hiện tại vs paper claim

| Hạng mục | Paper §5.3 (RQ1) | Hiện tại | Gap |
|---|---|---|---|
| BridgeSentry DR | ✓/✗ trên 12 benchmark | ✅ 20/20 trên Nomad | OK; cần loop 11 benchmark còn lại |
| BridgeSentry TTE | ~10-150s realistic | ❌ 0.0001s (simulator-shortcut) | **Lớn — cần real bytecode fuzzing** |
| BridgeSentry FPR | mention | ❌ chưa đo | Phase C |
| BridgeSentry XCC | mention | ✅ 100% (ATG-level) | OK; chỉ là proxy, không phải bytecode coverage |
| `basic_blocks_*` | thực sự đếm bytecode | ❌ placeholder = total_iterations | Phase A — Inspector hook |
| **6 baselines** (ItyFuzz / SmartShot / VulSEye / SmartAxe / GPTScan / XScope) | ✓/✗ + TTE × 12 benchmark | ❌ **0/6 chạy** | **Phase B** |
| Patched-benchmark FPR control | optional rigorous | ❌ không có | Phase C-2 |

**Critical path:** Phase A (real-bytecode fuzzing) là **foundation** —
mở đường cho TTE realistic + basic_blocks thật + meaningful baseline
comparison. Không xong A, không có cell nào trong bảng RQ1 đáng tin.

**Có thể parallelize:** Phase B (baseline setup) độc lập với A — chạy
song song để tiết kiệm thời gian.

---

## Phase A — Module 3 real-bytecode fuzzing (FOUNDATION)

> Owner: **Member B** (Rust). Effort: **~10-14 ngày**. Branch: tạo mới
> `feat/real-bytecode-fuzz` từ `test_module_3`.

Hiện tại Module 3 chạy theo flow:

```
scenario JSON → scenario_sim::global_state_from_scenario → checker → violation
```

→ TTE = thời gian load JSON + check struct math = ~0.1ms.

Để match paper, flow phải là:

```
scenario.action[i] → mutator(calldata bytes) → revm.transact_commit
   → real EVM state diff → checker reads state → violation
```

→ TTE = wall-clock thời gian fuzzer mới hit violation thật.

### A1. revm Inspector cho basic_blocks coverage (~2 ngày)

**File:** Tạo mới `src/module3_fuzzing/src/coverage_tracker.rs`

```rust
use revm::{Database, EvmContext, Inspector};
use revm::interpreter::{Interpreter, InterpreterAction};
use std::collections::HashSet;

/// Tracks unique (address, program_counter) pairs hit during execution.
/// Approximates basic-block coverage — paper Section 7.3.
pub struct CoverageTracker {
    pub touched: HashSet<(revm::primitives::Address, usize)>,
}

impl<DB: Database> Inspector<DB> for CoverageTracker {
    fn step(&mut self, interp: &mut Interpreter, _ctx: &mut EvmContext<DB>) {
        let pc = interp.program_counter();
        let addr = interp.contract.target_address;
        self.touched.insert((addr, pc));
    }
}
```

**Wire into `dual_evm.rs`:** mỗi `execute_on_source` / `execute_on_dest`
attach inspector, sau khi execute thì merge `touched` vào aggregate
coverage.

**Test:** unit test với simple contract bytecode (e.g., counter), confirm
PC count match.

### A2. Contract deployment helper (~2 ngày)

**File:** `src/module3_fuzzing/src/contract_loader.rs` (mới)

Trước fuzz loop, deploy contracts từ `benchmarks/<bridge>/contracts/*.sol`
vào revm forks (source + dest) để có real bytecode để fuzz.

Workflow:

1. Compile `*.sol` qua `solc 0.8.20` → bytecode + ABI (Member A đã có
   `solc-select` setup; reuse)
2. `revm` deploy bytecode tại fork block, get deployed address
3. Map `node_id` (từ ATG) → deployed address
4. Pass map xuống mutator để biết target nào để gọi

**Hoặc** dùng existing on-chain bytecode tại fork block (real address từ
metadata) — đỡ bước compile nhưng phải dùng RPC archive support. Lựa
chọn: **deploy local cho test bench, dùng on-chain cho production fuzz.**

### A3. Calldata-based mutator (~3 ngày)

**File:** rewrite `src/module3_fuzzing/src/mutator.rs`

Hiện tại mutator mutate scenario JSON. Thay bằng mutator sinh `Vec<u8>`
calldata bytes:

- **Initial seeds** từ scenario.actions: encode action.function +
  action.params thành ABI calldata
- **Mutations:**
  - **Bit-flip / byte-flip** trong calldata (classic fuzzing primitives)
  - **Boundary substitution:** replace amount với 0, MAX_UINT, MAX/2
  - **Address substitution:** swap recipient address
  - **Function-selector swap:** thay 4-byte selector từ list trong ATG
  - **Concatenate:** ghép 2 calldata seeds thành sequence
- **ATG-aware:** ưu tiên selectors thuộc edges chưa touched

**Test:** verify selector mutation chuyển từ `lock(...)` selector sang
`unlock(...)` selector đúng.

### A4. Fuzz loop refactor (~3 ngày)

**File:** rewrite `src/module3_fuzzing/src/fuzz_loop.rs`

Pseudo-code mới:

```rust
loop {
    // 1. pick seed from corpus
    let seed_bytes = pick_seed(&corpus);

    // 2. mutate
    let calldata = mutator.mutate_bytes(&seed_bytes, &atg);

    // 3. execute on both EVMs
    let mut tracker = CoverageTracker::default();
    let res_src = dual.execute_on_source_with_inspector(calldata, &mut tracker);
    relay.dispatch(&res_src.logs);
    let res_dst = dual.execute_on_dest_with_inspector(calldata, &mut tracker);

    // 4. read REAL state from EVMs
    let state = dual.collect_global_state();
    state.relay_state = relay.snapshot();

    // 5. check invariants against real state
    let results = checker.check(&state);
    for r in results.iter().filter(|r| r.violated) {
        violations.push(...)
    }

    // 6. update coverage
    bytecode_coverage.extend(tracker.touched);

    // 7. corpus power scheduling theo coverage growth
    ...
}
```

**Quan trọng:** simulator (`scenario_sim::global_state_from_scenario`)
**vẫn dùng** nhưng chỉ làm **seed encoder** (turn scenarios into initial
calldata) — không trực tiếp populate state cho checker nữa. State đến
từ EVM thật.

### A5. Verify TTE realistic (~1 ngày)

Chạy 1 benchmark (Nomad) với budget 60s, confirm:
- TTE > 1s (không còn 0.0001s)
- `basic_blocks_source` và `basic_blocks_dest` ≠ `total_iterations`
- Violations nếu có xuất phát từ real EVM state, không phải simulator
  shortcut

**Acceptance Phase A:** tất cả 5 sub-task đạt + `cargo test --release`
46 tests cũ pass + 5 test mới cho coverage tracker / contract loader /
calldata mutator.

---

## Phase B — Baseline tools (PARALLEL với A)

> Owner: **Member A** (cài đặt) + **Member B** (chạy). Effort: **~5-7
> ngày**.

### B1. Inventory + install (~3 ngày)

| Tool | Loại | Repo | Cài như | Input format |
|---|---|---|---|---|
| **ItyFuzz** | bytecode fuzzer | https://github.com/fuzzland/ityfuzz | cargo install | RPC fork + target address list |
| **SmartShot** | rule + LLM hybrid | check paper | TBD | Solidity source |
| **VulSEye** | symbolic + ML | check paper | TBD | Solidity source |
| **SmartAxe** | static analysis | https://github.com/...smartaxe | python | Solidity source |
| **GPTScan** | LLM-based | https://github.com/Beokro/GPTScan | python + OpenAI key | Solidity source |
| **XScope** | cross-chain analyzer | check paper | TBD | bridge config |

**Action items Member A:**
- [ ] Tạo `baselines/` directory ở repo root (hoặc external dir)
- [ ] Per-tool subdir: `baselines/<tool>/` với install script + version notes
- [ ] Document version + commit hash mỗi tool dùng (cho reproducibility)

### B2. Adapter scripts cho 12 benchmarks (~2 ngày)

Mỗi tool có input format khác. Cần adapter:

- ItyFuzz: cần `--target 0xABC` + RPC URL → adapter đọc
  `benchmarks/<bridge>/metadata.json`, extract address từ
  `contracts.<key>.address`, sinh ItyFuzz CLI args
- SmartAxe / GPTScan / SmartShot / VulSEye: nhận Solidity files →
  adapter point thẳng vào `benchmarks/<bridge>/contracts/`
- XScope: cần bridge mapping → dùng `benchmarks/<bridge>/mapping.json`

**File:** `scripts/run_baseline.sh <tool> <bridge>` — wrapper unified.

### B3. Run experiments (~2-3 ngày wall-clock)

```bash
for tool in ityfuzz smartshot vulseye smartaxe gptscan xscope; do
    for bridge in nomad qubit pgala polynetwork wormhole socket \
                  ronin harmony multichain orbit fegtoken gempad; do
        for run in $(seq 1 20); do
            bash scripts/run_baseline.sh $tool $bridge $run
        done
    done
done
```

72 cells × 20 runs = 1440 experiments. Một số sẽ timeout nhanh (tool
crash trên benchmark format mới). Realistic: 60-70% cells có data,
30-40% mark là `incompatible / timeout`.

**Output format chuẩn:** `results/baselines/<tool>/<bridge>/run_NNN.json`

```json
{
  "tool": "ityfuzz",
  "bridge": "nomad",
  "run": 5,
  "detected": true,
  "tte_seconds": 38.4,
  "violations": ["bug-pattern-a"],
  "stderr_excerpt": "...",
  "raw_output_path": "results/baselines/ityfuzz/nomad/run_005.raw.txt"
}
```

### B4. Alternative — Cite published results (~1 ngày)

Nếu install + run không khả thi cho tool X:

1. Đọc paper gốc của tool X
2. Trích kết quả của tool X trên benchmark mà paper test (e.g. SmartShot
   có thể đã test PolyNetwork trong paper gốc)
3. Note rõ trong methodology: "ItyFuzz numbers self-run; SmartShot
   numbers cited from [paper, Table 5]"
4. Cells không có data → mark `n/a` thay vì `✗` (phân biệt "không
   detect" vs "không test")

**Khuyến nghị:** Hybrid — run được cái nào thì run, cite cái còn lại.

---

## Phase C — FPR measurement

> Owner: **Member A**. Effort: **~3-7 ngày** tuỳ chọn approach.

### C1. Quick path — TP/FP classification (~1 ngày)

Cho mỗi benchmark, classify mỗi `violated_invariant` thành:

- **TP** — invariant tied to documented bug (e.g., Nomad V1 → tất cả
  asset_conservation_* invariants là TP)
- **FP** — invariant không liên quan bug được document (e.g., Nomad
  không phải fee bug → `authorization_fee_collector` violation = FP)

Output: `results/fpr_classification/<bridge>.json`:

```json
{
  "bridge": "nomad",
  "documented_vuln_classes": ["V1", "V3"],
  "documented_bug_summary": "zero-root verification bypass + state desync",
  "violated_invariants": [
    {"id": "asset_conservation_total", "category": "asset_conservation", "label": "TP", "rationale": "V1 — minted > locked is direct V1 manifestation"},
    {"id": "authorization_fee_collector", "category": "authorization", "label": "FP", "rationale": "Nomad has no fee mechanism"}
  ],
  "fpr": 0.50  // = #FP / #total_violated
}
```

**Process:**
- Member A đọc `benchmarks/<b>/metadata.json` `root_cause_summary`
- Map mỗi của 18 invariants → TP/FP với rationale 1 dòng
- Repeat cho 12 benchmark
- Aggregate: report mean FPR + per-bridge

**Lưu ý:** classification subjective → cần thầy cô / Member B sanity
check criteria.

### C2. Rigorous path — patched benchmarks (~5-7 ngày)

Mỗi benchmark, tạo `benchmarks/<bridge>/contracts_patched/*.sol` — fix
bug:

- Nomad: thêm `require(_committedRoot != bytes32(0))` vào `initialize`
- Qubit: thêm `require(msg.value == amount)` cho native path
- ...

Run fuzzer trên patched contracts → bất kỳ violation nào = FP thật sự.

```bash
for b in nomad qubit ...; do
    bridgesentry-fuzzer \
        --atg benchmarks/$b/llm_outputs/atg.json \
        --scenarios benchmarks/$b/llm_outputs/hypotheses.json \
        --contracts benchmarks/$b/contracts_patched/ \
        --output results/fpr_control/${b}.json
done

# FPR = mean(violations / total_invariants) across patched runs
```

Effort cao nhưng số liệu rigorous, defensible với reviewer.

**Khuyến nghị:** Dùng C1 cho thesis chính, mention C2 là future work
trong §6.

---

## Phase D — Final experiments + paper tables

> Owner: **Cả Member A + Member B**. Effort: **~5-7 ngày**.

### D1. Run BridgeSentry trên 12 benchmark với real-bytecode fuzzer (~2 ngày)

Sau Phase A xong:

```bash
for b in nomad qubit pgala polynetwork wormhole socket \
         ronin harmony multichain orbit fegtoken gempad; do
    for run in $(seq 1 20); do
        SEED=$((run * 1000 + 42))
        bridgesentry-fuzzer \
            --atg benchmarks/$b/llm_outputs/atg.json \
            --scenarios benchmarks/$b/llm_outputs/hypotheses.json \
            --output results/$b/run_$(printf %03d $run).json \
            --budget 600 \
            --seed $SEED \
            --source-rpc $ETH_RPC_URL \
            --dest-rpc $ETH_RPC_URL  # or per-bridge dest
    done
done
```

20 runs × 12 bridges × 600s ≈ 40 giờ wall-clock. Chia 2 ngày, chạy
overnight.

**Output:** 240 `run_NNN.json` files với DR / TTE / basic_blocks /
violations.

### D2. Aggregate scripts (~1 ngày)

Mở rộng `scripts/collect_results.py`:

- Add FPR field từ Phase C output
- Add basic_blocks coverage
- Add baseline comparison merge: read `results/baselines/<tool>/<bridge>/`
  và join vào table

Output formats: `--format table | latex | csv | json`.

### D3. Build paper tables (~2 ngày)

| Paper section | Bảng | Source |
|---|---|---|
| §5.3 RQ1 | Comparison với 6 baselines | `collect_results.py --format latex --bridges all --tools all` |
| §7.1 Benchmark statistics | 12 benchmark + DR | đã có |
| §7.2 Module 1+2 output | nodes/edges/inv/sc | `LLM_VERIFICATION_FULL_DATASET.md` |
| §7.3 Module 3 fuzzing | DR / TTE / basic_blocks / XCC / FPR | new aggregator |
| §6 Limitations | 5 findings + new | merge với existing |

### D4. Plots / figures (~1-2 ngày, optional)

- TTE distribution boxplot (BridgeSentry vs baselines)
- Coverage growth curve over time
- Per-vuln-class detection rate

---

## Tracking matrix — assign owner + status

> Cập nhật: 2026-04-28. Branch `feat/real-bytecode-fuzz` carries Phase A
> (5 commits A1→A5, 63 tests pass). Branch `feat/phase-b-baselines`
> carries Phase B1+B2+B3-BridgeSentry+B4-templates. Phase D1 sweep
> đang chạy daemonized trên lab (PID 36994, ETA 2026-04-29 ~18:00 UTC).

| Phase / Task | Owner | Effort | Status | Evidence |
|---|---|---|---|---|
| **A1** Inspector for basic_blocks | Member B | 2 ngày | ✅ DONE | commit `ebad790` — `coverage_tracker.rs` + 4 unit tests (PUSH1/PUSH1/ADD/STOP capture) |
| **A2** Contract deployment helper | Member B | 2 ngày | ✅ DONE | commit `34f34c7` — `contract_loader.rs::ContractRegistry` + selector tables + 5 tests (ERC-20 selector verified `0xa9059cbb`) |
| **A3** Calldata-based mutator | Member B | 3 ngày | ✅ DONE | commit `f39c02a` — `CalldataMutator` (selector-swap, byte-flip, boundary, address-word) + 4 tests |
| **A4** Fuzz loop refactor | Member B | 3 ngày | ✅ DONE | commit `075cae9` — fuzz_loop dispatches via inspector path, basic_blocks attribution per side |
| **A5** Verify TTE realistic | Member B | 1 ngày | ✅ DONE | commit `b78b3b5` — Nomad 60s run: TTE mean **6.40s** (>1s), bb_src=**997** ≠ iters=50,732. Artifacts in `docs/phase_a_artifacts/` |
| **B1** Baseline tools install | Member A | 3 ngày | ✅ DONE | ItyFuzz built (53MB, smoke 44.18% inst-cov on Nomad). GPTScan installed (Java + falcon + sha3 shim + openai 0.27.x). SmartAxe → cite-published path (404 on canonical URL). 2/3 self-installable working. |
| **B2** Adapter scripts | Member A | 2 ngày | ✅ DONE | 3/3 adapters shipped (`baselines/{ityfuzz,smartaxe,gptscan}/adapter.sh`); ItyFuzz adapter verified end-to-end on Nomad+Qubit. |
| **B3** Run baseline experiments | Member B | 2-3 ngày | 🔄 PARTIAL | BridgeSentry baseline sweep ✅ done on lab (12/12 × 20 runs = 240 runs / 14,291s ~4h, results pulled to `results/lab_sweep_2026_04_27/`). **ItyFuzz + GPTScan full sweeps chưa chạy** (overnight ~40h mỗi tool); SmartAxe blocked indefinitely. |
| **B4** Cite published (fallback) | Member A | 1 ngày | 🔄 PARTIAL | 5/6 JSON templates created (`baselines/_cited_results/{smartshot,vulseye,xscope,smartaxe,gptscan}.json`); cells `TBD` chờ Member A populate từ paper Tables (~5-8h đọc) |
| **C1** TP/FP classification | Member A | 1 ngày | ❌ TODO | (chưa bắt đầu) |
| **C2** Patched benchmarks (optional) | Member A | 5-7 ngày | OPTIONAL | (deferred — cite C1 cho thesis chính) |
| **D1** Run real-fuzz × 12 benchmark | Member A+B | 2 ngày | 🔄 IN PROGRESS | Sweep daemon PID 36994 trên lab (`~/sukem/CrossLLM/results/realbytecode_full_20260428T020921Z/`), 600s × 20 × 12 = 240 runs / ~40h. Snapshot 2026-04-28 03:35: 8/240 done (Nomad 8/20). ETA ~2026-04-29 18:00 UTC. |
| **D2** Aggregate scripts | Member A | 1 ngày | ❌ Blocked by D1 | `scripts/collect_baseline_results.py` đã có khung từ Phase B; cần extend với `basic_blocks_*` + `tte` từ real-bytecode output schema |
| **D3** Build paper tables | Member A | 2 ngày | ❌ Blocked by D2 | |
| **D4** Plots (optional) | Member A | 1-2 ngày | OPTIONAL | |

---

## Baseline tools — chi tiết (snapshot 2026-04-28)

> Mở rộng dòng B1+B2+B3 ở trên thành 6 dòng, mỗi tool một dòng, để theo
> dõi từng cột install / adapter / smoke / full sweep.

| Tool [ref] | Loại | Venue | Install | Adapter | Smoke | Full sweep (12 × 20) | Path cuối cùng |
|---|---|---|---|---|---|---|---|
| **ItyFuzz** [8] | Fuzzer snapshot đơn chuỗi | ISSTA 2023 | ✅ built (53 MB binary trên lab) | ✅ `baselines/ityfuzz/adapter.sh` | ✅ Nomad real-bytecode 90 s — 44.18 % inst-cov / 38.33 % branch | ❌ chưa | **self-run** — sẵn sàng kick off overnight (~40 h) |
| **SmartShot** [24] | Fuzzer snapshot có thể biến đổi | FSE 2025 | ❌ no public repo at writing | n/a | n/a | n/a | **B4 cite** — `baselines/_cited_results/smartshot.json` cells `TBD`, chờ đọc Table N của paper gốc |
| **VulSEye** [13] | Fuzzer graybox có hướng | IEEE TIFS 2025 | ❌ no public repo at writing | n/a | n/a | n/a | **B4 cite** — `baselines/_cited_results/vulseye.json` cells `TBD` |
| **SmartAxe** [3] | Phân tích tĩnh liên chuỗi | FSE 2024 | ❌ 404 trên 5 URL canonical thử qua | ✅ `baselines/smartaxe/adapter.sh` (làm trước khi xác nhận 404) | n/a | n/a | **B4 cite** — `baselines/_cited_results/smartaxe.json` cells `TBD` |
| **GPTScan** [9] | LLM + phân tích tĩnh | ICSE 2024 | ✅ Python + Java + patches (lab): falcon-analyzer `--no-deps` + sha3 shim qua pycryptodome + openai 0.27.x downgrade + NVIDIA NIM redirect | ✅ `baselines/gptscan/adapter.sh` + `patch_chatgpt_api.py` (per-file loop + cwd fix) | ✅ Nomad+Qubit — cả 2 `detected: false` (GPTScan 10 DeFi rules không cover bridge bugs — expected per paper §5.3) | ❌ chưa | **self-run** — sẵn sàng kick off overnight |
| **XScope** [6] | Phát hiện dựa trên quy tắc | ASE 2022 | ❌ academic artifact only | n/a | n/a | n/a | **B4 cite** — `baselines/_cited_results/xscope.json` cells `TBD` |

**Roll-up:**

- **Tự cài + chạy được**: 2/6 (ItyFuzz, GPTScan)
- **Cite-published (B4)**: 4/6 (SmartShot, VulSEye, SmartAxe, XScope) — JSON templates đã tạo, ô dữ liệu chờ Member A populate (~5-8 h đọc + extract)
- **Đã có smoke chứng minh path-end-to-end**: 2/6 (ItyFuzz / GPTScan)
- **Đã có full production sweep**: 0/6 — đang block sau Phase D1 (BridgeSentry sweep), khi xong sẽ tiếp ItyFuzz overnight 1 → GPTScan overnight 2

**Thứ tự dự kiến sau D1 finish (ETA 2026-04-29 ~18:00 UTC):**

1. Member A: bắt đầu fill 4 cited JSON files (chạy song song, không cần lab GPU)
2. Kick off ItyFuzz full sweep trên lab (single tool, 12 × 20 × 600 s ≈ 40 h) — đêm 1+2
3. Kick off GPTScan full sweep trên lab (12 × 20 × 600 s) — đêm 3+4
4. Aggregate (D2): merge BridgeSentry + ItyFuzz + GPTScan + 4 cited → 1 RQ1 LaTeX table

---

## Critical path / timeline

```
Week 1-2 (parallel):
   Member B: Phase A (A1 → A2 → A3 → A4 → A5)
   Member A: Phase B1 + B2 (install + adapters), Phase C1 (TP/FP classify)

Week 3:
   Member B: Phase B3 (run baselines, ~3 ngày)
   Member A: Phase B4 (cite published for incompatible tools)

Week 4:
   Member A+B: Phase D1 (40-giờ wall-clock 12-bench experiment, chạy đêm 2 đêm)
   Member A: D2 (aggregate scripts trong khi đợi D1)

Week 5:
   Member A: D3 (build paper tables) + D4 (plots)
   Cả 2: review + iterate

Buffer: Week 6 cho debug, re-run, plot polish
```

**Total: ~5-6 tuần** với realistic buffer.

---

## Acceptance criteria toàn cục (cho thesis)

- [x] **Phase A xong** → TTE realistic (Nomad mean **6.40s**, > 1s ✓),
      basic_blocks_source=**997** ≠ total_iterations=**50,732** ✓,
      fuzzer reads state from real EVM via revm Inspector ✓.
      Smoke #2 (post fuzzy-mapping fix) confirms 6/12 bridges hit
      non-trivial bytecode coverage; 10/12 show realistic TTE.
- [ ] Phase B xong → BridgeSentry baseline ✅ (240/240 runs, lab sweep
      `2026-04-27`); ItyFuzz/GPTScan self-run + 5 cited JSONs populate
      from papers vẫn pending (~5-8h cite work + ~40h × 2 self-run).
- [ ] Phase C xong → FPR estimate cho mỗi 12 benchmark + aggregate;
      C1 chưa bắt đầu.
- [ ] Phase D1 xong → 240 run JSON files (12 × 20). **Đang chạy** trên
      lab, 8/240 done at 2026-04-28 03:35 UTC; ETA ~2026-04-29 18:00 UTC.
- [ ] Phase D3 xong → §5.3 + §7.3 + §7.4 tables in `latex/paper.tex`
      compile được. Blocked by D1.
- [ ] Sanity check: BridgeSentry DR ≥ 90% trên real-bytecode mode.
      Smoke (60s × 1 × 12) ghi nhận 12/12 bridges produce violations,
      but full 600s × 20 sweep mới là số chính thức cho paper.

---

## Rủi ro + mitigations

| Rủi ro | Khả năng | Impact | Mitigation |
|---|---|---|---|
| Phase A overrun (tuần 3-4 thay vì 1-2) | Cao (revm Inspector tricky) | Block Phase D | Buffer 2 tuần; nếu trễ, cite TTE từ paper baselines + present XCC làm primary |
| Baselines incompatible với benchmark format | Cao (each tool có expectations khác) | Bảng RQ1 thưa | B4 fallback (cite published) cho ≥ 2 tools |
| Real-bytecode fuzz tìm ÍT hơn 100% DR (hiện tại) | Trung bình | Paper claim yếu | Document: simulator-based finds upper bound; bytecode-based finds bugs reachable in time budget. Both metrics reported. |
| FPR > 50% (nhiều violations không relevant) | Cao do 18 LLM invariants vs 4 mock | Reviewer hỏi | C1 classify rõ + note: "LLM diversifies invariants → high FPR is expected; per-class TPR is more meaningful" |
| RPC archive quota exhausted | Trung bình | Phase D1 fail | Cache forks; dùng `dest_rpc=$ETH_RPC_URL` cho single-chain fallback |

---

## Tài liệu tham chiếu

- Module 3 source: [`src/module3_fuzzing/`](../src/module3_fuzzing/)
- Existing scripts: [`scripts/run_module3_experiments.sh`](../scripts/run_module3_experiments.sh), [`scripts/collect_results.py`](../scripts/collect_results.py)
- Bench data: [`benchmarks/<bridge>/llm_outputs/`](../benchmarks/) (12 bridges, committed `967418a`)
- Current Module 3 fix: branch `test_module_3` (commits `198391f`, `9f08603`)
- Session findings: [`docs/SESSION_HANDOFF.md`](SESSION_HANDOFF.md) §5.0
- Tier-2 LLM verification: [`docs/LLM_VERIFICATION_FULL_DATASET.md`](LLM_VERIFICATION_FULL_DATASET.md)
- Existing test guide: [`docs/BENCHMARK_TEST_GUIDE.md`](BENCHMARK_TEST_GUIDE.md)
- Paper draft: [`latex/paper.tex`](../latex/paper.tex)

---

## Checkpoint hàng tuần

Mỗi cuối tuần:

```bash
# Kiểm tra trạng thái checklist
grep -c "\\[x\\]" docs/PLAN_PAPER_EXPERIMENTS.md
grep -c "\\[ \\]" docs/PLAN_PAPER_EXPERIMENTS.md

# Kiểm tra số benchmark đã có data thực
ls results/<bridge>/run_*.json 2>/dev/null | wc -l
ls results/baselines/*/<bridge>/run_*.json 2>/dev/null | wc -l
```

→ Update tracking matrix với `[x]` cho task xong, commit doc với
message `docs(plan): update Phase X progress`.
