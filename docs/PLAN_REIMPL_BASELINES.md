# Plan — Re-implement 4 baseline tools cho RQ1

> **Bối cảnh**: cite-published path (Phase B4) chỉ cho 1/72 cells positive
> trong bảng RQ1 vì 4 tools (XScope, SmartAxe, SmartShot, VulSEye) chưa
> hề test trên 12 bridges của ta. Thầy hướng dẫn: re-implement core
> algorithm trong codebase BridgeSentry, tự chạy trên 12 benchmarks để
> sinh per-bridge data. File này lập plan chi tiết cho 4 re-impl.
>
> **Time budget**: ~3 tháng = 12 tuần. **Owner mặc định**: Member B
> (Rust) cho 3 tools fuzzer, Member A (Python) cho SmartAxe (static
> analysis Solidity).
>
> **Trạng thái khởi điểm 2026-04-28**: Phase A done, D1 sweep đang chạy
> (ETA 2026-04-29 18:00 UTC), branch `feat/real-bytecode-fuzz` HEAD `389b0ef`.

---

## 0. Nguyên tắc re-implementation (không phải re-build full tool)

1. **Port core algorithm**, không port toàn bộ tool. Tool gốc thường có
   feature engineering / UI / reporting layer không cần thiết cho RQ1.
2. **Tích hợp vào BridgeSentry codebase** thay vì project độc lập:
   - Fuzzers (SmartShot, VulSEye) → thêm "mode" mới trong
     `src/module3_fuzzing/` (e.g. `fuzz_loop_smartshot.rs`, dispatched
     via `--baseline-mode smartshot` CLI arg).
   - Rule-based detector (XScope) → thêm modul `src/module3_fuzzing/src/checker/xscope_rules.rs`
     bên cạnh `checker.rs` hiện tại. Không cần fuzz, chỉ apply rules
     trên transaction stream từ benchmark scenarios.
   - Static analyzer (SmartAxe) → tách Python repo `tools/smartaxe_reimpl/`,
     parse Solidity bằng `slither` / `py-solc-ast`, output JSON đồng schema.
3. **Output schema thống nhất** với `baselines/_cited_results/<tool>.json`
   để aggregator `scripts/collect_baseline_results.py` không cần biết
   tool nào là cite vs re-impl.
4. **Validation gate trước khi sweep**: mỗi re-impl phải reproduce
   headline metric của paper gốc trên 1 example được công bố trước khi
   chạy trên 12 bridges của ta. Nếu không reproduce → re-impl sai → fix
   trước khi tốn 40h sweep.
5. **Honest scoping**: nếu re-impl không thể đạt 100% paper claim
   (e.g. SmartShot symbolic taint quá tricky), document trong
   methodology note. Reviewer paper sẽ chấp nhận miễn là ta thành thật.

---

## 1. Critical path & phasing

```
Tuần 1-2   : XScope (đơn giản nhất, ROI cao nhất, validate workflow)
Tuần 3-6   : SmartAxe (đối thủ trực tiếp nhất theo bảng baselines paper)
Tuần 7-9   : VulSEye (stateful directed fuzzer, gần BridgeSentry)
Tuần 10-12 : SmartShot (mutable snapshot fuzzer, phức tạp nhất; phần
             nhiều có thể parallel với VulSEye nếu Member B + Member A
             chia tay)

Buffer    : Tuần 12 cho sweep aggregation + paper table render
```

**Lý do thứ tự** (effort × risk × strategic value):

| # | Tool | Effort | Risk | Value | Lý do thứ tự |
|---|---|---|---|---|---|
| 1 | XScope | thấp | thấp | trung | Build workflow + validate methodology trước trên tool đơn giản |
| 2 | SmartAxe | trung | trung | **cao** | Bảng paper liệt kê là "đối thủ trực tiếp nhất" → phải có |
| 3 | VulSEye | trung | trung | trung | Algo gần BridgeSentry → có thể tái dùng nhiều code |
| 4 | SmartShot | cao | cao | thấp* | Phức tạp + domain mismatch (general DeFi) → ưu tiên thấp |

*SmartShot: nếu time pressure ở tuần 10, có thể giữ cite-published
+ note "general DeFi fuzzer, domain mismatch acknowledged" — paper
sẽ chấp nhận.

---

## 2. Per-tool plan

### 2.1 XScope — rule-based detector (Tuần 1-2, ~2 tuần)

**Mục đích**: detect cross-chain bridge attacks via 5-7 hand-written
invariant rules trên transaction stream.

**Paper reference**: Zhang et al., ASE 2022, [arXiv 2208.07119](https://arxiv.org/abs/2208.07119).
Rules trong paper §3:
1. **Inconsistent Event Parsing** — message event log on src ≠ parsed
   message on dst
2. **Unauthorized Unlocking** — unlock without matching lock event
3. **Unrestricted Deposit Emitting** — deposit event without actual
   token transfer (Qubit attack pattern)
4. **Replay Attack** — same nonce processed > 1 time on dst
5. **Asset Conservation** — sum(locked) ≠ sum(minted) ± fee tolerance

**Scope:**

| Sub-task | Effort | Output |
|---|---|---|
| **X1** Đọc paper §3-4, viết spec 5-7 rules dạng pseudocode | 1 ngày | `docs/REIMPL_XSCOPE_SPEC.md` |
| **X2** Tạo `src/module3_fuzzing/src/baselines/xscope.rs` với struct `XScopeChecker` impl trait `BaselineDetector` | 2 ngày | Rust module + 5 rule fns |
| **X3** Wire vào fuzz_loop: mode `--baseline-mode xscope` chỉ chạy detector trên scenario actions, KHÔNG mutate calldata | 1 ngày | CLI arg + dispatch |
| **X4** Validate: reproduce 4 bridges paper gốc (THORChain/pNetwork/Anyswap/Qubit) — confirm Qubit "Unrestricted Deposit Emitting" rule fires trên benchmark Qubit của ta | 2 ngày | Tests pass + commit |
| **X5** Run 12 × 20 sweep trên lab | ~2h (XScope nhanh, không phải fuzz) | `results/baselines/xscope/<bridge>/run_NNN.json` |
| **X6** Update `baselines/_cited_results/xscope.json` thành self-run version với per-bridge data | 0.5 ngày | JSON updated |

**Acceptance**: Qubit detected=true (matches paper's positive result),
12/12 bridges có run_*.json, JSON schema khớp aggregator.

**Risk**: rules trong paper có thể ambiguous. Mitigation: liên hệ tác
giả qua email nếu kẹt; document interpretation trong methodology note.

---

### 2.2 SmartAxe — cross-chain static analyzer (Tuần 3-6, ~4 tuần)

**Mục đích**: phát hiện cross-chain vulnerabilities qua xCFG (cross-chain
control-flow graph) + xDFG (data-flow graph) + probabilistic pattern
inference cho access control checks.

**Paper reference**: Liao et al., FSE 2024, [arXiv 2406.15999](https://arxiv.org/abs/2406.15999).
Core method §4:
1. Parse Solidity contracts → standard CFG/DFG per contract
2. Identify cross-chain communication points (events emit, message handlers)
3. Connect cross-contract via xCFG/xDFG
4. Probabilistic inference: from K labeled examples (access control
   patterns), infer expected security checks for each cross-chain
   transition
5. Report missing checks as CCVs

**Scope:**

| Sub-task | Effort | Output |
|---|---|---|
| **SA1** Đọc paper §3-5 + arXiv appendix; tóm tắt thuật toán xCFG/xDFG construction | 2 ngày | `docs/REIMPL_SMARTAXE_SPEC.md` |
| **SA2** Setup Python project `tools/smartaxe_reimpl/` với deps: `slither-analyzer`, `py-solc-ast`, `networkx` | 1 ngày | venv + pyproject.toml |
| **SA3** Implement single-contract CFG/DFG via Slither's IR (Slither đã có sẵn — chỉ cần adapter) | 3 ngày | `cfg_builder.py` + tests |
| **SA4** Implement cross-contract linking: parse `emit MessageDispatched` ↔ `function handle(...)` patterns thành xCFG edges | 5 ngày | `xcfg_builder.py` + tests trên Nomad benchmark |
| **SA5** Implement probabilistic pattern inference: từ tập K access-control patterns labeled trong `data/patterns/`, học expected check positions, flag mismatch | 5 ngày | `pattern_inference.py` + tests |
| **SA6** Validate: reproduce paper's aggregate P=84.95% / R=89.77% trên 1-2 example bugs họ list (PolyNetwork access-control bug). Nếu re-impl đạt P/R trong ±5pp → OK | 3 ngày | reproduction report |
| **SA7** Run trên 12 benchmarks (`benchmarks/<bridge>/contracts/*.sol`) | ~3-4h (static, single-pass) | `results/baselines/smartaxe/<bridge>/run_001.json` |
| **SA8** Update `baselines/_cited_results/smartaxe.json` → self-run version | 0.5 ngày | JSON updated |

**Acceptance**: PolyNetwork detected=true (per paper's motivating example),
re-impl P/R trong ±5pp paper claim, 12/12 bridges có data.

**Risk lớn**: SmartAxe artifact 403 → không có ground truth K patterns
để học. **Mitigation**: dùng patterns ta tự label từ `benchmarks/<bridge>/metadata.json.root_cause_summary` (đã có sẵn — chính là root cause cho 12 incidents). Note rõ trong methodology: "patterns trained on our 12-incident dataset, not paper's 88 CCVs".

---

### 2.3 VulSEye — stateful directed graybox fuzzer (Tuần 7-9, ~3 tuần)

**Mục đích**: directed fuzzing prioritise resources to vulnerable code
areas + contract states.

**Paper reference**: Liang et al., TIFS 2025, [arXiv 2408.10116](https://arxiv.org/abs/2408.10116).
Core method §3-4:
1. **Code targets**: static analysis + pattern matching → identify
   vulnerable code positions (e.g. unchecked external calls)
2. **State targets**: backward analysis on bytecode → critical state
   conditions để trigger vulns
3. **Fitness function**: combine code-target distance + state-target
   distance → guide fuzz mutations

**Scope:**

| Sub-task | Effort | Output |
|---|---|---|
| **VS1** Đọc paper §3-4; tóm tắt thuật toán directed fitness | 2 ngày | `docs/REIMPL_VULSEYE_SPEC.md` |
| **VS2** Implement code-target identification: 5-7 vulnerability patterns (reentrancy, unchecked-call, access-control) from paper Table 2 → matched on revm bytecode | 4 ngày | `src/module3_fuzzing/src/baselines/vulseye_targets.rs` |
| **VS3** Implement state-target backward analysis: từ vulnerability site, trace back required storage/balance preconditions | 5 ngày | `vulseye_backward.rs` + tests |
| **VS4** Implement directed fitness function: `f(input) = α·code_distance + β·state_distance` thay cho reward function hiện tại | 3 ngày | `vulseye_fuzz_loop.rs` |
| **VS5** Validate: reproduce paper's headline 9.7× speedup vs ItyFuzz trên 1 example contract (paper Fig. 5). Nếu speedup >= 5× → OK (ta dùng pattern subset, không cần đạt 9.7×) | 3 ngày | reproduction report |
| **VS6** Run 12 × 20 sweep trên lab (graybox fuzzer, ~600s/run = 40h overnight) | ~40h | `results/baselines/vulseye/...` |
| **VS7** Update `baselines/_cited_results/vulseye.json` → self-run | 0.5 ngày | JSON updated |

**Acceptance**: speedup ≥ 5× ItyFuzz baseline trên ít nhất 1 example,
12/12 bridges run.

**Risk**: backward analysis trên revm bytecode tricky (need symbolic
execution). **Mitigation**: simplified version dùng concrete-execution
fuzz traces từ ItyFuzz outputs làm "approximate backward state targets".
Document trong methodology.

---

### 2.4 SmartShot — mutable snapshot fuzzer (Tuần 10-12, ~3 tuần với buffer)

**Mục đích**: snapshot-based fuzzer with mutable contract state +
blockchain environment.

**Paper reference**: Liu et al., FSE 2025, [DOI 10.1145/3715714](https://doi.org/10.1145/3715714).
Core method:
1. Snapshot = (contract storage, block timestamp, block number, balances)
2. **Mutable** snapshots: fuzzer can mutate snapshot fields, không chỉ
   mutate input calldata
3. Symbolic taint analysis guide which snapshot fields đáng mutate
4. Double validation: re-run với original snapshot to confirm violation

**Scope:**

| Sub-task | Effort | Output |
|---|---|---|
| **SS1** Đọc paper §3-5; tóm tắt mutable-snapshot design | 2 ngày | `docs/REIMPL_SMARTSHOT_SPEC.md` |
| **SS2** Extend BridgeSentry's `SnapshotPool` to support mutation: add `mutate_snapshot(s, taint)` method that flips storage slots / advances timestamp / etc | 4 ngày | `src/module3_fuzzing/src/snapshot.rs` extended |
| **SS3** Implement symbolic taint analysis (simplified): track which storage slots a function reads → those are "interesting" để mutate | 5 ngày | `taint_tracker.rs` + Inspector hook |
| **SS4** Wire mutable-snapshot fuzz loop: pick snapshot, mutate, run, check violation, double-validate với original | 3 ngày | `fuzz_loop_smartshot.rs` |
| **SS5** Validate: reproduce paper's 4.8× speedup vs ItyFuzz trên 1 contract example. Nếu speedup ≥ 3× → OK | 2 ngày | reproduction report |
| **SS6** Run 12 × 20 sweep | ~40h | `results/baselines/smartshot/...` |
| **SS7** Update JSON | 0.5 ngày | done |

**Acceptance**: speedup ≥ 3× ItyFuzz, 12/12 bridges run.

**Cut-loss criterion**: nếu SS3 (symbolic taint) ngốn > 1 tuần debug,
**accept simplified version**: random snapshot mutation (no taint
guidance). Document trong methodology — reviewer sẽ chấp nhận miễn là
ta nhận thiếu sót thành thật.

---

## 3. Tracking matrix re-impl

| Phase / Sub-task | Owner | Effort | Status |
|---|---|---|---|
| **X1-X6** XScope re-impl + sweep | Member B | 2 tuần | ❌ TODO |
| **SA1-SA8** SmartAxe re-impl + sweep | Member A (Python) | 4 tuần | ❌ TODO |
| **VS1-VS7** VulSEye re-impl + sweep | Member B | 3 tuần | ❌ TODO |
| **SS1-SS7** SmartShot re-impl + sweep | Member B (or Member A nếu B kẹt) | 3 tuần | ❌ TODO |
| **D1** BridgeSentry sweep | (đang chạy) | ~40h | 🔄 IN PROGRESS |
| **D2** Aggregate re-impl + ItyFuzz + GPTScan + 4 self-run JSONs | Member A | 1 ngày | ❌ Blocked |
| **D3** LaTeX RQ1 table render | Member A | 2 ngày | ❌ Blocked |

---

## 4. Acceptance criteria toàn cục cho re-impl track

- [ ] **4/4 tools** có self-run JSON với per-bridge data trên 12 benchmarks
- [ ] **3/4 tools** validate reproduction trong ±5pp paper headline
      metric (XScope rule firing match, SmartAxe P/R, VulSEye/SmartShot
      speedup); 1/4 có thể fail validation và document làm "limitation"
- [ ] **Bảng RQ1 cuối** có ≥ 90% cells với data thực (12 × 7 = 84 cells,
      target ≥ 76 cells có giá trị, ≤ 8 cells `n/a`)
- [ ] Methodology note rõ cho từng tool: re-impl scope, simplifications,
      validation outcomes
- [ ] All re-impl code committed trên branch `feat/baseline-reimpl`
      (tạch riêng từ `feat/real-bytecode-fuzz` khi bắt đầu)

---

## 5. Rủi ro + mitigations

| Rủi ro | Khả năng | Impact | Mitigation |
|---|---|---|---|
| SmartAxe re-impl không reproduce P/R paper claim | Cao | RQ1 cell yếu | Document như limitation; vẫn cite re-impl numbers + caveat |
| SmartShot taint analysis quá tricky | Cao | Block tuần 10-12 | Cut-loss → simplified random-mutation version (đã ghi trong SS3) |
| VulSEye backward analysis cần Z3 deps không stable trên Windows local | Trung | Slowdown | Develop trên lab Linux; test trên Windows chỉ chạy fuzz, không build |
| Member B kẹt Phase A polish (gempad/multichain bb=0) | Trung | Re-impl chậm 1-2 tuần | Buffer ở tuần 12 đã tính; nếu kẹt > 2 tuần, drop SmartShot xuống cite-published |
| RPC quota exhausted trên Alchemy | Cao (4 tools × 12 × 20 = 960 runs RPC) | Sweeps fail | Dùng dest_rpc=ETH_RPC_URL fallback; spread sweeps qua nhiều ngày |
| Paper §5.3 Reviewer hỏi tại sao re-impl đạt khác paper số? | Cao | Submission feedback | Methodology note mỗi tool: scope subset, simplifications, validation result. Honest reporting > cherry-picked numbers |

---

## 6. Critical commands sau khi re-impl

```bash
# Sau khi tool i có release binary trên lab:
BUDGET=600 RUNS=20 BASELINE=xscope bash scripts/run_baseline_sweep_real.sh

# Sau khi tất cả 4 tools done:
python scripts/collect_baseline_results.py \
    --bridgesentry results/realbytecode_full_<TS>/ \
    --baselines results/baselines/ \
    --cited baselines/_cited_results/ \
    --format latex \
    > docs/rq1_table.tex
```

---

## 7. Tiến độ check-in hàng tuần

```bash
# Số sub-task hoàn thành
grep -c "✅" docs/PLAN_REIMPL_BASELINES.md
# Số benchmark đã có self-run JSON
ls results/baselines/*/<bridge>/run_001.json 2>/dev/null | wc -l
```

→ Update tracking matrix với `✅` cho task xong; commit doc với
message `docs(reimpl): update <tool> sub-task progress`.

---

## 8. Tham chiếu

- Cited results consolidated: [`docs/RQ1_BASELINE_CITED_RESULTS.md`](RQ1_BASELINE_CITED_RESULTS.md)
- Cited JSON templates: [`baselines/_cited_results/`](../baselines/_cited_results/)
- BridgeSentry codebase: [`src/module3_fuzzing/`](../src/module3_fuzzing/)
- Original paper PDFs (per cited JSON files):
  - XScope: [arXiv 2208.07119](https://arxiv.org/abs/2208.07119)
  - SmartAxe: [arXiv 2406.15999](https://arxiv.org/abs/2406.15999)
  - VulSEye: [arXiv 2408.10116](https://arxiv.org/abs/2408.10116)
  - SmartShot: [DOI 10.1145/3715714](https://doi.org/10.1145/3715714)
- Phase A foundation (must finish before re-impl Rust tools): commit `b78b3b5` trên `feat/real-bytecode-fuzz`
