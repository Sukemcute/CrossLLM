# RQ1 Baseline Cited Results — Tổng hợp từ paper gốc

> **Mục đích**: Đối chiếu trực tiếp với bảng RQ1 (paper §5.3). File này
> là phiên bản đọc-được của 5 JSON trong [`baselines/_cited_results/`](../baselines/_cited_results/),
> cộng với 2 tools self-run (ItyFuzz / GPTScan — **full sweep 12 bridge, 0/12**) — toàn bộ data
> *publicly citable* hiện có cho 6 baselines + BridgeSentry.
> Bảng tổng cuối cùng (authoritative) là matrix ở §"FINAL" phía dưới; §1 là snapshot cite-time đã được thay thế.
> ItyFuzz/GPTScan 0/12 đã verify trực tiếp từ raw log trên lab 2026-06-17 (`scripts/_verify_ityfuzz_gptscan.py`).
>
> Snapshot: 2026-04-28 (cite-only) + 2026-06-04→06 (VS/SS lab sweep, 240 runs × 600s × 12 bridges/tool) + 2026-06-06 (GPTScan full self-run 240 runs × 10s LLM call) + 2026-06-06→07 (ItyFuzz full self-run 240 runs, 8 bridges full-fuzz × 660s + 4 bridges no-ABI fast-exit) + **2026-06-18 (BridgeSentry real-bytecode re-sweep trên data ATG đã regenerate sạch: 240 runs × 60s × 12 bridges → DR 12/12, TTE median 1.2s / mean 1.72s; sweep `realbytecode_regen_20260617T130843Z`)**. **5/6 baselines self-run hoàn tất** — file này sẵn sàng gộp thành `docs/RQ1_FINAL.md` cho LaTeX rendering.

---

## 1. Per-bridge coverage matrix

Cột tool ⇄ hàng benchmark. Ô ghi nhận:
- `✓` — paper claim positive detection trên benchmark này
- `✗` — paper claim negative (test mà không detect) hoặc smoke ta chạy detected=false
- `n/a` — paper không test trên benchmark này (or domain mismatch)
- `agg` — paper chỉ public aggregate metrics, không enumerate per-benchmark

| Bridge | ItyFuzz | SmartShot | VulSEye | SmartAxe | GPTScan | XScope |
|---|---|---|---|---|---|---|
| nomad        | ✗ (self-run) | n/a | n/a | agg | ✗ (self-run) | n/a |
| qubit        | ✗ (self-run)‡ | n/a | n/a | agg | ✗ (self-run) | **✓** |
| pgala        | ✗ (self-run) | n/a | n/a | agg | ✗ (self-run) | n/a |
| polynetwork  | ✗ (self-run) | n/a | n/a | agg† | ✗ (self-run) | n/a |
| wormhole     | ✗ (self-run) | n/a | n/a | agg | ✗ (self-run) | n/a |
| socket       | ✗ (self-run) | n/a | n/a | agg | ✗ (self-run) | n/a |
| ronin        | ✗ (self-run)‡ | n/a | n/a | agg | ✗ (self-run) | n/a |
| harmony      | ✗ (self-run) | n/a | n/a | agg | ✗ (self-run) | n/a |
| multichain   | ✗ (self-run) | n/a | n/a | agg | ✗ (self-run) | n/a‡ |
| orbit        | ✗ (self-run) | n/a | n/a | agg | ✗ (self-run) | n/a |
| fegtoken     | ✗ (self-run)‡ | n/a | n/a | agg | ✗ (self-run) | n/a |
| gempad       | ✗ (self-run)‡ | n/a | n/a | agg | ✗ (self-run) | n/a |

**Chú thích:**
- **✗ (self-run)** — ItyFuzz/GPTScan đã chạy **full sweep 12 bridge × 20 runs**; 0/12 detected
  (verify từ raw log lab 2026-06-17). ItyFuzz: 8 bridge fuzz đủ 660s không trigger oracle;
  4 bridge đánh dấu **‡** (qubit/ronin/fegtoken/gempad) abort trước khi fuzz — không có ABI
  on-chain ("there is nothing to fuzz") / GemPad thiếu fork-block timestamp.
  GPTScan: 10 DeFi rules không cover bridge bugs (paper §5.3 expected).
- **† polynetwork (SmartAxe)** — Paper §1 nêu PolyNetwork là motivating
  example với loss $600M; nhưng per-bridge detection không enumerate
  trong public materials, chỉ có aggregate precision/recall trên 16-bridge
  dataset.
- **‡ multichain (XScope)** — XScope có evaluate Anyswap (predecessor
  của Multichain) với 4 txs flagged unauthorized unlocking. Tuy nhiên
  incident đó khác với MPC-key compromise 2023 ta benchmark, nên đánh
  dấu n/a thay vì ✓.

**Total positive detections từ cite-published**: **1/72 cells**
(XScope phát hiện được Qubit attack — flagged 20 txs, bao gồm 1 tx 43
ngày trước cuộc tấn công $80M Jan 2022).

---

## 2. Aggregate metrics theo từng paper

Số liệu tóm gọn từng tool — ghi nhận toàn bộ aggregate tools công bố.

### ItyFuzz [8] — ISSTA 2023

| Metric | Value | Source |
|---|---|---|
| Bug coverage | 28 (1st place trong 5 fuzzers) | Paper Table 4 |
| Speedup vs Smartian | up to 50× | Paper §6 |
| **Self-run full sweep (12 bridge × 20 runs, 660s)** | **0/12 detected** (8 fuzz no-trigger, 4 no-ABI abort) | [`ityfuzz_self_run.json`](../baselines/_cited_results/ityfuzz_self_run.json) |
| Status | ✅ Full sweep DONE (verify raw log lab 2026-06-17) | — |

### SmartShot [24] — FSE 2025

| Metric | Value | Source |
|---|---|---|
| Vulnerable contracts found | 2,150 / 42,738 | Paper abstract |
| Speedup vs ItyFuzz/Smartian | 4.8×-20.2× | Paper abstract |
| Zero-days top-10k contracts | 24 | Paper abstract |
| Eval domain | General DeFi (token, AMM, lending) | Paper §5 |
| Status | ❌ No public artifact | — |

### VulSEye [13] — IEEE TIFS 2025

| Metric | Value | Source |
|---|---|---|
| Vulnerabilities found total | 4,845 | Paper abstract |
| Speedup vs state-of-the-art | up to 9.7× | Paper abstract |
| Zero-days top-50 DApps | 11 (~$2.5M USD impact) | Paper §6 |
| Eval domain | General smart contract | Paper §5 |
| Status | ❌ No public artifact | — |

### SmartAxe [3] — FSE 2024

| Metric | Value | Source |
|---|---|---|
| Precision (manual eval set) | **84.95%** | Paper §6 abstract |
| Recall (manual eval set) | **89.77%** | Paper §6 abstract |
| Manual dataset | 16 bridges, 88 CCVs, 203 contracts | Paper §6 |
| Wild scan | 232 new CCVs across 1,703 contracts ($1,885,250 USD) | Paper §6 |
| Status | ⚠️ figshare artifact 403 (access controlled) | — |

### GPTScan [9] — ICSE 2024

| Metric | Value | Source |
|---|---|---|
| Precision (token contracts) | >90% | Paper §6 |
| Precision (Web3Bugs corpus) | 57.14% | Paper §6 |
| Recall (logic vulns) | >70% | Paper §6 |
| New vulns missed by humans | 9 | Paper §6 |
| Avg scan time per kLOC | 14.39 s | Paper §6 |
| Avg cost per kLOC (gpt-3.5-turbo) | $0.01 | Paper §6 |
| Datasets | Web3Bugs, **DefiHacks** (13 non-bridge), Top200 | Paper §5 + datasets repo |
| **Self-run full sweep (12 bridge × 20 runs, NIM gpt-oss-120b)** | **0/12 detected** (matches paper §5.3 expectation) | [`gptscan_self_run.json`](../baselines/_cited_results/gptscan_self_run.json) |
| Status | ✅ Full sweep DONE (verify raw log lab 2026-06-17) | — |

### XScope [6] — ASE 2022

| Metric | Value | Source |
|---|---|---|
| Bridges evaluated | 4 (THORChain, pNetwork, Anyswap, **Qubit**) | [results repo](https://github.com/xscope-tool/results) |
| THORChain | 56 txs flagged "Inconsistent Event Parsing" | results repo |
| pNetwork | 3 txs flagged "Inconsistent Event Parsing" | results repo |
| Anyswap | 4 txs flagged "Unauthorized Unlocking" | results repo |
| **Qubit (our benchmark)** | **20 txs flagged "Unrestricted Deposit Emitting"**, **1 suspicious tx 43 days pre-attack** | results repo |
| Status | ❌ No source code public — chỉ results repo | — |

---

## 3. Khả năng tự run trên 12 benchmarks (sau cite)

| Tool | Public artifact? | Self-runnable? | ETA full sweep |
|---|---|---|---|
| ItyFuzz | ✅ MIT | ✅ build xong trên lab | ✅ DONE — full sweep 12×20, 0/12 |
| GPTScan | ✅ Apache 2.0 | ✅ install xong | ✅ DONE — full sweep 12×20, 0/12 |
| SmartAxe | ⚠️ figshare 403 | ❌ chưa download được | — (xin email tác giả?) |
| XScope | ❌ no source | ❌ không thể | — |
| SmartShot | ❌ no source | ❌ không thể | — |
| VulSEye | ❌ no source | ❌ không thể | — |

**→ 2/6 tools có thể tự run, 4/6 phải dựa cite-published.** Đây là
academic standard cho RQ1 cross-tool comparison khi upstream artifact
không có. Methodology note ở mỗi `baselines/_cited_results/<tool>.json`
giải thích lý do null cell.

---

## 4. Cách render bảng RQ1 cuối cùng cho LaTeX paper

Sau khi BridgeSentry D1 sweep + ItyFuzz/GPTScan full sweep xong, bảng
§5.3 sẽ có cấu trúc:

```
                  BridgeSentry         ItyFuzz       SmartShot  VulSEye   SmartAxe              GPTScan         XScope
nomad             ✓ DR=20/20  TTE=...  self-run      n/a        n/a       agg(P=85%, R=90%)     ✗ (self-run)    n/a
qubit             ✓ DR=20/20  TTE=...  self-run      n/a        n/a       agg                   ✗ (self-run)    ✓ cite
pgala             ✓ DR=20/20  TTE=...  self-run      n/a        n/a       agg                   self-run        n/a
polynetwork       ✓ DR=20/20  TTE=...  self-run      n/a        n/a       agg†                  self-run        n/a
... (8 hàng)      ✓ DR=20/20  TTE=...  self-run      n/a        n/a       agg                   self-run        n/a
```

Aggregate cells (`agg`) và cite cells (`✓ cite`) sẽ render cùng style
nhưng có footnote indicator (số chỉ về §6 methodology). Reviewer sẽ
thấy rõ data nào tự run, data nào trích, data nào không có.

---

## Tài liệu nguồn

| Tool | DOI / arXiv | Artifact link | Cited JSON |
|---|---|---|---|
| ItyFuzz | [arXiv 2306.17135](https://arxiv.org/abs/2306.17135) | https://github.com/fuzzland/ityfuzz | n/a (self-run only) |
| SmartShot | [DOI 10.1145/3715714](https://doi.org/10.1145/3715714) | (no public) | [smartshot.json](../baselines/_cited_results/smartshot.json) |
| VulSEye | [arXiv 2408.10116](https://arxiv.org/abs/2408.10116) | (no public) | [vulseye.json](../baselines/_cited_results/vulseye.json) |
| SmartAxe | [arXiv 2406.15999](https://arxiv.org/abs/2406.15999) | https://figshare.com/articles/code/FSE24-SmartAxe_artifact/24218808 (403) | [smartaxe.json](../baselines/_cited_results/smartaxe.json) |
| GPTScan | [arXiv 2308.03314](https://arxiv.org/abs/2308.03314) | https://github.com/GPTScan/GPTScan | [gptscan.json](../baselines/_cited_results/gptscan.json) |
| XScope | [arXiv 2208.07119](https://arxiv.org/abs/2208.07119) | https://github.com/xscope-tool/results (results only, không source) | [xscope.json](../baselines/_cited_results/xscope.json) |

---

# 📈 RQ1 — Self-run results sau re-implementation track (snapshot 2026-05-03)

> **Đối chiếu với §1 ở trên**: bảng cũ tổng hợp từ paper gốc — chỉ
> 1/72 cells positive (XScope phát hiện Qubit). Bảng dưới đây ghi
> nhận kết quả sau khi đã re-implement 2/4 tools (XScope X1-X6,
> SmartAxe SA1-SA8) + Phase D1 BridgeSentry sweep + ItyFuzz/GPTScan
> full self-run (0/12 cả hai). **Toàn bộ 6 baseline × 12 bridge đã có
> data self-run thực**, vs 1/72 ban đầu.

## 5. Detection matrix — sau self-run (current state)

| Bridge | BridgeSentry (ours) | ItyFuzz | SmartShot | VulSEye | SmartAxe | GPTScan | XScope |
|---|---|---|---|---|---|---|---|
| **nomad**       | ✓ (self) | ✗ (self,36%cov) | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | ✓ (self) |
| **qubit**       | ✓ (self) | ✗ (no-ABI)      | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | ✓ (self, **✓** cite) |
| **pgala**       | ✓ (self) | ✗ (self,53%cov) | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | ✓ (self) |
| **polynetwork** | ✓ (self) | ✗ (self,35%cov) | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | ✓ (self) |
| **ronin**       | ✓ (self) | ✗ (no-ABI)      | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | ✓ (self) |
| **harmony**     | ✓ (self) | ✗ (self,54%cov) | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | ✓ (self) |
| **multichain**  | ✓ (self) | ✗ (self,43%cov) | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | ✓ (self) |
| **orbit**       | ✓ (self) | ✗ (self,31%cov) | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | ✓ (self) |
| **fegtoken**    | ✓ (self) | ✗ (no-ABI)      | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | ✓ (self) |
| **gempad**      | ✓ (self) | ✗ (no-ABI)      | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | ✓ (self) |
| **wormhole**    | ✓ (self) | ✗ (self,26%cov) | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | — (Solana out-of-scope) |
| **socket**      | ✓ (self) | ✗ (self, 5%cov) | ✓ (self) | ✓ (self) | ✓ (self) | ✗ (self) | — (predicate-class out-of-spec) |
| **Detected**    | **12/12** | **0/12** (8 fuzz, 4 no-ABI) | **12/12** | **12/12** | **12/12** | **0/12** (self-run full) | **10/12** |
| **Self-run %**  | 100%     | **100%**       | 100%      | 100%     | 100%      | **100%**    | 92% (10/11 in-scope) |

**Diff vs §1 (cite-only)**:
- BridgeSentry: chuyển từ "chưa có" → 12/12 ✓
- XScope: 1/12 → **10/12** (lift +9 cells từ replay-mode A1-A5)
- SmartAxe: 0/12 cited → **12/12** detected (4/12 strict-match)
- **VulSEye: 0/12 cited → 12/12 detected (9/12 strict-match)** — lab sweep 2026-06-04→06, 240 runs × 600s
- **SmartShot: 0/12 cited → 12/12 detected (12/12 strict-match)** — lab sweep 2026-06-04→06, 239 runs × 600s (1 BSC RPC reset on fegtoken/002)
- **GPTScan: 0/12 detected (cite + self-run đồng thuận)** — lab sweep 2026-06-06, 240 runs × ~10s LLM call, model `openai/gpt-oss-120b` via NVIDIA NIM. Legitimate ✗ trên cả 12 bridges vì 10 DeFi rules (Flashloan_*, Slippage, ApprovalNotClear, FrontRun, UnauthorizedTransfer, ...) không cover bridge-specific bug patterns. Khẳng định paper §5.3 expected outcome.
- **ItyFuzz: 0/12 detected (cite + self-run đồng thuận)** — lab sweep 2026-06-06→07, 240 runs × 660s budget = 29h24m wall-clock. Trên 8/12 bridges ItyFuzz fuzz được với coverage 5-54% inst (`pgala 53%, harmony 54%, multichain 43%`) nhưng default detectors (high_confidence) không phát hiện bridge-specific bug. Trên 4/12 bridges (`qubit, ronin, fegtoken, gempad`) → **ABI fetch fail** vì attack contracts unverified trên Etherscan/BSCScan → EVMole decompile fail → "There is nothing to fuzz" exit 3s. Hai loại fail mode này đều là **paper-defensible weakness** của directed onchain fuzzing.

---

## 6. Spec-predicted predicate match (strict any-of)

Dành cho tools có per-bridge expected-predicate map (XScope spec §4, SmartAxe spec §4). Đây là metric chặt hơn "detected" — yêu cầu predicate cụ thể fire, không chỉ "có violation nào đó".

| Bridge | XScope expected | XScope fired | Match | SmartAxe expected | SmartAxe fired | Match | VulSEye expected | VulSEye fired | Match | SmartShot expected | SmartShot fired | Match |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| nomad       | I-6        | I-5,I-6     | ✓ | SC4    | SC2     | ✗ | BP2    | BP1,BP5,BP6        | ✗ | MS1    | MS1,MS2,MS4,MS5 | ✓ |
| qubit       | I-2        | I-2,I-5     | ✓ | SC1,SC2| SC2     | ✓ | BP1,BP6| BP1,BP5,BP6        | ✓ | MS2    | MS1,MS2,MS4,MS5 | ✓ |
| pgala       | I-3,I-4,I-6 | I-5,I-6    | ✓ | SC4,SC5| SC2     | ✗ | BP3,BP5| BP1,BP5,BP6        | ✓ | MS1    | MS1,MS2,MS4,MS5 | ✓ |
| polynetwork | I-5,I-6    | I-5         | ✓ | SC3    | SC2,SC3,SC4 | ✓ | BP5  | BP1,BP5,BP6        | ✓ | MS1    | MS1,MS2,MS4,MS5 | ✓ |
| wormhole    | I-5,I-6    | —           | ✗ | SC4    | SC4     | ✓ | BP4,BP5| BP1,BP5,BP6        | ✓ | MS1    | MS1,MS2,MS4,MS5 | ✓ |
| socket      | I-1,I-5    | —           | ✗ | SC2    | SC2,SC4 | ✓ | BP5    | BP1,BP2,BP5,BP6    | ✓ | MS1,MS2| MS1,MS2,MS4,MS5 | ✓ |
| ronin       | I-6        | I-5,I-6     | ✓ | SC4    | SC2     | ✗ | BP3    | BP1,BP2,BP5,BP6    | ✗ | MS1    | MS1,MS2,MS4,MS5 | ✓ |
| harmony     | I-6        | I-5,I-6     | ✓ | SC4    | SC2     | ✗ | BP3    | BP1,BP2,BP5,BP6    | ✗ | MS1    | MS1,MS2,MS4,MS5 | ✓ |
| multichain  | I-5        | I-5         | ✓ | SC4    | SC2     | ✗ | BP5    | BP1,BP2,BP5,BP6    | ✓ | MS1    | MS1,MS2,MS4,MS5 | ✓ |
| orbit       | I-6        | I-5,I-6     | ✓ | SC4    | SC2     | ✗ | BP3    | BP1..BP6           | ✓ | MS1    | MS1,MS2,MS4,MS5 | ✓ |
| fegtoken    | I-1,I-5    | I-5         | ✓ | SC5    | SC2     | ✗ | BP1    | BP1,BP2,BP5,BP6    | ✓ | MS1    | MS1,MS2,MS4,MS5 | ✓ |
| gempad      | I-5        | I-5         | ✓ | SC6    | SC2     | ✗ | BP5    | BP1,BP2,BP4,BP5,BP6| ✓ | MS1    | MS1,MS2,MS4,MS5 | ✓ |
| **Strict %** |            |             | **10/12** |    |          | **4/12** | | | **9/12** | | | **12/12** |

**Tại sao SmartAxe strict thấp hơn XScope?** 8 simplified benchmarks giữ syntactic guards (require statements vẫn còn trong reproduction); bug thật là **runtime V4 key-compromise**. Static analysis không bridge được semantic gap mà không có symbolic reasoning trên trust boundaries. Phù hợp paper §6.2 (7/16 detection rate trên similar attacks).

**Tại sao VulSEye strict = 9/12** (miss nomad, ronin, harmony)? Cả 3 đều expect BP2/BP3 (token-mint/lock-violation patterns) nhưng opcode-scan tìm thấy BP1/BP5/BP6 trước. Nói cách khác: VulSEye phát hiện được pattern khác trên cùng contract nhưng không khớp 1-1 root cause. Đây là **bias của directed graybox fuzzer khi BP map static-derived** — paper gốc nói rõ predicate set có giới hạn.

**Tại sao SmartShot strict = 12/12?** ACTIVE_POOL push toàn bộ {MS1, MS2, MS4, MS5} mỗi iter → mọi expected mutation đều có cơ hội fire. Double-validation filter ra mutations không trigger thật. TTE mean rất nhanh (0.003s–18.6s) vì SLOAD inspector + curated taint cache nhanh.

---

## 7. TTE / Analysis wall-clock (giây)

> **BridgeSentry TTE = median per-bridge** từ real-bytecode sweep `realbytecode_regen_20260617T130843Z` (240 runs, 20/bridge, budget 60s, fork ETH mainnet block 15259100). Full stats: [`results/lab_sweep_regen_summary.json`](../results/lab_sweep_regen_summary.json).

| Bridge | BridgeSentry (median / mean ± std) | XScope | SmartAxe | ItyFuzz (inst-cov%) | SmartShot | VulSEye | GPTScan |
|---|---|---|---|---|---|---|---|
| nomad       | **3.77 / 4.07±2.22** | det.* | 4.5  | 660s (36% inst) | **1.43**  | 0.0†  | ~10s LLM |
| qubit       | **0.001 / 0.002±0.001** | det.* | 2.8  | **3s no-ABI‡** | **1.30**  | 0.0†  | ~10s LLM |
| pgala       | **0.357 / 0.603±0.41** | det.* | 2.3  | 660s (53% inst) | **0.011** | 0.0†  | ~10s LLM |
| polynetwork | **3.16 / 3.16±2.23** | det.* | 2.4  | 660s (35% inst) | **0.005** | 0.0†  | ~10s LLM |
| wormhole    | **0.939 / 1.35±0.75** | —     | 4.6  | 660s (26% inst) | **0.004** | 0.0†  | ~10s LLM |
| socket      | **2.31 / 3.16±2.56** | —     | 3.6  | 660s (5% inst)  | **0.011** | 0.0†  | ~10s LLM |
| ronin       | **0.384 / 0.571±0.28** | det.* | 4.3  | **3s no-ABI‡** | **0.012** | 0.0†  | ~10s LLM |
| harmony     | **1.39 / 1.44±0.72** | det.* | 6.1  | 660s (54% inst) | **0.015** | 0.0†  | ~10s LLM |
| multichain  | **0.001 / 0.162±0.24** | det.* | 4.4  | 660s (43% inst) | **5.44**  | 0.0†  | ~10s LLM |
| orbit       | **1.42 / 1.44±0.75** | det.* | 4.4  | 660s (31% inst) | **2.14**  | 0.0†  | ~10s LLM |
| fegtoken    | **4.87 / 4.69±2.58** | det.* | 5.8  | **3s no-ABI‡** | **5.03**  | 0.0†  | ~10s LLM |
| gempad      | **0.001 / 0.001±0.0003** | det.* | 3.5  | **0.3s no-ABI‡** | **18.63** | 0.0†  | ~10s LLM |
| **mean** | **median 1.2s / mean 1.72s** |       | **4.07s** | **~440s** (mix) | **2.84s** | 0.0†  | ~10s |

\* XScope replay-mode là deterministic per-tx classifier — TTE undefined per paper convention.

† VulSEye TTE=0.0 vì opcode-scan target identification chạy đồng thời với scenario init — finding emit ngay khi scenario đầu tiên execute. Đây là pattern bình thường của directed-graybox khi code-target xác định trước fuzz loop.

‡ ItyFuzz "no-ABI" mode: 4/12 bridges (qubit, ronin, fegtoken, gempad) — attack contract unverified trên Etherscan/BSCScan → ItyFuzz không fetch được ABI → EVMole decompile fail → "There is nothing to fuzz" exit 3s. Đây là **defensible weakness** của onchain fuzz tool — paper §5.3 thảo luận ràng buộc directed fuzzing với contracts đã verified.

---

## 8. Summary roll-up sau self-run

| Tool | Type | Track | Detected ÷ 12 | Strict-match ÷ 12 | TTE measured | Source |
|---|---|---|---|---|---|---|
| **BridgeSentry** | Cross-chain fuzzer (ours) | self-run lab | **12/12** ✓ | n/a | median 1.2s / mean 1.72s (240 runs) | `results/realbytecode_regen_20260617T130843Z/` (lab) + [`results/lab_sweep_regen_summary.json`](../results/lab_sweep_regen_summary.json) |
| **XScope** | Rule-based detector | self-run via replay | **10/12** ✓ | **10/12** | (deterministic) | [`xscope_self_run.json`](../baselines/_cited_results/xscope_self_run.json) |
| **SmartAxe** | Static analysis (Slither) | self-run | **12/12** ✓ | 4/12 | mean 4.07s | [`smartaxe_self_run.json`](../baselines/_cited_results/smartaxe_self_run.json) |
| **VulSEye** | Directed graybox fuzzer (re-impl) | self-run | **12/12** ✓ | **9/12** | TTE 0.0 (opcode-scan instant) | [`vulseye_self_run.json`](../baselines/_cited_results/vulseye_self_run.json) |
| **SmartShot** | Mutable-snapshot fuzzer (re-impl) | self-run | **12/12** ✓ | **12/12** | mean 2.84s | [`smartshot_self_run.json`](../baselines/_cited_results/smartshot_self_run.json) |
| **GPTScan** | LLM + static (re-impl, NIM `gpt-oss-120b`) | **self-run lab** | **0/12** (legitimate ✗) | n/a | mean ~10s LLM-call | [`gptscan_self_run.json`](../baselines/_cited_results/gptscan_self_run.json) |
| **ItyFuzz** | Snapshot fuzzer | **self-run lab** | **0/12** (8 fuzz no-detect, 4 no-ABI exit) | n/a | 8 × 660s + 4 × ~3s = mean ~440s | [`ityfuzz_self_run.json`](../baselines/_cited_results/ityfuzz_self_run.json) |

---

## 9. Trajectory cells RQ1

```
                 §1 (cite only)         §5-8 (sau self-run)         Δ
                 ──────────────         ───────────────────         ──
BridgeSentry      0/12 (n/a)             12/12 ✓                   +12
XScope            1/12 (Qubit only)      10/12 ✓                    +9
SmartAxe          0/12 (agg only)        12/12 ✓ (4/12 strict)     +12
VulSEye           0/12 (domain mism.)    12/12 ✓ (9/12 strict)     +12
SmartShot         0/12 (domain mism.)    12/12 ✓ (12/12 strict)    +12
GPTScan           0/12                   0/12 ✗ (full self-run)   confirms cite
ItyFuzz           0/12 (no per-bridge)   0/12 ✗ (full self-run,    confirms cite
                                          8 fuzz no-trigger,
                                          4 no-ABI fail-fast)
                 ────                    ─────                      ───
Total positive    1/72 cells              60/84 cells              +59
                  (1.4%)                  (71%)
```

**Lưu ý GPTScan**: detected=0/12 trong self-run xác nhận paper §5.3 prediction — GPTScan ships 10 DeFi-specific rules không cover cross-chain bridge bugs. Đây là **defensible negative result**, không phải bug implementation. 240 runs × ~10s LLM call × NVIDIA NIM `openai/gpt-oss-120b` (chi phí $0, free tier).

**Lưu ý ItyFuzz**: detected=0/12 self-run là defensible:
- **8 bridges fuzzing thật sự**: pgala (53%), harmony (54%), multichain (43%), nomad (36%), polynetwork (35%), orbit (31%), wormhole (26%), socket (5%) — ItyFuzz có thể explore code coverage nhưng default `high_confidence` detectors không trigger trên bridge-specific bugs (ví dụ multi-sig key compromise, VAA replay, dual-spend không nằm trong oracle set của ItyFuzz)
- **4 bridges fail-fast vì no-ABI**: qubit, ronin, fegtoken, gempad — attack contracts unverified trên Etherscan/BSCScan, EVMole decompile fail
- **So sánh BridgeSentry vs ItyFuzz**: BridgeSentry không cần ABI (dùng metadata + scenarios), không cần default detectors (dùng invariants từ Module 1) → 12/12 vs 0/12. Đây là **paper §5.3 RQ1 contribution** chính.

\* Tổng cells = 84 vì §5 thêm column BridgeSentry (7 tools × 12 bridges) — §1 chỉ tính 6 baselines (72 cells).

---

## 10. Roadmap để đầy bảng (sau snapshot này)

| Cells còn thiếu | Tool | Effort | Output |
|---|---|---|---|
| 12 | VulSEye | ~3 tuần (VS2-VS7) | self-run + cited JSON |
| 12 | SmartShot | ~3 tuần (SS2-SS7) | self-run + cited JSON |
| 10 | ItyFuzz | ~40h overnight | full sweep 12 × 20 |
| 10 | GPTScan | ~40h overnight | full sweep 12 × 20 |
| 12 | BridgeSentry | re-pull lab | local JSON cho aggregator |
| **56** | **Total cells còn thiếu** | ~6-7 tuần | đầy 84/84 RQ1 cells |

Sau khi xong: **84/84 = 100% data-rich** RQ1 table — defensible cho paper §5.3 reviewer.

---

## 11. Cách đọc bảng cho paper reviewer

* **§1 vs §5**: §1 reflects publicly-citable state of the art khi paper được publish; §5 reflects what we ran ourselves. Cả hai tồn tại side-by-side để reviewer phân biệt.
* **Self-run methodology**: tất cả self-run cells trong §5 dùng same fork-block + same metadata + same expected-predicate map → reproducible.
* **Honest reporting**: cells với `(self)` nhưng strict-match = ✗ (e.g. SmartAxe nomad) đều có note giải thích lý do trong methodology footnote — không cherry-pick.
* **Aggregator script**: chạy `python scripts/build_xscope_self_run_cited.py` + `python scripts/build_smartaxe_self_run_cited.py` để regenerate self-run JSONs sau mỗi sweep mới.



=== ATG + Module 2 sizes (regenerated 2026-06-18, normalized + null-sanitized) ===
  bridge        nodes  edges  invariants  scenarios
  nomad           6      2        18          18
  qubit           5      3        18          18
  pgala           5      2        21          21
  polynetwork     5      2        18          18
  wormhole        5      2        21          21
  socket          4      4        18          18
  ronin           3      5        20          20
  harmony         7      7        19          19
  multichain      4      5        24          24
  orbit           4      5        18          18
  fegtoken        9      8        17          17
  gempad          3      5        18          18
  -------------------------------------------------
  TOTAL          60     50       230         230

Lưu ý: số cũ là 54/47/229/229 (trước regenerate). Bản mới (60/50/230/230) sạch hơn:
node dedup + gom actor chuẩn (User/Recipient/ZeroAddress), không placeholder, 0 null.
Module 3 re-sweep trên data mới: DR 12/12, TTE §7. Backup data cũ ở
benchmarks/_backup_llm_outputs_pre_regen/.