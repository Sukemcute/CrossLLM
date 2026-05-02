# RQ1 Baseline Cited Results — Tổng hợp từ paper gốc

> **Mục đích**: Đối chiếu trực tiếp với bảng RQ1 (paper §5.3). File này
> là phiên bản đọc-được của 5 JSON trong [`baselines/_cited_results/`](../baselines/_cited_results/),
> cộng với 2 tools self-run (ItyFuzz / GPTScan smoke) — toàn bộ data
> *publicly citable* hiện có cho 6 baselines + BridgeSentry.
>
> Snapshot: 2026-04-28. Khi BridgeSentry full sweep + ItyFuzz/GPTScan
> full sweep hoàn tất, file này được gộp với data tự run thành
> `docs/RQ1_FINAL.md` cho LaTeX rendering.

---

## 1. Per-bridge coverage matrix

Cột tool ⇄ hàng benchmark. Ô ghi nhận:
- `✓` — paper claim positive detection trên benchmark này
- `✗` — paper claim negative (test mà không detect) hoặc smoke ta chạy detected=false
- `n/a` — paper không test trên benchmark này (or domain mismatch)
- `agg` — paper chỉ public aggregate metrics, không enumerate per-benchmark

| Bridge | ItyFuzz | SmartShot | VulSEye | SmartAxe | GPTScan | XScope |
|---|---|---|---|---|---|---|
| nomad        | smoke ok | n/a | n/a | agg | ✗ (smoke) | n/a |
| qubit        | smoke ok | n/a | n/a | agg | ✗ (smoke) | **✓** |
| pgala        | n/a      | n/a | n/a | agg | n/a       | n/a |
| polynetwork  | n/a      | n/a | n/a | agg† | n/a      | n/a |
| wormhole     | n/a      | n/a | n/a | agg | n/a       | n/a |
| socket       | n/a      | n/a | n/a | agg | n/a       | n/a |
| ronin        | n/a      | n/a | n/a | agg | n/a       | n/a |
| harmony      | n/a      | n/a | n/a | agg | n/a       | n/a |
| multichain   | n/a      | n/a | n/a | agg | n/a       | n/a‡ |
| orbit        | n/a      | n/a | n/a | agg | n/a       | n/a |
| fegtoken     | n/a      | n/a | n/a | agg | n/a       | n/a |
| gempad       | n/a      | n/a | n/a | agg | n/a       | n/a |

**Chú thích:**
- **smoke ok** — Member B đã chạy smoke trên lab; không phải full sweep.
  ItyFuzz Nomad 90s: 44.18% inst-cov / 38.33% branch, 0 objectives in
  short window. GPTScan Nomad/Qubit: cả 2 detected=false (paper §5.3
  predicts: 10 DeFi rules không cover bridge bugs).
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
| **Self-run smoke (Nomad, 90s, our lab)** | **44.18% inst-cov / 38.33% branch / 0 objectives** | `baselines/ityfuzz/INSTALL.md` |
| Status | ✅ Self-runnable, full sweep pending | — |

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
| **Self-run smoke (Nomad+Qubit, our lab, NIM gpt-oss-120b)** | **2/2 detected=false** (matches paper §5.3 expectation) | `baselines/gptscan/INSTALL.md` |
| Status | ✅ Self-runnable, full sweep pending | — |

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
| ItyFuzz | ✅ MIT | ✅ build xong trên lab | ~40h overnight (sau D1) |
| GPTScan | ✅ Apache 2.0 | ✅ install xong + 2 smoke | ~2h (LLM, không phải fuzz, nhanh — có thể chạy parallel với D1) |
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
