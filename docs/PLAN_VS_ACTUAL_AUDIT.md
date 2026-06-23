# Báo cáo Audit: Plan gốc ↔ Hệ thống thực tế (2026-06-22)

> Review chi tiết toàn hệ thống CrossLLM/BridgeSentry và đối chiếu với các plan
> ban đầu. Dựa trên: đọc đầy đủ 6 plan docs (CrossLLM/docs) + 10 vision docs
> (Blockchain/docs, gồm góp ý của thầy) + audit code thực tế (4 module, tests,
> benchmarks, results, paper, baselines).

---

## 0. TL;DR

- **Chất lượng kỹ thuật: cao.** 3 module đều code thật + chạy được, 12 benchmark đầy đủ, sweep 240 runs thật, 6 baseline re-impl, paper trung thực (không còn số bịa, TODO đánh dấu rõ). Không phát hiện fabrication.
- **Bám sát plan KỸ THUẬT** (PLAN_IMPLEMENTATION / PLAN_PAPER_EXPERIMENTS / PLAN_REIMPL_BASELINES): ~85% đúng hướng, một số phần vượt kế hoạch.
- **LỆCH đáng kể khỏi VISION GỐC của thầy** (Blockchain/docs): thiếu **Module TEE/cải tiến IvyCross**, thiếu **process isolation**, **RQ 5→3** (bỏ RQ tìm bug mới + chi phí), **dataset thu nhỏ** (12 reconstruction vs 20 real + Web3Bugs + synthetic + negative).
- **Việc dở dang đã biết:** RQ3 sensitivity chưa chạy, ablation `-Sync` chưa chạy, FPR chưa đo, citation KB-vs-Wu sai cần sửa.

---

## 1. Hai tầng plan (điều quan trọng nhất phải hiểu)

| Tầng | Nằm ở | Nội dung | Hệ thống có bám? |
|---|---|---|---|
| **Vision gốc (thầy)** | `Blockchain/docs/` (GIAI_THICH_KIEN_TRUC, MODULES_SPEC, KICH_BAN_THUC_NGHIEM, TASKS_THAY_GOP_Y, DATASET_MAPPING_IVYCROSS) | CrossLLM = LLM+ATG+Dual-EVM **+ Module TEE (cải tiến IvyCross) + process isolation**; 5 RQ; dataset 3-tier; demo chạy được | **Một phần** — lệch TEE/isolation/RQ/dataset |
| **Plan kỹ thuật** | `CrossLLM/docs/` (PLAN_IMPLEMENTATION, PLAN_PAPER_EXPERIMENTS, PLAN_REIMPL_BASELINES, PLAN_IMPROVE_MEMBER_A, PLAN_POPULATE_*) | 3 module (KHÔNG TEE); Phase A–D; RQ1-3; 12 benchmark; 6 baseline re-impl | **Sát** — ~85% |

→ Hệ thống hiện tại **= hiện thực của plan kỹ thuật**, nhưng plan kỹ thuật đã **âm thầm bỏ TEE/isolation/RQ4-5** so với vision thầy duyệt. Đây là nguồn lệch lớn nhất.

---

## 2. Đối chiếu KIẾN TRÚC / MODULE

| Thành phần | Plan | Thực tế | Trạng thái |
|---|---|---|---|
| Module 1 (LLM→ATG) | LLM trích xuất + ATG builder + invariant synth | ✅ Slither+regex fallback+LLM; ATG builder dedup/canonical; invariant synth 3-stage | **ĐÚNG** |
| Module 2 (RAG) | KB + embedder FAISS + scenario gen "rational adversary" | ✅ đủ, có template fallback per vuln-class | **ĐÚNG** |
| Module 3 (Dual-EVM fuzzer) | 2 revm + mock relay + synced snapshot + ATG-aware mutator + invariant checker | ✅ build được (binary 7.3MB), 14 .rs module, synced snapshot thật, reward α·cov+β·waypoint+γ·inv | **ĐÚNG — đóng góp lõi đã hiện thực** |
| **Module TEE (SGX, cải tiến IvyCross)** | **Thầy YÊU CẦU** (góp ý #2, #5); vision gốc có | ❌ **KHÔNG hiện thực, paper không nhắc** | **LỆCH NẶNG** |
| **Process isolation (Docker --cpus/--memory)** | **Thầy YÊU CẦU** (#6) | ⚠️ Không thấy Dockerfile dùng; sweep chạy thẳng trên lab | **LỆCH** |
| LLM backend | GPT-4 (vision) / gpt-4o-mini (plan) | gpt-oss-120b qua NVIDIA NIM | Khác (chấp nhận được, đã ghi) |
| Tên dự án | CrossLLM (mọi vision doc) | BridgeSentry (paper + code) | Không nhất quán (cần thống nhất) |

---

## 3. ⚑ Đối chiếu 11 GÓP Ý CỦA THẦY (quan trọng nhất cho bảo vệ)

| # | Thầy yêu cầu | Thực tế | OK? |
|---|---|---|---|
| 1 | Dataset multi-chain + mapping | mapping.json mỗi bridge, đa chuỗi | ✅ |
| 2 | **Cải tiến IvyCross** | không có | ❌ |
| 3 | Module dựng graph (ATG) | Module 1 | ✅ |
| 4 | Module fuzzing (multi-chain, snapshot) | Module 3 | ✅ |
| 5 | **Module TEE (cài hardware/môi trường TEE)** | không có | ❌ |
| 6 | **Process isolation (RAM/CPU riêng)** | không rõ/không thấy | ⚠️ |
| 7 | Sơ đồ kiến trúc rõ ràng | SO_DO_* + TikZ trong paper | ✅ |
| 8 | Luồng thực thi chi tiết từng bước | SO_DO_KIEN_TRUC_LUONG + Algorithm 1 | ✅ |
| 9 | Bảng survey vuln cross-chain (loại/mô tả/cách fix) | SURVEY_VULN_CROSSCHAIN (12 dòng) | ✅ |
| 10 | Related work cách họ nghiên cứu | paper Related Work | ✅ |
| 11 | Kịch bản thực nghiệm + **demo chạy được** | 12 benchmark + repro + sweep thật | ✅ |

→ **8/11 đạt. Thiếu #2 + #5 (TEE/IvyCross), #6 (isolation) không rõ.** Đây là gap dễ bị thầy hỏi nhất, vì "cải tiến IvyCross + TEE" chính là *framing gốc* của đề tài.

---

## 4. Đối chiếu RESEARCH QUESTIONS

| | Vision gốc (KICH_BAN) | Plan kỹ thuật | Paper thực tế | Trạng thái |
|---|---|---|---|---|
| RQ1 | bug đa chuỗi mà tool đơn chuỗi bỏ sót | so baseline | ✅ so 6 baseline ×12×20 | ĐÚNG (đã đo thật) |
| RQ2 | Precision/Recall/F1 per vuln-type | (ablation) | ablation coverage 2 biến thể | LỆCH — P/R/F1 per-type **chưa đo**; RQ2 thành ablation |
| RQ3 | ablation per-module | param sensitivity | **chưa chạy (TODO)** | DỞ DANG |
| RQ4 | **bug mới trên mainnet + disclosure** | bỏ | không có | **BỎ** |
| RQ5 | **chi phí compute/API vs baseline** | bỏ | không có | **BỎ** |

→ Vision 5 RQ → paper còn 3 RQ. **RQ4 (tìm bug mới) + RQ5 (cost) bị bỏ.** P/R/F1/FPR per-type — trụ cột đánh giá trong vision — **chưa đo**.

---

## 5. Đối chiếu DATASET

| | Vision gốc | Thực tế | Trạng thái |
|---|---|---|---|
| Tier 1 real | 20 bridge bị hack, ≥200 contract thật | 12 reconstruction **đơn giản hóa** | LỆCH (12 vs 20; simplified vs real) |
| Tier 2 | Web3Bugs+DeFiHacks 85 project, 62 ground-truth | không có | BỎ |
| Tier 3 synthetic | 20 kịch bản (5×4 vuln) | không có | BỎ |
| Negative (FPR) | 100 contract không CVE | không có | BỎ |
| Labeling | 2-3 người, Cohen κ≥0.7 | không có | BỎ |
| Vuln coverage | V1-V5 | ✅ V1-V5 đủ (12 benchmark) | ĐÚNG |

→ Dataset thu hẹp mạnh so với tham vọng Q1. 12 benchmark là reconstruction tự dựng (đủ cho luận văn, nhưng không phải "20 real ≥200 contracts" như vision).

---

## 6. Đối chiếu BASELINE

| | Plan | Thực tế | Trạng thái |
|---|---|---|---|
| Số lượng | 6 | 6 | ✅ |
| Danh sách | vision: SmartAxe/XScope/GPTScan/ItyFuzz/**Slither/GPT-4** | ItyFuzz/SmartShot/VulSEye/SmartAxe/GPTScan/XScope | Khác (bỏ Slither+GPT-4-alone, thêm SmartShot+VulSEye) |
| Cách làm | re-impl 4 closed-source (PLAN_REIMPL) | ✅ XScope 10/12, SmartAxe 12/12 det (4/12 strict), VulSEye 9/12 strict, SmartShot 12/12 strict, ItyFuzz 0/12, GPTScan 0/12 | ĐÚNG (vượt cite-only) |

---

## 7. Đối chiếu MỤC TIÊU SỐ

| Mục tiêu | Plan cam kết | Thực tế | Đánh giá |
|---|---|---|---|
| DR | 11/12 (paper); ≥90% (sanity) | **12/12** real-bytecode | ✅ VƯỢT |
| Median TTE | 47s (paper demo) | **1.2s / mean 1.72s** | Khác — số thật, nhanh hơn (47s là số demo bịa cũ) |
| KB records | 51 (header) / ≥30 (acceptance) | 48 (31 curated/12 xscope/5 smartaxe) | Đạt ≥30; "51" sai (nhầm Wu/BridgeShield) |
| Invariants/bridge | "18.3→12.1, precision 89.3%" | 16-24 (mean ~19); precision/retention **chưa đo** | LỆCH — số precision là TODO |
| Main runs | 240 | ✅ 240 | ✅ |
| Ablation | 720 (3×12×20) | **480 (2 biến thể)**; -Sync chưa chạy | DỞ — 480/720 |
| Sensitivity k/β/T | có | **chưa chạy** | DỞ (TODO) |
| Stats (MWU/A12/κ) | có | chưa (DR tất định → reframe) | LỆCH/reframe |
| FPR + negative set | có | **chưa đo** | DỞ (TODO) |
| Chi phí | ~$100-150 | gpt-oss free + lab → ~$0 | ✅ tiết kiệm |

---

## 8. LỆCH PHA — xếp theo mức nghiêm trọng

1. **🔴 NẶNG — Module TEE / cải tiến IvyCross bị bỏ.** Thầy yêu cầu rõ (#2,#5); là framing gốc của đề tài. Paper không nhắc TEE. → Rủi ro cao khi bảo vệ.
2. **🟠 LỚN — RQ thu hẹp 5→3.** Bỏ RQ4 (tìm bug mới + disclosure) và RQ5 (cost). P/R/F1/FPR per-vuln-type (trụ đánh giá vision) chưa đo.
3. **🟠 LỚN — Dataset thu nhỏ.** 12 reconstruction vs 20 real + Web3Bugs + synthetic + 100 negative. Không có negative set → không tính được FPR thật.
4. **🟡 VỪA — Ablation chưa đủ.** `-Sync` chưa chạy (thiếu flag `--no-sync`); RQ3 sensitivity chưa chạy.
5. **🟡 VỪA — Process isolation (Docker)** không thấy hiện thực dù thầy yêu cầu (#6).
6. **🟢 NHẸ — KB 48 vs "51" + citation Wu sai** (KB không lấy từ Wu; cần sửa nguồn trong paper).
7. **🟢 NHẸ — Tên CrossLLM vs BridgeSentry** không nhất quán; LLM GPT-4 (vision) vs gpt-oss-120b (thực tế).

---

## 9. ĐIỂM MẠNH / VƯỢT PLAN

- **Phase A real-bytecode fuzzing hoàn tất** — TTE thật (1.72s), không còn shortcut simulator. Đây là gap lớn nhất trong PLAN_PAPER_EXPERIMENTS, đã đóng.
- **DR 12/12 vượt mục tiêu 11/12.**
- **Re-impl 4 baseline closed-source** (XScope/SmartAxe/VulSEye/SmartShot) — khó hơn nhiều so với chỉ cite.
- **Ablation pivot sang coverage metric** — phát hiện trung thực (coverage 100%→2.6%) cứu được RQ2 khi DR bão hòa.
- **Liêm chính paper được khôi phục** — số bịa cũ đã thay bằng self-run thật, TODO đánh dấu rõ.
- **ATG data regenerate sạch** (dedup, fix null, 230/230).

---

## 10. KHUYẾN NGHỊ ĐỂ KÉO VỀ ĐÚNG HƯỚNG (ưu tiên)

1. **Quyết định về TEE/IvyCross (gấp nhất).** Hoặc (a) hiện thực Module TEE tối thiểu (Relayer/Verifier trong SGX hoặc mô phỏng) + viết vào paper, hoặc (b) **chốt với thầy việc descope TEE** và ghi lý do rõ. Đừng để im lặng — đây là framing thầy duyệt.
2. **Chốt số RQ.** Quyết định luận văn cam kết 3 hay 5 RQ; nếu giữ vision thì cần đo P/R/F1/FPR per-type + (RQ4) thử tìm bug mới.
3. **Chạy nốt phần dở:** RQ3 sensitivity (k/β/T — chạy được trên lab), `-Sync` ablation (cần Member B thêm `--no-sync`), FPR (C1 quick classification).
4. **Sửa citation KB:** ghi đúng nguồn (XScope+SmartAxe+curated, 48 record) hoặc re-ground theo Wu/BridgeShield; sửa "51"→thực tế.
5. **Thống nhất tên** CrossLLM ↔ BridgeSentry trên toàn bộ docs/paper.
6. **Process isolation:** thêm Dockerfile `--cpus/--memory` cho Module 3 (đáp #6 của thầy) — rẻ, dễ.

---

## 11. Kết luận

Hệ thống **vững về kỹ thuật và trung thực về số liệu** — bám tốt plan kỹ thuật, một số phần vượt. Nhưng **đã trôi khỏi vision gốc do thầy duyệt** ở 3 điểm cốt lõi: **TEE/IvyCross (bỏ), phạm vi RQ (5→3), quy mô dataset (thu nhỏ)**. Trước khi bảo vệ, cần chủ động xử lý hoặc thống nhất lại với thầy về 3 điểm này — đặc biệt là TEE, vì đó là điều thầy nhấn mạnh nhất.
