# 📑 Docs Index — BridgeSentry / CrossLLM

> Mục lục toàn bộ docs trong thư mục này, **phân nhóm theo mục đích
> sử dụng** — chứ không alphabet. Khi bạn cần làm việc gì, vào nhóm
> tương ứng và mở file.

---

## 🟢 1. Bắt đầu / Onboarding

Đọc khi mới setup máy hoặc tiếp quản project.

| File | Khi nào đọc | Cần gì để dùng |
|---|---|---|
| [SETUP_GUIDE.md](SETUP_GUIDE.md) | Lần đầu cài môi trường (Windows + WSL2) | None |
| [SESSION_HANDOFF.md](SESSION_HANDOFF.md) | Nắm tổng thể project ở thời điểm hiện tại — **luôn đọc đầu tiên khi quay lại sau nghỉ dài** | đã setup xong |

---

## 📊 2. Plans (đang còn dùng)

Các kế hoạch chính — đọc trước khi `/execute` hoặc commit code mới.

| File | Phạm vi | Trạng thái | Khi nào đọc |
|---|---|---|---|
| [PLAN_PAPER_EXPERIMENTS.md](PLAN_PAPER_EXPERIMENTS.md) | **Kế hoạch RQ1 toàn cục** — Phase A (real-bytecode fuzz), B (baselines), C (FPR), D (paper tables); 5-6 tuần | Phase A ✅, B 🔄, D1 🔄 đang chạy lab | Khi check tiến độ tổng / quyết định task tiếp theo |
| [PLAN_REIMPL_BASELINES.md](PLAN_REIMPL_BASELINES.md) | **Kế hoạch re-implement 4 closed-source baselines** (XScope, SmartAxe, VulSEye, SmartShot); 12 tuần | 4/4 specs ✅, impl ⏳ | Khi xem timeline re-impl + critical path |

---

## 🔬 3. Re-implementation specs (X1, SA1, VS1, SS1)

Spec docs — đọc TRƯỚC khi viết code re-impl từng tool.

| File | Tool | Effort | Acceptance bar | Khi nào đọc |
|---|---|---|---|---|
| [REIMPL_XSCOPE_SPEC.md](REIMPL_XSCOPE_SPEC.md) | XScope | 2 tuần | 11/12 bridges hit predicted predicate | Trước khi `/execute X2` |
| [REIMPL_SMARTAXE_SPEC.md](REIMPL_SMARTAXE_SPEC.md) | SmartAxe | 4 tuần | 11/12 + reproduce PolyNetwork bug | Trước khi `/execute SA2` |
| [REIMPL_VULSEYE_SPEC.md](REIMPL_VULSEYE_SPEC.md) | VulSEye | 3 tuần | 11/12 + ≥3× speedup vs ItyFuzz | Trước khi `/execute VS2` |
| [REIMPL_SMARTSHOT_SPEC.md](REIMPL_SMARTSHOT_SPEC.md) | SmartShot | 3 tuần | 11/12 + ≥3× speedup vs ItyFuzz | Trước khi `/execute SS2` |

---

## 📐 4. RQ1 / Bảng so sánh paper §5.3

Files để chuẩn bị data RQ1 cuối cùng.

| File | Nội dung | Khi nào đọc |
|---|---|---|
| [RQ1_BASELINE_CITED_RESULTS.md](RQ1_BASELINE_CITED_RESULTS.md) | **Tổng hợp cited results 5 baselines** từ paper gốc (XScope, SmartAxe, SmartShot, VulSEye, GPTScan); 1 bảng coverage 12×6 + aggregate metrics + self-run status | Khi build LaTeX RQ1 table; khi giải thích tại sao có cells `n/a` |

📌 **Backing data**: [`baselines/_cited_results/*.json`](../baselines/_cited_results/) — 5 JSON files chính thức. RQ1_BASELINE_CITED_RESULTS.md là phiên bản đọc-được của 5 JSONs đó.

---

## 🧪 5. Hướng dẫn test / vận hành

Đọc khi cần chạy thử pipeline hoặc verify một benchmark.

| File | Mục đích | Khi nào đọc |
|---|---|---|
| [BENCHMARK_TEST_GUIDE.md](BENCHMARK_TEST_GUIDE.md) | Test end-to-end **1 benchmark** (4 cấp test, ví dụ Qubit) | Khi muốn verify 1 benchmark cụ thể |
| [SPRINT1_TEST_GUIDE.md](SPRINT1_TEST_GUIDE.md) | Test Sprint 1 (Module 1 + Module 2 LLM pipeline end-to-end) | Khi debug pipeline LLM |

---

## 🧠 6. LLM verification artifacts (đã hoàn tất)

| File | Nội dung | Khi nào đọc |
|---|---|---|
| [LLM_VERIFICATION_FULL_DATASET.md](LLM_VERIFICATION_FULL_DATASET.md) | Kết quả Tier-2 LLM verify trên **toàn bộ 12 benchmarks** (229 invariants + 229 scenarios) | Khi cần số liệu §7.2 paper |
| [LLM_VERIFICATION_RONIN_HARMONY.md](LLM_VERIFICATION_RONIN_HARMONY.md) | Verify riêng Ronin + Harmony (multi-sig benchmarks phức tạp) | Khi cần case study deep dive |

---

## 📜 7. Plans (đã xong / lưu trữ)

Các plan trước đó — giữ để ngữ cảnh, không cần đọc trừ khi muốn truy nguyên decision.

| File | Đã hoàn tất khi | Còn dùng để gì |
|---|---|---|
| [PLAN_IMPLEMENTATION.md](PLAN_IMPLEMENTATION.md) | Sprint 1-3 đã merge — kế hoạch khởi đầu chia việc Member A/B | Trace back ai làm gì lúc đầu |
| [PLAN_IMPROVE_MEMBER_A.md](PLAN_IMPROVE_MEMBER_A.md) | Module 1+2 cải thiện (RAG, ATG validation) đã apply | Nếu cần thêm RAG nâng cao |
| [PLAN_POPULATE_BENCHMARKS.md](PLAN_POPULATE_BENCHMARKS.md) | Populate Q/P/N/W (4 benchmarks đầu) — 4/4 done | Khi populate benchmark mới sau này |
| [PLAN_POPULATE_OFFCHAIN.md](PLAN_POPULATE_OFFCHAIN.md) | Populate Ronin/Harmony/Multichain/Orbit/FEGtoken — 5/5 done | Khi populate benchmark off-chain mới |

---

## 📄 8. Paper draft

| File | Nội dung |
|---|---|
| [PAPER_TIENG_VIET.md](PAPER_TIENG_VIET.md) | **Bản paper tiếng Việt đang viết** — sections theo §1..§7 |

---

## 🗂️ Quick-look: tôi đang ở giai đoạn nào?

Mapping nhanh để biết file nào nên active mỗi giai đoạn:

| Giai đoạn | Active files |
|---|---|
| **Setup máy lần đầu** | SETUP_GUIDE.md → SESSION_HANDOFF.md |
| **Đang code Module 1+2 (LLM pipeline)** | SPRINT1_TEST_GUIDE.md + PLAN_IMPROVE_MEMBER_A.md |
| **Đang test 1 benchmark** | BENCHMARK_TEST_GUIDE.md |
| **Đang chuẩn bị paper §5.3 RQ1** | RQ1_BASELINE_CITED_RESULTS.md + PLAN_PAPER_EXPERIMENTS.md |
| **Đang re-implement 1 baseline** | PLAN_REIMPL_BASELINES.md + REIMPL_<TOOL>_SPEC.md tương ứng |
| **Đang viết paper Vietnamese** | PAPER_TIENG_VIET.md |
| **Quay lại project sau nghỉ** | SESSION_HANDOFF.md đầu tiên, rồi PLAN_PAPER_EXPERIMENTS.md để biết Phase nào đang active |

---

## 🔗 External references (không phải docs/)

Các file ngoài docs/ thường được tham chiếu:

| Path | Nội dung |
|---|---|
| [`benchmarks/<bridge>/metadata.json`](../benchmarks/) | Metadata mỗi bridge: addresses, fork block, root_cause_summary |
| [`benchmarks/<bridge>/llm_outputs/atg.json`](../benchmarks/) | ATG (Module 1 output) |
| [`benchmarks/<bridge>/llm_outputs/hypotheses.json`](../benchmarks/) | Scenarios (Module 2 output) |
| [`baselines/_cited_results/*.json`](../baselines/_cited_results/) | Cited baseline results JSON (5 files) |
| [`src/module3_fuzzing/`](../src/module3_fuzzing/) | Rust fuzzer (Phase A real-bytecode mode đã merge) |
| [`scripts/run_full_sweep_real.sh`](../scripts/run_full_sweep_real.sh) | D1 sweep runner |
| [`scripts/_lab_*.py`](../scripts/) | paramiko helpers cho lab server lifecycle |
| [`docs/phase_a_artifacts/`](phase_a_artifacts/) | A5 acceptance run artifacts (Nomad real-bytecode 60s) |

---

> **Maintenance note**: Khi thêm doc mới vào `docs/`, **cập nhật file
> này**. INDEX.md là thứ duy nhất bạn (hoặc Claude session sau) cần
> đọc đầu tiên để biết "có cái gì ở đâu".
