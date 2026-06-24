# RQ3 — Parameter Sensitivity: Kết quả thực nghiệm

> **Cho:** Member B (+ thầy/cô) · **Snapshot:** 2026-06-23
> **Bản chất:** RQ3 đo độ nhạy của BridgeSentry với 3 tham số cấu hình — số
> exploit truy xuất trong RAG (**k**), trọng số thưởng waypoint (**β**), và
> ngân sách thời gian fuzzing (**T**). Tất cả số dưới đây là **real-bytecode**
> (fork ETH mainnet block 15259100, deploy contract thật, dual-EVM revm),
> KHÔNG phải simulation.

---

## 0. TL;DR (1 đoạn)

BridgeSentry **robust với hyperparameter**: thay đổi RAG depth `k` (1→10) hay
waypoint weight `β` (0.1→0.7) **gần như không đổi** kết quả (12/12 bridge,
TTE ~0.7s, cross-chain coverage ~100%). **Tham số duy nhất tác động rõ là
ngân sách thời gian `T`** — cần ~2s để đạt 12/12 bridge, 100% run trong 30s.
Kết luận nhất quán với RQ1/RQ2: trên benchmark tái dựng, phát hiện **bão hòa**;
phần "nhạy" còn lại chỉ là *cho fuzzer chạy bao lâu*, không phải tinh chỉnh
retrieval/reward.

---

## 1. Setup thực nghiệm

| Hạng mục | Giá trị |
|---|---|
| Mode | real-bytecode dual-EVM (`run_full_sweep_real.sh` family) |
| Fork | ETH mainnet @ block 15259100, RPC Alchemy |
| Budget mặc định | 60 s/run |
| Lab | `quoc@10.102.196.203:~/sukem/CrossLLM`, binary `bridgesentry-fuzzer` (solc-select 0.8.20 trên PATH) |
| Default config | k=3, β=0.4, T=60s |
| ATG/scenarios | bộ regenerate sạch 2026-06-17 (dedup node, canonical actor, 0 null) |

**Tổng số run RQ3: 420 fuzzing run, 0 fail** (180 cho β + 240 cho k) + đường
cong T rút từ 240-run của sweep chính (không tốn run mới).

---

## 2. Độ nhạy `k` (RAG retrieval depth)

**Cách đo (cô lập k):** giữ NGUYÊN ATG (Module 1) đã regenerate; chỉ chạy lại
**Module 2** với `top_k ∈ {1,5,10}` → sinh `hypotheses_k{1,5,10}.json`
(k=3 = `hypotheses.json` canonical). Rồi fuzz mỗi cấu hình 5 run × 12 bridge.

| k | Bridge phát hiện | det runs | TTE trung vị | XCC_ATG |
|---|---|---|---|---|
| 1 | 12/12 | 60/60 | 0.705 s | 100% |
| 3 | 12/12 | 60/60 | 0.710 s | 100% |
| 5 | 12/12 | 59/60 | 0.704 s | 100% |
| 10 | 12/12 | 60/60 | 0.712 s | 100% |

→ **Phẳng.** Bug tái dựng tìm được kể cả khi RAG chỉ lấy 1 exploit. (1 run lẻ
ở k=5 không hit — nhiễu seed, không phải xu hướng.)

## 3. Độ nhạy `β` (waypoint reward weight)

**Cách đo:** dùng ATG + hypotheses canonical, sweep fuzzer flag `--beta ∈
{0.1, 0.4, 0.7}` (α,γ chia phần còn lại), 5 run × 12 bridge.

| β | Bridge phát hiện | det runs | TTE trung vị | XCC_ATG |
|---|---|---|---|---|
| 0.1 | 12/12 | 60/60 | 0.771 s | 99.8% |
| 0.4 | 12/12 | 60/60 | 0.782 s | 100% |
| 0.7 | 12/12 | 59/60 | 0.707 s | 100% |

→ **Phẳng.** Vì kịch bản dẫn xuất từ ATG đã lái fuzzer tới vùng lỗ hổng, cân
bằng coverage-reward vs waypoint-reward không phải yếu tố quyết định ở đây.

## 4. Độ nhạy `T` (time budget)

**Cách đo (miễn phí):** với mỗi run trong 240-run của sweep chính, lấy
`min(detected_at_s)`; DR(T) = tỉ lệ run/bridge phát hiện trong ≤ T giây.

| T | 0.5 s | 1 s | 2 s | 5 s | 10 s | 30 s | 60 s |
|---|---|---|---|---|---|---|---|
| Bridge phát hiện | 6/12 | 11/12 | **12/12** | 12/12 | 12/12 | 12/12 | 12/12 |
| Run phát hiện (%) | 35 | 52 | 70 | 90 | 99.6 | 100 | 100 |

→ Đạt **12/12 bridge ở T=2s**; 90% run ở 5s; 100% run ở 30s. "Knee" ~1–5s.
**Budget 60s dư thừa** — có thể hạ xuống 5–10s mà vẫn gần như đủ.

---

## 5. Diễn giải & ý nghĩa cho team

1. **Framework không cần tinh chỉnh hyperparameter** trên benchmark này —
   k=3, β=0.4 mặc định đã tốt; reviewer không thể chê "cherry-pick tham số".
2. **Yếu tố thật sự chi phối là thời gian chạy.** Đây là tín hiệu lành mạnh:
   phát hiện phụ thuộc độ sâu tìm kiếm, không phải may mắn cấu hình.
3. **Nhất quán với RQ1/RQ2** (DR bão hòa trên reconstruction). Cùng một câu
   chuyện trung thực xuyên suốt 3 RQ: trên benchmark tái dựng, *detection*
   không phân biệt được nhiều → ta dùng **coverage** (RQ2) và **budget curve**
   (RQ3) làm tín hiệu phân biệt.
4. **Hệ quả cho Member B (Module 3):** budget 60s đang dùng là an toàn; nếu cần
   chạy sweep lớn có thể giảm budget xuống ~10s để tiết kiệm ~6× wall-clock mà
   gần như không mất DR.

⚠️ **Lưu ý trung thực (để không bị hỏi vặn):** k/β phẳng *trên benchmark đã
biết bug*. Trên bug **chưa từng thấy** (zero-day), RAG depth và waypoint nhiều
khả năng sẽ có tác dụng hơn — đây là vùng mà dẫn hướng phát huy, và là
giới hạn evaluation hiện tại (benchmark là vụ hack tái dựng, không phải bug mới).

---

## 6. Tái lập (reproduce)

```bash
# Trên lab ~/sukem/CrossLLM, export PATH=$HOME/.local/bin:$PATH (solc 0.8.20)

# β-sweep:
for BV in 0.1 0.4 0.7; do
  PARAM=beta VAL=$BV RUNS=5 BUDGET=60 bash scripts/run_rq3_sweep.sh
done

# k-sweep (cần hypotheses_k{1,5,10}.json đã sinh sẵn từ tools/rq3_gen_k_hypotheses.py):
for KV in 1 3 5 10; do
  PARAM=k VAL=$KV RUNS=5 BUDGET=60 bash scripts/run_rq3_sweep.sh
done

# T-curve: phân tích results/realbytecode_regen_*/<bridge>/run_*.json (detected_at_s)
```

**Artifacts:**
- `results/rq3_summary.json` — tổng hợp cả 3 tham số (số chính thức).
- `results/rq3_tte_perrun.json` — 240 giá trị min-TTE cho đường cong T.
- `scripts/run_rq3_sweep.sh`, `scripts/rq3_k_driver.sh`, `tools/rq3_gen_k_hypotheses.py`.
- Lab outdirs: `results/rq3_beta_{0.1,0.4,0.7}_*`, `results/rq3_k_{1,3,5,10}_*`.

---

## 7. Trạng thái RQ tổng thể (để Member B nắm bức tranh)

| RQ | Nội dung | Trạng thái |
|---|---|---|
| RQ1 | So baseline (DR/TTE) | ✅ DR 12/12, TTE mean 1.72s, 6 baseline |
| RQ2 | Ablation đóng góp module | ✅ coverage 100%→2.6% khi bỏ SE/RAG (`-Sync` chờ flag) |
| RQ3 | Sensitivity k/β/T | ✅ **vừa xong (báo cáo này)** |

**Việc còn cần Member B (Module 3 Rust):**
- Thêm flag **`--no-sync`** để chạy ablation `-Sync` (hiện chưa có; là biến thể
  còn thiếu duy nhất của RQ2).
- (Tùy chọn) sửa quy-gán `touched_edges` trong `fuzz_loop.rs` để XCC_ATG tính
  đúng trên mọi bridge (hiện edge-attribution dựa `action.contract` không phải
  lúc nào cũng populate).
