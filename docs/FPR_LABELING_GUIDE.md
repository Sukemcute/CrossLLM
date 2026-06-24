# FPR Labeling Guide — hướng dẫn gán nhãn để đo False-Positive Rate

> **Mục đích:** đo **FPR** (tỷ lệ vi phạm báo cáo nhưng KHÔNG phải lỗ hổng thật)
> và **Cohen's κ** (độ đồng thuận 2 người đánh giá) cho RQ — đây là 2 con số mà
> paper hiện để TODO vì **bắt buộc cần người gán nhãn** (không tự sinh được, nếu
> sinh máy = bịa). Sau khi 2 người điền xong, chạy `tools/compute_fpr.py`.

---

## 1. Bạn cần làm gì (tóm tắt)

1. Mở [`docs/FPR_LABELING_SHEET_v2.csv`](FPR_LABELING_SHEET_v2.csv) (230 dòng = 230 vi
   phạm distinct, mỗi dòng = 1 invariant bị vi phạm trên 1 bridge).
2. **2 người đánh giá độc lập** (vd: bạn + Member B, hoặc bạn + thầy). Mỗi người
   điền cột của mình — **KHÔNG nhìn cột người kia**:
   - Người 1 → cột `R1_TP_or_FP`
   - Người 2 → cột `R2_TP_or_FP`
3. Mỗi ô điền đúng **`TP`** hoặc **`FP`** (xem tiêu chí §3).
4. Sau khi cả 2 điền xong, lưu file → chạy `python tools/compute_fpr.py` → ra
   FPR + Cohen's κ + bảng per-bridge.

---

## 2. Mỗi dòng có gì để bạn phán đoán

| Cột | Ý nghĩa |
|---|---|
| `bridge` | benchmark nào |
| `documented_root_cause` | **lỗ hổng THẬT đã ghi nhận** của vụ hack (ground truth để đối chiếu) |
| `invariant_id` + `category` | bất biến bị vi phạm |
| `predicate` | điều kiện bất biến (vd `totalLockedSource == totalMintedDest - fees`) |
| `representative_trace` | chuỗi hành động đã trigger vi phạm |
| `state_diff` | chênh lệch trạng thái nguồn/đích lúc vi phạm |
| `instances_across_20_runs` | vi phạm này fire bao nhiêu lần trong 20 run (mức độ phổ biến) |

---

## 3. Tiêu chí TP vs FP (quan trọng nhất)

Câu hỏi cốt lõi cho mỗi dòng:
> *"Vi phạm bất biến này có phản ánh **đúng** lỗ hổng khai thác được (đối chiếu
> `documented_root_cause`), hay chỉ là báo động sai/tầm thường?"*

### Gán **TP** (True Positive — vi phạm thật) khi:
- Vi phạm tương ứng với **cơ chế lỗ hổng đã ghi nhận** của bridge (vd nomad:
  mint không có lock hợp lệ → vi phạm `no_mint_without_lock` hoặc
  `asset_conservation` = TP, vì đúng bug "zero-root accept").
- `state_diff` cho thấy **mất cân đối tài sản thật** (dest > source bất hợp lý,
  mint vượt lock, double-spend...).
- Trace thể hiện **chuỗi tấn công hợp lệ** dẫn tới vi phạm.

### Gán **FP** (False Positive — báo động sai) khi:
- Vi phạm chỉ do **giả định bất biến quá chặt** (vd coi phí giao dịch là vi phạm
  bảo toàn tài sản trên token fee-on-transfer).
- Vi phạm ở **trạng thái không thể đạt được** trong thực thi hợp lệ (artifact của
  harness, vd trace toàn `err`/`reverted` mà vẫn báo vi phạm).
- Bất biến **không liên quan** root cause và chênh lệch chỉ là nhiễu làm tròn
  (vd lệch 1 wei).
- Vi phạm **trùng lặp tầm thường** của một bất biến generic không mang ngữ nghĩa
  bridge.

### Lưu ý
- **Không** dựa vào việc bridge "có bị hack thật hay không" (mọi bridge đều có
  bug thật) — phán đoán **từng vi phạm cụ thể** có khớp cơ chế hay là nhiễu.
- Nếu phân vân, đọc kỹ `predicate` + `state_diff` + `documented_root_cause`.
- Ghi lý do ngắn vào cột `notes` nếu cần (tùy chọn).

---

## 4. FPR và κ được tính thế nào (để bạn hiểu, không phải tự tính)

`tools/compute_fpr.py` đọc sheet đã điền và tính:

- **FPR (mỗi người)** = số ô `FP` ÷ tổng số ô đã điền.
- **FPR (consensus)** = chỉ tính các dòng 2 người ĐỒNG Ý; FPR = #(cả 2 = FP) ÷
  #(đồng ý). Đây là con số báo cáo trong paper.
- **Cohen's κ** = độ đồng thuận giữa R1 và R2, hiệu chỉnh cho đồng thuận ngẫu
  nhiên. Thang: >0.8 gần như hoàn hảo, 0.6–0.8 tốt, <0.4 yếu. Paper mục tiêu
  κ ≥ 0.7 (theo chuẩn KICH_BAN_THUC_NGHIEM của thầy).
- Bảng **FPR per-bridge** + danh sách dòng 2 người **bất đồng** (để thảo luận
  resolve trước khi chốt).

---

## 5. Quy trình chuẩn (để số liệu đáng tin)

1. 2 người gán nhãn **độc lập** (mỗi người 1 cột, không trao đổi) → đảm bảo κ có
   nghĩa.
2. Chạy `compute_fpr.py` → xem κ + danh sách bất đồng.
3. 2 người **họp resolve** các dòng bất đồng → thống nhất nhãn cuối.
4. Chạy lại → FPR consensus cuối + κ → điền vào paper §6 (Threats to Validity)
   và bảng RQ2 (cột FPR).

> ⚠️ Quan trọng: đừng để 1 người điền cả 2 cột — κ sẽ vô nghĩa. Phải 2 người thật.
