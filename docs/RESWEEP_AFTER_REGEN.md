# Re-sweep Module 3 sau khi regenerate ATG (2026-06)

> **Bối cảnh:** ngày 2026-06 đã regenerate 12 `atg.json` + `hypotheses.json`
> (data sạch: dedup node, actor chuẩn hóa `User`/`Recipient`/`ZeroAddress`, fix
> `conditions` char-explosion). Data mới **chỉ có trên máy local Windows** →
> lab CHƯA đồng bộ → sweep Module 3 cũ (`results/lab_sweep_2026_04_27/`) đã
> **stale**. Runbook này: upload data mới lên lab → chạy lại sweep → kéo kết quả về.

- **Local repo (WSL path):** `/mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM`
- **Lab repo:** `~/sukem/CrossLLM` (xác nhận bằng `ls ~/sukem/CrossLLM` — nếu lab dùng `~/CrossLLM` thì đổi lại cho khớp)
- **Sweep cũ dùng:** `BUDGET=60 RUNS=20` (12 bridge × 20 = 240 runs). Dùng đúng vậy để so sánh apples-to-apples.

---

## Bước 1 — Upload data mới lên lab (chạy từ WSL trên máy local)

```bash
LAB=<user>@<host>            # vd: sukem@10.0.0.5
LOCAL=/mnt/c/Users/INNOTECH/Documents/Blockchain/Blockchain/CrossLLM

rsync -avz --no-perms --no-times --exclude '_backup_*' \
    "$LOCAL/benchmarks/" "$LAB:~/sukem/CrossLLM/benchmarks/"
```

(Chỉ `benchmarks/` thay đổi cho sweep — binary Rust không đổi nên **không cần build lại**.
Nếu sau này muốn regenerate TRÊN lab thì sync thêm `src/` + `scripts/`.)

## Bước 2 — Verify đã sync đúng (chạy trên lab)

```bash
cd ~/sukem/CrossLLM
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
    md5sum benchmarks/$b/llm_outputs/atg.json benchmarks/$b/llm_outputs/hypotheses.json
done
```

So với manifest data mới (phải khớp 100%):

| bridge | atg.json md5 | hypotheses.json md5 |
|---|---|---|
| nomad | 37dfc4bf2464f9b50123289c6e2ed2ef | 602531ba2711fa87d207a71da805e118 |
| qubit | bafce4d9b24029e49dfa11bb6be4dfc9 | 9358b92f22feaa616c2299f47012b8af |
| pgala | 2166379f8e4cf92f8860088de734492f | 35b1edddb1d466a15b7f610f178f7868 |
| polynetwork | d9fcf554ac526df1e2d63cf632fc90b4 | caacbe76b129a40c2fdf2f5acaa07f74 |
| wormhole | 94b98c753f14f412f5e44bf38779fe3f | 92deadf6566ec12244df390920b73655 |
| socket | 066407ec89580e2f64bf5bc88d464623 | 4be15046022bb2cb08d96fc74ed76327 |
| ronin | b9fda64c6076afcdce2e30d333349735 | cd9355b1a24cc5df1e2e2b684d4545f0 |
| harmony | d41c5fcfa06d17a6adddfcfd0b071653 | d29d78ec7e7c887c7715a49603bc2b77 |
| multichain | aac529fad00fde58c37e72d947874609 | f7ad40507b3d8ced6df92ad91638d8ab |
| orbit | 255e54631de70bbe956d158e278e3bfd | db5fdb57cae331040e78c8e61d16eda9 |
| fegtoken | 47e7e5130cc5f0681fd1930ac9ba78df | 5f52d149d5a23c4e07b982619d53aad4 |
| gempad | 588a4a2df77a1a04a39bbf045cb6586e | b8311ff296bb41ba00fe119115bce949 |

## Bước 3 — Chạy lại sweep Module 3 (trên lab)

```bash
cd ~/sukem/CrossLLM
export PATH=$HOME/.local/bin:$PATH       # ⚠ BẮT BUỘC: dùng solc-select 0.8.20, KHÔNG phải /snap/bin/solc 0.5.16
set -a && source .env && set +a          # cần ETH_RPC_URL
# (nếu binary chưa có: cd src/module3_fuzzing && rustup override set 1.91.0 && cargo build --release && cd -)

BUDGET=60 RUNS=20 bash scripts/run_full_sweep_real.sh
```

> **⚠ Troubleshooting — fuzzer panic `solc failed: unrecognised option '--base-path'`:**
> Shell non-interactive lấy nhầm `/snap/bin/solc` (0.5.16, không có `--base-path`)
> thay vì shim solc-select `~/.local/bin/solc` (0.8.20). Mọi run FAIL ~2-3s ở
> `fuzz_loop.rs:199` (deploy validation). **Fix:** `export PATH=$HOME/.local/bin:$PATH`
> trước khi chạy (đã thêm ở trên). Verify: `which solc` phải ra `~/.local/bin/solc`,
> `solc --version` = 0.8.20. (Đây KHÔNG phải lỗi data — ATG/scenarios parse OK.)
>
> **Thời gian:** ~66s/run (fork RPC + deploy + fuzz 60s) → 240 run ≈ **~4.4 giờ**.
> Chạy nền: `BUDGET=60 RUNS=20 setsid -f nohup bash scripts/run_full_sweep_real.sh > /tmp/resweep.log 2>&1`

- Output: `results/realbytecode_<UTC>/<bridge>/run_NNN.json` (script in ra đường dẫn OUTDIR ở cuối).
- Chạy nền bền (sống qua disconnect):
  ```bash
  BUDGET=60 RUNS=20 setsid -f nohup bash scripts/run_full_sweep_real.sh > /tmp/resweep.log 2>&1
  tail -f /tmp/resweep.log
  ```

## Bước 4 — Kéo kết quả về local (từ WSL)

```bash
rsync -avz "$LAB:~/sukem/CrossLLM/results/realbytecode_<UTC>/" \
    "$LOCAL/results/lab_sweep_regen_<UTC>/"
```

Sau đó báo Claude (hoặc tự chạy): aggregate + cập nhật `RQ1_BASELINE_CITED_RESULTS.md`
§5–§9 (DR/TTE BridgeSentry mới) và `latex/paper.tex` + `PAPER_TIENG_VIET.md` §7.2
cho khớp data mới (inv/sc 230/230 thay vì 229/229).
