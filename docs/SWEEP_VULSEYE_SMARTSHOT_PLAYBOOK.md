# Sweep playbook — VulSEye (VS6) + SmartShot (SS6)

> Ready-to-paste commands cho lab `quoc@10.102.196.203`.
>
> Sweep size mặc định: 12 bridges × 20 runs × 600 s ≈ **40 h per tool**.
>
> Honest-fix commit `3532c73` đã land — verifier filter
> `target_source=opcode_scan` / `predicate_match=true` chỉ count
> findings thật.

---

## 0. Prep (one-time)

```bash
ssh quoc@10.102.196.203
cd ~/sukem/CrossLLM

# Pull the honest-fix + plan-matrix-sync commits
git fetch origin
git checkout main   # or feat/real-bytecode-fuzz
git pull --ff-only

# Build release binary (~30s)
cd src/module3_fuzzing && cargo build --release --bin bridgesentry-fuzzer && cd -

# Sanity check binary
./src/module3_fuzzing/target/release/bridgesentry-fuzzer --help | head -5

# Sanity check .env carries ETH_RPC_URL
grep -E "^ETH_RPC_URL" .env | sed -E 's/=.*/=***/'
```

---

## 1. VS6 — VulSEye full sweep (~40 h)

```bash
# Start in tmux so it survives ssh disconnect
tmux new -s vs_sweep

# Inside tmux:
cd ~/sukem/CrossLLM
BUDGET=600 RUNS=20 BASELINE=vulseye bash scripts/run_baseline_sweep_real.sh 2>&1 \
  | tee /tmp/vs_sweep_$(date -u +%Y%m%dT%H%M%SZ).log

# Detach: Ctrl-B then D
```

Output đáp ở `results/baselines/vulseye/<bridge>/run_NNN.json` (12 × 20 = 240 files).

**Smoke first (30 min — recommended):**
```bash
BUDGET=60 RUNS=1 BASELINE=vulseye bash scripts/run_baseline_sweep_real.sh
```
Nếu pass acceptance check → kick off full 40h sweep.

---

## 2. SS6 — SmartShot full sweep (~40 h)

```bash
tmux new -s ss_sweep

# Inside tmux:
cd ~/sukem/CrossLLM
BUDGET=600 RUNS=20 BASELINE=smartshot bash scripts/run_baseline_sweep_real.sh 2>&1 \
  | tee /tmp/ss_sweep_$(date -u +%Y%m%dT%H%M%SZ).log

# Detach: Ctrl-B D
```

**Smoke first:**
```bash
BUDGET=60 RUNS=1 BASELINE=smartshot bash scripts/run_baseline_sweep_real.sh
```

---

## 3. Monitor sweeps (chạy trên Windows local hoặc trên lab)

### Trên lab — quick checks

```bash
ssh quoc@10.102.196.203
tmux ls                            # vs_sweep / ss_sweep visible?
tmux attach -t vs_sweep            # reattach
# Ctrl-B D to detach again

# Per-tool progress
cd ~/sukem/CrossLLM
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
  n=$(ls results/baselines/vulseye/$b/run_*.json 2>/dev/null | wc -l)
  printf "  vulseye/%-12s %3d/20 runs\n" "$b" "$n"
done

# Memory + CPU
top -bn1 | head -10
```

### Trên Windows local — paramiko wrapper

```powershell
python scripts/_lab_check_full_sweep.py 10.102.196.203 quoc <password>
# Hoặc:
python scripts/_check_sweep.py 10.102.196.203 quoc <password>
```

---

## 4. Sau khi sweep xong — verifier + aggregator (chạy local hoặc lab)

```bash
# Pull results về Windows nếu chạy local
scp -r quoc@10.102.196.203:~/sukem/CrossLLM/results/baselines/vulseye \
       results/baselines/
scp -r quoc@10.102.196.203:~/sukem/CrossLLM/results/baselines/smartshot \
       results/baselines/

# Verifier — VulSEye
python scripts/verify_vulseye_acceptance.py results/baselines/vulseye/

# Verifier — SmartShot
python scripts/verify_smartshot_acceptance.py results/baselines/smartshot/

# Aggregator (self-run cited JSONs)
python scripts/build_vulseye_self_run_cited.py
python scripts/build_smartshot_self_run_cited.py

# Sau khi xong:
ls baselines/_cited_results/
# Phải thấy:
#   vulseye_self_run.json
#   smartshot_self_run.json
```

Cached verifier summaries (auto-saved):
- `docs/baseline_vulseye_artifacts/vulseye_smoke_acceptance.json`
- `docs/baseline_smartshot_artifacts/smartshot_smoke_acceptance.json`

---

## 5. Update RQ1 doc §5 với số liệu thật

Sau khi 2 self_run JSON sẵn sàng, edit
[`docs/RQ1_BASELINE_CITED_RESULTS.md`](RQ1_BASELINE_CITED_RESULTS.md) §5
bảng `Detection matrix — sau self-run`:

```diff
- | VulSEye    | spec only  | — | — | — | (cite-only all-null) |
- | SmartShot  | spec only  | — | — | — | (cite-only all-null) |
+ | VulSEye    | self-run   | X/12 ✓ | Y/12 strict | mean Zs | self_run.json |
+ | SmartShot  | self-run   | X/12 ✓ | Y/12 strict | mean Zs | self_run.json |
```

Cũng update §9 Trajectory cells matrix với số thật.

---

## 6. Cut-loss criteria (nếu sweep gặp vấn đề)

| Symptom | Action |
|---|---|
| 1 bridge bị stuck > 1h trong 1 run | Ctrl-C lệnh sweep, skip bridge đó (`BRIDGES="..." -bridge_to_skip`) |
| Lab OOM / disk full | Giảm `BUDGET=300` hoặc `RUNS=10` |
| `cargo build` fail trên lab | Pull lại + `cargo clean && cargo build --release` |
| Per-run TTE > 600s consistently | Set `BUDGET=300` để force fail-fast |
| Sweep daemon mất tmux session | Process còn chạy (orphan PPID=1) → `python scripts/_cleanup_orphan.py` |

---

## 7. Expected outcome

Theo SmartAxe pattern (detected 12/12, strict 4/12) — VulSEye + SmartShot
sau honest-fix dự kiến tương tự:

- **Detected**: 10-12/12 bridges fire ít nhất 1 finding (real opcode scan)
- **Strict**: 4-8/12 bridges hit expected predicate

Outcome thật cần ghi nhận, không cherry-pick. Đây là số liệu defensible cho
paper §5.3 RQ1.

---

## 8. Refs

- VS spec: [`docs/REIMPL_VULSEYE_SPEC.md`](REIMPL_VULSEYE_SPEC.md) §7 acceptance commands
- SS spec: [`docs/REIMPL_SMARTSHOT_SPEC.md`](REIMPL_SMARTSHOT_SPEC.md) §7
- SA7 outcome template: [`docs/REIMPL_SMARTAXE_SA7_OUTCOME.md`](REIMPL_SMARTAXE_SA7_OUTCOME.md)
- Honest fix commit: `3532c73`
