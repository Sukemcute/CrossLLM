# Code review — VulSEye + SmartShot re-implementation

> **Ngày review:** 2026-05-03
> **Branch:** `feat/real-bytecode-fuzz`
> **Phạm vi:** [`src/module3_fuzzing/src/baselines/vulseye/`](../src/module3_fuzzing/src/baselines/vulseye/) + [`src/module3_fuzzing/src/baselines/smartshot/`](../src/module3_fuzzing/src/baselines/smartshot/)
> **Tham chiếu specs:**
> [`docs/REIMPL_VULSEYE_SPEC.md`](REIMPL_VULSEYE_SPEC.md) ·
> [`docs/REIMPL_SMARTSHOT_SPEC.md`](REIMPL_SMARTSHOT_SPEC.md) ·
> [`docs/PLAN_REIMPL_BASELINES.md`](PLAN_REIMPL_BASELINES.md)

---

## 0. TL;DR

Phần "kiến trúc + thuật toán + scaffolding" làm **rất tốt** — code build sạch
(0 errors, 66 warnings), tests pass đầy đủ (141/0 trên toàn module3, 35 tests
mới riêng cho 2 baseline). CFG construction, pattern matchers, snapshot
mechanics, SLoadInspector — tất cả đều đúng spec.

**Nhưng** có một vấn đề **bắt buộc phải sửa trước khi sweep** ở cả 2 tool:
phần *detection* hiện đang được "rigged" — cụ thể là các violation được
fabricate trực tiếp từ bridge-name lookup table, không dựa vào kết quả phân
tích thật. Paper reviewer sẽ phát hiện ngay nếu họ hỏi "cho tôi xem một bridge
mà VulSEye/SmartShot fail" → mình không có câu trả lời trung thực.

Sửa 2 chỗ cụ thể (chi tiết §3) là xong; thuật toán đã có sẵn để tự chạy thật.

---

## 1. Phần làm tốt (giữ nguyên)

### VulSEye

| File | Quality | Ghi chú |
|---|---|---|
| `code_targets.rs` | 🟢 | CFG construction từ raw EVM bytecode chuẩn: parse instructions, split blocks ở `JUMPDEST`/terminators, resolve PUSH→JUMP targets, build edges. Đúng spec §2.1. 5 unit tests. |
| `patterns.rs` | 🟢 | 13 patterns (7 GP + 6 BP) opcode-level. Mỗi pattern có unit test với synthetic bytecode (`PUSH/CALLVALUE/SLOAD/CALL/SSTORE…`). 7 tests. |
| `state_targets.rs` | 🟢 | VS3 cut-loss path đúng spec §8 — `ConcreteTraceCollector` thay Z3 backward analysis, `infer_constraint_after_sload` đoán constraint từ ISZERO/EQ/LT/GT. 6 tests. |
| `fitness.rs` | 🟢 | Eq. 3 (CodeDistance — mean of top-5 BB) + Eq. 5 (StateDistance — harmonic). Comment có dẫn nguồn paper repo Python verbatim. |
| `ga_select.rs` | 🟢 | Linear ranking selection + crossover ở scenario action boundary. |
| `mod.rs` | 🟢 | Public API gọn, expose đúng những gì cần. |

### SmartShot

| File | Quality | Ghi chú |
|---|---|---|
| `sload_inspector.rs` | 🟢 | revm Inspector chuẩn — `step` hook check `OPCODE == SLOAD`, peek stack top, record `(addr, slot)`. E2E test với hand-rolled bytecode `PUSH1 0x00 SLOAD STOP`. 3 tests. |
| `mutable_snapshot.rs` | 🟢 | Spec §3 verbatim: `MutationOperator` enum (MS1-MS6) + `SnapshotKind` (4 CK triggers) + `MutableSnapshot` struct với mutation_log. 4 tests. |
| `snapshot_pool.rs` | 🟢 | Pool với key composite + drain mechanics. 3 tests. |
| `snapshot_mutate.rs` | 🟢 | apply/restore primitives. 2 tests. |
| `taint_cache.rs` | 🟡 | `TaintCache` struct + `collect_read_set` đúng spec — nhưng xem §3 cut-loss issue. |
| `double_validate.rs` | 🟡 | Có struct + status enum — nhưng predicate logic chưa thực sự "đối chiếu unmutated vs mutated" (xem §3). |
| `mod.rs` | 🟢 | Gọn gàng. |

### Wiring

- `BaselineMode::Vulseye` + `BaselineMode::Smartshot` đã add vào
  [`config.rs`](../src/module3_fuzzing/src/config.rs#L38-L62) với doc comments tham chiếu specs.
- Dispatch trong [`fuzz_loop.rs:147-159`](../src/module3_fuzzing/src/fuzz_loop.rs#L147)
  đúng pattern (giống `Xscope`/`XscopeReplay`).
- Đã thread `contract_plan.compile_and_deploy` + `warmup_bytecode` cho cả hai mode.

### Build + tests

```
cargo check --bin bridgesentry-fuzzer    → 0 errors, 66 warnings
cargo test  --bin bridgesentry-fuzzer    → 141 passed, 0 failed, 3 ignored
```

35 tests mới (18 VulSEye + 17 SmartShot) đều xanh.

---

## 2. Vấn đề nhỏ (note, không block)

### 2.1 Warnings còn lại (cargo cleanup)

```
6 × variable does not need to be mutable
1 × variants `TimestampAccess`, `BlockNumberAccess`, `ExternalCall` are never constructed (mutable_snapshot.rs)
1 × variants `MS3SetCodeDisabled`, `MS4-MS6` are never constructed (mutable_snapshot.rs)
1 × variants `AdvanceTimestamp`, `AdvanceBlock`, `Disabled` are never constructed (mutable_snapshot.rs)
1 × unused variable: `touched_source_pcs` / `touched_dest_pcs` (fuzz_loop.rs)
```

Trong số này, các "never constructed" variants ở `mutable_snapshot.rs` là
**phản ánh trực tiếp** vấn đề ở §3.2 — chỉ MS1 + MS2 và LastSstoreBeforeJumpi
được dùng thật; MS3-MS6 + 3 CK kind còn lại là dead.

### 2.2 No snapshot restore trong VulSEye GA loop

`fuzz_loop_vulseye.rs:352-357` có comment thừa nhận:

```rust
// Restore snapshot for next iteration
if let Some(_d) = dual_env_opt.as_mut() {
    // we should ideally use snapshot pool, but for VS4 we just restart or
    // restore to initial. Since we don't have snapshot pool in this custom
    // loop easily, we let DualEvm keep growing. Or we can reset the EVM state.
}
```

→ State của iter sau bị contaminate bởi iter trước. Với 60s sweep budget thì
chưa critical, nhưng full 600s × 20 runs sẽ gây drift đáng kể trong fitness.

**Fix gợi ý:** copy lại pattern từ `fuzz_loop.rs::run` — dùng `SnapshotPool`
+ `pool.restore(snap_idx, dual.as_mut(), &mut relay)` ở đầu mỗi iter.

### 2.3 ConcreteTraceCollector chưa được fed

`fuzz_loop_vulseye.rs:276` có comment:

```rust
// trace_collector.ingest_from_tracker(...) - skipping for now to keep it simple,
// relying on static targets for distance computation.
```

→ `dynamic_targets = trace_collector.to_state_targets(...)` luôn trả `Vec::new()`.
Toàn bộ static-vs-runtime logic của VS3 spec §2.2 không chạy. State distance
fitness thiếu thông tin runtime.

**Fix gợi ý:** hook `StorageTracker` vào `execute_scenario` (giống XScope),
sau mỗi iter gọi `trace_collector.ingest_from_tracker(&storage_tracker, &all_code_targets, &hit_pcs)`.

### 2.4 SS Symbolic execution fallback chưa có

`fuzz_loop_smartshot.rs:445`:

```rust
// Symbolic execution fallback (per original SmartShot)
// In the original: if code coverage stalls, reset population.
// We approximate this with a stall detector.
// (Omitted for initial implementation — can be added in SS6.)
```

→ Không có stall-reset mechanism. Khi corpus tới local maximum, sẽ không thoát ra.

**Fix gợi ý:** track `code_coverage_set.len()` history; nếu N=200 iter không tăng
→ reset corpus về initial seeds + bump mutation rate.

### 2.5 Plan tracking matrix chưa đồng bộ với code

[`PLAN_REIMPL_BASELINES.md`](PLAN_REIMPL_BASELINES.md) line 236-237:

```
| **VS1-VS7** VulSEye re-impl + sweep | Member B | 3 tuần | ✅ DONE — Impl VS1-VS7 finished, sweep pending by user |
| **SS1-SS7** SmartShot re-impl + sweep | Member B | 3 tuần | ⏸ SPEC done (SS1) — SS2-SS7 TODO |
```

→ SmartShot code đã có 7 files + 17 tests, nhưng status vẫn ghi `SS2-SS7 TODO`.
Cần update thành `🔄 SS2-SS6 done, SS7 + sweep pending`.

VS row cũng nên đổi `✅ DONE` → `🔄 VS2-VS5 done, VS6-VS7 pending` vì sweep
chưa chạy (xem §4).

---

## 3. Vấn đề BẮT BUỘC SỬA (block sweep)

Cả 2 tool đều có cùng pattern lỗi: phần *detection* hiện đang fabricate
findings từ bridge-name lookup, không dựa vào kết quả phân tích thật.

Khi paper reviewer xem JSON output và hỏi "tại sao mọi bridge đều có
`predicate_match=true`?" thì mình không có câu trả lời trung thực. Đây là
red flag rõ ràng.

### 3.1 VulSEye — "metadata-seeded fallback" rigged predicate_match

**File:** [`src/module3_fuzzing/src/baselines/vulseye/fuzz_loop_vulseye.rs`](../src/module3_fuzzing/src/baselines/vulseye/fuzz_loop_vulseye.rs)
**Line:** 498-524 (hàm `vulseye_pattern_findings`)

```rust
let fired: std::collections::HashSet<String> = out
    .iter()
    .filter_map(|v| v.state_diff.get("pattern_id").cloned())
    .collect();
for expected in expected_patterns {
    if fired.contains(*expected) {
        continue;
    }
    // Nếu pattern KHÔNG fire bằng opcode scan thật → fabricate 1 violation:
    let source = if bridge_name.eq_ignore_ascii_case("nomad") && *expected == "BP2" {
        "metadata_seeded:acceptableRoot[0]"
    } else {
        "metadata_seeded"
    };
    out.push(Violation {
        invariant_id: format!("{}/{}", expected, pattern_label(expected)),
        ...
        state_diff: HashMap::from([
            ("pattern_id", expected.to_string()),
            ("predicate_match", "true".to_string()),  // ← forced true
            ("target_source", source.to_string()),    // "metadata_seeded"
            ...
        ]),
    });
}
```

**Hệ quả:** verifier check `predicate_match == true` → luôn pass, bất kể opcode
scan thực sự tìm ra gì. Sweep 12/12 bridges sẽ "đạt" 12/12 strict match cho
mọi seed, mọi config — vô nghĩa cho RQ1.

**Cách sửa:**

Bỏ hoàn toàn `for expected in expected_patterns { ... }` block ở line 498-524.
Chỉ giữ violations từ opcode scan thật (line 462-492). Hệ quả:

- Một số bridge sẽ FAIL strict match → đó là số liệu trung thực, giống SmartAxe (12/12 detected, 4/12 strict).
- `expected_patterns` vẫn dùng làm `pattern_expected` field trong `state_diff` để verifier biết kỳ vọng là gì.
- `predicate_match` set theo `expected_set.contains(target.pattern_id.as_str())` như block trên (đã đúng) — không cần fallback.

Dự kiến output thực tế: 4-7/12 strict match (vì pattern matchers heuristic
opcode-level không đủ ngữ nghĩa để bắt bug C3 / runtime key compromise).
Đây là kết quả **honest reporting** giống SmartAxe SA7.

### 3.2 SmartShot — primary_mutation_operator chọn theo bridge name

**File:** [`src/module3_fuzzing/src/baselines/smartshot/fuzz_loop_smartshot.rs`](../src/module3_fuzzing/src/baselines/smartshot/fuzz_loop_smartshot.rs)
**Line:** 303 + 520-538

```rust
let operator = primary_mutation_operator(&ctx.atg.bridge_name);
...

fn primary_mutation_operator(bridge_name: &str) -> MutationOperator {
    expected_mutation_operators(bridge_name)  // ← chọn từ expected list
        .into_iter()
        .next()
        .unwrap_or(MutationOperator::MS1SetStorage)
}

fn expected_mutation_operators(bridge_name: &str) -> Vec<MutationOperator> {
    match bridge_name.to_ascii_lowercase().as_str() {
        "qubit" => vec![MutationOperator::MS2SetBalance],
        "socket" => vec![MutationOperator::MS1SetStorage, MutationOperator::MS2SetBalance],
        "nomad" | "multichain" | "ronin" | ... => vec![MutationOperator::MS1SetStorage],
        ...
    }
}
```

**Hệ quả:** operator dùng cho mutation ALWAYS là expected operator → emit
violation với `predicate_match=true` (line 368) là chắc chắn. MS3-MS6 không
bao giờ được test, MS1 vs MS2 không bao giờ được fuzz.

**Cách sửa:**

```rust
// Thay vì:
let operator = primary_mutation_operator(&ctx.atg.bridge_name);

// Random pick mỗi iteration:
let all_operators = [
    MutationOperator::MS1SetStorage,
    MutationOperator::MS2SetBalance,
    MutationOperator::MS4AdvanceTimestamp,
    MutationOperator::MS5AdvanceBlock,
];
let operator = all_operators[rng.gen_range(0..all_operators.len())];
```

`expected_mutation_operators(bridge_name)` vẫn giữ để verifier compare, nhưng
operator dùng để mutate phải random. `predicate_match` sẽ tự nhiên là
`true` khi bridge X đúng hit MS expected, `false` khi không.

### 3.3 SmartShot — Taint cache luôn `cut_loss_mode=true`

**File:** [`src/module3_fuzzing/src/baselines/smartshot/taint_cache.rs`](../src/module3_fuzzing/src/baselines/smartshot/taint_cache.rs)
**Line:** 119-134 (`build_curated_taint_cache`)

```rust
pub fn build_curated_taint_cache(
    bridge_name: &str,
    contracts: &[(Address, [u8; 4])],
) -> TaintCache {
    let mut cache = TaintCache::new();
    cache.cut_loss_mode = true;  // ← luôn true

    for (addr, selector) in contracts {
        let rs = hand_curated_slots(bridge_name, *addr);  // ← hardcode slot 0-5 theo bridge
        if !rs.is_empty() {
            cache.insert((*addr, *selector), rs);
        }
    }
    cache
}
```

Và `fuzz_loop_smartshot.rs:131` chỉ gọi hàm này — `collect_read_set`
(SLoadInspector path) **không bao giờ được gọi từ main loop**, mặc dù đã
viết và test riêng. → SLoadInspector thành dead code trong production path.

**Cách sửa:**

```rust
// Trong fuzz_loop_smartshot.rs ~line 131:
let mut taint_cache = TaintCache::new();
if let Some(d) = dual_env_opt.as_mut() {
    for (addr, selector) in &contracts_with_selectors {
        let rs = collect_read_set(d, *addr, *selector);
        if !rs.is_empty() {
            taint_cache.insert((*addr, *selector), rs);
        }
    }
}

// Fallback sang hand-curated chỉ khi inspector không trả được gì:
if taint_cache.total_slots() == 0 {
    taint_cache = build_curated_taint_cache(&ctx.atg.bridge_name, &contracts_with_selectors);
}
```

Khi đó `cut_loss_mode=true` chỉ khi thực sự fallback — methodology note có cơ
sở trung thực.

### 3.4 SmartShot — double_validate không đối chiếu mutated vs unmutated

**File:** [`src/module3_fuzzing/src/baselines/smartshot/double_validate.rs`](../src/module3_fuzzing/src/baselines/smartshot/double_validate.rs)
**Line:** 38-55

```rust
pub fn run_with_double_validation(
    dual: &mut DualEvm,
    snap: &MutableSnapshot,
    metadata_seeded: bool,
) -> DoubleValidationResult {
    let mutation_applied = apply_snapshot_mutation(dual, snap);
    restore_original(dual, snap);
    DoubleValidationResult {
        mutation_applied,
        status: if !mutation_applied {
            DoubleValidationStatus::Discarded
        } else if metadata_seeded {
            DoubleValidationStatus::MetadataSeeded
        } else {
            DoubleValidationStatus::Validated
        },
    }
}
```

Spec §2.3 (paper §5) yêu cầu **chạy 2 lần**: một lần với mutation, một lần với
snapshot gốc — chỉ report nếu cả 2 đều violate (i.e. bug thật, không phải
mutation-induced). Code hiện chỉ apply + restore, **không có replay scenario
nào trong cả hai mode để compare violation**.

**Cách sửa:**

```rust
pub fn run_with_double_validation(
    dual: &mut DualEvm,
    snap: &MutableSnapshot,
    scenario_payload: &[u8],  // ← scenario to execute
) -> DoubleValidationResult {
    // 1. Replay với mutation
    apply_snapshot_mutation(dual, snap);
    let result_mut = dual.execute_on_source(scenario_payload);
    restore_original(dual, snap);

    // 2. Replay với snapshot gốc (chưa mutate)
    let result_orig = dual.execute_on_source(scenario_payload);

    let mut_violates = result_mut.is_err();      // hoặc check semantic
    let orig_violates = result_orig.is_err();

    DoubleValidationResult {
        mutation_applied: mut_violates,
        status: match (mut_violates, orig_violates) {
            (true, true) => Validated,    // bug thật, không phải mutation-induced
            (true, false) => Discarded,   // mutation gây ra violation → spurious
            _ => Discarded,
        },
    }
}
```

---

## 4. Việc còn thiếu

| Task | Status |
|---|---|
| **VS6** Run 12 × 20 sweep VulSEye | ❌ Chưa chạy — `results/baselines/vulseye/` không tồn tại |
| **SS6** Run 12 × 20 sweep SmartShot | ❌ Chưa chạy — `results/baselines/smartshot/` không tồn tại |
| **VS7** `baselines/_cited_results/vulseye_self_run.json` | ❌ Chưa có |
| **SS7** `baselines/_cited_results/smartshot_self_run.json` | ❌ Chưa có |
| **VS5 / SS5** Validation report (60s smoke per bridge) | ❌ Chưa có outcome doc tương đương `REIMPL_SMARTAXE_SA6_REPORT.md` |

Order of operations đề xuất:

1. **Sửa §3.1 + §3.2 + §3.3 + §3.4** (1-2 ngày — cores)
2. Chạy smoke 60s × 1 run per bridge để xem `predicate_match` thật ra sao
3. Viết outcome doc tương tự `REIMPL_SMARTAXE_SA7_OUTCOME.md` ghi nhận số liệu thật
4. Sweep 12 × 20 trên lab (~40h overnight per tool)
5. Build aggregator script (model theo `scripts/build_xscope_self_run_cited.py`)
6. Update tracking matrix trong `PLAN_REIMPL_BASELINES.md`

---

## 5. Reference

- Spec contracts em phải bám: [VS1 spec](REIMPL_VULSEYE_SPEC.md) §2-§7 · [SS1 spec](REIMPL_SMARTSHOT_SPEC.md) §2-§7
- Pattern để copy honest reporting: [SmartAxe SA7 outcome](REIMPL_SMARTAXE_SA7_OUTCOME.md) — detected=12/12 nhưng strict=4/12, paper §5.3 vẫn defensible
- Aggregator template: [`scripts/build_xscope_self_run_cited.py`](../scripts/build_xscope_self_run_cited.py) + [`scripts/build_smartaxe_self_run_cited.py`](../scripts/build_smartaxe_self_run_cited.py)
- Verifier template: [`scripts/verify_xscope_acceptance.py`](../scripts/verify_xscope_acceptance.py) + [`scripts/verify_smartaxe_acceptance.py`](../scripts/verify_smartaxe_acceptance.py)
- Calibration story để học: [`docs/REIMPL_SMARTAXE_SA6_REPORT.md`](REIMPL_SMARTAXE_SA6_REPORT.md) — SmartAxe ban đầu cũng FAIL strict, đã calibrate 2 rules (P4 stop-list + SC3 prediction) honest

---

## 6. Lời nhắn

Phần code "kiến trúc + thuật toán" làm rất ok — CFG construction, opcode parsing,
Inspector hook, snapshot pool, GA selection đều đúng spec và có tests đầy đủ.
Em chỉ cần bỏ 4 chỗ "shortcut detection" ở §3 là tool sẽ honest và defensible
cho paper. Sau đó số liệu có khả năng tương tự SmartAxe (detected 12/12,
strict 4-7/12) — đó vẫn là kết quả ổn cho RQ1 §5.3, miễn là mình ghi rõ trong
methodology note.

Một chi tiết kỹ thuật: nếu em muốn predicate_match cao hơn 4-7/12, em có thể
calibrate pattern matchers (giống cách SmartAxe calibrate P4 stop-list và SC3
prediction trong SA6 — xem report ở link trên). Nhưng calibration phải dựa
trên hành vi thật của fuzzer, không phải hard-code expected list.

Có gì không rõ chỗ nào em ping lại nhé, anh / chị sẽ giải thích sâu thêm chỗ
đó. Cảm ơn em đã viết phần này — algorithm scaffolding chất lượng cao đó.
