# X4 outcome — XScope re-impl per-bridge validation

> **Result**: ❌ **0/12 bridges hit predicted predicate** (acceptance bar:
> 11/12 per [REIMPL_XSCOPE_SPEC.md](REIMPL_XSCOPE_SPEC.md) §4).
>
> **Date**: 2026-04-30. Smoke run: 60 s × 1 run × 12 benchmarks against
> Ethereum mainnet fork at the per-bridge fork block.
>
> **Verdict**: X3 wiring is correct end-to-end (the binary executes,
> ingests logs, runs predicates, emits violations) — Wormhole proves
> this by firing 3 violations on real on-chain logs. But the **specific
> predicates required by spec §4** (mostly I-5 + I-6) need primitives
> X3 explicitly deferred.
>
> Honest report. Not cherry-picking numbers — recording what failed and
> what is needed to lift the pass rate.

---

## 1. Per-bridge sweep digest

```
bridge       iters bb_src bb_dst viol fired       expected   verdict
fegtoken      20    0      0     0    —           I-1,I-5    FAIL
gempad        20    0      0     0    —           I-5        FAIL
harmony       19    0      0     0    —           I-6        FAIL
multichain    21    0      0     0    —           I-5        FAIL
nomad         18  1010      0    0    —           I-6        FAIL
orbit         18   459      0    0    —           I-6        FAIL
pgala         19   212      0    0    —           I-3,I-4,I-6 FAIL
polynetwork   16   215      0    0    —           I-5,I-6    FAIL
qubit         20    0      0     0    —           I-2        FAIL
ronin         20    0      0     0    —           I-6        FAIL
socket        19   177      0    0    —           I-1,I-5    FAIL
wormhole      19  1502      0    3    I-1,I-2     I-5,I-6    FAIL  (extra: I-1,I-2)
```

Source data:
- [`docs/baseline_x4_artifacts/xscope_x4_verification.json`](baseline_x4_artifacts/xscope_x4_verification.json) — verifier output
- [`docs/baseline_x4_artifacts/xscope_x4_summary.json`](baseline_x4_artifacts/xscope_x4_summary.json) — per-bridge slim digest

The full per-run JSONs live at `results/baselines/xscope/<bridge>/run_*.json` (gitignored).

---

## 2. What worked

- **CLI integration**: `bridgesentry-fuzzer --baseline-mode xscope` runs
  cleanly on all 12 bridges. 12/12 sweeps complete in 34 s wall-clock,
  no crashes.
- **Real EVM execution** on 5/12 bridges: nomad (1010 PCs), wormhole
  (1502 PCs), orbit (459 PCs), polynetwork (215 PCs), pgala (212 PCs),
  socket (177 PCs). The `_with_inspector_full` log-capturing path is
  confirmed working.
- **Wormhole fired 3 violations** including I-1 and I-2 on real on-chain
  logs, proving the predicate dispatch + topic-filtering pipeline
  end-to-end. Just not the predicates spec §4 expected.
- **6/6 X3 unit tests + 24/24 X2 unit tests pass** — the predicate
  logic itself is correct against synthetic fixtures.

---

## 3. Why 0/12 (root-cause analysis)

Three distinct failure modes across the 12 bridges:

### 3.1 No real execution → no logs → no predicates fire (6 bridges)

`bb_src = 0` indicates the EVM never reached opcode level. Affected:
**qubit, ronin, harmony, multichain, fegtoken, gempad**.

Two upstream issues conspire:

- **Encode-action returns `None`** for actions whose ATG `contract`
  field doesn't resolve to a deployed address. The metadata override
  table covers some contracts (e.g. ronin_bridge_manager) but not
  every node the LLM-produced ATG refers to (e.g. ATG node names like
  `MaliciousToken`, `SignerSet` have no `metadata.contracts.<key>`).
- **CalldataMutator dispatches to `Relay`** for actions tagged with
  unknown chain side (the same fix landed for default mode in
  Phase A but only when the action's `contract` is recognised).

### 3.2 Real execution + logs, but no expected predicate fires (5 bridges)

`bb_src > 0` and yet `fired = []`. Affected: **nomad, orbit,
polynetwork, pgala, socket**.

- I-1 / I-2 / I-5 require **lock or unlock log topics** that match the
  per-bridge event-signature table. X3 falls back to "ATG-edge keccak +
  known-emitter address". For these 5 bridges either:
  - The ATG edge `function_signature` doesn't match what the deployed
    bytecode actually emits at the fork block (bridges have evolved
    contracts), **or**
  - The deployed contract emits a `Deposit`/`Mint` shape we don't
    decode (e.g. the recipient sits in a different word offset than
    `data[32..52]`).
- I-6 requires an `AuthWitness ≠ AcceptableRoot`. X3 derives the
  witness heuristically from `MockRelay::mode`, which stays
  `Faithful` for every action that is **not** an explicit `chain:
  "relay"` step. Most scenarios in our 12-benchmark dataset don't
  emit relay actions at all, so the heuristic always returns
  `AcceptableRoot` → I-6 always **holds**.

### 3.3 Wrong predicates fire (1 bridge)

**Wormhole** fires I-1 (no-balance-change) and I-2 (recipient-zero)
because the WormholeCore real-bytecode logs we capture lack the amount
field at the offset our adapter reads, so the decoded amount is zero
but the topic table still routes the log to `lock_events`. Predicates
correctly raise — but spec §4 expected I-5 + I-6 (signature replay),
not I-1 + I-2 (deposit shape).

This is not a bug in the predicate logic; it's the same auth-witness
issue from §3.2 plus the field-offset issue.

---

## 4. What's needed to lift X4 to ≥ 11/12

Two work items, both inside the **X3 polish** scope (deferred when X3
shipped, called out explicitly in `REIMPL_XSCOPE_SPEC.md` §3):

### 4.1 Storage-write Inspector for I-6 auth-witness reconstruction

Spec §3 line: *"state_diff.storage_delta — New: a thin
StorageWriteTracker Inspector merged into the existing CoverageTracker
rebuild. **Required for I-6** (`acceptableRoot[root] == true` trace,
multisig threshold reconstruction)."*

Concrete plan:

1. Extend `coverage_tracker.rs` (or add `storage_tracker.rs`) with
   `Inspector::step` matching `SSTORE` → record `(addr, slot, value)`
   tuples per iteration.
2. Per-bridge "auth-witness recipe" loaded from `metadata.json`:
   - Nomad: `(replica, slot=keccak256(0)) == 1` ⇒ ZeroRoot
   - Ronin: count matching slots `signers[i].admin == true`,
     compare to threshold ⇒ Multisig{signatures, threshold}
   - Wormhole: `guardian_set_index` storage value ⇒ Mpc{matches_canonical}
   - …
3. Replace `derive_auth_witness(&relay)` in `fuzz_loop.rs` with the
   storage-trace lookup.

Estimated effort: **~3-4 days** (one Phase-A4-sized piece). This is
roughly what `REIMPL_XSCOPE_SPEC.md §3` priced in already.

### 4.2 Per-bridge event signature table in metadata.json

Spec §6.1 already defines an optional `contracts.<key>.events.{lock_topic,
unlock_topic}` field. Populating it for the 12 bridges (~24 hex topics)
would replace the unreliable "ATG-edge keccak" fallback for the 5
bridges in failure mode §3.2.

Estimated effort: **~1 day** (lookup on Etherscan; one row per bridge).

### 4.3 Address overrides for ATG node names not in metadata

For the 6 bridges in failure mode §3.1, populate `metadata.contracts`
with synthetic entries pointing to deployed mock contracts (or skip
those bridges with a methodology note for now). This is also a known
limitation called out in the original `merge_address_overrides` design
(spec §3 of REIMPL_XSCOPE_SPEC.md).

Estimated effort: **~0.5 day per bridge** ⇒ ~3 days total for 6.

**Total to reach 11/12**: ~7-8 days of X3-polish work. The X3 budget
was 1 day so this slipped into X4; the reasonable path is to recognise
this slip, log it as a known limitation now, and decide whether to
invest the polish before the SmartAxe / VulSEye / SmartShot impl phases.

---

## 5. Decision needed (advisor escalation)

Three options, each with paper-§5.3 RQ1 implications:

| # | Option | Effort | RQ1 column for XScope |
|---|---|---|---|
| **A** | Invest 7-8 days X3 polish to reach ≥ 11/12 | ~1.5 weeks | Self-run, per-bridge truth |
| **B** | Ship XScope as 1/12 cited (Wormhole I-1/I-2 honest result) + cite-published for the rest | 0 days | Mixed self-run / cite |
| **C** | Drop XScope from RQ1 self-run, fall back to cite-published only (current `baselines/_cited_results/xscope.json`) | 0 days | Pure cite |

**Recommend A** — it's the smallest investment that lets us claim
"self-run on 12 bridges" for XScope, and the same storage-write
inspector serves the **VulSEye** (state targets) and **SmartShot**
(taint) re-impls coming up — i.e. the work amortises across three of
the four re-impl tracks.

Option A's first sub-task would be a new `X3.1 Storage-write Inspector`
spec entry in PLAN_REIMPL_BASELINES.md and a corresponding 3-4 day
implementation block before X4 is re-attempted.

---

## 6. Acceptance status

```
X4 ACCEPTANCE: FAIL  (0/12, bar 11/12)
```

This file + the JSON artifacts in
[`docs/baseline_x4_artifacts/`](baseline_x4_artifacts/) constitute the
honest record. The verifier
[`scripts/verify_xscope_acceptance.py`](../scripts/verify_xscope_acceptance.py)
re-runs the same check and writes the same summary; future X3-polish
work re-runs it to track the pass rate climbing from 0/12 toward
11/12.
