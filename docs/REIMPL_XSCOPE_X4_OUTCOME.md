# X4 outcome — XScope re-impl per-bridge validation

> **Latest run (after C1+C2+C3 polish, 2026-04-30)**: ❌ **0/12 bridges hit
> predicted predicate** (acceptance bar: 11/12 per
> [REIMPL_XSCOPE_SPEC.md](REIMPL_XSCOPE_SPEC.md) §4).
>
> **Original run (X3 only, before polish)**: 0/12 — but only 1/12 fired
> any violation at all.
>
> **Verdict**: X3-polish lifts execution from 6/12 → 9/12 bridges and
> violations from 1/12 → 4/12 (all of them I-2, the deposit-recipient-
> zero predicate). The architectural pieces (storage tracker, recipe
> loader, alias map, composite Inspector) work end-to-end. **What is
> still missing for ≥ 11/12**: the LLM-generated scenarios do not
> faithfully reproduce the per-incident storage / event sequences the
> spec §4 predicates require — chiefly the SSTORE patterns that drive
> I-6 (`AuthWitness != AcceptableRoot`) and the unlock-without-lock
> log shapes that drive I-5.
>
> Honest reporting; no cherry-picking. The C1+C2+C3 commits are
> committed-worthy as the foundation for the next round of polish that
> targets scenario quality.

---

## 1. Per-bridge sweep digest — three runs side by side

```
                     X3 only (before polish)        After C1+C2+C3 polish
bridge          bb_src  fired       expected      bb_src  fired       expected
fegtoken           0    —           I-1,I-5            0    —           I-1,I-5
gempad             0    —           I-5                0    —           I-5
harmony            0    —           I-6                0    —           I-6
multichain         0    —           I-5              132    I-2         I-5
nomad           1010    —           I-6             1222    —           I-6
orbit            459    —           I-6              721    I-2         I-6
pgala            212    —           I-3,I-4,I-6     212    —           I-3,I-4,I-6
polynetwork      215    —           I-5,I-6         215    —           I-5,I-6
qubit              0    —           I-2                0    —           I-2
ronin              0    —           I-6              405    I-2         I-6
socket           177    —           I-1,I-5         217    —           I-1,I-5
wormhole        1502    I-1,I-2     I-5,I-6        1672    I-2         I-5,I-6
                ────                              ────
total bb=0:   6/12                              3/12
fire any:    1/12                              4/12
match exp:   0/12                              0/12
```

Source data:
- [`docs/baseline_x4_artifacts/xscope_x4_verification.json`](baseline_x4_artifacts/xscope_x4_verification.json) — original X3-only verifier output
- [`docs/baseline_x4_artifacts/xscope_x4_post_c3_verification.json`](baseline_x4_artifacts/xscope_x4_post_c3_verification.json) — verifier after C1+C2+C3
- [`docs/baseline_x4_artifacts/xscope_x4_post_c3_summary.json`](baseline_x4_artifacts/xscope_x4_post_c3_summary.json) — per-bridge digest after polish
- [`docs/baseline_x4_artifacts/xscope_x4_summary.json`](baseline_x4_artifacts/xscope_x4_summary.json) — same digest before polish

---

## 2. What C1+C2+C3 fixed

- **C1 (storage tracker)**: SSTORE Inspector + `XScopeInspector` composite
  land in [`src/module3_fuzzing/src/storage_tracker.rs`](../src/module3_fuzzing/src/storage_tracker.rs).
  98 → 104 tests pass; the composite Inspector demonstrably populates
  both coverage and storage in a single revm pass.
- **C2 (metadata)**: 12/12 `metadata.json` files now carry an
  `address_aliases` block (resolves "MockToken", "WrappedToken",
  "FlashLoanProvider", … ATG node names that don't substring-match any
  contract key) and an `auth_witness` recipe (`zero_root` /
  `multisig{threshold}` / `mpc` / `none` keyed on a
  `contracts.<key>.address`).
- **C3 (wiring)**: `fuzz_loop::run_xscope` applies the aliases first,
  attaches the `XScopeInspector` to every per-iteration execute, and
  feeds the per-scenario SSTORE trace into a recipe-driven
  `derive_auth_witness`. Three new bridges (multichain / ronin / orbit)
  now reach the EVM thanks to aliases; four bridges fire violations
  whereas only one did before.

The architectural goal of "stop using `RelayMode` as a proxy for
authorisation state" is achieved.

---

## 3. What C1+C2+C3 did **not** fix

The remaining 0/12 predicted-predicate match has two distinct root
causes, neither of which is in the detector itself:

### 3.1 The fired I-2 violations are false positives

Four bridges (multichain / ronin / orbit / wormhole) fire I-2
(`recipient_zero`). Their documented incidents are not
deposit-recipient bugs — multichain is MPC compromise, ronin is
multisig forgery, orbit is MPC threshold, wormhole is signature
replay. The I-2 firings come from
[`xscope_adapter::read_address_word`](../src/module3_fuzzing/src/baselines/xscope_adapter.rs):
we read 20 bytes at offset 32 + 12 of the log data, but real bridges
emit events whose recipient sits at a different offset (or in an
indexed topic instead of the data field). The decoded recipient is
all-zero, so I-2 violates spuriously.

**Fix**: per-bridge event ABI in `metadata.contracts.<key>.events`
(spec §6.1, deferred from C2) — populate `lock_recipient_offset` /
`lock_amount_offset` so the decoder uses real layouts. ~½ day per
bridge × 12.

### 3.2 The recipe-derived auth witnesses don't fire

The 8 bridges with non-`none` `auth_witness` recipes (nomad / ronin /
harmony / orbit / wormhole / multichain / polynetwork / pgala) all
return `AcceptableRoot` from `derive_auth_witness` because there are
no SSTOREs landing on the configured `contract_address` during the
short scenarios. Real on-chain attacks DO produce SSTOREs — Nomad's
incident sets `acceptableRoot[bytes32(0)] = 1` during `initialize()`,
Ronin's writes the forged signer set, etc. — but those storage writes
require executing **the actual incident transaction**, which the
LLM-generated scenarios don't reliably reproduce.

**Fix path A**: Curated exploit-trace scenarios. Take each benchmark's
`exploit_trace.json` (we already have these — see
`benchmarks/<bridge>/exploit_trace.json`) and replay the exact tx
sequence in XScope mode rather than running the abstract LLM
scenarios. Effort: ~½ day per bridge to build a replay loader, then
~1-2 days to wire `--mode xscope-replay`.

**Fix path B**: Slot-aware auth-witness check. Instead of "any SSTORE
on contract X fires", parse the contract's Solidity source to find
the actual auth-control mapping slot, then check `latest_value(addr,
slot)` against the documented attack value. Effort: same as path A
plus the per-bridge Solidity reading.

Both paths are scenario-quality work, not detector-quality work.
Recommend path A — `exploit_trace.json` already exists for all 12
bridges and is the faithful incident reproduction the spec §4
predictions implicitly assume.

---

## 4. What's needed to lift X4 to ≥ 11/12

Ordered by impact-per-effort:

1. **Replay-mode XScope** (~3-4 days) — Add `--baseline-mode xscope-replay`
   that reads `exploit_trace.json` and dispatches the exact transactions
   instead of the LLM scenarios. Each replay tx hits the real auth
   storage path → SSTOREs land → `derive_auth_witness` produces real
   classifications → I-6 fires correctly on the 8 auth-bridge incidents.
   Probably hits 8-10/12 alone.
2. **Per-bridge event ABI** (~1 day if focused on the offset table only) —
   eliminates I-2 false positives + lets I-1 and I-5 evaluate proper
   amount/recipient/hash fields. Targets the 4 already-firing bridges
   plus the 5 with execution but no fires (nomad / orbit /
   polynetwork / pgala / socket).
3. **Address-alias retry on bb=0 bridges** (~½ day) — fegtoken /
   gempad / qubit / harmony still have bb_src=0 because their alias
   maps don't cover every action.contract value the LLM scenarios
   emit. Spot-check + extend the alias dict in
   `scripts/_apply_x3polish_metadata.py`.

Total to reach ≥ 11/12: ~4-6 days. Strictly less than the 7-8 days
estimated in the original X4 outcome (commit 05e9ae7) because C1+C2+C3
already paid down the storage-tracker debt.

---

## 5. Decision needed

The right next move depends on the paper §5.3 RQ1 deadline:

| # | Option | Effort | Outcome |
|---|---|---|---|
| **A** | Push C4: replay-mode + ABI + extra aliases | ~4-6 days | 11/12 self-run, full RQ1 column |
| **B** | Ship XScope as **mixed**: wormhole/multichain/ronin/orbit self-run (I-2 false positives noted in methodology) + cite-published for the rest | 0 days | 4/12 self-run + 1/12 cited (Qubit) |
| **C** | Drop self-run for XScope, keep cite-published only | 0 days | 1/12 cited |

Recommend **A** — same logic as the previous outcome (replay-mode
amortises into VulSEye's scenario harness too: same `exploit_trace.json`
replay seeds VulSEye's directed fuzzing).

---

## 6. Acceptance status

```
X4 ACCEPTANCE: FAIL  (0/12 predicted; bar 11/12)
X4 PROGRESS:    +3 bridges executing, +3 bridges firing violations
                vs before C1+C2+C3.
```

The verifier script + the JSON artifacts in
[`docs/baseline_x4_artifacts/`](baseline_x4_artifacts/) make
incremental progress trackable. C4 (replay mode) re-runs the same
verifier against new sweep results.
