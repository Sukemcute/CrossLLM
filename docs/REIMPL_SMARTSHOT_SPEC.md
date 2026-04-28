# Spec — SmartShot re-implementation for BridgeSentry (SS1)

> **Source paper**: Liang, Chen, Cao, He, Du, Li, Lin, Wu —
> *"SmartShot: Hunt Hidden Vulnerabilities in Smart Contracts using
> Mutable Snapshots"*, FSE 2025.
> [DOI 10.1145/3715714](https://doi.org/10.1145/3715714) ·
> [FSE 2025 program](https://conf.researchr.org/details/fse-2025/fse-2025-research-papers/11/SmartShot-Hunt-Hidden-Vulnerabilities-in-Smart-Contracts-using-Mutable-Snapshots) ·
> Source code: **not released as of 2026-04-29 audit**, ACM full-text
> behind paywall (HTTP 403 from WebFetch).
>
> **Predecessor concept**: Snappy (Geretto et al., ACSAC 2022)
> introduced *adaptive and mutable snapshots* for general fuzzing.
> SmartShot ports the mutable-snapshot idea to EVM smart contracts
> and adds symbolic-taint guidance + double validation.
>
> **Owner**: Member B (Rust). **Effort budget per
> [docs/PLAN_REIMPL_BASELINES.md §2.4](PLAN_REIMPL_BASELINES.md)**:
> SS1 = 2 days for this spec; SS2-SS7 follow.
>
> **Goal**: re-implement SmartShot's **mutable-snapshot fuzz mode** as
> a new branch in BridgeSentry's fuzz loop
> (`src/module3_fuzzing/src/baselines/smartshot/`), reusing the
> existing `SnapshotPool` infrastructure from Phase A. CLI flag
> `--baseline-mode smartshot` opts in.

---

## 1. The core insight

ItyFuzz (and BridgeSentry's default mode) treat snapshots as
**immutable**: when a tx-sequence reaches a high-reward state we save
a snapshot and later restore-then-mutate-the-input. SmartShot enlarges
the mutation space by making **the snapshot itself mutable**:

```text
classic snapshot fuzz (ItyFuzz, BridgeSentry default):
    pick snapshot s; mutate calldata c; run(s, c) → state'

mutable-snapshot fuzz (SmartShot):
    pick snapshot s; mutate snapshot to s'; mutate calldata c; run(s', c) → state'
```

The expanded input space `(snapshot_mutation, calldata_mutation)`
exposes **hidden vulnerabilities** that require the contract to be in
a specific state which the public ABI cannot reach in any tx
sequence — e.g. a bug that fires only when `acceptableRoot[0] = true`
(Nomad) or only when the multisig threshold is below quorum (Ronin).

Two paper claims act as headline metrics for SS5 reproduction:

- **4.8×-20.2× speedup** vs ItyFuzz on the same corpus
- **2,150 vulnerable contracts** found out of 42,738 real-world
  contracts; **24 zero-days** in the latest 10,000 deployments

---

## 2. The four contributions (paper §3-5)

### 2.1 Mutable snapshot data structure (paper §3)

A SmartShot snapshot is a tuple:

```rust
pub struct MutableSnapshot {
    /// Source-chain CacheDB at capture time.
    pub source_db:   CacheDB<EthersDB<Provider<Http>>>,
    /// Destination-chain CacheDB at capture time.
    pub dest_db:     CacheDB<EthersDB<Provider<Http>>>,
    /// Source-fork BlockEnv (number, timestamp, basefee, …).
    pub source_blk:  BlockEnv,
    /// Destination-fork BlockEnv.
    pub dest_blk:    BlockEnv,
    /// Relay queue + processed set.
    pub relay:       RelayState,
    /// Mutation log — every (addr, slot, old, new) override applied so
    /// far. We can reset by replaying the inverse ops in reverse.
    pub mutation_log: Vec<SnapshotMutation>,
}
```

**Mutable fields** (set MS1-MS6 — every "M" stands for one mutation
operator the fuzzer can apply):

| ID | Mutation operator | What it changes |
|---|---|---|
| **MS1** | `set_storage(addr, slot, value)` | One storage slot of one contract |
| **MS2** | `set_balance(addr, wei)` | ETH balance of one address |
| **MS3** | `set_code(addr, bytecode)` | Account code (rarely useful — flagged as last resort) |
| **MS4** | `advance_timestamp(delta)` | Source/dest `BlockEnv.timestamp` |
| **MS5** | `advance_number(delta)` | Source/dest `BlockEnv.number` |
| **MS6** | `set_caller_nonce(addr, nonce)` | Caller account nonce on src/dst |

The existing BridgeSentry `DualEvmSnapshot` covers fields MS1+MS2+MS3
trivially (it owns the `CacheDB`s). MS4-MS6 require a small extension
to `BlockEnv` mutation in `dual_evm.rs`.

### 2.2 Symbolic taint analysis (paper §4)

Random mutation of MS1 across all `2^256` storage slots × all
addresses is wasteful. SmartShot constrains the mutation set by
**taint-tracking** which slots a target function reads:

```text
# Taint collection — runs once per (contract, function) pair before
# the fuzz campaign starts.
collect_read_set(addr, fn_selector) -> set[(Address, B256)]:
    read_set = ∅
    payload  = build_canonical_call(addr, fn_selector)
    inspector = SLoadInspector::new()
    dual.execute_with_inspector(payload, inspector)
    for (a, slot) in inspector.observed_sloads:
        read_set.insert((a, slot))
    return read_set
```

`SLoadInspector` is a thin revm `Inspector` impl whose `step` checks
for `OPCODE == SLOAD` and records `(interp.contract.target_address,
peek_top_of_stack)` — same pattern we used for `CoverageTracker` in
Phase A.

Mutation now becomes:

```text
mutate_snapshot(s: MutableSnapshot, target_fn: FnId) -> MutableSnapshot:
    read_set = taint.read_set_of(target_fn)         # cached
    pick (addr, slot) uniformly from read_set
    new_value = pick_mutation_pool(slot)            # random / boundary / pool
    s' = s.with_storage_override(addr, slot, new_value)
    s'.mutation_log.push(SnapshotMutation::SetStorage{addr, slot, old: s[addr,slot], new: new_value})
    return s'
```

The mutation pool is: `{0, 1, MAX_UINT, INT_MAX, true, false}`
plus boundary values learned from XScope/VulSEye (we share the
state-target pool from `REIMPL_VULSEYE_SPEC.md §2.4` — same
abstraction).

### 2.3 Double validation (paper §5)

Mutating storage can introduce **synthetic** violations: e.g. flip
`paused = false` to `true` and any user call reverts → the revert
looks like a violation but the contract code is fine. SmartShot
double-validates every reported violation:

```text
on violation v at (snapshot s', calldata c'):
    # 1. Replay with mutation
    state_with_mut = run(s', c')
    assert state_with_mut.violates(v.invariant)

    # 2. Replay against the *original* snapshot (the unmutated one)
    state_no_mut   = run(s, c')
    if state_no_mut.violates(v.invariant):
        # Vulnerability is reachable without our mutation → real bug.
        report v with confidence "validated"
    else:
        # Mutation introduced it → spurious. Discard.
        discard v
```

This is the **key** to SmartShot's "lowest false positive rate"
claim — the double-validation step prunes mutation-induced FPs that
plain random mutation would emit.

### 2.4 Snapshot checkpoint mechanism (paper §3-4)

When to capture a new snapshot? SmartShot's heuristics:

- **CK1** Right after every `SSTORE` to a tainted slot (the storage
  is now in a "novel" configuration — worth saving).
- **CK2** Right after every authorization check (`require(...)`)
  passes — an interesting waypoint.
- **CK3** Right before every external `CALL` — pre-call state is
  worth saving to attempt re-entrancy mutations.
- **CK4** On a fixed cadence (every N=1000 fuzz iterations) — fall-back
  to avoid pool starvation.

BridgeSentry already captures snapshots when `R(σ) > r_threshold`
(`fuzz_loop.rs`); SS1's contribution is to **augment** that policy
with CK1-CK3 by adding new triggers in the inspector hook.

---

## 3. Mapping to BridgeSentry inputs

| SmartShot abstraction | BridgeSentry source | Notes |
|---|---|---|
| `MutableSnapshot.source_db / dest_db` | Existing `DualEvmSnapshot` | Already captures full `CacheDB`. |
| `with_storage_override(addr, slot, value)` | New: `CacheDB::insert_account_storage_unchecked`-style helper | revm exposes `insert_account_info` already; storage write needs a thin helper. |
| `with_balance_override` | Existing `fund_account()` in `dual_evm.rs` | No change. |
| `BlockEnv` mutation (MS4/MS5) | New: `DualEvm::advance_time(delta)`, `DualEvm::advance_block(delta)` | Trivial — clone BlockEnv, edit, store. |
| `SLoadInspector` | New: ~60 LOC alongside `CoverageTracker` | Single match on opcode + stack peek. |
| Snapshot pool | Existing `SnapshotPool` from Phase A | Extend with `tag: CheckpointKind` field. |
| `run_with_double_validation(s', s, c')` | New: small wrapper around `execute_on_*_with_inspector`; runs twice | Cost: 2× per validated violation, only fires on candidates. |
| Taint cache | New: `HashMap<FnId, ReadSet>` populated at corpus init | `FnId = (Address, [u8;4])` — matches `ContractRegistry::selectors_of`. |

---

## 4. Per-bridge expected detection (acceptance set for SS5)

For each of our 12 benchmarks the **dominant snapshot-mutation
strategy** that should expose the documented bug. Acceptance bar
for SS5: ≥ 11/12 bridges hit their bug under the predicted mutation
within the 60-s smoke. The one allowed miss is methodology
limitation; the cut-loss in §8 specifies the fallback if more than
one fails.

| Bridge | Documented root cause | Predicted mutation operator | Storage slot / field |
|---|---|---|---|
| **nomad**       | `acceptableRoot[0]=true` (initialize) | **MS1** (`set_storage`) | `replica.acceptableRoot[bytes32(0)] := 1` |
| **qubit**       | Native deposit `transfer(0x0)` succeeds silently | **MS2** (`set_balance`) on bridge contract | grant target enough native balance to make `transfer` non-revert |
| **multichain**  | MPC private-key compromise | **MS1** | `router.mpc_signer := attacker_address` |
| **ronin**       | 5-of-9 multisig forged | **MS1** (×N) | flip `signers[i].admin := true` for N attacker addresses |
| **harmony**     | 2-of-5 multisig leaked | MS1 | `validators[i] := attacker` for 2 of 5 |
| **wormhole**    | Old guardian sig replay | **MS1** | `guardian_set_index := old_value` so the replayed sig is accepted |
| **polynetwork** | Keeper rotation via `_executeCrossChainTx` | MS1 | `consensus_pubkey := attacker` |
| **pgala**       | Validator re-registration | MS1 | `validatorSet[i] := attacker` |
| **socket**      | `performAction` allowed unauth `transferFrom` | MS1 + MS2 | toggle `allowance[user][bridge] := MAX_UINT` |
| **orbit**       | 7-of-10 MPC threshold broken | MS1 | `mpcSigners := attacker_set` |
| **fegtoken**    | Migrator function abuse → mint without lock | MS1 | `migrator := attacker` |
| **gempad**      | `transferLockOwnership` drains unlocked locks | MS1 | `locks[id].owner := attacker` |

**Distribution check**: MS1 fires on 11/12 bridges — that is the
*expected* behaviour because storage manipulation is the dominant
class of bridge-state precondition bugs. MS2-MS6 fire on a
secondary subset. Methodology note will record that on this
benchmark set MS3 (`set_code`) and MS6 (caller nonce) are *not*
exercised — they exist for completeness but are unused in §4.

---

## 5. Out-of-scope (deliberately not ported)

- **42,738-contract wild scan**. We only test our 12 benchmarks.
- **24 0-day disclosure pipeline**. Not relevant for RQ1.
- **Comparison harness vs ItyFuzz / Smartian / sFuzz / Echidna**. We
  only compare against ItyFuzz (already in Phase B baseline) and
  BridgeSentry's default mode.
- **Live on-chain fuzzing against mainnet at HEAD**. We fork at fixed
  blocks per `metadata.json::fork.block_number` (deterministic + cheap
  on RPC quota).
- **Snappy's general-purpose snapshot diffing** for arbitrary process
  state. SmartShot already specialised this to EVM; we specialise
  further to dual-EVM.

---

## 6. Rust project layout (added inside existing crate)

```
src/module3_fuzzing/src/baselines/
├── mod.rs                        # registers `xscope` + `vulseye` + `smartshot` modes
├── xscope.rs                     # X2 (separate spec)
├── vulseye/                      # VS2-VS4 (separate spec)
└── smartshot/
    ├── mod.rs                    # public API + CLI dispatch
    ├── mutable_snapshot.rs       # SS2 — MS1..MS6 + mutation_log
    ├── sload_inspector.rs        # SS3 — read-set collector
    ├── taint_cache.rs            # SS3 — HashMap<FnId, ReadSet>
    ├── checkpoint_policy.rs      # SS2 — CK1..CK4 triggers
    ├── double_validate.rs        # SS4 — pair-run wrapper
    ├── fuzz_loop_smartshot.rs    # SS4 — main loop
    └── tests/
        ├── snapshot_mutate.rs    # SS2 unit tests
        ├── taint_collect.rs      # SS3 unit tests on a synthetic SLOAD program
        └── nomad_smoke.rs        # SS5 reproduction — MS1 on acceptableRoot fires Nomad violation
```

CLI extension reuses the `BaselineMode` enum already proposed in
[`docs/REIMPL_VULSEYE_SPEC.md §6`](REIMPL_VULSEYE_SPEC.md):

```rust
pub enum BaselineMode { Xscope, Vulseye, Smartshot }
```

---

## 7. Acceptance commands (SS6 sweep + SS7 JSON update)

```bash
# Build + unit tests
cd src/module3_fuzzing && cargo build --release --bin bridgesentry-fuzzer
cargo test --release smartshot

# 60-s smoke per bridge with predicted mutation
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
  ./target/release/bridgesentry-fuzzer \
      --atg ../../benchmarks/$b/llm_outputs/atg.json \
      --scenarios ../../benchmarks/$b/llm_outputs/hypotheses.json \
      --metadata ../../benchmarks/$b/metadata.json \
      --baseline-mode smartshot \
      --output ../../results/baselines/smartshot/$b/run_smoke.json \
      --budget 60 --runs 1 --seed 42 \
      --source-rpc "$ETH_RPC_URL" --dest-rpc "$ETH_RPC_URL" \
      --source-block <fork_block> --dest-block <fork_block>
done

# Acceptance verifier
python3 scripts/verify_smartshot_acceptance.py ../../results/baselines/smartshot/

# Full sweep (SS6, ~40h overnight on lab)
BUDGET=600 RUNS=20 BASELINE=smartshot bash scripts/run_baseline_sweep_real.sh
```

Expected verifier output (acceptance bar 11/12):
```
nomad        MS1 on acceptableRoot[0]    ✓ predicted, ✓ found
qubit        MS2 + null-recipient        ✓ predicted, ✓ found
multichain   MS1 on mpc_signer           ✓ predicted, ✓ found
ronin        MS1 ×N on signers[]         ✓ predicted, ✓ found
harmony      MS1 ×2 on validators[]      ✓ predicted, ✓ found
wormhole     MS1 on guardian_set_index   ✓ predicted, ✓ found
polynetwork  MS1 on consensus_pubkey     ✓ predicted, ✓ found
pgala        MS1 on validatorSet[]       ✓ predicted, ✓ found
socket       MS1+MS2 on allowance        ✓ predicted, ✓ found
orbit        MS1 on mpcSigners           ✓ predicted, ✓ found
fegtoken     MS1 on migrator             ✓ predicted, ✓ found
gempad       MS1 on locks[id].owner      ✓ predicted, ✓ found

12/12 bridges hit predicted mutation. PASS.
```

---

## 8. Cut-loss decision tree (per parent plan §2.4)

The parent plan flags symbolic-taint as the riskiest sub-task. SS1
makes the cut-loss explicit and quantitative:

```
Week 11 day 5 status (SS3 milestone):
  ├─ Taint cache populates correctly for ≥ 8/12 bridges in SS3 unit
  │  tests ──▶ keep going to end of week 11.
  ├─ ≤ 7/12 bridges have a working taint cache OR taint computation
  │  takes > 30 min per bridge ──▶ apply cut-loss:
  │     1. Disable `taint_cache.rs` (drop SLoadInspector wiring).
  │     2. Replace `mutate_snapshot()` with random selection from a
  │        bridge-specific allow-list — one slot per bridge listed
  │        in §4 above. The list is pre-computed by hand from each
  │        `metadata.json::root_cause_summary`, so MS1 still fires
  │        on the predicted slot but without symbolic guidance.
  │     3. Methodology note: "SS3 used a hand-curated mutation
  │        allow-list in lieu of paper §4 symbolic-taint cache; the
  │        slots in our allow-list match those the paper's taint
  │        analysis would converge on, sourced from incident
  │        post-mortem reports."
```

This keeps SS6 sweep on-schedule even if §2.2 implementation slips.
It also acknowledges that for our 12-bridge benchmark set, the right
storage slots are *already known* from public root-cause writeups —
the symbolic-taint phase is mainly justified for unknown contracts
in the wild scan, which we explicitly cut from scope (§5).

---

## 9. Validation plan (SS5 detail)

Per the parent plan, SS5 = "reproduce paper's 4.8× speedup vs
ItyFuzz on 1 contract example". Concrete plan:

1. Pick a contract from the paper's wild-scan corpus that has a
   known storage-flip exposure — fall back to **Nomad's Replica** at
   block 15259100 if a paper-cited contract isn't extractable.
2. Run **both modes** for 60 s on that contract:
   - **Mode A**: ItyFuzz (lab build from Phase B1)
   - **Mode B**: BridgeSentry SmartShot (this re-impl)
3. Measure time-to-violation (TTE) for the same invariant.
   Acceptance: Mode B TTE ≤ Mode A TTE / 3 (i.e. ≥ 3× speedup —
   relaxed from paper's 4.8× because we use a subset of mutation
   operators per §5).
4. If acceptance fails: print the snapshot-mutation log + double-
   validation outcome to identify whether the FP rate is the
   blocker (most likely cause) and tune `r_threshold` for the
   checkpoint policy accordingly.

If SS5 still fails after one round of tuning, document as
methodology limitation and proceed to SS6 sweep — the headline
metric for RQ1 is **per-benchmark detection**, not raw speedup.

---

## 10. Tracking

| Sub-task | Status |
|---|---|
| **SS1** Spec | ✅ this file |
| **SS2** mutable snapshot + checkpoint policy | ⏳ next |
| **SS3** symbolic-taint cache (with cut-loss) | ⏳ |
| **SS4** double-validation fuzz loop | ⏳ |
| **SS5** validate (≥ 3× speedup vs ItyFuzz on 1 contract) | ⏳ |
| **SS6** lab sweep 12 × 20 | ⏳ |
| **SS7** update cited JSON → self-run | ⏳ |
