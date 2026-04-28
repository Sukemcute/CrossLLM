# Spec — XScope re-implementation for BridgeSentry (X1)

> **Source paper**: Zhang, Gao, Li, Chen, Guan, Chen — *"Xscope: Hunting
> for Cross-Chain Bridge Attacks"*, ASE 2022.
> [arXiv 2208.07119](https://arxiv.org/abs/2208.07119) ·
> [DOI 10.1145/3551349.3559520](https://doi.org/10.1145/3551349.3559520) ·
> [results repo](https://github.com/xscope-tool/results)
>
> **Owner**: Member B (Rust). **Effort budget**: 1 day for spec, 2 days
> for implementation, 2 days for validation. Per
> [docs/PLAN_REIMPL_BASELINES.md §2.1](PLAN_REIMPL_BASELINES.md).
>
> **Goal**: re-implement the **detection algorithm** (not the full tool)
> as a Rust module in `src/module3_fuzzing/src/baselines/xscope.rs`,
> driven from the existing `DualEvm` + scenario stream — output
> conforms to `baselines/_cited_results/xscope.json` schema so the
> RQ1 aggregator handles cite + re-impl uniformly.

---

## 1. The three bug classes (paper §3)

Per the abstract + Medium summary, XScope characterises **three new
classes of bugs** in cross-chain bridges:

| # | Class | Plain-English definition |
|---|---|---|
| **C1** | **Inconsistency of Deposits** | The source-chain router emits a deposit / lock event whose amount or recipient does not match the real on-chain state change (e.g. transfer to `0x0` succeeds silently, fee-on-transfer tokens lock less than the event amount). |
| **C2** | **Inconsistent Event Parsing** | The off-chain relayer parses the source-chain event in a way that disagrees with what the contract emitted (e.g. wrong field offset, signed-vs-unsigned mistake). The relay then dispatches a destination-chain action with the wrong amount / recipient / chain. |
| **C3** | **Unauthorized Unlocking** | The destination-chain replica/handler accepts an unlock or mint message that has no matching source-chain lock event. Either the relayer is bypassed entirely or the authentication check (Merkle root, multisig threshold, MPC) is broken. |

The paper's eval-set findings ([results repo](https://github.com/xscope-tool/results)):

| Bridge | Class triggered | # txs flagged |
|---|---|---|
| THORChain (3 incidents) | C2 — Inconsistent Event Parsing | 9 + 41 + 6 = 56 |
| pNetwork | C2 | 3 |
| Anyswap | C3 — Unauthorized Unlocking | 4 |
| **Qubit** | **C1 — Unrestricted Deposit Emitting** (sub-case: transfer to `0x0` silently succeeds) | **20** (incl. 1 tx 43 days pre-attack) |

We unfold these three classes into **6 concrete invariant predicates**
(I-1 … I-6) so that each predicate is independently testable on a
single fuzzer iteration. Two predicates per class.

---

## 2. The 6 invariant predicates (pseudocode)

All predicates run on a per-iteration view of state, where:

- `lock_events[]` — `LogEntry`s emitted on the **source** fork during
  the iteration whose `topic[0]` matches a known bridge `Lock` /
  `Deposit` / `MessageDispatched` signature.
- `unlock_events[]` — `LogEntry`s on the **destination** fork whose
  `topic[0]` matches a known `Unlock` / `Mint` / `Process` signature.
- `relay_state` — `RelaySnapshot` from the existing `MockRelay`
  (`pending_messages`, `processed_set`).
- `state_diff` — pre/post `(addr, slot, value)` triples from the
  inspector hook (we already record balance deltas on tracked
  addresses; storage deltas land via the existing
  `CoverageTracker` + a thin storage-write inspector).
- `caller`, `target` — addresses involved in the calldata.

A predicate evaluates to **`Violated { trigger, evidence }`** or
**`Hold`**. The XScope mode of the fuzzer collects all violations
across iterations and reports the per-rule per-bridge counts.

### Class C1 — Inconsistency of Deposits

```text
# I-1: Lock event must be backed by a real balance delta
predicate lock_event_matches_balance(lock_evt, state_diff) -> Violation:
    addr      = lock_evt.address                  # the router
    amount    = decode_uint(lock_evt.data, "amount")
    delta     = state_diff.balance_delta(addr)    # post - pre, on tokens.balanceOf(router)
    if delta < amount - fee_tolerance(amount):
        return Violated {
            class:  "C1.deposit_event_no_balance_change",
            evidence: { addr, declared_amount: amount, real_delta: delta }
        }
    return Hold
```

```text
# I-2: Lock event recipient field must not be 0x0 (XScope's Qubit finding)
predicate lock_event_recipient_nonzero(lock_evt) -> Violation:
    recipient = decode_address(lock_evt.data, "recipient")
    if recipient == ZERO_ADDRESS:
        return Violated {
            class:  "C1.unrestricted_deposit_emitting",
            evidence: { lock_event_topics: lock_evt.topics, recipient: ZERO_ADDRESS }
        }
    return Hold
```

### Class C2 — Inconsistent Event Parsing

```text
# I-3: Relayer-parsed amount must equal source-chain event amount
predicate relay_amount_roundtrips(lock_evt, relay_msg) -> Violation:
    src_amount = decode_uint(lock_evt.data, "amount")
    parsed     = relay_msg.parsed_amount          # MockRelay logs how it parsed each msg
    if parsed != src_amount:
        return Violated {
            class:  "C2.amount_parse_mismatch",
            evidence: { src_amount, parsed_amount: parsed, msg_id: relay_msg.id }
        }
    return Hold
```

```text
# I-4: Relayer-parsed recipient must equal source-chain event recipient
predicate relay_recipient_roundtrips(lock_evt, relay_msg) -> Violation:
    src_recipient    = decode_address(lock_evt.data, "recipient")
    parsed_recipient = relay_msg.parsed_recipient
    if parsed_recipient != src_recipient:
        return Violated {
            class:  "C2.recipient_parse_mismatch",
            evidence: { src_recipient, parsed_recipient, msg_id: relay_msg.id }
        }
    return Hold
```

### Class C3 — Unauthorized Unlocking

```text
# I-5: Every unlock/mint event must trace back to a lock event with
#      the same message hash. If no source-side ancestor exists, the
#      relayer was bypassed (root forgery, MPC compromise, multisig
#      threshold broken, etc.).
predicate unlock_has_source_ancestor(unlock_evt, lock_events) -> Violation:
    msg_hash = decode_bytes32(unlock_evt.data, "messageHash")
    if not any(lock.topics[1] == msg_hash for lock in lock_events):
        return Violated {
            class:  "C3.unauthorized_unlocking",
            evidence: { unlock_msg_hash: msg_hash, witnessed_lock_hashes: lock.topics[1] for lock in lock_events }
        }
    return Hold
```

```text
# I-6: Authorization check witness must be present
#      For every unlock, verify either:
#        (a) replica.acceptableRoot(root) == true AND root != 0x0, or
#        (b) the multisig signers set covers >= K signatures on the
#            committed message, or
#        (c) the MPC public key of the message matches the canonical key.
#      If none of (a)/(b)/(c) can be reconstructed from the trace,
#      treat as unauthorised.
predicate unlock_carries_valid_authorization(unlock_evt, state_diff, relay_state) -> Violation:
    auth = reconstruct_auth_witness(unlock_evt, state_diff, relay_state)
    if auth.kind == NONE:
        return Violated {
            class:  "C3.no_authorization_witness",
            evidence: { unlock_msg_hash: ..., reason: "no acceptableRoot / multisig / MPC trace" }
        }
    if auth.kind == ZERO_ROOT:
        return Violated {
            class:  "C3.zero_root_accepted",       # Nomad-style
            evidence: { auth, root: ZERO_BYTES32 }
        }
    if auth.kind == MULTISIG and auth.signatures < auth.threshold:
        return Violated {
            class:  "C3.multisig_under_threshold", # Ronin-style
            evidence: auth
        }
    return Hold
```

---

## 3. Mapping to BridgeSentry's data model

XScope's invariants run over *(events, state diff, relay messages)*.
BridgeSentry already produces every input we need; the spec just names
the wires.

| XScope abstraction | BridgeSentry source | Notes |
|---|---|---|
| `lock_events[]` | `TransactionResult.logs` after `DualEvm::execute_on_source_with_inspector` | Filter by `topic[0]` against a per-bridge "lock signature" table loaded from `benchmarks/<bridge>/metadata.json::contracts.<key>.lock_event_topic` (we'll add this field; see §6). Falls back to `keccak256("Dispatch(...)")` etc. for known signatures. |
| `unlock_events[]` | `TransactionResult.logs` after `execute_on_dest_with_inspector` | Same logic, for `Mint` / `Process` / `Release` / `Unlock`. |
| `state_diff.balance_delta` | `DualEvm::collect_global_state` already snapshots tracked balances pre/post — we expose a `balance_delta(addr)` helper. | Tracked addresses come from the contract registry built in Phase A2. |
| `relay_msg.parsed_amount` etc. | New: `MockRelay::parsed_message_log` — extend `MockRelay::relay_message` to record `(raw_payload, parsed_amount, parsed_recipient, parse_mode)` per call. | Required for I-3 / I-4. Tampered/Replayed/Faithful modes already exist; we just record what each mode parsed. |
| `state_diff.storage_delta` | New: a thin `StorageWriteTracker` Inspector (impl `Inspector::log` + sstore step hook) merged into the existing `CoverageTracker` rebuild. | Required for I-6 (`acceptableRoot[root] == true` trace, multisig threshold reconstruction). |
| `caller`, `target` | Already in `parse_execute_payload` (`caller (20) || to (20) || calldata`). | No change. |

The per-bridge "known event topic" table we need to populate once for
each of the 12 benchmarks. Each `metadata.json` already has
`contracts.<key>.role` text describing the contract; we append a small
`events` block (see §6) with `lock_topic` and `unlock_topic`. Where we
do not have an obvious topic (mock/synthetic contracts), we fall back
to the function-signature → keccak hash already used by
`contract_loader::function_selector`.

---

## 4. Per-bridge expected detection map

Honest mapping of which predicate **should** fire on each of our 12
benchmarks given the documented incident root cause. Acts as the
acceptance set for X4 validation: if the re-impl runs the benchmark
and the predicted predicate **does not** fire, the implementation
is wrong.

| Bridge | Documented root cause (`metadata.json`) | Predicted firing predicate(s) |
|---|---|---|
| **nomad**       | `acceptableRoot[0]=true`, processed messages with `root=0x0` | **I-6 (zero-root-accepted)** |
| **qubit**       | Native deposit path bypassed (transfer to `0x0` silently succeeds, mint event fires) | **I-2 (recipient_nonzero)** + I-1 (no balance delta) |
| **multichain**  | MPC private-key compromise — unlock messages signed by attacker, no lock | **I-5 (no source ancestor)** |
| **ronin**       | 5-of-9 multisig forged with stolen keys → invalid threshold | **I-6 (multisig_under_threshold)** |
| **harmony**     | 2-of-5 multisig private keys leaked → forged unlock | I-6 (multisig_under_threshold) + I-5 |
| **wormhole**    | Signature verification bypass: replay old guardian signatures on a forged VAA | I-5 (no source ancestor) + I-6 |
| **polynetwork** | `_executeCrossChainTx` calls arbitrary function via 4-byte selector smuggle → keeper rotation → unlock | I-5 + **I-6 (no_authorization_witness)** |
| **pgala**       | Validator re-registration before re-deploy → forged sign | I-6 (multisig_under_threshold-ish) |
| **socket**      | `performAction` allowed unauthorised `transferFrom` of approved tokens (V5) | I-1 (deposit_event_no_balance_change) + I-5 |
| **orbit**       | 7-of-10 MPC threshold broken → forged unlock | I-6 (multisig_under_threshold-style) |
| **fegtoken**    | Migrator function abused to mint without lock (V2/V4 chain) | I-1 + I-5 |
| **gempad**      | `transferLockOwnership` lets attacker drain unlocked locks (V1) | I-5 |

**Acceptance**: ≥ 11/12 bridges have **at least one** predicted
predicate firing on **at least one** scenario when the XScope mode is
run for 60 s with seed `42`. The one allowed miss is left as
methodology limitation. Beyond detection, we also expect
**zero crashes** (re-impl quality bar).

---

## 5. Out-of-scope (what we explicitly do not port)

To keep effort within the 2-week budget, we deliberately drop:

- **Off-chain relayer crawler**. XScope ingests live transaction
  streams from Etherscan/BSC scanners; we ingest scenarios + revm
  forks instead. The detection algorithm is the same; only the
  ingestion changes.
- **Web UI dashboard, alerting hooks, manual review queue**. We emit
  only the JSON-per-run schema (`baselines/_cited_results/xscope.json`).
- **Auto-discovery of bridge contracts**. We trust the registry built
  by `ContractRegistry::from_atg` + `metadata.json` overrides. XScope
  paper crawls many bridges; we only test our 12.
- **Invariant learning (§4 of paper)**. The original tool can derive
  new invariants from labelled examples; we hard-code the 6 predicates
  above. Methodology note will record this.

---

## 6. Schema additions required

Two minimal additions to make I-3/I-4 and I-6 implementable:

### 6.1 `metadata.json`: per-contract event topics (optional)

```jsonc
"contracts": {
  "replica_ethereum": {
    "address": "0xB923336759618F55bd0F8313bd843604592E27bd8",
    "role": "...",
    "events": {           // NEW (optional)
      "lock_topic":   "0xabcd...",   // keccak256("Dispatch(uint32,bytes32,uint256,bytes)")
      "unlock_topic": "0xefab..."    // keccak256("Process(bytes32)")
    }
  }
}
```

If absent, XScope mode falls back to:
- `lock_topic` = `keccak256(function_signature)` for any edge whose label
  contains `lock` / `dispatch` / `deposit` (we already build this set in
  `ContractRegistry::selectors_of_node`).
- `unlock_topic` = same logic for `unlock` / `mint` / `process` /
  `handle` / `release`.

This keeps the per-bridge metadata edits small (~12 contracts × 2
topics ≈ 24 hex strings — under 1h to fill from Etherscan).

### 6.2 `MockRelay::parsed_message_log`

```rust
// New struct exposed by mock_relay.rs
pub struct ParsedRelayMessage {
    pub raw_payload:      Vec<u8>,
    pub parsed_amount:    U256,
    pub parsed_recipient: Address,
    pub parse_mode:       RelayMode,   // Faithful / Tampered / Replayed / Delayed
    pub source_msg_hash:  Option<B256>,
}

impl MockRelay {
    pub fn parsed_log(&self) -> &[ParsedRelayMessage] { ... }
}
```

`relay_message(payload)` becomes `relay_message_with_decode(payload, decoder)`,
where `decoder: fn(&[u8]) -> ParsedRelayMessage` is per-bridge (default:
ABI uint256 + address layout). Tampered mode mutates the parsed fields
deterministically so I-3/I-4 actually have something to flag.

---

## 7. Acceptance commands (rerun on lab after X4)

```bash
# Build + smoke
cd src/module3_fuzzing && cargo build --release --bin bridgesentry-fuzzer
cargo test --release xscope          # unit tests for predicates I-1..I-6

# Per-bridge acceptance (60 s smoke)
BUDGET=60 RUNS=1 BASELINE=xscope OUTDIR=/tmp/xscope_smoke \
    bash scripts/run_baseline_sweep_real.sh

# Verify ≥ 11/12 bridges have at least one violation in the predicted class
python3 scripts/verify_xscope_acceptance.py /tmp/xscope_smoke/
```

Expected verifier output:
```
nomad        I-6  ✓ (1 violation)
qubit        I-2  ✓ (3 violations)
multichain   I-5  ✓ (2 violations)
...
gempad       I-5  ✓ (1 violation)

11/12 bridges hit the predicted predicate. PASS.
```

---

## 8. Tracking in the bigger plan

This file fulfils sub-task **X1** of
[docs/PLAN_REIMPL_BASELINES.md §2.1](PLAN_REIMPL_BASELINES.md). Updates
the tracking matrix:

| Sub-task | Status |
|---|---|
| X1 spec | ✅ this file |
| X2 Rust module + 6 predicates | ⏳ next |
| X3 wiring + CLI | ⏳ |
| X4 validation against per-bridge map (§4) | ⏳ |
| X5 lab sweep (12 × 20) | ⏳ |
| X6 update cited JSON → self-run | ⏳ |
