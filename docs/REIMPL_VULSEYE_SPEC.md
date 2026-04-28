# Spec — VulSEye re-implementation for BridgeSentry (VS1)

> **Source paper**: Liang, Chen, Wu, He, Wu, Cao, Du, Zhao, Liu —
> *"Vulseye: Detect Smart Contract Vulnerabilities via Stateful Directed
> Graybox Fuzzing"*, IEEE TIFS 2025.
> [arXiv 2408.10116](https://arxiv.org/abs/2408.10116) ·
> [IEEE 10869489](https://ieeexplore.ieee.org/document/10869489) ·
> Author copy: [wu-yueming.github.io PDF](https://wu-yueming.github.io/Files/TIFS2025_VULSEYE.pdf) ·
> Source code: **not released as of 2026-04-29 audit**.
>
> **Owner**: Member B (Rust). **Effort budget per
> [docs/PLAN_REIMPL_BASELINES.md §2.3](PLAN_REIMPL_BASELINES.md)**:
> VS1 = 2 days for this spec; VS2-VS7 follow.
>
> **Goal**: re-implement VulSEye's **directed-graybox fitness function +
> code/state targets** as a new fuzz mode in BridgeSentry's existing
> Rust binary (`src/module3_fuzzing/src/baselines/vulseye/`), driven by
> the existing `DualEvm` + revm + scenario corpus. CLI flag
> `--baseline-mode vulseye` opts in.

---

## 1. Algorithm overview (paper §3-4)

VulSEye is a **stateful directed graybox fuzzer**. Key novelty over
ItyFuzz / Smartian: rather than blindly maximising coverage, it
*directs* mutations toward a precomputed set of `(code_target,
state_target)` pairs that the static phase identified as
vulnerability-prone. Three distinct stages:

```
┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│ 1. Code targets      │    │ 2. State targets     │    │ 3. Directed fuzz     │
│   pattern-match CFG  │───▶│   backward analysis  │───▶│   GA-based seed      │
│   IR for hazardous   │    │   from each target   │    │   selection driven   │
│   behaviours         │    │   to extract state   │    │   by Eq. 8 fitness   │
│   (paper §3.2)       │    │   constraints (§3.3) │    │   (paper §3.4-4)     │
└──────────────────────┘    └──────────────────────┘    └──────────────────────┘
```

The paper reports **9.7× speedup vs state-of-the-art** on a corpus of
42,738 contracts and **11 zero-days in top-50 Ethereum DApps**
(~$2.5M USD impact). Its 7 vulnerability patterns are general DeFi
(reentrancy, delegatecall, etc.), not bridge-specific — so for RQ1 we
**substitute a bridge-specific pattern set** drawn from XScope's
invariant model + our `metadata.json::root_cause_summary`. Methodology
note will record this scope adjustment.

---

## 2. The three algorithms

### 2.1 Code-target identification (paper Algorithm 1)

> "for ir in node.irs do offset ← PatternMatching (ir,cfg,res)
>  CodeTargets ← Locating (offset,cfg)"

Pattern-match each contract's CFG IR (per VulSEye, the IR is
SlithIR-like; we use revm's `Bytecode` opcode stream since we already
fuzz at bytecode level).

**Paper's 7 general-DeFi patterns** (we transcribe verbatim, then
**override** with our bridge-specific set in §2.4):

| # | Pattern | Hazardous shape |
|---|---|---|
| GP1 | Lock Ether | Payable function with no fund-sending opcode (`CALL`/`CALLCODE`/`SELFDESTRUCT`) |
| GP2 | Controlled Delegatecall | `DELEGATECALL` whose `address` arg flows from `msg.data` |
| GP3 | Dangerous Delegatecall | `DELEGATECALL` whose argv flows from `msg.data` |
| GP4 | Block Dependency | `BLOCKHASH`/`TIMESTAMP`/`NUMBER` feeding a `JUMPI` before a `CALL` |
| GP5 | Reentrancy | `SLOAD(x)` → `CALL` → `SSTORE(x)` ordering on the same slot |
| GP6 | Arbitrary Send Ether | Unprotected `CALL` with value where receiver flows from `msg.sender`/`msg.data` |
| GP7 | Suicidal | Unprotected `SELFDESTRUCT` |

```text
identify_code_targets(bytecode: &[u8], cfg: &Cfg, patterns: &[Pattern]) -> Vec<CodeTarget>:
    targets = []
    for bb in cfg.basic_blocks:
        for ir in bb.opcodes:
            for p in patterns:
                if p.matches(ir, bb, cfg):
                    targets.push(CodeTarget {
                        pattern_id: p.id,
                        bb_id:      bb.id,
                        pc:         ir.pc,
                        contract:   cfg.contract_addr,
                    })
    return dedup(targets)
```

### 2.2 State-target identification (paper Algorithms 2 + 3)

> "Algorithm 2 takes the contract's CFG and a code target as input,
>  producing state targets as output. The algorithm: identifies all
>  paths leading to the target basic block; extracts branch points
>  (typically JUMPI instructions) on each path; conducts backward
>  analysis at each branch point to gather constraints; intersects
>  constraints per path and unions across paths; employs a constraint
>  solver to resolve symbolic constraints into concrete state
>  requirements."
>
> "Algorithm 3 (Contract Bytecode Backward Analysis) traverses
>  instructions in reverse from a branch point, reconstructing the EVM
>  stack and tracing symbolic variables back to state variables until
>  all traced targets manifest as either state variables or
>  state-independent constants."

**State target** = a tuple `(state_var, value_range)` — concrete
preconditions on contract storage that must hold for execution to
reach the code target.

```text
identify_state_targets(cfg, code_targets) -> Map<CodeTarget, Vec<StateTarget>>:
    out = {}
    for ct in code_targets:
        paths = enumerate_paths_to_bb(cfg, ct.bb_id)
        per_path_constraints = []
        for path in paths:
            branch_points = [n for n in path if n.opcode == JUMPI]
            constraints   = []
            for bp in branch_points:
                expr = backward_analyze(cfg, bp)             # Algorithm 3
                constraints.extend(expr_to_state_constraints(expr))
            per_path_constraints.append(intersect(constraints))
        merged = union(per_path_constraints)
        ranges = solve_with_z3(merged)                       # constraint solver
        out[ct] = ranges
    return out
```

**Cut-loss for VS3** (per parent plan §2.3): if Z3-based backward
analysis blows the 1-week budget, fall back to **concrete-trace
approximation**: collect (state_var, observed_value) pairs from
ItyFuzz's runtime traces on each contract; treat "values that
ItyFuzz hit when reaching the code-target BB" as approximate
state targets. Loses precision but compiles and runs. Methodology
note records the substitution.

### 2.3 Directed fitness (paper §3.4 + Eq. 3, 5, 8)

```text
# Eq. 3 — code distance: average shortest-path distance from current
#         seed's executed BBs to the n closest code targets.
CodeDistance(S) = (1/n) * sum(D(BB) for BB in N)
# where N is the set of n basic blocks (with smallest distances) along
# the execution trace of S.

# Eq. 5 — state distance: 0 if any state target reached, else
#         |P| / (Σ_ST 1/d_ST(S))  i.e. harmonic-style aggregation across
#         the |P| state targets.
StateDistance(S) = 0                                 if ∃ST: dST(S) == 0
                 = |P| * (Σ_ST dST(S)^{-1})^{-1}     otherwise

# Eq. 8 — overall fitness, γ ∈ [0,1] is a tuning constant (paper picks
#         a value implicitly, we calibrate in VS5).
Fitness(S) = γ * SC_bug(S) + (1-γ) * (SC_branch(S) + SC_dep(S))

# where:
#   SC_bug    = a/CodeDistance + b/StateDistance      (lower distance -> higher score)
#   SC_branch = number of *newly* covered branch edges this iteration
#   SC_dep    = frequency of state-variable writes in the iteration
```

**Seed-selection genetic-algorithm step** (paper §4):

```text
# Probability of picking seed S in generation G
P(S) = Fitness(S) / Σ_{T ∈ corpus} Fitness(T)
```

Crossover uses **read-after-write** dependency on storage variables;
mutation uses **pool-based mutation** seeded from the values found in
state targets (e.g. if the state target says
`acceptableRoot[0] == true`, we add `bytes32(0)` and `1` to the input
pool).

### 2.4 Bridge-specific pattern overlay (our adjustment)

Paper's 7 patterns (GP1-7) are general DeFi. They will **fire 0 times**
on the cross-chain semantic bugs we benchmark (Nomad's zero-root
acceptance is not a reentrancy / delegatecall / suicide bug). To
preserve the paper's algorithm while making it relevant to RQ1, we
**add 6 bridge-specific patterns** drawn from XScope's invariant
classes (already documented in
[`docs/REIMPL_XSCOPE_SPEC.md §2`](REIMPL_XSCOPE_SPEC.md) — same source
abstractions).

| # | Pattern | Hazardous shape (opcode-level) |
|---|---|---|
| **BP1** | Mint without lock | `LOG3` of a mint topic on dst, with no preceding `LOG3` of a lock topic on src in the same iteration |
| **BP2** | Zero-root acceptance | `SSTORE` to `acceptableRoot[0]` slot followed by a `SLOAD`+JUMPI pair where the loaded slot equals 0 yet branch goes to "ok" path |
| **BP3** | Multisig under threshold | `JUMPI` whose backward-analyzed constraint on `signers_count` resolves to `< threshold` from metadata |
| **BP4** | Replay accepted | `SSTORE` to `processed[hash]` not preceding the unlock CALL — i.e. unlock fires first, then mark-processed (or never) |
| **BP5** | Authorization bypass | `CALL` to a token transfer whose preceding JUMPI does not check `msg.sender` against an admin / `signed_by(msg)` whitelist |
| **BP6** | Recipient zero | Outbound `LOG3`/`CALL` whose `recipient` arg is `0x0` (Qubit pattern) |

**Code targets** = union of GP1-7 ∪ BP1-6, but in §4 evaluation we
will report BP detections separately so the "domain-mismatch" risk is
visible in the methodology note.

---

## 3. Mapping to BridgeSentry inputs

| VulSEye abstraction | BridgeSentry source | Notes |
|---|---|---|
| Per-contract `Cfg` | New: lift from revm `Bytecode` via the existing `CoverageTracker` (already records (addr, pc) hits) + a one-time CFG construction pass per contract | We already touch every PC during fuzzing; lifting to BBs is `JUMPDEST/JUMPI/JUMP` + fall-through edges. |
| `pattern.matches(ir, bb, cfg)` | New: Rust functions in `src/module3_fuzzing/src/baselines/vulseye/patterns.rs` for each GP*/BP* | Each pattern is an opcode-sequence matcher; ~30-80 LOC each. |
| `enumerate_paths_to_bb` | Standard DFS on the CFG | Bound depth at 32 to avoid path explosion. |
| `backward_analyze` (Algorithm 3) | New: Rust port using **`z3` crate** if it builds on Windows, else cut-loss to concrete-trace approximation | Plan §2.3 cut-loss already documented. |
| `Fitness(S)` | Replace existing `InvariantChecker::reward` body | Same call site in `fuzz_loop.rs`; just dispatch on `--baseline-mode`. |
| `P(S)` GA selection | Already implemented as `pick_corpus_index` in `fuzz_loop.rs` | Just feed the new fitness values in. |
| Crossover (read-after-write) | New: `crossover_raw` in `mutator.rs` — splice two seeds at a `CALL`/`SSTORE` boundary | Lightweight; preserves byte-level compatibility with `CalldataMutator`. |
| Pool-based mutation seeded from state targets | New: extend `CalldataMutator::known_selectors` with a `state_target_pool` field of `[u8; 32]` words derived from solved state targets | At fuzz init, populate from §2.2 output. |

---

## 4. Per-bridge expected detection (acceptance set for VS5)

For each of our 12 benchmarks the **dominant VulSEye pattern** we
expect, derived from `metadata.json::root_cause_summary`. Acceptance
gate for VS5: ≥ 11/12 bridges hit the predicted bridge-specific
pattern in a 60-s smoke; the one allowed miss is methodology
limitation.

| Bridge | Documented root cause | Predicted pattern firing |
|---|---|---|
| **nomad**       | `acceptableRoot[0]=true` (initialize) | **BP2 (zero-root acceptance)** |
| **qubit**       | Native deposit transfer to `0x0` | **BP6 (recipient zero)** + BP1 (mint without lock — destination side) |
| **multichain**  | MPC private-key compromise | **BP5 (authorization bypass)** |
| **ronin**       | 5-of-9 multisig forged | **BP3 (multisig under threshold)** |
| **harmony**     | 2-of-5 multisig leaked | BP3 |
| **wormhole**    | Old guardian sig replay on forged VAA | BP4 (replay accepted) + BP5 |
| **polynetwork** | `_executeCrossChainTx` smuggles arbitrary selector → keeper rotation | BP5 (authorization bypass) |
| **pgala**       | Validator re-registration before re-deploy | BP3 + BP5 |
| **socket**      | `performAction` allowed unauth `transferFrom` | BP5 |
| **orbit**       | 7-of-10 MPC threshold broken | BP3 |
| **fegtoken**    | Migrator function used to mint without lock | **BP1 (mint without lock)** |
| **gempad**      | `transferLockOwnership` drains unlocked locks | BP5 |

**Distribution check**: BP1 = 2 bridges, BP2 = 1, BP3 = 4, BP4 = 1,
BP5 = 6, BP6 = 1. Every BP* fires on at least one bridge, so the
6-pattern set is non-redundant.

---

## 5. Out-of-scope (deliberately not ported)

- **42,738-contract wild scan**. We only test our 12 benchmarks.
- **11 zero-day reports + responsible disclosure pipeline**. Out of
  scope; we just emit JSON.
- **SmartDagger/SmartState replacements**. Same Slither substitution
  we made for SmartAxe — methodology note records the shift.
- **VulSEye's exact 9.7× speedup vs ItyFuzz**. We measure speedup
  inside our own ItyFuzz baseline (Phase B3) — paper claim acts as a
  sanity reference, not a target.
- **Original 7 GP* patterns weight calibration**. We ship them at
  equal weight in `Fitness` but de-emphasise them at output time
  because they are not bridge-relevant.

---

## 6. Rust project layout (added inside existing crate)

```
src/module3_fuzzing/src/baselines/
├── mod.rs                       # registers `vulseye` + `xscope` modes
├── xscope.rs                    # X2 (separate spec)
└── vulseye/
    ├── mod.rs                   # public API + CLI dispatch
    ├── patterns.rs              # GP1-7 + BP1-6 matchers (VS2)
    ├── code_targets.rs          # Algorithm 1 (VS2)
    ├── state_targets.rs         # Algorithm 2+3 (VS3) — feature-gated by `cfg(feature = "z3")`
    ├── fitness.rs               # Eq. 3 / 5 / 8 (VS4)
    ├── ga_select.rs             # P(S) sampler + crossover (VS4)
    └── tests/
        ├── pattern_unit.rs      # one synthetic bytecode per pattern
        ├── fitness_distance.rs  # CodeDistance / StateDistance edge cases
        └── nomad_smoke.rs       # VS5 reproduction — BP2 fires on Nomad fork
```

CLI new flag (extends `src/module3_fuzzing/src/config.rs`):

```rust
/// Baseline mode for re-impl tools. Off → run BridgeSentry (default).
#[arg(long, value_name = "TOOL")]
pub baseline_mode: Option<BaselineMode>,

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum BaselineMode { Xscope, Vulseye, Smartshot }
```

Routing in `fuzz_loop::run` dispatches on `ctx.config.baseline_mode`
to either `vulseye::run_directed_fuzz` or the existing default loop.

---

## 7. Acceptance commands (for VS6 sweep + VS7 JSON update)

```bash
# Build
cd src/module3_fuzzing && cargo build --release --bin bridgesentry-fuzzer

# Unit tests
cargo test --release vulseye

# 60-s smoke per bridge with the new mode
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
  ./target/release/bridgesentry-fuzzer \
      --atg ../../benchmarks/$b/llm_outputs/atg.json \
      --scenarios ../../benchmarks/$b/llm_outputs/hypotheses.json \
      --metadata ../../benchmarks/$b/metadata.json \
      --baseline-mode vulseye \
      --output ../../results/baselines/vulseye/$b/run_smoke.json \
      --budget 60 --runs 1 --seed 42 \
      --source-rpc "$ETH_RPC_URL" --dest-rpc "$ETH_RPC_URL" \
      --source-block <fork_block> --dest-block <fork_block>
done

# Acceptance verifier
python3 scripts/verify_vulseye_acceptance.py ../../results/baselines/vulseye/

# Full sweep (VS6, ~40h overnight on lab)
BUDGET=600 RUNS=20 BASELINE=vulseye bash scripts/run_baseline_sweep_real.sh
```

Expected verifier output (acceptance bar 11/12):
```
nomad        BP2  ✓ predicted, ✓ found
qubit        BP6  ✓ predicted, ✓ found  (BP1 also fired)
multichain   BP5  ✓ predicted, ✓ found
ronin        BP3  ✓ predicted, ✓ found
harmony      BP3  ✓ predicted, ✓ found
wormhole     BP4  ✓ predicted, ✓ found  (BP5 also fired)
polynetwork  BP5  ✓ predicted, ✓ found
pgala        BP3  ✓ predicted, ✓ found
socket       BP5  ✓ predicted, ✓ found
orbit        BP3  ✓ predicted, ✓ found
fegtoken     BP1  ✓ predicted, ✓ found
gempad       BP5  ✓ predicted, ✓ found

12/12 bridges hit predicted pattern. PASS.
```

---

## 8. VS3 cut-loss decision tree

If at end of week 8 (mid VS3) Z3 backward analysis is not converging:

```
Week 8 day 5 status:
   ├─ ≥ 1 bridge gives clean state targets ──▶ keep going to end of week 8
   ├─ 0 bridges; symbolic blowup on every JUMPI ──▶ apply cut-loss:
   │    1. Disable `state_targets.rs` (drop StateDistance term in Eq. 8)
   │    2. Replace with concrete-trace approximation:
   │       - For each (bridge, code_target), run BridgeSentry default mode 60s
   │       - Collect (slot, value) pairs observed at the BB containing target
   │       - Treat top-N most frequent pairs as "approximate state targets"
   │    3. Methodology note: "VS3 used concrete-trace state-target
   │       approximation in lieu of paper Algorithm 3 due to
   │       Z3 timeout > 30s/JUMPI on our bytecode set."
```

This keeps VS6 sweep on schedule even if §2.2 implementation slips.

---

## 9. Tracking

| Sub-task | Status |
|---|---|
| **VS1** Spec | ✅ this file |
| **VS2** code-target patterns (GP+BP) | ⏳ next |
| **VS3** state-target backward analysis (with Z3 cut-loss) | ⏳ |
| **VS4** fitness Eq. 3/5/8 + GA select | ⏳ |
| **VS5** validate (per-bridge BP firing 11/12) | ⏳ |
| **VS6** lab sweep 12 × 20 | ⏳ |
| **VS7** update cited JSON → self-run | ⏳ |
