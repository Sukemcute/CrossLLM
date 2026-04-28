# Spec — SmartAxe re-implementation for BridgeSentry (SA1)

> **Source paper**: Liao, Nan, Liang, Hao, Zhai, Wu, Zheng — *"SmartAxe:
> Detecting Cross-Chain Vulnerabilities in Bridge Smart Contracts via
> Fine-Grained Static Analysis"*, FSE 2024.
> [arXiv 2406.15999](https://arxiv.org/abs/2406.15999) ·
> [DOI 10.1145/3643738](https://doi.org/10.1145/3643738) ·
> Artifact: figshare 24218808 (HTTP 403, no public access).
>
> **Owner**: Member A (Python). **Effort budget per
> [docs/PLAN_REIMPL_BASELINES.md §2.2](PLAN_REIMPL_BASELINES.md)**:
> SA1 = 2 days for this spec; SA2-SA8 follow.
>
> **Goal**: re-implement the **core static-analysis pipeline** (xCFG,
> xDFG, security-check model, probabilistic pattern inference) as a
> Python project at `tools/smartaxe_reimpl/`. Inputs: Solidity sources
> at `benchmarks/<bridge>/contracts/*.sol`. Output: JSON conforming to
> `baselines/_cited_results/smartaxe.json` schema.

---

## 1. Algorithm overview (paper §3-5)

SmartAxe is a four-stage static analyzer:

```
┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐    ┌────────────────────┐
│ 1. Single-chain    │───▶│ 2. xCFG: cross-    │───▶│ 3. xDFG: cross-    │───▶│ 4. Security-check  │
│    CFG/DFG (per    │    │    chain CFG with  │    │    chain DFG with  │    │    omission / path │
│    contract)       │    │    Ee + Ei edges   │    │    propagation     │    │    inconsistency   │
└────────────────────┘    │    (paper §4.3)    │    │    (paper §4.3)    │    │    (paper §4.4-5)  │
                          └────────────────────┘    └────────────────────┘    └────────────────────┘
                                                                                       │
                                                                              ┌────────▼────────┐
                                                                              │ 5. Probabilistic│
                                                                              │    pattern      │
                                                                              │    inference    │
                                                                              │    (Table 2)    │
                                                                              └─────────────────┘
```

The paper reports **84.95% precision / 89.77% recall** on a manually
curated set of 16 bridges with 88 cross-chain vulnerabilities (CCVs),
against ~3200 LOC Python 3.8.10 implementation that builds on
**SmartDagger** (cross-function CFG recovery) and **SmartState**
(taint analysis). Neither dependency is public; we substitute
**Slither** for both, which is the standard accessible Solidity AST
analyzer — methodology note will record this.

---

## 2. The four key data structures

### 2.1 Single-chain CFG (paper §4.3 input)

Standard per-contract control-flow graph. Slither already produces
these via `slither.core.cfg.node.Node`. Each node owns:

```python
@dataclass
class CfgNode:
    contract:    str              # contract name
    function:    str              # function selector (canonical sig)
    statement:   str              # the Solidity statement at this node
    successors:  list["CfgNode"]
    reads:       set[Resource]    # state vars / params read
    writes:      set[Resource]    # state vars written
    emits:       list[EventEmit]  # `emit Foo(...)` statements at this node
    requires:    list[Check]      # `require(...) / if (...) revert` predicates
```

### 2.2 xCFG — cross-chain control-flow graph (paper Eq. for Gc)

```python
@dataclass
class XCfg:
    """G_c = (N_c, E_c) where N_c = N_b ∪ N_r ∪ N_l."""
    basic_blocks: list[CfgNode]   # N_b — per-contract per-function CFG nodes
    relayer:      RelayerNode     # N_r — single sink/source per bridge
    client:       ClientNode      # N_l — abstract end-user
    edges_ef:     list[Edge]      # control-flow edges (intra-chain)
    edges_ee:     list[Edge]      # emitting edges: emit-statement → relayer/client
    edges_ei:     list[Edge]      # informing edges: relayer → authorization stmt on dst
```

**Edge construction rules** (paper §4.3 — Algorithm 1 sketch in the
spec is implicit; we give a concrete one below):

```text
build_xcfg(src_cfgs: list[CfgNode], dst_cfgs: list[CfgNode]) -> XCfg:
    Gc = empty XCfg
    Gc.relayer = RelayerNode("relay")
    Gc.client  = ClientNode("user")

    # 1. Pull all per-contract CFG nodes into the basic-block set.
    for node in src_cfgs + dst_cfgs:
        Gc.basic_blocks.add(node)
        for succ in node.successors:
            Gc.edges_ef.add(Edge(node, succ, "ef"))

    # 2. Emitting edges (Ee): every node that emits a cross-chain event
    #    becomes a source. Targets: relayer (if event is consumed by
    #    relayer pattern) or client (if consumed by user query).
    for node in src_cfgs:
        for emit in node.emits:
            if is_cross_chain_event(emit.signature):    # canonical list §6
                Gc.edges_ee.add(Edge(node, Gc.relayer, "ee"))

    # 3. Informing edges (Ei): the relayer informs destination-chain
    #    authorization sites.
    for node in dst_cfgs:
        for chk in node.requires:
            if chk.is_cross_chain_authorization():     # see §3 Resource Table
                Gc.edges_ei.add(Edge(Gc.relayer, node, "ei"))
    return Gc
```

`is_cross_chain_event(sig)` consults a per-bridge event-signature table
populated from `benchmarks/<bridge>/metadata.json::contracts.<key>.events`
(spec to land in §6, same schema as we already proposed for XScope's
X1 spec).

### 2.3 xDFG — cross-chain data-flow graph (paper Eq. for Gd)

```python
@dataclass
class XDfg:
    nodes: list[Resource]         # N_d — variables / arguments tracked
    edges: list[DataEdge]         # E_d
```

**Propagation rules** (paper §4.3 — explicit):

```text
build_xdfg(Gc: XCfg) -> XDfg:
    Gd = empty XDfg
    # Standard intra-chain data flow on Ef edges.
    for edge in Gc.edges_ef:
        for v in edge.src.writes ∩ edge.dst.reads:
            Gd.edges.add(DataEdge(edge.src, edge.dst, v, "ef"))

    # Cross-chain rule 1 (paper §4.3): "only the arguments of the
    # event can propagate through the emitting edges forward".
    for edge in Gc.edges_ee:
        emit = edge.src.emit_at(edge)
        for arg in emit.arguments:
            Gd.edges.add(DataEdge(edge.src, edge.dst, arg, "ee"))

    # Cross-chain rule 2: "only the arguments invoked by the
    # authorization method can propagate through the informing edge
    # forward".
    for edge in Gc.edges_ei:
        auth = edge.dst.first_auth_call()
        for arg in auth.arguments:
            Gd.edges.add(DataEdge(edge.src, edge.dst, arg, "ei"))
    return Gd
```

### 2.4 Security check model (paper Table 1)

Hardcoded; we transcribe Table 1 verbatim into `security_checks.py`:

| ID | Category | Required check | Predicates we look for |
|---|---|---|---|
| **SC1** | C1 deposit | Success check for the deposit | `require(token.transferFrom(...) returns true)` / non-zero balance delta |
| **SC2** | C1 deposit | Validation check for user arguments | `require(amount > 0)`, `require(token != 0x0)`, `require(recipient != 0x0)` |
| **SC3** | C2 router | Correctness check for cross-chain router | `require(msg.sender == bridge)` / `require(_executeCrossChainTx ok)` |
| **SC4** | C3 withdraw | Validation check for verification (sig / root / timeout) | `require(signers >= threshold)` / `require(acceptableRoot(root))` / `require(block.timestamp <= deadline)` |
| **SC5** | C3 withdraw | Repetitive withdrawal prevention | `require(!processed[hash]); processed[hash] = true` |
| **SC6** | C3 withdraw | Correctness of releasing | `require(recipient == decoded.recipient)` |

**Protected resources** (paper §4.4):

| ID | Resource type | Notation | Slither symbol |
|---|---|---|---|
| **R1** | FieldAccess (state-var read/write) | `f` | `StateVariableRead/Written` |
| **R2** | Internal method call | `m` | `InternalCall` |
| **R3** | ABI / external call | `a` | `HighLevelCall` / `LowLevelCall` |
| **R4** | Event emission | `e` | `EmitEvent` |

### 2.5 Probabilistic pattern inference (paper Table 2)

Five **predefined** patterns relating a security check `c` to a
protected resource `r`. **No training set required** — confidence
scores are hardcoded from Table 2.

| Pattern | Description (paper) | Confidence |
|---|---|---|
| **P1** | Direct control-flow dependency: `c` directly dominates `r` on Gc | **0.95** |
| **P2** | Indirect control-flow / resource membership: `c` dominates `r` transitively, or `c` and `r` are both members of the same struct/mapping | **0.60** |
| **P3** | Same basic-block proximity: `c` and `r` share a basic block | **0.60** |
| **P4** | Semantic correlation: `c` and `r` share an identifier / type relationship (e.g. `require(amount > 0)` near `transfer(amount)`) | **0.70** |
| **P5** | Data-flow dependency: `r` depends on a value flowing from `c` via Gd | **0.80** |

For each `(c, r)` pair the score is the **max** across the five
patterns that match (not sum, not product — this matches the paper's
"prior probability" wording).

```text
score(c, r) = max(P_i.confidence for P_i in P1..P5 if P_i.matches(c, r))
            = 0     if no pattern matches
```

### 2.6 Vulnerability detection

A **CCV** (cross-chain vulnerability) is reported when at least one
of two conditions fires (paper §4.5):

```text
def detect_ccv(xcfg, xdfg):
    violations = []

    # 1. Access-control omission: a resource of type R3 (ABI external
    #    call to bridge state mutators) or R4 (event emit) reachable
    #    on a path that lacks any required SC1..SC6 with score > 0.5.
    for r in resources_of_kinds(R3, R4):
        guarding_checks = checks_with_pattern_match(r, xcfg, xdfg)
        if max((score(c, r) for c in guarding_checks), default=0) < 0.5:
            violations.append(("omission", r.location, r))

    # 2. Path inconsistency: among multiple paths reaching the same r,
    #    if the set of guarding checks differs.
    for r in resources_of_kinds(R3, R4):
        paths = enumerate_paths_to(r, xcfg)
        check_sets = [frozenset(c for c in p.guarding_checks) for p in paths]
        if len(set(check_sets)) > 1:
            violations.append(("path_inconsistency", r.location, r))

    return violations
```

Threshold `0.5` is **our pick** — paper says "all associations above 0
confidence contribute" but does not commit to a numeric cutoff. We
calibrate this in SA6 validation against the PolyNetwork example.

---

## 3. Mapping to BridgeSentry inputs

| SmartAxe abstraction | BridgeSentry source | Notes |
|---|---|---|
| `src_cfgs` / `dst_cfgs` | `benchmarks/<bridge>/contracts/*.sol` parsed by Slither | Per-bridge `metadata.json::contracts.<key>.role` text labels which contract is source vs destination side. |
| Cross-chain event signature table | `metadata.json::contracts.<key>.events.lock_topic` / `unlock_topic` | Same schema we agreed in `REIMPL_XSCOPE_SPEC.md §6.1` — populate once for both tools to share. |
| Authorization-method whitelist | Per-bridge map: `acceptableRoot`, `process`, `confirmAt`, `submitMessage`, `verifySignatures`, `validateMpcSignature`, … | We hand-populate from the bridge's solidity. |
| Output schema | `baselines/_cited_results/smartaxe.json` (already exists) | Replace `agg`/`null` cells with per-bridge `detected: bool` + `tte_seconds: <static-analysis wall-clock>` + `note: <CCV class fired>`. |

---

## 4. Per-bridge expected detection (acceptance set for SA6)

For each of our 12 benchmarks the **dominant SmartAxe finding** we
expect, derived from `metadata.json::root_cause_summary` and mapped
into Table 1 / Table 2:

| Bridge | Documented root cause | Predicted SmartAxe verdict |
|---|---|---|
| **nomad**       | `acceptableRoot[0]=true` (initialize bug) → root validation broken | **omission of SC4** (verification check) on `process()` |
| **qubit**       | Native-deposit `transfer(0x0)` succeeds silently, `Deposit` event still fires | **omission of SC1+SC2** (deposit success / arg validation) on `deposit()` |
| **multichain**  | MPC private-key compromise → unlock signed by attacker | **omission of SC4** (signature validity) on `redeem()` |
| **ronin**       | 5-of-9 multisig forged with stolen keys → invalid threshold | **omission of SC4** (signers ≥ threshold) on `withdrawal()` |
| **harmony**     | 2-of-5 multisig private keys leaked → forged unlock | **omission of SC4** + **path inconsistency** between admin / public unlock paths |
| **wormhole**    | Old guardian-signature replay on a forged VAA | **omission of SC4** (sig validity) on `verifyVAA` |
| **polynetwork** | `_executeCrossChainTx` smuggles arbitrary 4-byte selector → keeper rotation | **omission of SC3** (cross-chain router correctness) |
| **pgala**       | Validator re-registration before re-deploy → forged sign | omission of SC4 + SC5 |
| **socket**      | `performAction` allowed unauth `transferFrom` of approved tokens | **omission of SC2** (arg validation) + **path inconsistency** |
| **orbit**       | 7-of-10 MPC threshold broken → forged unlock | omission of SC4 |
| **fegtoken**    | Migrator function abused to mint without lock | **omission of SC5** (repetitive withdrawal prevention) |
| **gempad**      | `transferLockOwnership` lets attacker drain unlocked locks | **omission of SC6** (correctness of releasing) |

**Acceptance**: ≥ 11/12 bridges hit the predicted SC violation when
SmartAxe re-impl is run on the bridge's `contracts/`. The one allowed
miss is documented as methodology limitation.

---

## 5. Out-of-scope (deliberately not ported)

- **SmartDagger** cross-function CFG enrichment. We rely on Slither's
  built-in inter-procedural analysis. Methodology note: "we did not
  port SmartDagger; cross-function recovery uses Slither's standard
  call-graph analysis. This may understate recall on contracts with
  complex inheritance / dynamic dispatch."
- **SmartState** taint analysis. Same substitution: Slither's
  `data_dependency` module covers the cases we need (forward
  data flow on event arguments and authorization arguments).
- **Wild scan** of 1,703 contracts from 129 bridge applications. We
  only run on our 12 benchmarks.
- **Manual labeling UI** for the 88-CCV ground-truth set. We use
  `metadata.json::root_cause_summary` directly as ground truth (which
  we authored) and report against it.
- **PDF / web bug report generation**. JSON output only.
- **10-minute timeout per contract** — we use 60 s per contract since
  our contracts are smaller than the wild-scan corpus.

---

## 6. Project layout

```
tools/smartaxe_reimpl/
├── pyproject.toml
├── README.md
├── smartaxe_reimpl/
│   ├── __init__.py
│   ├── __main__.py              # CLI: smartaxe-reimpl run --benchmark nomad --output ...
│   ├── cfg_builder.py           # Slither → CfgNode (SA3)
│   ├── xcfg_builder.py          # SA4 — emitting + informing edges
│   ├── xdfg_builder.py          # SA4 — propagation rules
│   ├── security_checks.py       # SA5 — Table 1 SC1..SC6 + R1..R4
│   ├── pattern_inference.py     # SA5 — Table 2 P1..P5 + score()
│   ├── detector.py              # detect_ccv() — pulls everything together
│   └── output.py                # JSON writer matching baselines/_cited_results/smartaxe.json schema
├── data/
│   └── event_signatures.json    # canonical lock/unlock topics per bridge
└── tests/
    ├── test_cfg_builder.py      # SA3 acceptance
    ├── test_xcfg_construction.py # SA4 acceptance (Nomad fixture)
    ├── test_pattern_match.py    # SA5 unit (each P1..P5 fires on a synthetic CFG)
    └── test_detector_polynet.py # SA6 reproduction — PolyNetwork bug fires SC3 omission
```

---

## 7. Acceptance commands (for SA8)

```bash
# Build venv + install Slither
cd tools/smartaxe_reimpl
python3 -m venv .venv && . .venv/bin/activate
pip install slither-analyzer networkx pydantic
pip install -e .

# Unit + reproduction tests
pytest -v tests/

# Run on all 12 benchmarks
for b in nomad qubit pgala polynetwork wormhole socket ronin harmony multichain orbit fegtoken gempad; do
  smartaxe-reimpl run \
      --contracts ../../benchmarks/$b/contracts/ \
      --metadata ../../benchmarks/$b/metadata.json \
      --output ../../results/baselines/smartaxe/$b/run_001.json
done

# Acceptance verifier (compares per-bridge findings vs §4 expected map)
python3 ../../scripts/verify_smartaxe_acceptance.py ../../results/baselines/smartaxe/
```

Expected verifier output:
```
nomad        SC4 omission           ✓ predicted, ✓ found
qubit        SC1+SC2 omission       ✓ predicted, ✓ found
multichain   SC4 omission           ✓ predicted, ✓ found
...
gempad       SC6 omission           ✓ predicted, ✓ found

11/12 bridges hit predicted CCV class. PASS.
```

---

## 8. Validation plan (SA6 detail)

Per the parent plan, SA6 = "reproduce paper's aggregate P=84.95% /
R=89.77% on a published example". Concrete plan:

1. Fetch PolyNetwork's vulnerable contract source from
   [`polynetwork/eth-contracts`](https://github.com/polynetwork/eth-contracts)
   at commit `d16252b2` (pre-fix).
2. Manually annotate ground truth: the `_executeCrossChainTx` function
   is the SC3 omission point.
3. Run our SA-impl: assert `detect_ccv()` flags `_executeCrossChainTx`
   with classification `omission_of_SC3`.
4. If our detector also flags ≤ 2 false positives elsewhere in the
   same contract, our precision on this single example is ≥ 33%
   (1 TP / max 3 reports) — well below paper's 84.95% but acceptable
   as a smoke validation. Tighter precision is measured against the
   12-bridge set in SA7.

If SA6 fails (e.g. the PolyNetwork bug isn't caught), the bug is
**either** in cfg_builder (SA3, missing some statement) **or** in
pattern_inference (SA5, the threshold of 0.5 is wrong). The fix loop:
print the score table for `(SC3, _executeCrossChainTx)` and either
adjust the threshold or fix the pattern detector.

---

## 9. Tracking

| Sub-task | Status |
|---|---|
| **SA1** Spec | ✅ this file |
| **SA2** Python project skeleton + Slither dep | ⏳ next |
| **SA3** Single-chain CFG via Slither | ⏳ |
| **SA4** xCFG / xDFG construction | ⏳ |
| **SA5** Security checks + pattern inference | ⏳ |
| **SA6** Validate on PolyNetwork | ⏳ |
| **SA7** Run 12-benchmark sweep | ⏳ |
| **SA8** Update cited JSON → self-run | ⏳ |
