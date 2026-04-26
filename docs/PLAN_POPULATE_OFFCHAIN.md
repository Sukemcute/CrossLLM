# Plan — Populate 5 Off-Chain Benchmarks (Ronin, Harmony, Multichain, Orbit, FEGtoken)

> Tiếp nối `PLAN_POPULATE_BENCHMARKS.md` (Q/P/N/W) và Sprint S (Socket).
> Tham chiếu mẫu chuẩn: `benchmarks/wormhole/` cho cách document
> "simulation gap"; `benchmarks/qubit/` cho cấu trúc 6-file tối thiểu.

## Tổng quan

**Mục tiêu:** Populate 5 benchmark off-chain compromise còn lại để đạt
**12/12 benchmarks**, kèm một mock multi-sig harness chung tránh
re-implement validator/MPC quorum lặp lại trong từng bridge.

| # | Bridge | Loss | Compromise | Vuln class | Off-chain artifact cần mock |
|---|--------|------|------------|-----------|----------------------------|
| 1 | **Ronin** | $624M | 5/9 validator key compromise | V4 | 9-of-9 PoA validator multi-sig |
| 2 | **Harmony Horizon** | $100M | 2/4 multi-sig key compromise | V4 | 4-of-4 (2-of-4 threshold) multi-sig |
| 3 | **Multichain** | $126M | MPC ceremony compromise | V2, V4 | TSS / MPC simplified to 1-of-1 trusted signer |
| 4 | **Orbit Bridge** | $82M | 7/10 validator key compromise | V4 | 10-of-10 (7-of-10 threshold) multi-sig |
| 5 | **FEGtoken** | $0.9M | flash-loan + hijacked migrator | V4 | Migrator role-grant + flash-loan precondition |

**Chú ý GemPad ($1.9M, BSC dst chain, V1):** không thuộc plan này — đây
là logic bug single-chain trên BSC, đi theo pattern Sprint S thay vì
mock multi-sig. Sprint G nên tách riêng (~3-4h, copy-paste cấu trúc
Socket).

**Tổng thời gian dự kiến:** ~22-26 giờ
- 1.5h thiết kế + implement mock multi-sig harness chung
- 4h × 5 sprint = 20h
- 1h reconcile + final verify

---

## Pre-requisites

### 1. RPC URLs (.env)

Bốn vụ dùng Ethereum làm chuỗi nguồn (Ronin/Harmony/Multichain/Orbit);
FEGtoken có cả ETH lẫn BSC. Tận dụng RPC đã có:

```bash
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
BSC_RPC_URL=https://bsc-dataseed.binance.org/   # public, no archive
# Optional — chuỗi đích để verify_benchmark.py không [skip]:
RONIN_RPC_URL=https://api.roninchain.com/rpc
HARMONY_RPC_URL=https://api.harmony.one
FANTOM_RPC_URL=https://rpc.ftm.tools/
ORBIT_RPC_URL=https://public-node-api.klaytnapi.com/v1/cypress   # Orbit chain not on every provider; use Klaytn endpoint as proxy
```

`*_RPC_URL` cho chuỗi đích **không bắt buộc** — `verify_benchmark.py`
sẽ `[skip]` gọn nếu không set, giống cách Wormhole skip Solana.

### 2. Common references

- https://rekt.news/leaderboard
- https://defillama.com/hacks
- https://github.com/Sukemcute/CrossLLM/blob/develop/benchmarks/wormhole/ — mẫu cho cách document non-standard simulation
- Mỗi bridge có post-mortem riêng (link trong từng sprint dưới).

---

## Sprint M0 — Mock Multi-Sig Harness (làm trước, dùng chung)

**Mục tiêu:** Tránh viết lại validator-quorum logic cho từng bridge.
Một file `benchmarks/_shared/MockMultisig.sol` đáp ứng được 4/5 vụ
(Ronin/Harmony/Orbit dùng K-of-N PoA; Multichain mô hình 1-of-1 vì
TSS/MPC không thể on-chain hoá đơn giản).

**Tasks:**

| Task | Mô tả | Time |
|------|-------|------|
| M0.1 | Tạo `benchmarks/_shared/MockMultisig.sol` — K-of-N ECDSA threshold | 45 min |
| M0.2 | Tạo `benchmarks/_shared/README.md` — note dùng chung, không thuộc bất kỳ bridge nào | 10 min |
| M0.3 | Update `BENCHMARK_TEST_GUIDE.md` để mention `_shared/` được mỗi benchmark import qua relative path | 15 min |
| M0.4 | Test compile-static: regex parse OK, mỗi bridge có thể `import "../_shared/MockMultisig.sol"` | 10 min |

**Skeleton dự kiến:**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title MockMultisig
 * @notice Generic K-of-N ECDSA threshold harness for off-chain compromise
 *         benchmarks (Ronin, Harmony, Orbit). Each bridge configures N
 *         signer addresses + threshold K at construction. The compromise
 *         model is "attacker controls K signers' private keys"; in the
 *         benchmark this collapses to "attacker can submit valid sigs
 *         from K addresses, bypassing the security assumption that <=K-1
 *         signers can be compromised".
 */
contract MockMultisig {
    address[] public signers;
    uint256 public threshold;
    mapping(address => bool) public isSigner;
    mapping(bytes32 => bool) public executed;

    event Executed(bytes32 indexed digest, address target, uint256 value, bytes data);

    constructor(address[] memory signers_, uint256 threshold_) {
        require(threshold_ > 0 && threshold_ <= signers_.length, "bad threshold");
        signers = signers_;
        threshold = threshold_;
        for (uint i; i < signers_.length; ++i) {
            isSigner[signers_[i]] = true;
        }
    }

    /**
     * @notice Execute an arbitrary call once `threshold` signers have signed
     *         the digest = keccak256(target, value, data, nonce). The bug
     *         being modelled is upstream of this contract: the *signers
     *         themselves* were compromised. This contract enforces its
     *         spec correctly — the assumption "fewer than K signers will
     *         be compromised" is what failed.
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce,
        bytes[] calldata sigs
    ) external returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked(target, value, data, nonce, address(this)));
        require(!executed[digest], "replay");
        require(sigs.length >= threshold, "below threshold");

        // Verify each sig is from a distinct signer.
        address last = address(0);
        for (uint i; i < sigs.length; ++i) {
            address recovered = _recover(digest, sigs[i]);
            require(isSigner[recovered], "not signer");
            require(uint160(recovered) > uint160(last), "duplicate or unsorted");
            last = recovered;
        }

        executed[digest] = true;
        (bool ok, bytes memory ret) = target.call{value: value}(data);
        require(ok, "call failed");
        emit Executed(digest, target, value, data);
        return ret;
    }

    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig");
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        return ecrecover(digest, v, r, s);
    }
}
```

**Acceptance M0:**
- [ ] `benchmarks/_shared/MockMultisig.sol` exists, parses, has K-of-N threshold + nonce replay guard.
- [ ] Each off-chain benchmark below imports it via `../_shared/MockMultisig.sol`.
- [ ] `verify_benchmark.py` does not flag `_shared/` as a missing benchmark (it does not contain `metadata.json` so the script never visits it; safe by construction).

---

## SPRINT R — Ronin ($624M, Ethereum→Ronin)

**Background:** 2022-03-23. Sky Mavis's Ronin Bridge is a 9-of-9 PoA
multi-sig where 5/9 validators were compromised (4 internal + 1 third-party
Axie DAO key still trusted after Sky Mavis stopped using Axie DAO's
support). Attacker submitted two crafted withdrawal proofs signed by
the 5 compromised keys, draining 173,600 ETH + 25.5M USDC.

### Tasks

| Task | Mô tả | Time |
|------|-------|------|
| R1 | Research: Sky Mavis post-mortem + Halborn analysis | 1h |
| R2 | Reconstruct: `RoninBridgeManager.sol` (calls into shared `MockMultisig`) + `WrappedToken.sol` for ETH/USDC representations | 1.5h |
| R3 | metadata.json — V4 key_compromise, fork ETH 14442835 (1 block before first attack tx) | 30 min |
| R4 | exploit_trace.json — 2 fraudulent withdrawal txs + Axie DAO key staleness backstory in `forensics` | 30 min |
| R5 | mapping.json — ETH ↔ Ronin chain (chain_id 2020) | 20 min |
| R6 | README — clearly note "5/9 signers compromised, threshold 5/9 → met" + repro + smoke | 30 min |

**Bug pattern to reconstruct:**

```solidity
import "../../_shared/MockMultisig.sol";  // contracts live two levels deep

contract RoninBridgeManager is MockMultisig {
    // 9 signers, threshold 5. The "bug" is upstream: 5 keys fell into
    // attacker's hands. The on-chain code enforced its spec correctly,
    // which is what makes V4 (key compromise) the right classification.
    constructor(address[] memory signers_) MockMultisig(signers_, 5) {}

    /// Withdraw representation. In production this called LockProxy.unlock;
    /// here it forwards a `target.call(data)` via the Multisig's execute().
    function withdraw(/* same as MockMultisig.execute */) external { ... }
}
```

**Acceptance R:**
- [ ] vuln_classes = ["V4"], attack_type = "key_compromise"
- [ ] metadata documents the Axie DAO stale-permission backstory in `root_cause_summary.notes`
- [ ] Module 1 surfaces a `validator_set_authority` invariant
- [ ] Module 2 sinh ra ≥1 scenario `key_compromise` / `validator_collusion`

**References:**
- https://roninblockchain.substack.com/p/community-alert-ronin-validators
- https://www.halborn.com/blog/post/explained-the-ronin-hack-march-2022
- https://etherscan.io/address/0x098B716B8Aaf21512996dC57EB0615e2383E2f96 — Ronin Bridge proxy

---

## SPRINT H — Harmony Horizon ($100M, Ethereum→Harmony)

**Background:** 2022-06-23. Horizon Bridge used a 2-of-4 multi-sig.
Two of four operator hot wallets were compromised (private keys
exfiltrated from Sky Mavis-style key-management failure). Attacker
submitted batched withdrawal txs signed by 2 keys, draining ~$100M
across ETH/USDC/USDT/WBTC/SHIB.

### Tasks

| Task | Mô tả | Time |
|------|-------|------|
| H1 | Research: Harmony post-mortem (3 chronological updates) + Elliptic analysis | 1h |
| H2 | Reconstruct: `HorizonEthManager.sol` (uses `MockMultisig` with N=4, K=2) + `EthBucket.sol` (the lock pool) | 1.5h |
| H3 | metadata.json — V4, fork ETH 15011934 | 30 min |
| H4 | exploit_trace.json — 11 batched withdraw txs over ~5 blocks, attribute to Lazarus Group per Elliptic | 30 min |
| H5 | mapping.json — ETH ↔ Harmony (chain_id 1666600000) | 20 min |
| H6 | README + repro + smoke | 30 min |

**Bug pattern:** identical structure to Ronin but threshold 2/4. The
benchmark differentiator is the smaller threshold + the asset diversity
(5+ tokens). Module 1 should generalize the multi-sig pattern across the
two benchmarks if RAG retrieves the Ronin scenario template — this is
intentionally a stress test of the LLM's reuse capability.

**Acceptance H:**
- [ ] vuln_classes = ["V4"], threshold = 2 in metadata.contracts
- [ ] mapping.json lists ≥4 distinct asset types (ETH/USDC/USDT/WBTC/SHIB)
- [ ] Module 2 sinh scenario `key_compromise` reusing Ronin template if both populated

**References:**
- https://medium.com/harmony-one/lessons-from-the-harmony-bridge-hack-1c3a72b9d58b
- https://www.elliptic.co/blog/harmony-horizon-bridge-100-million-hack-may-be-linked-to-lazarus-group

---

## SPRINT M — Multichain ($126M, ETH→FTM/AVAX/Polygon)

**Background:** 2023-07-06. Multichain (formerly AnySwap) used a
threshold MPC ceremony for cross-chain custody. The CEO retained
unilateral control of the MPC nodes; after his arrest in China, attacker
(plausibly successor staff or law-enforcement-coerced) drained $126M
from the bridge's locked pools across ETH→FTM/AVAX/Polygon.

### Tasks

| Task | Mô tả | Time |
|------|-------|------|
| M1 | Research: Fantom Foundation post-mortem + ChainArgos timeline | 1h |
| M2 | Reconstruct: `MultichainAnyCallV6.sol` (custody) + use `MockMultisig` with N=1, K=1 to model "trusted signer" (TSS collapses to 1-of-1 because we cannot replay MPC ceremony in Solidity) — note this gap explicitly in README, similar to Wormhole's Solana note | 2h |
| M3 | metadata.json — V2+V4, fork ETH 17529623 | 30 min |
| M4 | exploit_trace.json — 6 large withdrawals over 24h, multiple destination chains | 30 min |
| M5 | mapping.json — ETH ↔ Fantom (chain_id 250); secondary: AVAX/Polygon | 20 min |
| M6 | README — explicit MPC simulation gap note (`mpc_simulation: { reason: ..., implication: ... }` block in metadata mirroring Wormhole's `non_evm_simulation`) + repro + smoke | 1h |

**Important — MPC gap:** TSS/MPC cannot be modelled in Solidity in any
faithful way; the on-chain code only ever saw ECDSA signatures. The
benchmark therefore degrades to a 1-of-1 multi-sig with the README
explaining: "MPC compromise -> single attacker-controlled signer; the
threshold ceremony is the off-chain artifact that was broken, not the
on-chain code."

**Acceptance M:**
- [ ] vuln_classes = ["V2", "V4"], attack_type = "mpc_compromise"
- [ ] README's "Simulation gap" section is at least as prominent as
      Wormhole's Solana note (paper §6 reference)
- [ ] metadata.contracts notes `mpc_signer_address` as `is_eoa: true`

**References:**
- https://twitter.com/FantomFDN/status/1676923210660429825
- https://chainargos.com/2023/07/06/multichain-the-end/
- https://etherscan.io/address/0x6b7a87899490ece95443e979ca9485cbe7e71522 — anyCallV6 router

---

## SPRINT O — Orbit Bridge ($82M, ETH→Orbit)

**Background:** 2024-01-01. Orbit Bridge (Ozys, Korea) used a 7-of-10
ECDSA multi-sig. Attacker compromised 7/10 operator keys (suspected
Lazarus per Match Systems) and drained $82M across ETH/USDT/USDC/WBTC/DAI.

### Tasks

| Task | Mô tả | Time |
|------|-------|------|
| O1 | Research: Match Systems writeup + Etherscan tx tracing | 1h |
| O2 | Reconstruct: `OrbitVault.sol` extending `MockMultisig(10, 7)` | 1.5h |
| O3 | metadata.json — V4, fork ETH 18900000 (matches benchmarks/README.md table) | 30 min |
| O4 | exploit_trace.json — 5 large drain txs over 1 block | 30 min |
| O5 | mapping.json — ETH ↔ Orbit (custom chain) | 20 min |
| O6 | README + repro + smoke | 30 min |

**Bug pattern:** identical multi-sig structure to Ronin/Harmony but
N=10, K=7. The N=10 setup tests Module 1's ability to scale the entity
count without exploding the ATG node count.

**Acceptance O:**
- [ ] vuln_classes = ["V4"]
- [ ] metadata.contracts.orbit_vault.threshold = 7
- [ ] N=10 signer addresses listed (placeholder hashes OK)

**References:**
- https://x.com/Ozys_Official/status/1741655068636635461
- https://matchsystems.io/research/orbit-bridge-hack/
- https://etherscan.io/address/0x1Bf68A9d1EaEe7826b3593C20a0ca93293cb489a

---

## SPRINT F — FEGtoken ($0.9M, ETH+BSC)

**Background:** 2022-04-28. FEG's `migrator` contract had an
arbitrary-token `swapToSwap` function that called
`tokenA.transferFrom(user, attacker, amount)` after a flash-loan
established a fake `attacker == migrator` calling context. Attack
required (a) a flash-loan precondition + (b) a previously-granted
`migrator` role on FEG token. Drained ~$0.9M (small but instructive
because it combines V2 replay-style flash loan + V4 role
mis-attribution).

### Tasks

| Task | Mô tả | Time |
|------|-------|------|
| F1 | Research: PeckShield analysis + BscScan tx tracing | 1h |
| F2 | Reconstruct: `FEGToken.sol` (migrator role) + `FEGSwap.sol` (the swapToSwap entry) + `FlashLoanProvider.sol` (mock pool) | 2h |
| F3 | metadata.json — V2+V4, fork BSC 17127537 | 30 min |
| F4 | exploit_trace.json — flash-loan → migrator-grant exploit → drain → repay | 30 min |
| F5 | mapping.json — ETH ↔ BSC (FEG had pools on both) | 20 min |
| F6 | README + repro + smoke | 30 min |

**Note BSC archive limitation:** Public BSC RPC (`bsc-dataseed`) cannot
serve archive queries. `verify_benchmark.py` already auto-falls-back to
latest block (memory-noted gotcha) — same behavior as Qubit/pGALA.

**Acceptance F:**
- [ ] vuln_classes = ["V2", "V4"]
- [ ] At least 3 contracts reconstructed (token / swap / flash-loan)
- [ ] exploit_trace stages cover: flash-loan-borrow → exploit-call → flash-loan-repay

**References:**
- https://peckshield.medium.com/fegtoken-incident-april-2022-a26793a1a35e
- https://rekt.news/feg-rekt/
- https://bscscan.com/address/0x4b9be7e93f02d94c87c20cd71a90b6f5a3c3ca42 — FEGSwap

---

## Tracking matrix

| Sprint | Bridge | Loss | N-of-K | Vuln class | Status |
|--------|--------|------|--------|-----------|--------|
| M0 | _shared/MockMultisig | n/a | template | n/a | TODO |
| R | Ronin | $624M | 5/9 | V4 | TODO |
| H | Harmony | $100M | 2/4 | V4 | TODO |
| M | Multichain | $126M | 1/1 (TSS gap) | V2+V4 | TODO |
| O | Orbit | $82M | 7/10 | V4 | TODO |
| F | FEGtoken | $0.9M | flash+role | V2+V4 | TODO |

---

## Order of execution & checklists

### Day 1 (2-3h): Mock harness + Ronin

- [ ] M0: implement `benchmarks/_shared/MockMultisig.sol`
- [ ] Sprint R tasks R1 → R6
- [ ] `python scripts/verify_benchmark.py benchmarks/ronin/` passes
- [ ] Smoke test: `bash benchmarks/ronin/repro.sh`

### Day 2 (4h): Harmony

- [ ] Sprint H tasks H1 → H6
- [ ] verify pass
- [ ] smoke pass + cross-check Module 2 reuses Ronin template (if same NIM session)

### Day 3 (4-5h): Multichain (extra time for MPC gap doc)

- [ ] Sprint M tasks M1 → M6
- [ ] README has dedicated "Simulation gap" section parallel to Wormhole
- [ ] verify pass

### Day 4 (4h): Orbit

- [ ] Sprint O tasks O1 → O6
- [ ] verify pass with N=10 signer placeholders

### Day 5 (4h): FEGtoken

- [ ] Sprint F tasks F1 → F6
- [ ] flash-loan precondition explicit in exploit_trace
- [ ] verify pass (BSC archive fallback expected)

### Final verification (30 min)

```bash
for b in nomad qubit pgala polynetwork wormhole socket gempad ronin harmony multichain orbit fegtoken; do
    python scripts/verify_benchmark.py benchmarks/$b/
done
# Expected: all 12 pass
```

```bash
for b in nomad qubit pgala polynetwork wormhole socket gempad ronin harmony multichain orbit fegtoken; do
    python -m src.orchestrator \
        --benchmark benchmarks/$b/ \
        --time-budget 5 --runs 1 --rag-k 3 \
        --skip-fuzzer --strict-schema \
        --output results/${b}_smoke/
done
```

Acceptance toàn cục:
- [ ] 12/12 benchmarks chạy pipeline thành công
- [ ] Atg.json + hypotheses.json validate schema cho tất cả 12
- [ ] LLM gen invariants/scenarios cho cả 12 (tier 2 — chạy với NIM key trong WSL)
- [ ] Coverage 5 lớp vuln V1-V5 (đã có sẵn V1/V3/V4/V5; V2 đến từ Multichain + FEGtoken)

---

## Sau khi xong 5 off-chain benchmarks

Còn **GemPad** ($1.9M, BSC, V1) — single-chain logic bug, đi theo
pattern Sprint S thay vì plan này. Sprint G nên là một file plan riêng
ngắn (~1 trang) hoặc append vào `PLAN_POPULATE_BENCHMARKS.md`.

Sau khi **12/12 benchmarks** xong:
1. Update `benchmarks/README.md` tracking table với link đến từng folder.
2. Run full LLM tier (tier 2) trong WSL với NVIDIA_API_KEY.
3. Snapshot kết quả LLM ATG/scenarios cho 12 benchmarks → input cho
   paper Section 7 (Evaluation).
4. Pivot sang **Phase 5 (paper finalization)**: fold benchmark stats
   vào Table 5/6/7 of paper.tex.

---

## Tài liệu tham khảo nhanh

| Bridge | Post-mortem chính | Address chính | Block |
|--------|-------------------|---------------|-------|
| Ronin | https://roninblockchain.substack.com/p/community-alert-ronin-validators | eth:0x098B716B8Aaf21512996dC57EB0615e2383E2f96 | eth:14442835 |
| Harmony | https://medium.com/harmony-one/lessons-from-the-harmony-bridge-hack-1c3a72b9d58b | eth:0x2dCCDB493827E15a5dC8f8b72147E6c4A5620857 | eth:15011934 |
| Multichain | https://twitter.com/FantomFDN/status/1676923210660429825 | eth:0x6b7a87899490ece95443e979ca9485cbe7e71522 | eth:17529623 |
| Orbit | https://matchsystems.io/research/orbit-bridge-hack/ | eth:0x1Bf68A9d1EaEe7826b3593C20a0ca93293cb489a | eth:18900000 |
| FEGtoken | https://peckshield.medium.com/fegtoken-incident-april-2022-a26793a1a35e | bsc:0x4b9be7e93f02d94c87c20cd71a90b6f5a3c3ca42 | bsc:17127537 |
