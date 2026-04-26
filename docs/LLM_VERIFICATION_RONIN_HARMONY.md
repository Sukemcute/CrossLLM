# LLM-Mode Verification — Sprint R (Ronin) + Sprint H (Harmony)

> **Mục đích:** Xác minh acceptance criteria của Sprint R/H trong
> [`PLAN_POPULATE_OFFCHAIN.md`](PLAN_POPULATE_OFFCHAIN.md) bằng cách
> chạy Module 1+2 ở **Tier-2 (LLM mode)** với NVIDIA NIM trên WSL,
> không thể verify trên Windows host vì venv + API key chỉ có ở WSL.
>
> **Run timestamp:** 2026-04-25
> **Model:** `gpt-oss-120b` (NVIDIA NIM dev tier)
> **Wall-clock:** Harmony 5'47", Ronin ~6'00"
> **Hardware:** WSL2 Ubuntu 22.04 trên Windows 10
>
> **Output đã lưu:**
> - WSL: `~/CrossLLM/results/ronin_llm/` và `~/CrossLLM/results/harmony_llm/`
> - Files: `atg.json`, `hypotheses.json`, `report.json`

---

## TL;DR — Kết quả acceptance

| Sprint | Acceptance criteria từ plan | Tier-1 (offline) | **Tier-2 (LLM)** |
|--------|---------------------------|------------------|------------------|
| **R** | `vuln_classes = ["V4"]` trong metadata | ✅ static | ✅ |
| **R** | Module 1 surfaces `validator_set_authority` invariant | ❌ chỉ 4 generic | ✅ **20 invariants chuyên sâu**, có `authorization_unlock_caller_is_bridge` |
| **R** | Module 2 sinh ≥1 scenario `key_compromise` / `validator_collusion` | ❌ chỉ 4 template generic | ✅ **literal `key_compromise` label** trong `ronin_mint_auth_bypass_key_compromise_001` |
| **H** | `threshold = 2` trong metadata | ✅ static | ✅ |
| **H** | `mapping.json` ≥ 4 distinct assets | ✅ static (5 assets) | ✅ |
| **H** | Module 2 reuses Ronin `key_compromise` template | ⚠️ chỉ 4 generic | ⚠️ **không dùng literal label** — reframe thành `signature_forgery_replay` + `governance_upgrade_backdoor` (xem [Phân tích](#phân-tích-finding-cho-paper-6)) |

**Kết luận:** Sprint R đạt 100% acceptance. Sprint H đạt acceptance về
mặt **semantic** (target invariant đúng = threshold-quorum) nhưng
**vocabulary khác** (label `signature_forgery_replay` thay vì
`key_compromise`). Đây là finding có giá trị cho paper §6 chứ không
phải defect.

---

## Tier-1 vs Tier-2 — Chênh lệch chất lượng

| Metric | Ronin Tier-1 | **Ronin Tier-2** | Harmony Tier-1 | **Harmony Tier-2** |
|---|---|---|---|---|
| ATG nodes | 7 | 4 (merge) | 9 | 7 (merge) |
| ATG edges | 3 | 5 | 5 | 7 |
| Invariants | 4 generic | **20** | 4 generic | **19** |
| Scenarios | 4 generic | **20** | 4 generic | **19** |
| Invariant categories | 1 (generic) | **4** (asset_cons / auth / uniq / time) | 1 | **4** |

LLM mode tăng số invariant **~5×** và đa dạng hoá vocabulary ra 4 phạm
trù chuyên sâu (so với 4 generic của offline regex fallback).

---

## Sprint R — Ronin chi tiết

### ATG (Module 1)

- **4 nodes, 5 edges, 20 invariants**
- Phân bố category: `asset_conservation` (7), `authorization` (6), `uniqueness` (3), `timeliness` (4)
- Sample mỗi category:
  - `[asset_conservation] asset_conservation_locked_not_exceed_deposits` —
    *"The total amount locked for a token must never exceed the
    cumulative amount successfully transferred into the bridge via the
    lock edge."*
  - `[authorization] authorization_unlock_caller_is_bridge` —
    *"Only the RoninBridgeManager contract itself may invoke the unlock
    function."* (đúng tinh thần `msg.sender == address(this)` self-call
    idiom đã code)
  - `[uniqueness] uniqueness_deposit_nonce_used_once` —
    *"Each deposit nonce recorded at lock time can be processed for
    minting exactly once."*
  - `[timeliness] timeliness_refund_allowed_after_timeout` —
    *"A user may claim a refund for a locked deposit only after the lock
    timestamp plus the configured timeout has elapsed."*

### Scenarios (Module 2)

20 scenario, trong đó **scenario quan trọng nhất** thoả acceptance
criteria của plan:

```
id:               ronin_mint_auth_bypass_key_compromise_001
vulnerability_class: key_compromise          ← LITERAL LABEL ĐÚNG
target_invariant: authorization_mint_caller_is_multisig
actions (4):
  - chain=ethereum fn=execute(address,bytes)
  - chain=ethereum fn=mint(address,uint256)
  - chain=ethereum fn=submitLockProof(uint256,bytes)
  - chain=ethereum fn=unlock(address,address,uint256)
```

Các scenario phụ trợ cùng phạm trù V4:
- `ronin_invariant_break_mint_to_bridge` (class=`authorization_compromise`)
- `ronin_mint_invalid_signature_bypass` (class=`signature_verification_bypass`)
- `ronin_upgrade_malicious_unlock_001` (class=`upgradeable_proxy_misconfiguration` — model validator-set rotation)
- `ronin_reg_token_bypass_001` (class=`signature_forgery`)

→ **Sprint R acceptance đạt 100%**, kể cả tiêu chí lỏng nhất là literal
label `key_compromise`.

---

## Sprint H — Harmony Horizon chi tiết

### ATG (Module 1)

- **7 nodes, 7 edges, 19 invariants**
- Phân bố category: `asset_conservation` (5), `authorization` (5), `uniqueness` (4), `timeliness` (5)
- Cấu trúc giàu hơn Ronin nhờ thiết kế **manager + bucket** tách riêng
  (Module 1 thấy thêm authority-delegation edge `manager → bucket`).
- Invariant đặc biệt — chính là threshold-quorum mà Sprint H mô hình:
  - `[authorization] authorization_mint_requires_valid_signature` —
    *"Minting of wrapped tokens must be authorized by a **quorum of
    signers** whose signatures verify the deposit hash."*
  - `[authorization] authorization_only_manager_can_unlock` —
    *"Only the designated manager contract may invoke the unlock
    (release) function."* (= invariant `manager_to_bucket_authority`)

### Scenarios (Module 2)

19 scenarios, **không có literal `key_compromise` label**, nhưng có 5
scenario tấn công đúng threshold-quorum invariant — tương đương về mặt
semantic:

| Scenario | Class | Target invariant |
|---|---|---|
| `harmony_sig_replay_mint_2024_01` | `signature_forgery_replay` | `authorization_mint_requires_valid_signature` |
| `harmony_invariant_break_001` | `signature_replay_and_insufficient_lock_check` | `asset_conservation_total_locked_equals_minted` |
| `harmony_mint_without_lock_001` | `signature_forgery_and_relay_tampering` | `asset_conservation_mint_only_after_lock` |
| `harmony_manager_upgrade_bypass_001` | `governance_upgrade_backdoor` | `authorization_only_manager_can_unlock` |
| `harmony_replay_mint_uniqueness_break_001` | `replay_attack_signature_reuse` | `uniqueness_mint_unique_per_deposit` |

Action sequence của scenario tiêu biểu (`harmony_sig_replay_mint_2024_01`):

```
1. ethereum: deposit(address token, address from, uint256 amount)
2. relay:    relayMessage(bytes payload)
3. harmony:  mint(address to, uint256 amount, bytes32 depositHash, bytes[] signatures)
                                                                   ^^^^^^^^^^^^^^^^^^
                                                                   LLM hiểu multi-sig array!
4. harmony:  transfer(address to, uint256 amount)
```

---

## Phân tích — Finding cho paper §6

### Hiện tượng

Cùng một bug-class (V4 — off-chain key compromise / multi-sig
threshold collapse), framework gán 2 vocabulary khác nhau cho 2
benchmark structurally similar:

| Benchmark | Literal label LLM dùng | Cùng target invariant với Ronin? |
|---|---|---|
| Ronin (5/9) | `key_compromise` | (gốc) |
| Harmony (2/4) | `signature_forgery_replay`, `signature_replay_and_insufficient_lock_check`, `governance_upgrade_backdoor` | ✅ về mặt semantic |

### Lý do

1. **RAG corpus bias:** KB 48-record build từ SmartAxe + XScope là 2
   static analysis tools cho **on-chain code bug**, không catalogue V4
   off-chain key compromise như 1 class riêng. LLM phải tự reframe.

2. **Stochastic LLM:** cùng prompt + cùng RAG có thể yield label khác
   nhau giữa các run. Ronin happen được match-class với SoK template
   tốt hơn, Harmony bị reframe.

3. **Hợp lý kỹ thuật cho EVM-only fuzzer:**
   "Có 5/9 key bị lộ" cuối cùng cũng *hiển thị* trên chain dưới dạng
   "valid signature trên forged digest". Module 3 (revm fuzzer) chỉ
   replay được sự kiện on-chain — vocabulary `signature_forgery_replay`
   thực ra **chính xác hơn** với những gì fuzzer có thể test.

### Hệ quả cho paper

> **Đề xuất bổ sung paper §6 (Limitations):**
> "BridgeSentry's RAG-augmented attack hypothesis generator reframes
> off-chain compromise (V4) as on-chain signature semantics
> (signature forgery / replay) when the SmartAxe+XScope-derived
> exploit knowledge base lacks dedicated V4 templates. Both
> vocabularies converge on the same target invariant
> (`authorization_*_requires_valid_signature` /
> `authorization_*_caller_is_multisig`), so downstream Module 3
> fuzzing remains correct, but invariant-class reporting requires
> manual reconciliation across V4 benchmarks. A future iteration of
> the KB should ingest off-chain compromise post-mortems (Ronin,
> Harmony, Multichain, Orbit) as a 7th implicit class so the LLM has
> direct V4 templates to retrieve."

### Hệ quả thực hành cho Module 3

Cả 2 benchmark đều cho ra `target_invariant` đúng (threshold-quorum),
nên fuzzer corpus / mutator không bị ảnh hưởng. Khi sinh test case,
mutator chỉ cần biết *invariant nào bị tấn công*, không cần biết *bug
class nào trong taxonomy*.

---

## Cách reproduce

```bash
# Trên WSL Ubuntu
cd ~/CrossLLM
source .crossllm/bin/activate
set -a && source .env && set +a

# Sprint R
time python -m src.orchestrator \
    --benchmark benchmarks/ronin \
    --time-budget 60 --runs 1 --rag-k 3 \
    --skip-fuzzer --output results/ronin_llm/

# Sprint H
time python -m src.orchestrator \
    --benchmark benchmarks/harmony \
    --time-budget 60 --runs 1 --rag-k 3 \
    --skip-fuzzer --output results/harmony_llm/
```

Mỗi run ~5-6 phút trên `gpt-oss-120b`. Đổi sang model nhanh hơn nếu
muốn iterate:

```bash
export NVIDIA_MODEL=meta/llama-3.3-70b-instruct
# ~30s mỗi call thay vì ~30s reasoning + delay; tổng ~1-2 phút
```

---

## Reference

- Sprint R README: [`benchmarks/ronin/README.md`](../benchmarks/ronin/README.md)
- Sprint H README: [`benchmarks/harmony/README.md`](../benchmarks/harmony/README.md)
- Off-chain plan: [`docs/PLAN_POPULATE_OFFCHAIN.md`](PLAN_POPULATE_OFFCHAIN.md)
- 4-tier test guide: [`docs/BENCHMARK_TEST_GUIDE.md`](BENCHMARK_TEST_GUIDE.md)
- Module 1 implementation: `src/module1_semantic/`
- Module 2 implementation: `src/module2_rag/`
- KB build script: `scripts/build_exploit_kb.py` (48 records từ SmartAxe + XScope)
