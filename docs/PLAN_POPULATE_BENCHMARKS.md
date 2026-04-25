# Plan — Populate 4 Benchmarks (Qubit, pGALA, PolyNetwork, Wormhole)

> Tài liệu hướng dẫn từng bước populate 4 benchmark dễ nhất. Tham chiếu mẫu chuẩn: `benchmarks/nomad/`.

## Tổng quan

**Mục tiêu:** Mỗi benchmark có đủ 6 file để chạy được pipeline Module 1+2+3:

```
benchmarks/<bridge>/
├── README.md              # Bridge-specific notes
├── metadata.json          # Bridge info, fork block, vuln class, contracts (validates against BENCHMARK_METADATA.schema.json)
├── contracts/             # Reconstructed simplified Solidity (3-5 files)
│   ├── *.sol
├── exploit_trace.json     # Curated attack timeline + real tx hashes
├── mapping.json           # Cross-chain address/asset mapping
└── repro.sh / repro.ps1   # Optional smoke repro for Module 1+2
```

**Thứ tự ưu tiên (dễ → khó):**

| # | Bridge | Network | Loss | Lý do dễ |
|---|--------|---------|------|----------|
| 1 | **Qubit** | BSC | $80M | Đơn chuỗi, source verified, bug rõ ràng |
| 2 | **pGALA** | BSC | $10M | Đơn chuỗi BSC, bug operational đơn giản |
| 3 | **PolyNetwork** | ETH→BSC/Polygon | $611M | Source verified, bug logic rõ |
| 4 | **Wormhole** | Solana→ETH | $326M | Cần mock Solana guardian (phức tạp nhất) |

**Tổng thời gian dự kiến:** ~16 giờ (4h/benchmark × 4) — ~2-3 ngày part-time.

---

## Pre-requisites

### 1. Bổ sung RPC URLs vào `.env`

```bash
# BSC (cho Qubit, pGALA)
BSC_RPC_URL=https://bsc-dataseed.binance.org/
# Hoặc archive node (Alchemy không hỗ trợ BSC, dùng QuickNode/Ankr free tier):
# BSC_RPC_URL=https://rpc.ankr.com/bsc

# Ethereum đã có
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY

# Polygon (PolyNetwork có nhánh Polygon)
POLYGON_RPC_URL=https://polygon-rpc.com/
```

### 2. Common references

Mở 4 tab trình duyệt:
- https://rekt.news/leaderboard
- https://defillama.com/hacks
- https://etherscan.io / https://bscscan.com
- https://github.com/Sukemcute/CrossLLM/blob/develop/benchmarks/nomad/ (mẫu)

### 3. Helper script (sẽ tạo trong Sprint này)

```bash
# Verify benchmark sau khi populate
python scripts/verify_benchmark.py benchmarks/qubit/
```

Script kiểm tra:
- metadata.json validates against schema
- contract addresses tồn tại trên chain (qua RPC)
- fork block tồn tại
- references[] reachable

---

## SPRINT Q — Qubit Bridge ($80M, BSC)

**Background:** Tháng 1/2022, attacker khai thác `deposit()` của QBridge router bằng cách dùng WETH events forge mint events trên BSC. Lỗi cốt lõi: function `deposit()` accept native ETH path (address(0) sentinel) nhưng không validate `msg.value`, nên attacker submit empty deposit log và xQubit (xETH wrapped) được mint trên BSC.

### Task Q1: Research (1h)

Mở các tab và thu thập thông tin:

| Source | Lấy gì |
|--------|--------|
| https://medium.com/@QubitFin/protocol-exploit-report-305c34540fa3 | Root cause text, attack flow |
| https://rekt.news/qubit-rekt/ | Loss USD confirmation, summary |
| https://bscscan.com/address/0xF734985f7d40Bcc0B2E3FA5d0cb2A86C12BDF7eb | QBridge contract on BSC, verify source |
| https://etherscan.io/address/0x67568a64ee0a8d44fcb35e1c64620a25c1d3ca5a | Qubit deposit contract on Ethereum (proxy) |

Ghi note vào `benchmarks/qubit/RESEARCH.md` (sẽ xoá sau khi xong, không commit):
- Real attack tx hash (cả ETH side + BSC side)
- Block number bên ETH ngay trước attack (~14160000-14180000)
- Block number bên BSC ngay trước attack
- Token được mint sai: `qXETH`, `qBNB`...

### Task Q2: Reconstruct Solidity contracts (~2h)

Tạo 3-4 file đơn giản trong `benchmarks/qubit/contracts/`:

#### `QBridgeETH.sol` (Ethereum side — deposit + emit Deposit event)
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title QBridgeETH (Qubit-inspired vulnerable reconstruction)
 * @notice Models the deposit-side flaw: native-token sentinel path (address(0))
 *         emits Deposit events without validating msg.value.
 *
 * Bug pattern (reconstructed from QBridge incident, 2022-01-27):
 * - When tokenContract == address(0) (native), legacy code uses safeTransferFrom
 *   path; on Ethereum it succeeded silently for 0-value calls because the
 *   wrapped-ETH adapter ignored msg.value sentinel.
 * - Result: an attacker submits deposit(address(0), 0, recipient) and the bridge
 *   emits a Deposit event for an arbitrary amount field.
 */
contract QBridgeETH {
    event Deposit(address indexed token, uint256 amount, address indexed to, uint64 nonce);
    uint64 public nonce;
    mapping(uint64 => bool) public processed;

    function deposit(address token, uint256 amount, address recipient) external payable {
        // VULN: legacy "native sentinel" path skips msg.value validation
        if (token == address(0)) {
            // No msg.value check here — attacker passes amount > 0 with msg.value == 0
            emit Deposit(token, amount, recipient, ++nonce);
            return;
        }
        // Normal ERC-20 path
        // (simplified) IERC20(token).transferFrom(msg.sender, address(this), amount);
        emit Deposit(token, amount, recipient, ++nonce);
    }
}
```

#### `QBridgeBSC.sol` (BSC side — process deposit event, mint xToken)
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MockToken.sol";

/**
 * @title QBridgeBSC (mint side reconstruction)
 * @notice Trusts deposit events from ETH side without re-validating msg.value
 *         provenance. Mints xToken proportional to event's `amount` field.
 */
contract QBridgeBSC {
    MockToken public xToken;
    mapping(uint64 => bool) public processed;
    uint256 public totalMinted;

    event Mint(address indexed to, uint256 amount, uint64 nonce);

    constructor(address xTokenAddr) {
        xToken = MockToken(xTokenAddr);
    }

    function process(address recipient, uint256 amount, uint64 nonce_) external {
        require(!processed[nonce_], "already processed");
        processed[nonce_] = true;
        totalMinted += amount;
        xToken.mint(recipient, amount);
        emit Mint(recipient, amount, nonce_);
    }
}
```

#### `MockToken.sol`
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockToken {
    string public name = "xQubit";
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }
}
```

### Task Q3: metadata.json (~30 phút)

```json
{
  "schema_version": "1.0",
  "benchmark_id": "qubit_20220127",
  "name": "Qubit Bridge Exploit",
  "incident_date_utc": "2022-01-27",
  "loss_usd_estimate": 80000000,
  "attack_type": "verification_bypass",
  "vulnerability_classes": ["V1"],
  "attack_stage": "destination_chain",
  "source_chain": {
    "name": "ethereum",
    "chain_id": 1,
    "rpc_env": "ETH_RPC_URL"
  },
  "destination_chain": {
    "name": "bsc",
    "chain_id": 56,
    "rpc_env": "BSC_RPC_URL"
  },
  "fork": {
    "block_number": 14180000,
    "first_exploit_block": 14180001,
    "repro_rpc_port": 8545
  },
  "contracts": {
    "qbridge_eth": {
      "address": "<fill from research>",
      "etherscan_url": "https://etherscan.io/address/...",
      "role": "deposit-side router with native sentinel flaw"
    },
    "qbridge_bsc": {
      "address": "0xF734985f7d40Bcc0B2E3FA5d0cb2A86C12BDF7eb",
      "bscscan_url": "https://bscscan.com/address/0xF734985f7d40Bcc0B2E3FA5d0cb2A86C12BDF7eb",
      "role": "destination-side mint router"
    }
  },
  "root_cause_summary": {
    "vulnerable_pattern": "deposit() in QBridgeETH bypasses msg.value validation when token == address(0)",
    "verification_bypass": "BSC side mints xToken using event-payload amount without re-validating provenance",
    "affected_logic": ["QBridgeETH.deposit", "QBridgeBSC.process"]
  },
  "exploit_characteristics": {
    "style": "deposit-event forgery via native-sentinel path",
    "num_transactions_estimate": 1,
    "notes": "Single attacker transaction minted ~$80M of xQubit on BSC."
  },
  "references": [
    {"title": "Qubit Finance — Protocol Exploit Report", "url": "https://medium.com/@QubitFin/protocol-exploit-report-305c34540fa3"},
    {"title": "Rekt News — Qubit Rekt", "url": "https://rekt.news/qubit-rekt/"}
  ],
  "status": {
    "contracts_reconstructed": true,
    "trace_curated": true,
    "ready_for_module1_2_pipeline": true,
    "ready_for_full_dual_evm_replay": false
  },
  "reporting": {
    "table_row": 12,
    "loss_usd_confidence": "estimate"
  }
}
```

### Task Q4: exploit_trace.json + mapping.json (~30 phút)

`exploit_trace.json`:
```json
{
  "benchmark_id": "qubit_20220127",
  "stages": [
    {
      "stage": "deposit",
      "chain": "ethereum",
      "tx_hash": "<real attack tx — fill from etherscan>",
      "block": 14180001,
      "description": "Attacker calls deposit(address(0), large_amount, attacker) with msg.value=0",
      "predicate": "QBridgeETH.deposit emits Deposit event without ETH transfer"
    },
    {
      "stage": "relay",
      "chain": "offchain",
      "description": "Validator picks up Deposit event and relays to BSC"
    },
    {
      "stage": "mint",
      "chain": "bsc",
      "tx_hash": "<real BSC mint tx>",
      "block": "<bsc block>",
      "description": "QBridgeBSC.process mints xQubit to attacker",
      "predicate": "totalMinted > sum(legitimate ETH deposits)"
    }
  ]
}
```

`mapping.json`:
```json
{
  "benchmark_id": "qubit_20220127",
  "address_mapping": [
    {
      "asset": "xQubit (xETH equivalent)",
      "ethereum": {"contract": "<eth deposit token>", "decimals": 18},
      "bsc": {"contract": "<bsc xQubit token>", "decimals": 18}
    }
  ],
  "function_mapping": [
    {"source_fn": "QBridgeETH.deposit(address,uint256,address)", "dest_fn": "QBridgeBSC.process(address,uint256,uint64)"}
  ]
}
```

### Task Q5: README.md + repro scripts (~30 phút)

`README.md`:
```markdown
# Qubit Bridge Benchmark

Reconstructed from the January 2022 Qubit Finance bridge exploit ($80M).

## Bug summary
QBridge router treated `address(0)` as a native-ETH sentinel but did not require
`msg.value > 0`, so attackers could emit arbitrary `Deposit` events with zero
ETH transferred. The BSC side blindly minted xQubit against these forged events.

## Attack flow
1. Attacker calls `QBridgeETH.deposit(address(0), 1000 ether, attacker)` with msg.value = 0.
2. Bridge emits `Deposit(address(0), 1000 ether, attacker, nonce)`.
3. BSC validator processes event, calls `QBridgeBSC.process(attacker, 1000 ether, nonce)`.
4. xQubit minted to attacker without backing.

## Files
- contracts/QBridgeETH.sol — deposit-side router (vulnerable)
- contracts/QBridgeBSC.sol — destination mint router
- contracts/MockToken.sol — xQubit token
- metadata.json — fork config + addresses
- exploit_trace.json — curated attack timeline
- mapping.json — cross-chain mapping

## Pipeline test
```bash
python -m src.orchestrator --benchmark benchmarks/qubit/ --time-budget 5 --skip-fuzzer --output results/qubit_smoke/
```
```

`repro.sh`:
```bash
#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/../.."
python -m src.orchestrator \
    --benchmark "$(dirname "$0")" \
    --time-budget 10 \
    --runs 1 \
    --rag-k 3 \
    --skip-fuzzer \
    --output results/qubit_smoke/
```

### Task Q6: Smoke test + verify (~15 phút)

```bash
cd ~/CrossLLM
source .crossllm/bin/activate
bash benchmarks/qubit/repro.sh
```

**Acceptance Q:**
- [ ] `metadata.json` validates against `BENCHMARK_METADATA.schema.json`
- [ ] 3-4 file `.sol` compile được (`solc 0.8.20`)
- [ ] Module 1 sinh được ATG cho Qubit (>=2 nodes, >=2 edges)
- [ ] Module 2 sinh được ≥4 scenarios
- [ ] Output validate against schema (no warning)

---

## SPRINT P — pGALA ($10M, BSC)

**Background:** Tháng 11/2022, pNetwork accidentally re-deploy bridge custodian với old GalaGames signer. Legacy custodian không retire → attacker dùng legacy signing key mint 1B pGALA trên BSC, sell vào PancakeSwap drain liquidity.

### Tasks (theo pattern Qubit)

| Task | Mô tả | Time |
|------|-------|------|
| P1 | Research từ pNetwork post-mortem + rekt.news | 1h |
| P2 | Reconstruct: `LegacyCustodian.sol` + `pGALAToken.sol` + `PancakeSwapMock.sol` | 1.5h |
| P3 | metadata.json (BSC fork block 22700000, vuln V1, key_compromise) | 30 min |
| P4 | exploit_trace.json (mint event, swap event) | 20 min |
| P5 | mapping.json (Gala token: BSC pGALA ↔ ETH GALA) | 10 min |
| P6 | README + repro + smoke test | 30 min |

**Bug pattern reconstruct:**
```solidity
contract LegacyCustodian {
    address public signer;  // OLD signer not rotated after redeploy
    mapping(uint64 => bool) public used;

    function mint(address to, uint256 amount, uint64 nonce, bytes calldata sig) external {
        require(!used[nonce], "used");
        // Verify sig from OLD signer (still authoritative)
        // ... ecrecover check ...
        used[nonce] = true;
        pGALA.mint(to, amount);
    }
}
```

**Key references:**
- https://medium.com/pnetwork/pgala-on-bsc-token-incident-2022-11-03-a09ac6cf68f3
- https://bscscan.com/tx/<attack_tx>

**Acceptance P:**
- [ ] Same as Q acceptance + key_compromise vuln_class trong metadata
- [ ] LLM Module 1 sinh ra invariant về key/signer

---

## SPRINT N — PolyNetwork ($611M, ETH↔BSC↔Polygon)

**Background:** Tháng 8/2021, attacker forge crafted `putCurEpochConPubKeyBytes` call qua `verifyHeaderAndExecuteTx`, replace keeper pubkey với attacker key → sign arbitrary withdrawals trên 3 chains. Bug cốt lõi: EthCrossChainManager forwarded calls to EthCrossChainData using `msg.sender = manager`.

### Tasks

| Task | Mô tả | Time |
|------|-------|------|
| N1 | Research: BlockSec writeup + Etherscan EthCrossChainManager + EthCrossChainData | 1h |
| N2 | Reconstruct: `EthCrossChainManager.sol` + `EthCrossChainData.sol` (vuln keeper override) | 2h |
| N3 | metadata.json (3 chains: ETH source, BSC + Polygon dest) | 30 min |
| N4 | exploit_trace.json (3 stages: forge keeper, sign withdrawals, drain pools) | 30 min |
| N5 | mapping.json (multi-chain: WETH/USDC across ETH/BSC/Polygon) | 20 min |
| N6 | README + repro + smoke test | 30 min |

**Bug pattern reconstruct:**
```solidity
contract EthCrossChainManager {
    address public ethCrossChainData;  // points to data contract
    address public keeper;

    function verifyHeaderAndExecuteTx(bytes calldata data) external {
        (address target, bytes memory call) = decode(data);
        // VULN: forward arbitrary call to ANY target with msg.sender = manager
        target.call(call);
        // Attacker passed target=ethCrossChainData, call=putCurEpochConPubKeyBytes(attackerPubkey)
        // → keeper now == attacker
    }
}

contract EthCrossChainData {
    address public keeper;

    function putCurEpochConPubKeyBytes(address newKeeper) external onlyManager {
        keeper = newKeeper;  // No additional auth — relies on manager being trusted
    }
}
```

**Note:** Attack involves **3 chains**, but reconstruct chỉ cần 1 (ETH side) — bug isolated trên ETH manager. BSC/Polygon side là replay của cùng pattern.

**Acceptance N:**
- [ ] Reconstruct demonstrates keeper hijack via `verifyHeaderAndExecuteTx`
- [ ] metadata vuln_classes = ["V3", "V4"] (state desync + key compromise)
- [ ] Module 1 sinh invariant về keeper authorization

---

## SPRINT W — Wormhole ($326M, Solana↔ETH)

**Background:** Tháng 2/2022, attacker bypass Solana guardian signature verification bằng cách spoof Sysvar Instructions account, mint 120k wETH trên Solana không có collateral trên Ethereum.

**LƯU Ý:** Wormhole là vụ hack phía **Solana**, không phải EVM. Project chọn fork ETH side (block 14268080) và **mock guardian set** vì revm chỉ chạy EVM.

### Tasks

| Task | Mô tả | Time |
|------|-------|------|
| W1 | Research: Extropy writeup + Wormhole post-mortem | 1h |
| W2 | Reconstruct EVM-side: `WormholeCore.sol` + `TokenBridge.sol` (mock guardian verify) | 2h |
| W3 | metadata.json (note: Solana side simulated by mock) | 30 min |
| W4 | exploit_trace.json (forged VAA → ETH process) | 30 min |
| W5 | mapping.json (wETH on Solana ↔ ETH) | 20 min |
| W6 | README rõ ràng note simulation limit + repro + smoke test | 1h |

**Bug pattern reconstruct (EVM-side approximation):**
```solidity
contract WormholeCore {
    mapping(bytes32 => bool) public processed;

    function verifyAndExecute(bytes calldata vaa) external {
        bytes32 hash = keccak256(vaa);
        require(!processed[hash], "replay");
        // VULN (modeled): no real signature check — attacker submits VAA
        // with arbitrary guardian set thay because verifyGuardianSet
        // doesn't validate the signing set's authority chain.
        processed[hash] = true;
        TokenBridge(bridge).completeTransfer(vaa);
    }
}
```

**Note rõ trong README:**
> Wormhole exploit happened on Solana side. This benchmark models the
> trust boundary that was broken (guardian signature verification) using
> an EVM-side simulation. Full reproduction requires a Solana SVM harness
> not available in BridgeSentry's revm-only fuzzer (limitation documented
> in paper Section 6).

**Acceptance W:**
- [ ] README clearly notes Solana → EVM simulation gap
- [ ] vulnerability_class = "signature_forgery"
- [ ] mock guardian verify pattern matches paper Section 4

---

## Verify script (làm trước Sprint Q)

Tạo `scripts/verify_benchmark.py`:

```python
"""Verify a benchmark's metadata + contracts + RPC connectivity.

Usage:
    python scripts/verify_benchmark.py benchmarks/qubit/
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import requests
from web3 import Web3


def main(benchmark_dir: Path) -> int:
    issues: list[str] = []

    # 1. metadata.json validates against schema
    metadata_path = benchmark_dir / "metadata.json"
    if not metadata_path.exists():
        issues.append(f"missing {metadata_path}")
        return _report(issues)

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    print(f"=== Verifying {benchmark_dir.name} ===")

    # 2. Schema validation
    schema_path = benchmark_dir.parent / "BENCHMARK_METADATA.schema.json"
    if schema_path.exists():
        try:
            import jsonschema
            jsonschema.validate(metadata, json.loads(schema_path.read_text(encoding="utf-8")))
            print("[schema] OK")
        except Exception as exc:
            issues.append(f"schema validation failed: {exc}")
    else:
        print("[schema] (skipping — schema file not found)")

    # 3. Contracts directory has .sol files
    contracts_dir = benchmark_dir / "contracts"
    sol_files = list(contracts_dir.glob("*.sol")) if contracts_dir.exists() else []
    if sol_files:
        print(f"[contracts] {len(sol_files)} .sol files")
    else:
        issues.append("no .sol files in contracts/")

    # 4. RPC connectivity for each chain
    for chain_field in ("source_chain", "destination_chain"):
        chain = metadata.get(chain_field)
        if not chain:
            continue
        rpc_var = chain.get("rpc_env")
        rpc_url = os.getenv(rpc_var) if rpc_var else None
        if not rpc_url:
            issues.append(f"{chain_field}.rpc_env={rpc_var} not set in environment")
            continue
        try:
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 10}))
            if w3.is_connected():
                print(f"[rpc {chain.get('name')}] connected, latest block {w3.eth.block_number}")
            else:
                issues.append(f"{rpc_var} not connecting")
        except Exception as exc:
            issues.append(f"{rpc_var} error: {exc}")

    # 5. Fork block exists
    fork = metadata.get("fork", {})
    block_number = fork.get("block_number")
    src = metadata.get("source_chain", {})
    rpc = os.getenv(src.get("rpc_env", ""))
    if block_number and rpc:
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
            block = w3.eth.get_block(block_number)
            print(f"[fork] block {block_number} exists, ts={block.timestamp}")
        except Exception as exc:
            issues.append(f"fork block {block_number} not found: {exc}")

    # 6. Contract addresses have bytecode at fork block
    if block_number and rpc:
        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
        for name, info in metadata.get("contracts", {}).items():
            addr = info.get("address", "")
            if not addr or addr.startswith("<"):
                issues.append(f"contracts.{name}.address is placeholder")
                continue
            try:
                code = w3.eth.get_code(addr, block_identifier=block_number)
                tag = "contract" if len(code) > 2 else "EOA"
                print(f"[code] {name} {addr} -> {tag}")
            except Exception as exc:
                issues.append(f"contracts.{name} error: {exc}")

    # 7. References reachable
    for ref in metadata.get("references", [])[:3]:  # max 3 to keep fast
        url = ref.get("url", "")
        if not url:
            continue
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            if r.status_code < 400:
                print(f"[ref] {url[:60]} -> {r.status_code}")
            else:
                issues.append(f"reference {url} returned {r.status_code}")
        except Exception as exc:
            print(f"[ref] {url[:60]} unreachable ({exc})")

    return _report(issues)


def _report(issues: list[str]) -> int:
    print()
    if not issues:
        print("✅ ALL CHECKS PASSED")
        return 0
    print(f"❌ {len(issues)} issue(s):")
    for i, msg in enumerate(issues, 1):
        print(f"  {i}. {msg}")
    return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/verify_benchmark.py <benchmark_dir>")
        sys.exit(2)
    sys.exit(main(Path(sys.argv[1])))
```

---

## Tracking matrix

| Sprint | Bridge | Loss | Fork chain | Vuln class | Status |
|--------|--------|------|-----------|------------|--------|
| Q | Qubit | $80M | BSC | V1 | TODO |
| P | pGALA | $10M | BSC | V1 / V4 | TODO |
| N | PolyNetwork | $611M | ETH | V3 / V4 | TODO |
| W | Wormhole | $326M | ETH (mock Solana) | V1 | TODO |

---

## Order of execution & checklists

### Day 1 (4-5h): Verify script + Qubit

- [ ] Implement `scripts/verify_benchmark.py`
- [ ] Run on existing Nomad → all pass (baseline)
- [ ] Sprint Q tasks Q1 → Q6
- [ ] `python scripts/verify_benchmark.py benchmarks/qubit/` passes
- [ ] Smoke test: `bash benchmarks/qubit/repro.sh` produces atg.json + hypotheses.json

### Day 2 (3-4h): pGALA

- [ ] Sprint P tasks P1 → P6
- [ ] verify pass
- [ ] smoke test pass

### Day 3 (4h): PolyNetwork

- [ ] Sprint N tasks N1 → N6
- [ ] verify pass (note: 3-chain — chỉ verify ETH chain bắt buộc)
- [ ] smoke test pass

### Day 4 (4-5h): Wormhole

- [ ] Sprint W tasks W1 → W6
- [ ] README rõ Solana simulation limit
- [ ] verify pass (note skip Solana RPC)
- [ ] smoke test pass

### Final verification (30 min)

```bash
for b in qubit pgala polynetwork wormhole; do
    python scripts/verify_benchmark.py benchmarks/$b/
done

# Expected: all 4 pass
```

Plus run pipeline trên cả 4 + Nomad:

```bash
for b in nomad qubit pgala polynetwork wormhole; do
    python -m src.orchestrator \
        --benchmark benchmarks/$b/ \
        --time-budget 5 --runs 1 --rag-k 3 \
        --skip-fuzzer --strict-schema \
        --output results/${b}_smoke/
done
```

Acceptance toàn cục:
- [ ] 5/5 benchmarks chạy pipeline thành công
- [ ] 5/5 atg.json + hypotheses.json validate schema
- [ ] LLM gen invariants/scenarios cho cả 5

---

## Tài liệu tham khảo nhanh

| Bridge | Post-mortem chính | Address chính | Block |
|--------|-------------------|---------------|-------|
| Qubit | https://medium.com/@QubitFin/protocol-exploit-report-305c34540fa3 | bsc:0xF734985f7d40Bcc0B2E3FA5d0cb2A86C12BDF7eb | bsc:14180000 |
| pGALA | https://medium.com/pnetwork/pgala-on-bsc-token-incident-2022-11-03-a09ac6cf68f3 | bsc: (search "pGALA exploit") | bsc:22700000 |
| PolyNetwork | https://blocksecteam.medium.com/the-further-analysis-of-the-poly-network-attack-6c459199c057 | eth:0x250e76987d838a75310c34bf422ea9f1AC4Cc906 | eth:12996658 |
| Wormhole | https://extropy-io.medium.com/solanas-wormhole-hack-post-mortem-analysis-3b68b9e88e13 | eth:0x3ee18b2214aff97000d974cf647e7c347e8fa585 (TokenBridge) | eth:14268080 |

---

## Sau khi xong 4 benchmark

7 benchmarks còn lại (Ronin, Harmony, Multichain, Socket, Orbit, GemPad, FEGtoken) phức tạp hơn vì:
- 5 vụ là **off-chain compromise** (cần mock relay multi-sig phức tạp)
- 2 vụ là logic nhỏ (Socket, FEG, GemPad — dễ nhưng ít refs)

→ Mở Sprint riêng (`PLAN_POPULATE_OFFCHAIN.md`) khi xong Sprint Q/P/N/W.
