# Benchmark Dataset

12 reconstructed real-world cross-chain bridge exploits.

Shared fields for all `metadata.json` files are described in
[`BENCHMARK_METADATA.schema.json`](BENCHMARK_METADATA.schema.json)
(JSON Schema draft 2020-12; optional `schema_version` + `reporting` for the report table).

## Directory Structure

Each benchmark contains:
```
benchmarks/<bridge_name>/
├── metadata.json          # Bridge info, fork block, vulnerability class
├── repro.sh / repro.ps1  # optional: smoke repro for Module 1+2 (where provided)
├── contracts/             # Verified or reconstructed Solidity sources
│   ├── SourceRouter.sol   # (names vary by benchmark)
│   ├── DestRouter.sol
│   ├── Token.sol
│   └── ...
├── exploit_trace.json     # Curated attack timeline / tx pointers
└── mapping.json           # Cross-chain address/asset mapping
```

The **nomad** benchmark is the reference full package (see `benchmarks/nomad/README.md`); the other rows are to be filled in the same shape over time.

## Benchmarks

| # | Bridge | Loss | Vuln Type | Chuỗi nguồn | Chuỗi đích | Block fork | Hướng tấn công |
|---|--------|------|-----------|-------------|------------|------------|----------------|
| 1 | PolyNetwork (2021) | $611M | V3, V4 | Ethereum | BSC / Polygon | 12996658 | Src Chain |
| 2 | Wormhole (2022) | $326M | V1, V5 | Solana | Ethereum | 14268080 | Dst Chain |
| 3 | Ronin Network (2022) | $624M | V4 | Ethereum | Ronin | 14442835 | Off-chain |
| 4 | Nomad (2022) | $190M | V1, V3 | Ethereum | Moonbeam | 15259100 | Dst Chain |
| 5 | Harmony Horizon (2022) | $100M | V4 | Ethereum | Harmony | 15000000 | Off-chain |
| 6 | Multichain (2023) | $126M | V2, V4 | Ethereum | Fantom | 17700000 | Off-chain |
| 7 | Socket Gateway (2024) | $3.3M | V5 | Ethereum | — | 19100000 | Src Chain |
| 8 | Orbit Bridge (2024) | $82M | V4 | Ethereum | Orbit | 18900000 | Off-chain |
| 9 | GemPad (2024) | $1.9M | V1 | BSC | — | 44500000 | Dst Chain |
| 10 | FEGtoken (2024) | $0.9M | V4 | Ethereum | BSC | 21500000 | Off-chain |
| 11 | pGALA (2022) | $10M | V1 | BSC | — | 22700000 | Src Chain |
| 12 | Qubit Finance (2022) | $80M | V1 | Ethereum | BSC | 14180000 | Dst Chain |

**Ghi chú ngắn:** Block fork cho **Wormhole** là phía **Ethereum** (đích EVM); phần Solana cần mô hình riêng hoặc giả lập guardian. Các vụ **off-chain** (Ronin, Harmony, Multichain, Orbit, FEG) cần mock relay / multisig ngoài fork thuần contract. **GemPad / pGALA:** số block là trên **BSC**. Ô **chuỗi đích “—”**: một chuỗi hoặc bổ sung trong `metadata.json` khi đủ artifact.

## Vulnerability Types
- V1: Verification Bypass
- V2: Replay Attack
- V3: State Desync
- V4: Unauthorized Access / Key Compromise
- V5: Logic / Business Rule Bug
