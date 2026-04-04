# Benchmark Dataset

12 reconstructed real-world cross-chain bridge exploits.

## Directory Structure

Each benchmark contains:
```
benchmarks/<bridge_name>/
├── metadata.json          # Bridge info, fork block, vulnerability class
├── contracts/             # Verified Solidity source files
│   ├── SourceRouter.sol
│   ├── DestRouter.sol
│   └── Token.sol
├── exploit_trace.json     # Original attack transaction sequence
└── mapping.json           # Cross-chain address/asset mapping
```

## Benchmarks

| # | Bridge | Loss | Vuln Type | Attack Stage | Fork Block |
|---|--------|------|-----------|--------------|------------|
| 1 | PolyNetwork | $611M | V3, V4 | Src Chain | 12996658 |
| 2 | Wormhole | $326M | V1, V5 | Dst Chain | 14268080 |
| 3 | Ronin | $624M | V4 | Off-chain | 14442835 |
| 4 | Nomad | $190M | V1, V3 | Dst Chain | 15259100 |
| 5 | Harmony | $100M | V4 | Off-chain | - |
| 6 | Multichain | $126M | V2, V4 | Off-chain | - |
| 7 | Socket | $3.3M | V5 | Src Chain | - |
| 8 | Orbit | $82M | V4 | Off-chain | - |
| 9 | GemPad | $1.9M | V1 | Dst Chain | - |
| 10 | FEGtoken | $0.9M | V4 | Off-chain | - |
| 11 | pGALA | $10M | V1 | Src Chain | - |
| 12 | Qubit | $80M | V1 | Dst Chain | 14125814 |

## Vulnerability Types
- V1: Verification Bypass
- V2: Replay Attack
- V3: State Desync
- V4: Unauthorized Access / Key Compromise
- V5: Logic / Business Rule Bug
