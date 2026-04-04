# BridgeSentry

**LLM-Guided Vulnerability Discovery in Cross-Chain Bridges via Semantic Modeling and Synchronized Dual-Chain Fuzzing**

## Overview

BridgeSentry is a framework for proactive vulnerability discovery in cross-chain blockchain bridges. It combines LLM-based semantic understanding with synchronized dual-chain dynamic testing to detect logic vulnerabilities that single-chain tools miss.

### Pipeline

```
Bridge Source Code
       │
       ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Module 1        │     │  Module 2        │     │  Module 3        │
│  Semantic        │────▶│  RAG Attack      │────▶│  Dual-Chain      │
│  Extraction      │     │  Scenario Gen    │     │  Fuzzing         │
│  (LLM + ATG)    │     │  (51 exploits)   │     │  (Synced EVM)    │
└──────────────────┘     └──────────────────┘     └──────────────────┘
                                                          │
                                                          ▼
                                                  Vulnerability Reports
```

### Vulnerability Types

| ID | Type | Example |
|----|------|---------|
| V1 | Verification Bypass | Nomad ($190M) |
| V2 | Replay Attack | Multichain |
| V3 | State Desync | PolyNetwork ($611M) |
| V4 | Key Compromise | Ronin ($624M) |
| V5 | Business Logic Bug | Wormhole ($326M) |

## Project Structure

```
CrossLLM/
├── src/
│   ├── module1_semantic/           # Module 1: LLM Semantic Extraction
│   │   ├── extractor.py            #   Contract parsing + entity recognition
│   │   ├── atg_builder.py          #   Atomic Transfer Graph construction
│   │   ├── invariant_synth.py      #   Protocol invariant synthesis
│   │   └── prompts/                #   LLM prompt templates
│   ├── module2_rag/                # Module 2: RAG Attack Scenario Generation
│   │   ├── knowledge_base.py       #   51-exploit knowledge base manager
│   │   ├── embedder.py             #   FAISS vector index for retrieval
│   │   ├── scenario_gen.py         #   Attack scenario generator
│   │   └── data/                   #   Exploit records (JSON)
│   ├── module3_fuzzing/            # Module 3: Synchronized Dual-Chain Fuzzer (Rust)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs             #   CLI entry point
│   │       ├── dual_evm.rs         #   Dual-EVM environment (revm)
│   │       ├── mock_relay.rs       #   Mock relay (4 modes)
│   │       ├── snapshot.rs         #   Synchronized snapshot management
│   │       ├── mutator.rs          #   ATG-aware mutation operator
│   │       └── checker.rs          #   Invariant checker + waypoint reward
│   └── orchestrator.py             # Pipeline orchestrator
├── benchmarks/                     # 12 reconstructed bridge exploits
├── results/                        # Experiment outputs
├── scripts/                        # Setup & run scripts
├── tests/                          # Unit tests
├── docs/                           # Research papers & guides
└── latex/                          # Paper source (IEEE format)
```

## Quick Start

```bash
# 1. Setup environment
./scripts/setup_env.sh

# 2. Configure API keys
cp .env.example .env
# Edit .env with your keys

# 3. Run on a single benchmark
./scripts/run_benchmark.sh nomad 600 5

# 4. Run all benchmarks
./scripts/run_all_benchmarks.sh
```

## Requirements

- Python 3.10+
- Rust 1.75+
- Foundry (anvil, forge, cast)
- OpenAI API key (GPT-4o)

## Baselines

| Tool | Type | Venue |
|------|------|-------|
| ItyFuzz | Snapshot fuzzer (single-chain) | ISSTA 2023 |
| SmartShot | Mutable-snapshot fuzzer | FSE 2025 |
| VulSEye | Directed graybox fuzzer | IEEE TIFS 2025 |
| SmartAxe | Static cross-chain analyzer | FSE 2024 |
| GPTScan | LLM + static analysis | ICSE 2024 |
| XScope | Rule-based detector | ASE 2022 |

## References

- Paper: `latex/paper.tex`
- Experiment guide: `docs/experiment_guide.html`
