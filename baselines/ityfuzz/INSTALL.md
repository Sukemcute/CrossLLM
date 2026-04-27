# ItyFuzz install + run

> ItyFuzz is a stateful EVM/Move/SUI fuzzer (Fuzzland team).
> https://github.com/fuzzland/ityfuzz

## Status

- **Cloned**: `~/baselines/ityfuzz/ityfuzz/` (commit pinned in `version.txt`)
- **Build**: in progress at time of writing (Rust 1.91.0, `--release --no-default-features --features evm,cmp,dataflow`)
- **Binary**: `target/release/ityfuzz` after build

## Prerequisites — SYSTEM PACKAGES (need sudo)

ItyFuzz pulls in `c-kzg` / `blst` deps that require `cmake` to build.
Install before `cargo build`:

```bash
sudo apt update
sudo apt install -y cmake build-essential libssl-dev pkg-config
```

Without `cmake`, `cargo build` fails with:

```
thread 'main' panicked at .../cmake-0.1.50/src/lib.rs:1098:5:
failed to execute command: No such file or directory (os error 2)
is `cmake` not installed?
```

## Toolchain

ItyFuzz pins `nightly-2024-01-01` via `rust-toolchain.toml`. `rustup`
will auto-install it on first build. **Do not delete the toolchain
file** — ItyFuzz uses some nightly-only features.

```bash
# rustup will fetch the pinned nightly automatically, but if you want
# to pre-install:
rustup toolchain install nightly-2024-01-01
```

## Install

```bash
# Prerequisites first: see "Prerequisites — SYSTEM PACKAGES" above.
mkdir -p ~/baselines/ityfuzz
cd ~/baselines/ityfuzz
git clone --depth 1 https://github.com/fuzzland/ityfuzz.git
cd ityfuzz
git submodule update --init --depth 1

# Pin commit for reproducibility
git rev-parse HEAD > ../version.txt

# Build (use minimal features set; full features needs Foundry/Move support)
cargo build --release --no-default-features --features "evm,cmp,dataflow"
# Binary: target/release/ityfuzz
```

Disk: cargo target dir ~5-8GB after compile. Time: 10-20 minutes on
modest laptop (after cmake + nightly installed).

## CLI signature (extracted from `src/evm/mod.rs`)

```
ityfuzz evm [OPTIONS]
    -t, --target <PATTERN>             Glob pattern / contract address
    -c, --chain-type <CHAIN_TYPE>      ETH | BSC | POLYGON | ...
    -b, --onchain-block-number <N>     Fork block number
    -u, --onchain-url <URL>            RPC URL
    -i, --onchain-chain-id <ID>        EVM chain id (1 = ETH, 56 = BSC, ...)
    -k, --onchain-etherscan-api-key <KEY>   Required for fetching ABI / source
    --concolic                         Enable concolic execution
    --detectors <NAMES>                Default: high_confidence
    -o                                 Onchain mode flag
```

## Run on a benchmark

ItyFuzz expects a deployed contract address + chain to fuzz. Two modes:

### Mode 1 — Onchain (fork, real bytecode)

Requires Etherscan-family API key for source fetch.

```bash
ITYFUZZ=~/baselines/ityfuzz/ityfuzz/target/release/ityfuzz
$ITYFUZZ evm \
    -o \
    -t 0x88A69B4E698A4B090DF6CF5BD7B2D47325AD30A3 \
    -c ETH \
    -b 15259100 \
    -i 1 \
    --onchain-url $ETH_RPC_URL \
    --onchain-etherscan-api-key $ETHERSCAN_API_KEY \
    --work-dir results/baselines/ityfuzz/nomad/work_dir_run_001
```

### Mode 2 — Offchain (compiled bytecode + ABI)

Works without API key if you pre-compile contracts locally.

```bash
# Compile our benchmark contract
solc --bin --abi -o /tmp/nomad_bin benchmarks/nomad/contracts/Replica.sol

$ITYFUZZ evm \
    -t '/tmp/nomad_bin/*' \
    --target-type address
```

ItyFuzz's offchain mode is less mature; recommended path is **onchain**
once you have an Etherscan key.

## Adapter

`baselines/ityfuzz/adapter.sh` translates `benchmarks/<bridge>/metadata.json`
into ItyFuzz CLI args. See file in same directory.

## Known issues / mitigations

- **Foundry feature** disabled in our build (`--no-default-features`)
  because foundry submodule has flaky pinning. We don't need cheatcodes
  for benchmark fuzzing.
- **Etherscan API quota**: ItyFuzz fetches ABI per address; rate-limited.
  Cache via `--storage-cache-dir` if running 12 benchmarks × 20 runs.
- **Block-number drift**: ItyFuzz forks at the *current* state of the
  RPC by default. `-b <block>` pins to historical block; ensure the RPC
  you use serves archive data (Alchemy / QuickNode / Ankr archive tier).
