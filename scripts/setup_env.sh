#!/bin/bash
# Environment setup script for BridgeSentry

set -e

echo "=== BridgeSentry Environment Setup ==="

# 1. Python virtual environment
echo "[1/4] Setting up Python environment..."
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# 2. Rust toolchain
echo "[2/4] Checking Rust toolchain..."
if ! command -v rustc &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
rustc --version

# 3. Foundry (anvil, forge, cast)
echo "[3/4] Checking Foundry..."
if ! command -v anvil &> /dev/null; then
    echo "Installing Foundry..."
    curl -L https://foundry.paradigm.xyz | bash
    foundryup
fi
anvil --version

# 4. Build Rust fuzzer
echo "[4/4] Building Dual-EVM fuzzer..."
cd src/module3_fuzzing
cargo build --release
cd ../..

echo "=== Setup complete ==="
echo "Activate venv: source .venv/bin/activate"
echo "Copy .env.example to .env and fill in your API keys"
