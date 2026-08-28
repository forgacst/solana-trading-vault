#!/usr/bin/env bash
set -e

echo "=== Solana Trading Vault Codespace setup ==="

# Rust 1.75 - used for Cargo.lock maintenance
if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  export PATH="$HOME/.cargo/bin:$PATH"
fi

rustup toolchain install 1.75.0

# solana-verify
if ! command -v solana-verify >/dev/null 2>&1; then
  cargo +1.75.0 install solana-verify --version 0.5.1
fi

echo
echo "Installing Node dependencies..."
npm ci

echo
echo "Rust:"
rustc --version || true
cargo --version || true

echo
echo "solana-verify:"
solana-verify --version

echo
echo "Setup complete."
echo "IMPORTANT: Never store authority keypairs in the repository."
