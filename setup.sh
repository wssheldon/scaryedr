#!/bin/bash
set -e

# Install required packages
sudo apt-get -y update && sudo apt-get -y upgrade
sudo apt-get install -y clang llvm libelf-dev linux-headers-generic libssl-dev pkg-config build-essential

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"

# Install Rust toolchains
rustup install stable
rustup toolchain install nightly --component rust-src

# Install bpf-linker
cargo install bpf-linker

# Install cargo-generate
cargo install cargo-generate

# Print versions for verification
rustc --version
cargo --version
bpf-linker --version
cargo generate --version
cargo xtask build-ebpf
echo "Setup complete!"
