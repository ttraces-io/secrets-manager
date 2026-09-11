---
icon: download
description: "Installation and build setup for traces-sm across Linux, Windows, and macOS."
---

# Installation & Setup

`traces-sm` supports both hardware-enforced SGX production environments and simulation/development execution across Linux, Windows, and macOS.

## Prerequisites

* **Rust Toolchain**: Stable `1.80+` (`rustup update stable`)
* **Operating System Support**:
  * **Linux (Production)**: Ubuntu 22.04 / 24.04 with Intel SGX DCAP Driver (`/dev/sgx_enclave`)
  * **Windows / macOS (Simulation & Client)**: Full simulation mode supported natively

## Building the Workspace

```bash
# Clone the repository
git clone https://github.com/ttraces-io/secrets-manager.git
cd secrets-manager

# Build entire multi-crate workspace
cargo build --workspace --release

# Run comprehensive test harness
cargo test -p traces-sm-devtest -- --nocapture
```

## Running with Debug Mode

To enable debug diagnostic logging, launch the CLI or Desktop application with `--debug` or set `TRACES_SM_DEBUG=1`:

```bash
# CLI with debug diagnostics
cargo run --release -p traces-sm -- --debug health

# Desktop GUI with diagnostics drawer
cargo run --release -p traces-sm-desktop -- --debug
```
