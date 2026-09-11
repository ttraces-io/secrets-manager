---
icon: bolt
description: "Quick start guide for interacting with traces-sm CLI and Desktop applications."
---

# Quickstart Guide

Get up and running with `traces-sm` in less than 5 minutes.

## 1. Start the Host Gateway & Enclave

```bash
cd host
cargo run --release
```

The host daemon initializes the SQLite metadata store and binds the HTTP API listener on `http://127.0.0.1:8080`.

## 2. Generate a Cryptographic Keypair

Generate an RSA-4096 or Ed25519 keypair inside SGX memory:

```bash
# Generate in-enclave Ed25519 signing key
traces-sm key generate --name primary-signer --algorithm ed25519

# Generate NIST FIPS 203 ML-KEM-768 Post-Quantum key
traces-sm key generate --name pqc-kem-key --algorithm ml-kem-768
```

## 3. Seal and Retrieve a Confidential Secret

```bash
# Seal a sensitive API token into hardware-encrypted storage
traces-sm secret create --name db-password --value "super_secret_master_password_987654"

# Inspect metadata (note: plaintext is never exposed in metadata)
traces-sm secret get --name db-password
```

## 4. Run the Desktop GUI Console

```bash
cd desktop
cargo run --release
```
