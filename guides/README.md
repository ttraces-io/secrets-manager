---
icon: book-open
description: "Overview and user guides for the traces-sm Intel SGX secrets and key management platform."
---

# Guides & Quickstart

Welcome to the **`traces-sm`** documentation guides. `traces-sm` is a 100% Rust-Native, enterprise-grade Key & Secret Management Framework built on **Intel SGX using Fortanix EDP** (`x86_64-fortanix-unknown-sgx`).

## What is traces-sm?

`traces-sm` delivers hardware-isolated cryptographic operations and key lifecycle management directly inside Intel SGX Enclave Page Cache (EPC) memory. The untrusted host OS, hypervisor, and co-located processes cannot inspect or tamper with plaintext keys, random number generator states, or threshold shares.

> [!NOTE]
> `traces-sm` implements full compliance with **NIST SP 800-57 / SP 800-130 / FIPS 140-3** lifecycle guidelines, featuring Post-Quantum Cryptography, $M$-of-$N$ Threshold DKG, and Mandatory Security Policies.

## Next Steps

* [Installation](getting-started/installation.md) — Install prerequisites and build the workspace.
* [Quickstart](getting-started/quickstart.md) — Initialize the enclave and execute key operations.
* [Architecture Overview](concepts/architecture.md) — Understand the zero-trust enclave boundary.
