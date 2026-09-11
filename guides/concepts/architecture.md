---
icon: network-wired
description: "Architectural design and zero-trust hardware boundaries of traces-sm."
---

# Architecture Overview

`traces-sm` partitions confidential secrets management into a zero-trust model:

```
┌────────────────────────────────────────────────────────────────────────┐
│ UNTRUSTED HOST OS / HYPERVISOR                                         │
│ • Axum REST & JSON-RPC Gateway                                         │
│ • SQLite Metadata Database (WAL mode, unencrypted tags/names only)     │
│ • Desktop GUI (eframe / egui) & CLI Tool                               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ EENTER / EEXIT (mTLS & RPC Dispatch)
┌───────────────────────────────────▼────────────────────────────────────┐
│ INTEL SGX ENCLAVE PAGE CACHE (EPC RAM)                                 │
│ • NIST SP 800-90A HMAC-DRBG with SP 800-90B RCT/APT Continuous Tests   │
│ • In-Enclave Asymmetric & PQC Key Generation (RSA, ECDSA, ML-KEM)      │
│ • Mandatory Security Policy (MSP) Engine                               │
│ • Zeroization on Drop (`zeroize::Zeroizing<T>`)                        │
│ • Hardware Master Sealing Key Derivation (AES-256-GCM)                 │
└────────────────────────────────────────────────────────────────────────┘
```

## Core Invariants

1. **CPU Hardware Isolation**: Plaintext keys, DRBG entropy states, and private keys reside exclusively in CPU-encrypted EPC memory.
2. **Deterministic Hardware Sealing**: Data written to host disk is encrypted under hardware-derived keys bound to the enclave measurement (`MRENCLAVE`).
3. **FIPS 140-3 Zeroization**: Volatile memory is overwritten with zeroes before deallocation.
