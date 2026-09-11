---
icon: shield-halved
description: "Mandatory Security Policy engine, cryptoperiod enforcement, and Safe Mode quarantine."
---

# Mandatory Security Policy (MSP) Engine

The **Mandatory Security Policy (MSP) Engine** acts as an in-enclave governance authority, evaluating declarative security constraints before executing any cryptographic operation.

## Invariant Enforcement Rules

* **Hardware Boundary**: Disallows export of unencrypted private key material.
* **Algorithm Restriction**: Enforces permitted algorithm lists (e.g. `AES-256-GCM`, `ML-KEM-768`).
* **Cryptoperiod Volume Limits**: Automatically enforces maximum byte thresholds (default: $2^{32}$ bytes = 4 GiB).
* **Safe Mode Quarantine**: When environmental or network anomalies are detected, the enclave enters an emergency lockdown state.
