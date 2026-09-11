# 🧪 `devtest` — Enterprise Testing & Verification Module for `traces-sm`

`devtest` is a rigorous, automated testing and diagnostic framework engineered to verify every subsystem, cryptographic primitive, policy invariant, and network endpoint of `traces-sm` across all target environments (including Windows native and Non-SGX simulation mode).

---

## 🏗️ Architectural Overview & Test Suites

The module comprises **12 specialized test suites** executing end-to-end assertions:

| # | Suite Name | Category | Description |
| :- | :--- | :--- | :--- |
| **01** | **Environment & Windows Simulation** | `Environment` | Verifies 64-bit target platform, Windows path normalization, and non-SGX fallback. |
| **02** | **Cryptographic Algorithms** | `Cryptography` | Tests AES-128/256-GCM, RSA (2048/4096 OAEP/PSS), ECDSA P-256/384, Ed25519, X25519, ChaCha20-Poly1305, and PQC parameters. |
| **03** | **NIST SP 800-57 Key Lifecycle** | `NIST Standards` | Validates PreOperational $\to$ Operational $\to$ Deactivated $\to$ Destroyed transitions, permission bitmasks, and SP 800-108 KDF in Counter Mode. |
| **04** | **NIST SP 800-90B Entropy Health** | `Entropy & TRNG` | Executes continuous Repetition Count Test (RCT $C=16$), Adaptive Proportion Test (APT $W=512, C=13$), and Shannon entropy statistical checks. |
| **05** | **FIPS 140-3 Zeroization & Policies** | `Compliance` | Verifies in-memory `Zeroizing` buffer scrubbing upon drop and Mandatory Security Policy (MSP) invariants. |
| **06** | **Zero-Knowledge Proofs (ZKP)** | `ZKP Protocols` | Evaluates Schnorr $\Sigma$-protocol Proof-of-Knowledge, Bulletproofs 32-bit range proofs, and Pedersen homomorphic commitments. |
| **07** | **Paillier Homomorphic Encryption** | `Homomorphic Crypto` | Tests 2048-bit Paillier PHE keygen, encryption, homomorphic ciphertext addition ($C_1 \cdot C_2 \pmod{n^2} \implies m_1 + m_2$), and scalar multiplication. |
| **08** | **DKG & FROST Threshold Signatures** | `Threshold DKG` | Verifies Shamir $(3,5)$ secret sharing/reconstruction and FROST 2-of-3 threshold Ed25519 signing (commitment, sign shares, aggregate, verify). |
| **09** | **Sealed Storage & Tamper Resistance** | `Storage & Security` | Tests `SimSealingProvider`, on-disk CRUD operations, NIST SP 800-88 crypto-shredding, and ciphertext/MAC corruption detection. |
| **10** | **In-Enclave JWT Authentication** | `Authentication` | Verifies Ed25519 JWT issuance, claims decoding, role-based access control, and JTI revocation list enforcement. |
| **11** | **Host SQLite Database** | `Host Gateway` | Tests SQLite schema initialization, Write-Ahead Logging (WAL) pragmas, concurrent queries, and audit log appending. |
| **12** | **Live In-Enclave HTTP/1.1 Server** | `Network & Endpoints` | Spawns an ephemeral live in-enclave HTTP listener on loopback and executes live end-to-end requests across all REST endpoints. |

---

## 🚀 Execution Instructions

### Option 1: Automated Script (Recommended)

#### On Windows (PowerShell):
```powershell
.\devtest\run_all_tests.ps1
```

#### On Linux / macOS (Bash):
```bash
./devtest/run_all_tests.sh
```

---

### Option 2: Standalone CLI Diagnostic Runner

Run with full colorful terminal dashboard and generate an audit report:
```bash
cargo run -p traces-sm-devtest -- --all --report devtest/test_report.md
```

Output machine-readable JSON:
```bash
cargo run -p traces-sm-devtest -- --json
```

---

### Option 3: Standard Cargo Integration Tests

```bash
cargo test -p traces-sm-devtest -- --nocapture
```
