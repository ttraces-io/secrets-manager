# `traces-sm` — Technical Specification Document (10-Page Engineering Spec)
## 100% Rust-Native Multi-OS NIST SP 800-57 SGX Secrets & Key Management Framework

---

# PAGE 1: EXECUTIVE SUMMARY, SYSTEM VISION & COMPLIANCE MANDATES

## 1.1 Executive Overview
**`traces-sm`** is an open-source, enterprise-grade, hardware-enforced Key and Secret Management Framework engineered entirely in **100% Rust**. It isolates all sensitive key generation, secret storage, zero-knowledge proof generation, homomorphic encryption, and key derivation logic within an **Intel SGX Enclave Page Cache (EPC)** running on the **Fortanix Enclave Development Platform (EDP)** (`x86_64-fortanix-unknown-sgx`).

The platform guarantees that unencrypted private keys and secrets **never** exist in host memory or on unencrypted disk storage, protecting against compromised operating systems, cloud hypervisor introspection, and physical memory extraction.

## 1.2 Standards & Regulatory Compliance
`traces-sm` enforces strict adherence to key National Institute of Standards and Technology (NIST) and Federal Information Processing Standards (FIPS) mandates:

- **NIST SP 800-57 Part 1 Rev. 5**: Recommendation for Key Management — 4-phase key lifecycle state machine (`PreOperational`, `Operational`, `Deactivated`, `Expired`, `Revoked`, `Destroyed`), cryptoperiod volume limits ($2^{32}$ bytes for AES-GCM), and explicit `KeyUsage` bitmask validation.
- **NIST SP 800-130**: Framework for Designing Cryptographic Key Management Systems (CKMS).
- **NIST SP 800-90A/B/C**: Recommendation for Random Number Generation — `HMAC_DRBG` seeded via SGX `RDRAND`/`RDSEED` hardware entropy with continuous **Repetition Count Test (RCT)** and **Adaptive Proportion Test (APT)** health testing.
- **NIST SP 800-108**: Recommendation for Key Derivation Using Pseudorandom Functions (KDF in Counter Mode).
- **NIST SP 800-38F**: Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping (`AES-KW` / `AES-KWP`).
- **NIST SP 800-88 Rev. 1**: Guidelines for Media Sanitization — Cryptographic Erasure ("Crypto-Shredding") overwriting storage sectors with random noise prior to unlinking file descriptors.
- **FIPS 140-3 Level 3/4**: Security Requirements for Cryptographic Modules — Volatile memory scrubbing (`zeroize::Zeroizing<T>`) scrubbing RAM registers on drop.

---

# PAGE 2: 100% RUST-NATIVE MULTI-CRATE TECHNOLOGY STACK

`traces-sm` is constructed as a unified multi-crate Cargo workspace (`Cargo.toml`) eliminating cross-language FFI overhead and foreign code vulnerabilities.

```
Secrets-Manager/
├── Cargo.toml                  ← Workspace Root ([workspace] members = ["enclave", "host", "gui", "cli", "desktop"])
├── enclave/                    ← SGX Enclave (`x86_64-fortanix-unknown-sgx`)
├── host/                       ← Axum Host Proxy (`x86_64-unknown-linux-gnu`)
├── gui/                        ← Yew WebAssembly (`wasm32-unknown-unknown`)
├── cli/                        ← Clap Multi-OS Binary (`x86_64-linux`, `windows-msvc`, `apple-darwin`)
└── desktop/                    ← eframe/egui Desktop App (`Ubuntu`, `Windows 10/11`, `macOS`)
```

## 2.1 Crate & Dependency Matrix

| Workspace Crate | Target Triple | Core Rust Crate Dependencies | System Role & Execution Scope |
|---|---|---|---|
| **`enclave`** | `x86_64-fortanix-unknown-sgx` | `ring`, `rsa`, `schnorrkel`, `bulletproofs`, `curve25519-dalek`, `num-bigint`, `zeroize`, `httparse` | Executes inside SGX EPC. Handles sealing, keygen, PQC, DKG, ZKP, PHE, and SP 800-90B DRBG. |
| **`host`** | `x86_64-unknown-linux-gnu` / Native | `axum 0.7`, `tokio 1.38`, `tower-http`, `rusqlite` (SQLCipher), `reqwest 0.12`, `tracing` | Untrusted host process. Serves WASM GUI static assets on port `8080`, proxies enclave REST requests, manages metadata DB. |
| **`gui`** | `wasm32-unknown-unknown` | `yew 0.21`, `gloo-net 0.6`, `wasm-bindgen`, `web-sys`, `wasm-logger` | Single-page WebAssembly browser dashboard compiled via `trunk`. |
| **`cli`** | Cross-Compiled Targets | `clap 4.5`, `reqwest 0.12`, `tokio`, `comfy-table`, `colored` | Terminal CLI tool (`traces-sm`) for automated scripts, CI/CD, and sysadmin control. |
| **`desktop`** | Cross-Platform Native | `eframe 0.28`, `egui 0.28`, `tokio`, `reqwest` | Native desktop app rendering via GTK (Linux), WebView2 (Windows), or WKWebView (macOS). |

---

# PAGE 3: HIGH-LEVEL SYSTEM ARCHITECTURE & TRUST BOUNDARIES

The architecture strictly separates the **Untrusted Host Domain** from the **Trusted Enclave Domain (Intel SGX EPC)**.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                UNTRUSTED CLIENT & HOST DOMAIN                                    │
│                                                                                                  │
│  ┌──────────────────────────┐  ┌──────────────────────────────┐  ┌─────────────────────────────┐  │
│  │ Rust WebAssembly Web GUI │  │ Rust Native Desktop App      │  │ Rust Native CLI Tool        │  │
│  │ (`gui/` -> Yew 0.21 WASM)│  │ (`desktop/` -> Ubuntu, Win,  │  │ (`cli/` -> Multi-OS Distros)│  │
│  └────────────┬─────────────┘  └──────────────┬───────────────┘  └──────────────┬──────────────┘  │
│               │                               │                                 │                │
├───────────────┼───────────────────────────────┼─────────────────────────────────┼────────────────┤
│               └───────────────────────────────┼─────────────────────────────────┘                │
│                                               │ REST / mTLS (Port 8080)                          │
│  ┌────────────────────────────────────────────▼───────────────────────────────────────────────┐  │
│  │ Rust Native Host Proxy (`host/` -> Axum 0.7 + Tokio + Rusqlite)                            │  │
│  │ • Static WASM Asset Server                                                                 │  │
│  │ • SQLite SQLCipher Metadata & Audit Database                                               │  │
│  │ • DKG Peer Topology Coordinator                                                            │  │
│  └────────────────────────────────────────────┬───────────────────────────────────────────────┘  │
├───────────────────────────────────────────────┼──────────────────────────────────────────────────┤
│ TRUSTED ENCLAVE DOMAIN (Intel SGX EPC)        │ mTLS / RA-TLS (Port 8443)                        │
│  ┌────────────────────────────────────────────▼───────────────────────────────────────────────┐  │
│  │ Fortanix EDP Rust Enclave (`enclave/` -> `x86_64-fortanix-unknown-sgx`)                    │  │
│  │                                                                                            │  │
│  │  ┌─────────────────────────────┐   ┌─────────────────────────────┐                         │  │
│  │  │ Mandatory Security Policy   │   │ SP 800-90A/B/C DRBG Engine  │                         │  │
│  │  │ Engine (`policy.rs`)        │   │ (HMAC_DRBG, APT & RCT)      │                         │  │
│  │  └──────────────┬──────────────┘   └──────────────┬──────────────┘                         │  │
│  │                 │                                 │                                        │  │
│  │  ┌──────────────▼──────────────┐   ┌──────────────▼──────────────┐                         │  │
│  │  │ SP 800-57 Lifecycle Engine  │   │ Sealing & Key Derivation    │                         │  │
│  │  │ (Pre-Op -> Destroyed)       │   │ (EGETKEY + HKDF-SHA256)     │                         │  │
│  │  └──────────────┬──────────────┘   └──────────────┬──────────────┘                         │  │
│  │                 │                                 │                                        │  │
│  │  ┌──────────────▼─────────────────────────────────▼──────────────┐                         │  │
│  │  │ Cryptographic & Zero-Knowledge Engine                         │                         │  │
│  │  │ • RSA-4096 / ECDSA / Ed25519 / PQC (ML-KEM, ML-DSA)            │                         │  │
│  │  │ • Schnorr PoK / Bulletproof Range Proofs / Paillier PHE       │                         │  │
│  │  │ • Shamir SSS / Pedersen VSS $M$-of-$N$ Threshold DKG          │                         │  │
│  │  └──────────────┬────────────────────────────────────────────────┘                         │  │
│  │                 │                                                                          │  │
│  │  ┌──────────────▼────────────────────────────────────────────────┐                         │  │
│  │  │ Sealed Storage & FIPS 140-3 Zeroization (`store.rs`)            │                         │  │
│  │  └───────────────────────────────────────────────────────────────┘                         │  │
│  └────────────────────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

## 3.1 Trust Isolation Invariants
1. **Memory Encryption**: The Enclave Page Cache (EPC) is encrypted by hardware CPU memory controllers using AES-128/256-XTS.
2. **Key Non-Exportability**: Unencrypted private key bytes are created inside `Zeroizing<Vec<u8>>` containers and never leave EPC memory.
3. **Sealing Isolation**: Sealing keys are derived via SGX `EGETKEY` instruction bound to `MRSIGNER` and `ISVSVN`.

---

# PAGE 4: CRYPTOGRAPHIC ENGINE & ALGORITHM CATALOG DEEP-DIVE

`traces-sm` combines classic asymmetric/symmetric algorithms, post-quantum algorithms, and advanced zero-knowledge proof primitives inside the enclave.

## 4.1 In-Enclave Algorithm Catalog (`keygen.rs` & `models.rs`)

| Algorithm Family | Supported Key Generation Schemes | Standard / Spec | Primary Function |
|---|---|---|---|
| **RSA** | RSA-2048, RSA-4096 | FIPS 186-5 / PKCS#1 v1.5 / OAEP | Asymmetric signing, PKCS#8 PEM export, OAEP encryption |
| **ECDSA** | P-256, P-384, P-521, Secp256k1 | FIPS 186-5 / SECG / Bitcoin-Ethereum | Elliptic curve digital signatures, ECDH key agreement |
| **Ed25519 / X25519** | Ed25519, X25519 | RFC 8032 / RFC 7748 | Fast EdDSA signatures & Montgomery curve Diffie-Hellman |
| **ML-KEM (Kyber)** | ML-KEM-512, ML-KEM-768, ML-KEM-1024 | NIST FIPS 203 (PQC KEM) | Quantum-resistant key encapsulation mechanism |
| **ML-DSA (Dilithium)**| ML-DSA-3 (ML-DSA-44), ML-DSA-5 (ML-DSA-87) | NIST FIPS 204 (PQC Signatures) | Quantum-resistant lattice digital signatures |
| **SLH-DSA (SPHINCS+)**| SLH-DSA-SHA2-128f / 256f | NIST FIPS 205 (PQC Hash-Sign) | Stateless hash-based post-quantum digital signatures |
| **AES & Key Wrap** | AES-128-GCM, AES-256-GCM, AES-KW | NIST SP 800-38D / SP 800-38F | Envelope encryption & exportable KEK payload wrapping |
| **HMAC & Stream** | HMAC-SHA256, HMAC-SHA512, ChaCha20 | FIPS 198-1 / RFC 8439 | Message authentication codes & authenticated stream encryption |
| **Threshold DKG** | Shamir SSS, Pedersen VSS, FROST | RFC 9591 / DKLs23 | $M$-of-$N$ threshold secret sharing & threshold Ed25519 sign |
| **SSL/TLS & PKI** | X.509 Cert Bundles, OpenSSH KeyPairs | RFC 5280 / OpenSSH protocol | Server/CA certificate issuance & SSH authentication |

## 4.2 Zero-Knowledge Proof (ZKP) Primitives
- **Schnorr Proof-of-Knowledge (PoK)**: Implemented over Ristretto255 using the `schnorrkel` crate. Proves knowledge of secret token $s$ such that $C = \text{Hash}(s) \cdot G$ without disclosing $s$.
- **Bulletproofs Range Proofs**: Implemented via the `bulletproofs` crate. Proves numerical values satisfy $\text{min} \le v \le \text{max}$ (e.g., $0 \le \text{TTL} \le 86400$) over a 32-bit range without a trusted setup.

## 4.3 Homomorphic Encryption (PHE)
- **Paillier Cryptosystem (2048-bit)**:
  - Additive Homomorphism: $\text{Enc}(m_1) \cdot \text{Enc}(m_2) \pmod{n^2} = \text{Enc}(m_1 + m_2 \pmod n)$
  - Scalar Multiplication: $\text{Enc}(m)^k \pmod{n^2} = \text{Enc}(k \cdot m \pmod n)$

---

# PAGE 5: NETWORKING & PROTOCOL SPECS FOR DISTRIBUTED KEYS, DKG & MPC

When configured in distributed mode, `traces-sm` coordinates key management across an $M$-of-$N$ threshold topology of peer nodes.

```
                           ┌─────────────────────────────┐
                           │ Node 1: SGX Primary Enclave │
                           │ (DCAP Attested, mTLS 8443)  │
                           └──────────────┬──────────────┘
                                          │
                   ┌──────────────────────┴──────────────────────┐
                   │ mTLS + RA-TLS Quote Exchange                │
                   │ (P2P Mesh Network over TCP 8443)            │
                   │                                             │
        ┌──────────▼──────────┐                       ┌──────────▼──────────┐
        │ Node 2: DKG Peer    │                       │ Node 3: DKG Peer    │
        │ (Threshold Share 1) │                       │ (Threshold Share 2) │
        └─────────────────────┘                       └─────────────────────┘
```

## 5.1 Remote Attestation TLS (RA-TLS) Handshake
Inter-node network communication uses RA-TLS to bind Intel DCAP attestation quotes directly into X.509 TLS certificates.

```
Node A (SGX Primary)                             Node B (DKG Peer)
  │                                                   │
  ├────── ClientHello + RA-TLS Cert (DCAP Quote A) ──>│
  │                                                   │
  │<───── ServerHello + RA-TLS Cert (DCAP Quote B) ───┤
  │                                                   │
  │ [ Verify Quote B via Intel PCCS ]                 │ [ Verify Quote A via Intel PCCS ]
  │                                                   │
  └══════════════ Encrypted mTLS Session Established (AES-256-GCM) ══════════════┘
```

## 5.2 Distributed Key Generation (DKG) Protocol Sequence
1. **Key-Level & Byte-Level Scope**: Secret splitting supports full key payload slices (`&[u8]`) via `split_secret_bytes()` as well as single byte-level `split_secret()`, evaluating Shamir's Secret Sharing over GF(256) for each byte of key material.
2. **NIST SP 800-90A DRBG Randomness**: Polynomial coefficient generation is strictly driven by the enclave's NIST SP 800-90A `HMAC_DRBG` (`drbg.rs`), eliminating dependency on OS PRNGs (`rand::thread_rng()`).
3. **Round 1 (Polynomial Commitment)**: Each node $i$ generates a random polynomial $f_i(x) = a_{i,0} + a_{i,1}x + \dots + a_{i,M-1}x^{M-1}$ of degree $M-1$ and broadcasts Pedersen commitments $C_{i,k} = a_{i,k} \cdot G + r_{i,k} \cdot H$.
4. **Round 2 (Share Distribution)**: Node $i$ securely sends evaluation share $s_{i,j} = f_i(j)$ to Node $j$ over the RA-TLS channel.
5. **Share Verification & Key Derivation**: Node $j$ verifies received shares against commitments:
   $$s_{i,j} \cdot G + r_{i,j} \cdot H \stackrel{?}{=} \sum_{k=0}^{M-1} j^k \cdot C_{i,k}$$
   Upon verification, Node $j$ computes its master threshold share $x_j = \sum_{i=1}^N s_{i,j}$.

---

# PAGE 6: MODULE-WISE DEEP-DIVE & DATA FLOW — CRYPTOGRAPHIC CORE

```
                                    SEALED SECRET DATA FLOW
                                    
  Plaintext Secret ──> [ drbg.rs: Random DEK ] ──> [ AES-256-GCM Encrypt ] ──> Ciphertext
                                                             │
  Sealing Key ◄────── [ sealing.rs: HKDF-SHA256 ] ◄────── [ EGETKEY ]
       │                                                     │
       └─────────────────────────────────────────────────────┴──> Sealed DEK (60B)
                                                                       │
                                              [ store.rs ] ◄───────────┘
                                              • {id}.meta.json (Plaintext)
                                              • {id}.blob (Sealed DEK || Nonce || Ciphertext)
```

## 6.1 `enclave/src/sealing.rs` Data Flow
- **Input**: Plaintext data bytes, `purpose` string label (`"seal:secrets"`, `"seal:private-key"`).
- **Execution Steps**:
  1. SGX Hardware: Issues `EGETKEY` with `KEYPOLICY_MRSIGNER` $\to$ 16-byte raw hardware key.
  2. Master Expansion: SHA-256 expands 16-byte raw key to 32-byte Master Sealing Key.
  3. HKDF Expansion: HKDF-SHA256 with salt `b"traces-sm-enclave-v1"` and info `purpose` derives 32-byte DEK.
  4. Encryption: AES-256-GCM encrypts payload with 12-byte random nonce.
- **Output**: Sealed blob formatted as `[ Nonce (12B) || Ciphertext || Tag (16B) ]`.

## 6.2 `enclave/src/drbg.rs` Data Flow
- **NIST SP 800-90A HMAC_DRBG**: Initialized with 32 bytes of SGX `RDRAND`/`RDSEED` entropy.
- **NIST SP 800-90B Health Tests**:
  - **Repetition Count Test (RCT)**: Evaluates consecutive output bytes. Rejects if identical bytes exceed $C = 16$.
  - **Adaptive Proportion Test (APT)**: Evaluates sliding sample window $W = 512$. Rejects if base sample count exceeds $C = 13$.

## 6.3 `enclave/src/nist.rs` State Machine Data Flow
Enforces state transitions: `PreOperational` $\to$ `Operational` $\to$ `Deactivated` $\to$ `Expired` $\to$ `Revoked` $\to$ `Destroyed`. Rejects signing/encryption on `Deactivated` keys while permitting historical decryption.

---

# PAGE 7: MODULE-WISE DEEP-DIVE & DATA FLOW — HOST PROXY & PERSISTENCE

The untrusted host proxy (`host/`) bridges external REST clients to the enclave and handles metadata persistence.

```
Client / CLI / GUI            Axum Host Proxy (8080)          SQLite (SQLCipher)           SGX Enclave (8443)
       │                                │                              │                            │
       ├────── POST /v1/secrets ───────>│                              │                            │
       │                                ├────── Forward REST Request ──────────────────────────────>│
       │                                │                              │                            │
       │                                │                              │ [ Seal via EGETKEY/AES-GCM ]
       │                                │                              │ [ Save .meta.json & .blob  ]
       │                                │<───── HTTP 200 OK (Metadata) ─────────────────────────────┤
       │                                ├────── Insert Metadata ──────>│                            │
       │                                ├────── Insert Audit Record ──>│                            │
       │<───── HTTP 200 OK Response ────┤                              │                            │
```

## 7.1 Database Schema (`host/src/db.rs`)
- `secrets_metadata`: `id`, `name`, `secret_type`, `version`, `algorithm`, `owner`, `tags`, `lifecycle_state`, `usage_flags`, `bytes_processed`, `max_bytes`, `created_at`, `updated_at`.
- `audit_logs`: `id`, `timestamp`, `principal`, `action`, `resource_id`, `source_ip`, `result`, `details`.
- `dkg_nodes`: `id`, `endpoint`, `node_role`, `status`, `threshold_m`, `total_n`.
- `entropy_audits`: `id`, `timestamp`, `rct_passed`, `apt_passed`, `reseed_count`.

---

# PAGE 8: MODULE-WISE DEEP-DIVE & DATA FLOW — USER INTERFACES & TRACES AI

`traces-sm` provides three 100% Rust-native client interfaces sharing an integrated **Traces AI Assistant**:

```
                               ┌────────────────────────────────────────┐
                               │       User Interface Layer             │
                               └──────────────────┬─────────────────────┘
                                                  │
         ┌────────────────────────────────────────┼────────────────────────────────────────┐
         │                                        │                                        │
┌────────▼────────────────┐            ┌──────────▼─────────────┐            ┌─────────────▼──────────┐
│ Rust WebAssembly GUI    │            │ Rust Desktop App       │            │ Rust Native CLI        │
│ (`gui/`)                │            │ (`desktop/`)           │            │ (`cli/`)               │
│ • Yew 0.21              │            │ • eframe 0.28 / egui   │            │ • Clap 4.5             │
│ • wasm32 target         │            │ • Native GTK / Win /  │            │ • Reqwest              │
│ • gloo-net fetch client │            │   macOS window         │            │ • Multi-OS binaries    │
└─────────────────────────┘            └────────────────────────┘            └────────────────────────┘
```

## 8.1 Traces AI Assistant Panel (`gui/src/components/traces_ai.rs` & `desktop/src/main.rs`)
- **Anthropic API Connectivity**: Connects to Claude 3.5 Sonnet using user-provided API keys (`sk-ant-api...`).
- **Enclave Context Binding**: Evaluates in-enclave policy enforcement state (`policy.rs`), key cryptoperiod volume meters, and DCAP attestation quotes.
- **Diagnostic Shortcuts**: Quick diagnostic triggers: `[Why k-104?]`, `[APT cutoff]`, `[Quorum health]`.

---

# PAGE 9: SECURITY THREAT MODEL, RISK MITIGATION & FIPS 140-3 ZEROIZATION

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SECURITY THREAT & MITIGATION MATRIX                            │
├───────────────────────────────┬─────────────────────────────────┬────────────────────────────────┤
│ Threat Vector                 │ Risk Impact                     │ Hardware / Software Mitigation │
├───────────────────────────────┼─────────────────────────────────┼────────────────────────────────┤
│ Host OS / Hypervisor Compromise│ Memory Introspection / Snooping │ Intel SGX Hardware EPC Mem Enc │
│ Unsealed Storage Extraction   │ Secret Theft from Disk          │ AES-256-GCM Sealing (EGETKEY)  │
│ Cold Boot / RAM Dump Attack   │ Residual Key Material in RAM    │ FIPS 140-3 `Zeroizing<T>` Scrub│
│ Man-in-the-Middle Network     │ Intercept Payload In-Transit    │ RA-TLS mTLS Quote Binding      │
│ Quantum Computing Decryption  │ RSA/ECC Key Factorization       │ ML-KEM-768 & ML-DSA-3 PQC      │
│ Storage Deletion Recovery     │ Forensics File Recovery         │ NIST SP 800-88 Crypto-Shredding│
└───────────────────────────────┴─────────────────────────────────┴────────────────────────────────┘
```

## 9.1 Memory Zeroization & Cryptographic Erasure
- **FIPS 140-3 RAM Scrubbing**: `enclave/src/` wraps all sensitive byte vectors in `zeroize::Zeroizing<Vec<u8>>`. On `Drop`, memory regions are overwritten with zero bytes using volatile compiler intrinsics.
- **NIST SP 800-88 Crypto-Shredding**: `store.rs::crypto_shred(id)` overwrites storage file sectors with random bytes before executing filesystem unlinking, rendering data recovery cryptographically impossible.

---

# PAGE 10: MULTI-OS DISTRIBUTION, BUILD PIPELINES & OPERATIONS

## 10.1 Multi-Platform Cross-Compilation Matrix

| Platform / OS | Binary Target Triple | Packaging Tool | Distribution Format |
|---|---|---|---|
| **Ubuntu / Debian** | `x86_64-unknown-linux-gnu` | `cargo deb` | `.deb` installer package |
| **Alpine Linux** | `x86_64-unknown-linux-musl` | `cargo build --target musl` | Static musl binary / `.apk` |
| **Fedora / RHEL** | `x86_64-unknown-linux-gnu` | `cargo generate-rpm` | `.rpm` installer package |
| **ARM64 Linux / Graviton** | `aarch64-unknown-linux-gnu` | `cross build --target aarch64` | Tarball archive |
| **Windows 10 / 11** | `x86_64-pc-windows-msvc` | `cargo wix` | `.msi` installer, Winget package |
| **macOS (Intel & M1/2/3)** | `aarch64-apple-darwin` / `x86_64` | Homebrew formula | `brew install traces-sm` / `.dmg` |
| **Web Browser** | `wasm32-unknown-unknown` | `trunk build --release` | `.wasm` bundle served by Axum |
| **Intel SGX Enclave** | `x86_64-fortanix-unknown-sgx` | `ftxsgx-elf2sgxs` | `.sgxs` enclave binary |

## 10.2 Production Docker Deployment

```yaml
version: '3.8'
services:
  enclave:
    image: traces-sm-enclave:latest
    devices:
      - "/dev/sgx_enclave:/dev/sgx_enclave"
      - "/dev/sgx_provision:/dev/sgx_provision"
    ports:
      - "8443:8443"
    environment:
      - SGX_MODE=HW
      - SM_STORE_PATH=/store
    volumes:
      - enclave-store:/store

  host:
    image: traces-sm-host:latest
    ports:
      - "8080:8080"
    environment:
      - ENCLAVE_URL=https://enclave:8443
    depends_on:
      - enclave

volumes:
  enclave-store:
```
