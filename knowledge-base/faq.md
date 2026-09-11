# ❓ Frequently Asked Questions (FAQs): `traces-sm`

---

## 🏗️ 1. Architecture & General

### What is `traces-sm`?
`traces-sm` is a 100% Rust-Native, enterprise-grade Key and Secret Management Framework that leverages Intel SGX (Software Guard Extensions) and the Fortanix Enclave Development Platform (EDP). It guarantees that all key generation, lifecycle states, envelope encryption, and signing operations take place inside hardware-isolated memory enclaves.

### How does `traces-sm` protect secrets against root/kernel exploits?
Even if an attacker gains root (`sudo`) access or compromises the host kernel/hypervisor, they cannot read the contents of the SGX Enclave Page Cache (EPC). The CPU's hardware memory encryption engine automatically encrypts and integrity-protects enclave memory pages at the silicon layer.

### What components are included in the repository?
* **`enclave/`**: The core SGX Fortanix EDP secure enclave containing all cryptographic algorithms and lifecycle state machines.
* **`host/`**: Axum 0.7 async REST API proxy with persistent SQLite metadata storage.
* **`cli/`**: Multi-OS command-line binary (`traces-sm`) for terminal automation and scripts.
* **`gui/`**: Rust WebAssembly (Yew 0.21) web client.
* **`desktop/`**: Cross-platform native desktop application (Linux, Windows, macOS via `egui`/`eframe`).
* **`bounty_bot/`**: Automated AI-driven bug bounty and security vulnerability tracker.

---

## 💻 2. Hardware, Intel SGX & Simulation Mode

### Do I need physical Intel SGX hardware to run or develop `traces-sm`?
**No.** `traces-sm` includes full software emulation and mock modes for local development and CI testing on any standard x86_64 or ARM64 computer (macOS, Windows, Ubuntu).

* **Development / Test Mode**: Compiles with standard target (`cargo build --workspace`). Enclave operations run with memory-isolated software simulation.
* **Production Hardware Mode**: Compiles for the Fortanix target (`x86_64-fortanix-unknown-sgx`) with `--features sgx-hw` to leverage real CPU `EGETKEY` sealing and DCAP attestation quotes.

### Which cloud providers support running `traces-sm` in hardware mode?
You can run `traces-sm` in full hardware SGX mode on:
* **Microsoft Azure**: DCsv2, DCsv3, and DCdsv3 confidential computing virtual machines.
* **Google Cloud Platform (GCP)**: Confidential VM nodes with SGX or TDX support.
* **Alibaba Cloud / OVHcloud / Equinix Metal**: Bare-metal and confidential instances with Intel Xeon SGX enabled.

---

## 🔐 3. Cryptography & Security

### What Post-Quantum Cryptography (PQC) algorithms are supported?
`traces-sm` implements the official NIST Post-Quantum standards:
* **ML-KEM-512 / 768 / 1024** (FIPS 203, Kyber): Quantum-resistant key encapsulation.
* **ML-DSA-44 / 87** (FIPS 204, Dilithium): Lattice-based digital signatures.
* **SLH-DSA** (FIPS 205, SPHINCS+): Stateless hash-based signatures.

### How does Zeroization work in `traces-sm`?
All cryptographic buffers, key shares, and plaintexts utilize Rust's `zeroize` crate with `ZeroizeOnDrop`. Whenever a secret object leaves scope or an operation encounters a panic/error, the underlying memory bytes are unconditionally overwritten with zeros, preventing memory forensics or cold-boot attacks.

### How does Threshold Cryptography work?
`traces-sm` provides built-in $M$-of-$N$ threshold schemes:
* **Shamir Secret Sharing (SSS)** over $GF(256)$ for classic key sharding.
* **Pedersen Verifiable Secret Sharing (VSS)** over Ristretto255.
* **FROST Ed25519**: Round-based threshold multi-party signing where the full private key is never assembled in a single location.

---

## ⚖️ 4. Comparison: `traces-sm` vs. Traditional Alternatives

| Feature | `traces-sm` | HashiCorp Vault | Cloud KMS (AWS/GCP/Azure) | Traditional Physical HSM |
| :--- | :---: | :---: | :---: | :---: |
| **Execution Environment** | Hardware Enclave (SGX) | Untrusted Host OS | Cloud Provider Memory | Dedicated Appliance |
| **Trust Model** | Zero-Trust Silicon Isolation | Relies on OS & Host Admin | Relies on Cloud Vendor Trust | Hardware Appliance |
| **Post-Quantum Native** | ✅ ML-KEM, ML-DSA, SLH-DSA | ❌ Third-party plugins | ⚠️ Limited Beta | ❌ Requires costly firmware |
| **Cost** | 💸 Low (Commodity SGX) | 💵 High (Enterprise licensing)| 💳 Per-API Call Pricing | 💰 $20k-$100k per box |
| **Threshold DKG & ZKP** | ✅ Built-in FROST / Bulletproofs| ❌ Classic Shamir Unseal only | ❌ Cloud-proprietary | ⚠️ Limited vendor APIs |
| **100% Rust-Native** | ✅ Full Memory Safety | ❌ Go (Garbage Collected) | ❌ Proprietary C/C++ | ❌ Proprietary Firmware |

---

## 🚀 5. Operations, Deployment & CI/CD

### How do I run `traces-sm` locally?
```bash
# Clone repository
git clone https://github.com/ttraces-io/secrets-manager.git
cd secrets-manager

# Run Desktop Application
cd desktop && cargo run --release

# Run Host Service Proxy
cd host && cargo run --release

# Generate a Key via CLI
cd cli && cargo run --release -- key generate --name app-key --algorithm aes-256-gcm
```

### Can I run `traces-sm` in Docker?
Yes! Multi-stage Dockerfiles and `docker-compose.yml` configurations are provided in the repository for both development simulation and production SGX device passthrough (`/dev/sgx_enclave` and `/dev/sgx_provision`).

---

## 🎁 6. Community & Contributor Rewards

### What is the Monthly $100 in BTC Lucky Contributor Reward?
Every calendar month, one lucky GitHub contributor who submits a merged, meaningful Pull Request (bug fixes, features, documentation, cryptographic tests, optimizations) is randomly selected to win **$100 in Bitcoin (BTC)**!

### Where can I join the community discussions?
* **Ecosystem Hub**: [https://ttraces.io](https://ttraces.io)
* **Discord Community**: [https://discord.gg/traces](https://discord.gg/traces)
* **GitHub Discussions**: [ttraces-io/secrets-manager Discussions](https://github.com/ttraces-io/secrets-manager/discussions)

### Where can I donate to support the project?
Open donations are gratefully accepted to our Solana (SOL) address:
```text
12D1qoP13upaB6AffHhvcpzBMwZkUGDAsYiNmJA5Jqsa
```
