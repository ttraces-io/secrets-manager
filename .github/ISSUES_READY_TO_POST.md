# GitHub Issues Ready to Post for `traces-sm`

This document contains 8 fully formulated, high-impact GitHub Issues ready to be created in the [ttraces-io/secrets-manager](https://github.com/ttraces-io/secrets-manager/issues) repository.

---

## 📌 Issue #1: [BUG] SGX Enclave Sealing Key Derivation Edge-Case Under High Concurrency
**Labels**: `bug`, `enclave`, `security`, `p0`  
**Assignee**: Open for contributors  

### Description
Under heavy concurrent sealing and unsealing requests to the SGX enclave, the derived sealing key cache in `enclave/src/sealing.rs` may encounter lock contention or potential race conditions during key rotation events.

### Reproduction Steps
1. Launch the SGX enclave with `--concurrency 64`.
2. Dispatch 10,000 rapid sealing operations across multiple threads.
3. Observe intermittent `EnclaveError::SealingKeyDerivationFailed` or delayed response times.

### Expected Behavior
Key derivation and envelope sealing should remain lock-free or use fine-grained read-write locks (`parking_lot::RwLock`) to ensure deterministic performance and thread safety.

### Acceptance Criteria
- [ ] Add concurrency stress unit tests in `enclave/tests/sealing_concurrency.rs`.
- [ ] Refactor sealing key derivation cache to avoid thread contention.
- [ ] Ensure all zeroization guarantees remain intact during thread aborts.

---

## 📌 Issue #2: [FEAT] Add Post-Quantum ML-DSA-87 (Dilithium5) Signature Verification in CLI
**Labels**: `enhancement`, `pqc`, `cli`, `fips-204`  
**Assignee**: Open for contributors  

### Description
`traces-sm` currently supports ML-DSA-3 (ML-DSA-44) key generation and signing in the enclave. We need to expose CLI subcommands for ML-DSA-87 (FIPS 204 Parameter Set 5) signature generation and verification.

### Proposed CLI Interface
```bash
# Key Generation
traces-sm key generate --algorithm ml-dsa-87 --name post-quantum-sign-key

# Sign Payload
traces-sm sign --key post-quantum-sign-key --input data.bin --output signature.sig

# Verify Payload
traces-sm verify --key post-quantum-sign-key --input data.bin --signature signature.sig
```

### Acceptance Criteria
- [ ] Integrate ML-DSA-87 parameters into `cli/src/commands/sign.rs` and `cli/src/commands/verify.rs`.
- [ ] Add CLI integration tests checking round-trip sign/verify.
- [ ] Document the CLI usage in `docs/CLI.md`.

---

## 📌 Issue #3: [INFRA] Fix CI Workspace Linux Dependencies for Desktop egui/eframe Compilation
**Labels**: `ci`, `infrastructure`, `build`  
**Assignee**: Open for contributors  

### Description
In `.github/workflows/ci.yml`, the `rust-workspace` job runs `cargo build --workspace --all-targets` on `ubuntu-latest`. Because `desktop` depends on `eframe`/`egui`, building on Linux without X11/xcb development headers fails.

### Solution
Install `pkg-config libx11-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libxkbcommon-dev libgtk-3-dev libssl-dev` in the workspace build step.

### Acceptance Criteria
- [ ] Update `.github/workflows/ci.yml` with the required system packages.
- [ ] Ensure `cargo build --workspace --all-targets` and `cargo test --workspace` pass green on Ubuntu CI.

---

## 📌 Issue #4: [FEAT] Implement Automated Monthly BTC Contributor Draw Script with Provable Fairness
**Labels**: `community`, `automation`, `bounty`, `python`  
**Assignee**: Open for contributors  

### Description
To support our Monthly $100 BTC Contributor Reward, we need an automated Python script (or GitHub Action) that queries merged PRs from the previous calendar month via the GitHub GraphQL API, filters eligible non-spam contributors, and performs a provably fair raffle using a verifiable random beacon (such as NIST or Drand).

### Requirements
1. Script located at `scripts/monthly_contributor_raffle.py`.
2. Uses `httpx` or `gh api` to fetch merged PR authors for `ttraces-io/secrets-manager`.
3. Filters out bots and disqualified accounts.
4. Outputs the winner, list of participants, and the randomness seed/proof.

### Acceptance Criteria
- [ ] Script implemented with unit tests in `scripts/tests/`.
- [ ] Generates a clean Markdown summary for posting to GitHub Discussions and Discord.

---

## 📌 Issue #5: [SECURITY] Add Memory Zeroization Verification Tests for Threshold FROST Key Shares
**Labels**: `security`, `crypto`, `frost`, `zeroize`  
**Assignee**: Open for contributors  

### Description
Ensure that all threshold key share buffers in `enclave/src/threshold/frost.rs` and `enclave/src/crypto/` properly zeroize secret material when dropped or when errors occur mid-computation.

### Acceptance Criteria
- [ ] Add memory inspection tests using `zeroize` verification patterns.
- [ ] Verify no secrets remain in stack or heap buffers upon failure or normal drop.
- [ ] Run `cargo test --workspace` and confirm passing zeroization assertions.

---

## 📌 Issue #6: [OPTIMIZATION] Axum Host Proxy Connection Pooling & Rusqlite WAL Mode
**Labels**: `performance`, `host`, `database`  
**Assignee**: Open for contributors  

### Description
The `host` service proxy currently opens sqlite connections without explicitly configuring Write-Ahead Logging (WAL) mode and `busy_timeout`. Under moderate HTTP load, this can result in `database is locked` (SQLITE_BUSY) errors.

### Proposed Changes
- In `host/src/db.rs`, execute `PRAGMA journal_mode = WAL;` and `PRAGMA busy_timeout = 5000;` on connection initialization.
- Configure `r2d2` or `deadpool-sqlite` connection pool.

### Acceptance Criteria
- [ ] Benchmark concurrent SQLite writes without lock contention.
- [ ] Add integration test verifying concurrent metadata reads and writes.

---

## 📌 Issue #7: [FEAT] WebAssembly GUI Hardware Token / WebAuthn Support Mockup
**Labels**: `gui`, `wasm`, `yew`, `ux`  
**Assignee**: Open for contributors  

### Description
In the Yew WebAssembly GUI (`gui/`), add UI controls and JavaScript FFI hooks for FIDO2/WebAuthn hardware token authentication when unlocking encrypted key vaults.

### Acceptance Criteria
- [ ] Add WebAuthn credential assertion UI component in `gui/src/components/auth.rs`.
- [ ] Provide WASM-safe JS bindings fallback for browsers lacking WebAuthn.
- [ ] Validate compilation with `trunk build --release`.

---

## 📌 Issue #8: [BUG] Fix macOS Runner Architecture Mismatch in Release CI Workflow
**Labels**: `ci`, `release`, `macos`  
**Assignee**: Open for contributors  

### Description
In `.github/workflows/release.yml`, the macOS build matrix targets `x86_64-apple-darwin` on `macos-latest`. However, GitHub-hosted `macos-latest` runners are now Apple Silicon (`aarch64-apple-darwin`), causing compilation target mismatches or unnecessary cross-compilation overhead.

### Acceptance Criteria
- [ ] Update `release.yml` matrix to build both `x86_64-apple-darwin` and `aarch64-apple-darwin` (Universal Binary or separate release artifacts).
- [ ] Verify artifact generation on GitHub Actions.
