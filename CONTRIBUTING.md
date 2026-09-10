# Contributing to `traces-sm`

Welcome! We appreciate your interest in contributing to **`traces-sm`**.

Official Guide URL: [https://github.com/ttraces-io/secrets-manager/CONTRIBUTING.md](https://github.com/ttraces-io/secrets-manager/CONTRIBUTING.md)

---

### 1. Start with the Community
Before writing code, visit **[ttraces.io](https://ttraces.io)** to explore our ecosystem and architectural overview. Next, join our **[Discord](https://discord.gg/traces)** to participate in community discussions. Please align on issue scope and implementation details with the team before opening pull requests.

### 2. 🎁 Monthly Contributor Reward ($100 in BTC)
Every calendar month, one lucky GitHub contributor with merged pull requests is randomly selected to receive **$100 in Bitcoin (BTC)**! All meaningful contributions—features, bug fixes, cryptographic enhancements, security hardening, tests, and documentation—are eligible.

### 3. Engineering, Security & FLOSS Testing Standards
All contributions must adhere to our security, cryptographic, and code quality benchmarks:
- **Lint & Format**: Code must pass `cargo fmt --all -- --check` and `cargo clippy`. We accept at most 1 warning per 500 lines of code.
- **FLOSS Automated Testing**: All workspace unit and integration tests must pass cleanly (`cargo test --workspace` and `pytest`). See [**`BUILD.md`**](BUILD.md) for detailed test execution instructions.
- **Cryptographic Safety**: Sensitive data must implement memory zeroization (`zeroize`). Any `unsafe` blocks require explicit `// SAFETY:` justifications.

### 4. Contribution Workflow & Checkpoints
1. Fork the repo and create your branch (`git checkout -b feat/your-feature`).
2. Make your changes and verify formatting, lints, and tests locally.
3. Commit with Conventional Commits (e.g., `feat(enclave): ...`, `fix(cli): ...`).
4. Submit a Pull Request referencing relevant community discussions or issues.
5. **Checkpoint Integration**: At planned checkpoints, the branches are merged to ensure, unstable unpublished versions are accessible for testing and improvements.
