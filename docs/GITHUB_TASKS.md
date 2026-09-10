# `traces-sm` — GitHub Deployment & Operations Task List

> All documentation, landing pages, technical specifications, build guides, and community guidelines are maintained directly on GitHub via **GitHub Pages**, **GitHub Wiki**, and **GitHub Actions**.

---

## 📋 Task Progress Summary

- [x] **Phase 1: GitHub Pages & Site Setup**
  - [x] Configure `docs/index.md` as GitHub Pages landing homepage.
  - [x] Configure `docs/_config.yml` Jekyll site theme, title, and navigation.
  - [x] Add GitHub Pages deployment workflow (`.github/workflows/deploy-pages.yml`).

- [x] **Phase 2: GitHub Wiki Synchronization**
  - [x] Create `scripts/sync_github_wiki.ps1` script to clone and push to `traces-sm.wiki.git`.
  - [x] Map `docs/TECHNICAL_SPECIFICATION.md` -> `Wiki: Technical-Specification.md`.
  - [x] Map `docs/PRODUCT_SPECIFICATION.md` -> `Wiki: Product-Specification.md`.
  - [x] Map `docs/CONFORMANCE_REPORT.md` -> `Wiki: Conformance-Report.md`.
  - [x] Map `docs/ARCHITECTURE_WALKTHROUGH.md` -> `Wiki: Architecture-Walkthrough.md`.
  - [x] Map `docs/WINDOWS_BUILD_GUIDE.md` -> `Wiki: Windows-Build-Guide.md`.
  - [x] Map `docs/PAGE_BY_PAGE_DESIGN.md` -> `Wiki: Page-by-Page-Design.md`.
  - [x] Map `docs/KNOWLEDGE_BANK.md` -> `Wiki: Knowledge-Bank.md`.

- [x] **Phase 3: GitHub Actions CI/CD Workflows (`.github/workflows/`)**
  - [x] `ci.yml`: Multi-OS Rust compilation & testing matrix (Ubuntu, Windows, macOS).
  - [x] `deploy-pages.yml`: Automated GitHub Pages publisher on push to `main`.
  - [x] `sync-wiki.yml`: GitHub Actions workflow for automatic Wiki synchronization.
  - [x] `release.yml`: Multi-OS release asset builder (`.deb`, `.rpm`, `.msi`, `.dmg`, Homebrew formula).

- [x] **Phase 4: GitHub Community & Repository Setup**
  - [x] `.github/SECURITY.md`: Vulnerability disclosure policy for Intel SGX enclave bugs.
  - [x] `.github/CONTRIBUTING.md`: Developer contribution guidelines for 5-crate workspace.
  - [x] `.github/ISSUE_TEMPLATE/`: Bug report & feature request templates.
  - [x] `.github/PULL_REQUEST_TEMPLATE.md`: PR verification checklist.

---

## 🛠️ Detailed Task Action Items

### Phase 1: GitHub Pages Setup
- [x] Enable GitHub Pages in repository settings (`ttraces-io/secrets-manager` -> Settings -> Pages -> Source: GitHub Actions).
- [x] Verify Jekyll dark mode theme rendering for NIST specifications.
- [x] Add WebAssembly demo iframe loader to `docs/index.md`.

### Phase 2: GitHub Wiki Content Mapping
- [x] `Home.md`: Main navigation sidebar linking to all specifications and guides.
- [x] `NIST-Compliance-Matrix.md`: Detailed SP 800-57, SP 800-90B, SP 800-38F conformance tables.
- [x] `Traces-AI-Setup.md`: Guide for connecting Anthropic API keys (`sk-ant-api...`) to Traces AI panel.

### Phase 3: GitHub Release Pipeline
- [x] Package `.deb` installer for Ubuntu 22.04 / 24.04 (`cargo deb`).
- [x] Package `.rpm` installer for RHEL / Fedora (`cargo generate-rpm`).
- [x] Package `.msi` installer for Windows 10 / 11 (`cargo wix`).
- [x] Package Homebrew Formula (`traces-sm.rb`) for macOS Intel & Apple Silicon.
