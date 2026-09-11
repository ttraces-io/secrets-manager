#!/usr/bin/env bash
set -euo pipefail

echo "================================================================="
echo " 🔒 Starting traces-sm DevTest Automated Verification Suite"
echo "================================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

echo -e "\n[1/3] Checking workspace compilation..."
cargo check --workspace

echo -e "\n[2/3] Running Cargo Integration Tests..."
cargo test -p traces-sm-devtest -- --nocapture

echo -e "\n[3/3] Executing DevTest Diagnostic Runner..."
REPORT_PATH="$SCRIPT_DIR/test_report.md"
cargo run -p traces-sm-devtest -- --all --report "$REPORT_PATH"

echo "================================================================="
echo " ✨ ALL DEVTEST SUITES PASSED CLEANLY!"
echo " 📄 Audit report generated at: $REPORT_PATH"
echo "================================================================="
