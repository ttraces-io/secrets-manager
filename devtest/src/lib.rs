//! # `traces-sm-devtest` — Rigorous Test Suite & Verification Engine
//!
//! Comprehensive automated test harness validating all cryptographic algorithms,
//! NIST SP 800-57 lifecycle states, NIST SP 800-90B entropy tests, ZKP, PHE, DKG,
//! sealed storage, live in-enclave HTTP REST server, and cross-environment execution.

pub mod env;
pub mod suites;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Individual test case outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCaseResult {
    pub name: String,
    pub passed: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
}

/// Suite level test outcome containing multiple test cases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuiteResult {
    pub name: String,
    pub category: String,
    pub passed: bool,
    pub duration_ms: u64,
    pub tests: Vec<TestCaseResult>,
}

/// Overall test execution summary report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullReport {
    pub timestamp: String,
    pub environment: env::EnvironmentInfo,
    pub total_suites: usize,
    pub passed_suites: usize,
    pub failed_suites: usize,
    pub total_duration_ms: u64,
    pub suites: Vec<SuiteResult>,
}

/// The main DevTest engine runner.
pub struct DevTestRunner {
    pub env_info: env::EnvironmentInfo,
}

impl Default for DevTestRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl DevTestRunner {
    pub fn new() -> Self {
        Self {
            env_info: env::EnvironmentInfo::collect(),
        }
    }

    /// Executes all 12 test suites sequentially and aggregates the full report.
    pub async fn run_all(&self) -> FullReport {
        let start_time = Instant::now();
        let mut suite_results = vec![
            // 1. Environment & Simulation Suite
            Self::execute_sync_suite(
                "Environment & Windows Simulation",
                "Environment",
                suites::environment_suite::run_suite,
            ),
            // 2. Cryptographic Algorithms Suite
            Self::execute_sync_suite(
                "Cryptographic Algorithms (AES, RSA, ECDSA, Ed25519, PQC)",
                "Cryptography",
                suites::crypto_suite::run_suite,
            ),
            // 3. NIST SP 800-57 Key Lifecycle & KDF Suite
            Self::execute_sync_suite(
                "NIST SP 800-57 Lifecycle & SP 800-108 KDF",
                "NIST Standards",
                suites::lifecycle_suite::run_suite,
            ),
            // 4. NIST SP 800-90B Entropy & Continuous DRBG Health Suite
            Self::execute_sync_suite(
                "NIST SP 800-90B Entropy & Continuous RCT/APT DRBG Health",
                "Entropy & TRNG",
                suites::drbg_entropy_suite::run_suite,
            ),
            // 5. FIPS 140-3 Zeroization & Mandatory Security Policy Suite
            Self::execute_sync_suite(
                "FIPS 140-3 Zeroization & Mandatory Security Policies",
                "Compliance",
                suites::policy_zeroize_suite::run_suite,
            ),
            // 6. Zero-Knowledge Proofs (Schnorr, Bulletproofs, Pedersen) Suite
            Self::execute_sync_suite(
                "Zero-Knowledge Proofs (Schnorr PoK, Bulletproofs, Pedersen)",
                "ZKP Protocols",
                suites::zkp_suite::run_suite,
            ),
            // 7. Paillier Partially Homomorphic Encryption (PHE) Suite
            Self::execute_sync_suite(
                "Paillier Homomorphic Encryption & Ciphertext Addition",
                "Homomorphic Crypto",
                suites::he_paillier_suite::run_suite,
            ),
            // 8. Distributed Key Generation & FROST Threshold Signatures Suite
            Self::execute_sync_suite(
                "Distributed Key Generation & FROST Threshold Signatures",
                "Threshold DKG",
                suites::dkg_frost_suite::run_suite,
            ),
            // 9. Hardware & Simulation Sealed Storage & Tamper Resistance Suite
            Self::execute_sync_suite(
                "Sealed Storage Persistence & Ciphertext Tamper Resistance",
                "Storage & Security",
                suites::sealing_store_suite::run_suite,
            ),
            // 10. Enclave Authentication & JWT RBAC Token Suite
            Self::execute_sync_suite(
                "In-Enclave JWT Authentication & JTI Revocation",
                "Authentication",
                suites::auth_token_suite::run_suite,
            ),
            // 11. Host SQLite Database & Schema Suite
            Self::execute_sync_suite(
                "Host SQLite Metadata Database & WAL Mode",
                "Host Gateway",
                suites::host_db_suite::run_suite,
            ),
            // 12. Desktop GUI & CLI Interoperability Suite
            Self::execute_sync_suite(
                "Desktop GUI & CLI Subcommand Interoperability (25 Cases)",
                "Surface Interop",
                suites::desktop_cli_interop_suite::run_suite,
            ),
        ];

        // 13. Live In-Enclave HTTP/1.1 API Server Integration Suite
        let http_start = Instant::now();
        let http_res = suites::http_live_server_suite::run_suite().await;
        let http_duration = http_start.elapsed().as_millis() as u64;
        suite_results.push(SuiteResult {
            name: "Live In-Enclave HTTP/1.1 REST Server Integration".to_string(),
            category: "Network & Endpoints".to_string(),
            passed: http_res.is_ok(),
            duration_ms: http_duration,
            tests: vec![TestCaseResult {
                name: "Full REST API Lifecycle (Health, Keys, Secrets, ZKP, DKG)".to_string(),
                passed: http_res.is_ok(),
                duration_ms: http_duration,
                error: http_res.err().map(|e| e.to_string()),
            }],
        });

        // 14. P2P Dual-Instance Port Sharing Suite
        let p2p_start = Instant::now();
        let p2p_res = suites::p2p_sharing_suite::run_suite().await;
        let p2p_duration = p2p_start.elapsed().as_millis() as u64;
        suite_results.push(SuiteResult {
            name: "P2P Dual-Instance Port Sharing & DKG Exchange (25 Cases)".to_string(),
            category: "P2P & Cluster".to_string(),
            passed: p2p_res.is_ok(),
            duration_ms: p2p_duration,
            tests: vec![TestCaseResult {
                name: "Multi-Port DKG Secret & VSS Share Transfer".to_string(),
                passed: p2p_res.is_ok(),
                duration_ms: p2p_duration,
                error: p2p_res.err().map(|e| e.to_string()),
            }],
        });

        let total_duration_ms = start_time.elapsed().as_millis() as u64;
        let passed_suites = suite_results.iter().filter(|s| s.passed).count();
        let failed_suites = suite_results.len() - passed_suites;

        FullReport {
            timestamp: Utc::now().to_rfc3339(),
            environment: self.env_info.clone(),
            total_suites: suite_results.len(),
            passed_suites,
            failed_suites,
            total_duration_ms,
            suites: suite_results,
        }
    }

    fn execute_sync_suite<F>(name: &str, category: &str, f: F) -> SuiteResult
    where
        F: FnOnce() -> anyhow::Result<()>,
    {
        let start = Instant::now();
        let res = f();
        let duration_ms = start.elapsed().as_millis() as u64;
        let passed = res.is_ok();
        let error = res.err().map(|e| e.to_string());

        SuiteResult {
            name: name.to_string(),
            category: category.to_string(),
            passed,
            duration_ms,
            tests: vec![TestCaseResult {
                name: format!("{} verification", name),
                passed,
                duration_ms,
                error,
            }],
        }
    }

    /// Renders a comprehensive Markdown audit report.
    pub fn render_markdown_report(report: &FullReport) -> String {
        let mut md = String::new();
        md.push_str("# 🧪 `traces-sm` Comprehensive DevTest Audit Report\n\n");
        md.push_str(&format!("- **Timestamp**: `{}`\n", report.timestamp));
        md.push_str(&format!(
            "- **Environment**: `{}` (`{}`), Mode: `{}` (Simulation: `{}`)\n",
            report.environment.os,
            report.environment.arch,
            report.environment.sgx_mode,
            report.environment.is_simulation
        ));
        md.push_str(&format!(
            "- **Total Suites Executed**: `{}` | **Passed**: `{}` | **Failed**: `{}`\n",
            report.total_suites, report.passed_suites, report.failed_suites
        ));
        md.push_str(&format!(
            "- **Total Duration**: `{} ms`\n\n",
            report.total_duration_ms
        ));

        md.push_str("## 📊 Test Suites Execution Summary\n\n");
        md.push_str("| # | Suite Name | Category | Status | Duration |\n");
        md.push_str("| :- | :--- | :--- | :---: | :---: |\n");

        for (idx, suite) in report.suites.iter().enumerate() {
            let status = if suite.passed { "✅ PASS" } else { "❌ FAIL" };
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} ms |\n",
                idx + 1,
                suite.name,
                suite.category,
                status,
                suite.duration_ms
            ));
        }

        md.push_str("\n---\n\n## 📝 Detailed Test Results\n\n");
        for suite in &report.suites {
            let status = if suite.passed { "✅ PASS" } else { "❌ FAIL" };
            md.push_str(&format!("### {} — {}\n", status, suite.name));
            md.push_str(&format!("- **Category**: {}\n", suite.category));
            md.push_str(&format!("- **Duration**: {} ms\n", suite.duration_ms));
            for test in &suite.tests {
                if let Some(ref err) = test.error {
                    md.push_str(&format!("- **Error**: `{}`\n", err));
                }
            }
            md.push('\n');
        }

        md
    }
}
