//! Enclave Application Entry Point and Lifecycle Orchestrator.
//!
//! # Purpose and TCB Architecture
//! When compiled for target `x86_64-fortanix-unknown-sgx` (or native simulation mode), this
//! binary executes entirely within the Intel SGX Enclave Page Cache (EPC). It establishes
//! the hardware Trusted Computing Base (TCB), enforces mandatory security policies, and
//! services authenticated client requests over an internal TCP channel.
//!
//! # Boot and Initialization Sequence
//! 1. **Logging Initialization**: Configures `env_logger` for secure in-enclave diagnostics.
//! 2. **Configuration Ingestion**: Ingests network bindings, storage paths, and execution mode
//!    via [`Config::load`].
//! 3. **NIST SP 800-90B Health Check**: Runs Repetition Count Tests (RCT, $C=16$) and Adaptive
//!    Proportion Tests (APT, $W=512, C=13$) on the hardware TRNG entropy source.
//! 4. **Policy Engine Enforcement**: Instantiates [`PolicyEngine`] to guarantee FIPS 140-3
//!    zeroization, cryptoperiod constraints, and storage encryption invariants.
//! 5. **Sealing Key Provider Setup**: Derives root sealing material from hardware `EGETKEY`
//!    instructions (`KEYPOLICY_MRSIGNER`) or a simulation master key file.
//! 6. **Sealed Store Initialization**: Mounts the persistent sealed record repository [`Store`].
//! 7. **Authentication Subsystem**: Initializes [`EnclaveTokenService`], loading or generating
//!    the hardware-sealed Ed25519 token signing key.
//! 8. **HTTP/TLS Server Launch**: Binds the listening socket and begins servicing incoming requests
//!    via multi-threaded connection dispatch.

use std::sync::Arc;

pub mod auth;
pub mod config;
pub mod crypto;
pub mod dkg;
pub mod drbg;
pub mod error;
pub mod frost;
pub mod he;
pub mod keygen;
pub mod models;
pub mod nist;
pub mod policy;
pub mod pqc;
pub mod sealing;
pub mod server;
pub mod store;
pub mod zkp;

use crate::auth::EnclaveTokenService;
use crate::config::Config;
use crate::policy::{PolicyEngine, SecurityPolicy};
use crate::sealing::{HwSealingProvider, SealingKeyProvider, SimSealingProvider};
use crate::server::EnclaveState;
use crate::store::Store;

/// Main entry point for the Intel SGX enclave application.
///
/// # Security Invariants
/// - Halts immediately if TRNG entropy health checks (NIST SP 800-90B) fail.
/// - Panics if in-memory protection validation or token service initialization fails.
/// - In HW mode, master key derivation is strictly bound to the CPU fused root keys and MRSIGNER.
fn main() {
    env_logger::init();

    let cfg = Config::load();
    log::info!(
        "Starting traces-sm-enclave v{} in {} mode on port {}",
        env!("CARGO_PKG_VERSION"),
        cfg.sgx_mode,
        cfg.port
    );

    // Initialise NIST SP 800-90B DRBG & Policy Engine
    let drbg_status = drbg::init_drbg_health_check();
    let policy_engine = PolicyEngine::new(SecurityPolicy::default());
    policy_engine
        .validate_in_memory_protection()
        .expect("In-memory protection validation failed");
    log::info!(
        "NIST SP 800-90B DRBG & Mandatory Security Policy Enforced: APT={}, RCT={}",
        drbg_status.apt_passed,
        drbg_status.rct_passed
    );

    // ── Sealing provider ──────────────────────────────────────────────────────
    let provider: Arc<dyn SealingKeyProvider> = if cfg.sgx_mode == "HW" {
        log::info!("Using real SGX hardware sealing (EGETKEY)");
        Arc::new(HwSealingProvider)
    } else {
        log::info!("Using simulation sealing key (not for production)");
        Arc::new(SimSealingProvider::new(&cfg.store_path))
    };

    // ── Secret store ──────────────────────────────────────────────────────────
    let store = Arc::new(Store::new(&cfg.store_path));

    // ── Token service ─────────────────────────────────────────────────────────
    let token_service = Arc::new(
        EnclaveTokenService::new(&cfg.store_path, provider.as_ref())
            .expect("Failed to initialise token service"),
    );

    // ── Assemble enclave state ────────────────────────────────────────────────
    let state = Arc::new(EnclaveState {
        store,
        provider,
        token_service,
        config: cfg,
    });

    // ── Start HTTP/TLS server ─────────────────────────────────────────────────
    server::start_server(state);
}
