//! Enclave Configuration and Environment Settings.
//!
//! # Purpose and Scope
//! This module defines the runtime configuration parameters for the Intel SGX enclave
//! server environment, including network binding ports, persistent storage base paths,
//! hardware execution modes (`HW` vs `SIM`), and authentication token lifetimes.
//!
//! # Invariants and Boundary Constraints
//! - **Environment Precedence**: Configuration is read from process environment variables
//!   during initial boot. If an environment variable is unset or unparseable, hardened
//!   safe defaults are used.
//! - **Security Invariant**: `sgx_mode` determines whether hardware `EGETKEY` instructions
//!   or software-simulated master keys are used. Production builds must strictly enforce `HW`.
//! - **Port Binding**: The enclave binds to internal localhost or container-isolated interfaces,
//!   relying on a host-side TLS reverse proxy for external client termination.

use std::env;

/// Enclave runtime configuration options.
#[derive(Debug, Clone)]
pub struct Config {
    /// TCP port on which the in-enclave HTTP server listens (default: `8443`).
    pub port: u16,
    /// Absolute or relative filesystem path to the directory hosting sealed secret blobs and metadata.
    pub store_path: String,
    /// Intel SGX execution mode: `"HW"` for hardware enclave (EGETKEY), `"SIM"` for software simulation.
    pub sgx_mode: String,
    /// Default validity duration (in seconds) for newly minted in-enclave JWT tokens (default: 3600s / 1hr).
    pub jwt_validity_secs: u64,
}

impl Config {
    /// Loads enclave configuration from environment variables with hardened fallback defaults.
    ///
    /// # Environment Variables
    /// - `ENCLAVE_PORT`: Integer TCP port (default: `8443`).
    /// - `ENCLAVE_STORE_PATH`: Filesystem directory for sealed records (default: `"/tmp/sm-store"`).
    /// - `SGX_MODE`: `"HW"` for hardware execution or `"SIM"` for simulation (default: `"SIM"`).
    /// - `JWT_VALIDITY_SECS`: Token expiration duration in seconds (default: `3600`).
    ///
    /// # Side Effects
    /// Reads environment variables from the parent OS environment via [`std::env::var`].
    pub fn load() -> Self {
        Self {
            port: env::var("ENCLAVE_PORT")
                .unwrap_or_else(|_| "8443".to_string())
                .parse()
                .unwrap_or(8443),
            store_path: env::var("ENCLAVE_STORE_PATH")
                .unwrap_or_else(|_| "/tmp/sm-store".to_string()),
            sgx_mode: env::var("SGX_MODE").unwrap_or_else(|_| "SIM".to_string()),
            jwt_validity_secs: env::var("JWT_VALIDITY_SECS")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .unwrap_or(3600),
        }
    }
}
