//! In-Enclave HTTP/1.1 API Server and Shared State Engine.
//!
//! # Concurrency and State Architecture
//! The in-enclave HTTP server binds to an internal TCP listener and spawns a thread per connection.
//! State is centralized in [`EnclaveState`], which wraps the sealed storage repository,
//! hardware/simulation sealing key provider, authentication token service, and runtime config
//! in thread-safe [`std::sync::Arc`] references.
//!
//! # Network Boundary and TLS Architecture
//! - In local testing and simulation environments, the enclave communicates over plain HTTP/1.1.
//! - In production deployments, TLS 1.3 termination is performed by an enclave-fronting reverse proxy
//!   (or in-enclave TLS layer) using certificates bound to the SGX remote attestation quote.

use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use crate::auth::EnclaveTokenService;
use crate::config::Config;
use crate::sealing::SealingKeyProvider;
use crate::store::Store;

pub mod handlers;
pub mod router;

// ─────────────────────────────────────────────────────────────────────────────
// Shared enclave state (Arc-cloned into each request handler thread)
// ─────────────────────────────────────────────────────────────────────────────

/// Centralized thread-safe in-enclave shared runtime state.
pub struct EnclaveState {
    /// Persistent sealed storage repository.
    pub store: Arc<Store>,
    /// Active sealing key derivation provider (hardware or simulation).
    pub provider: Arc<dyn SealingKeyProvider>,
    /// In-enclave JWT token issuance and revocation service.
    pub token_service: Arc<EnclaveTokenService>,
    /// Enclave runtime configuration options.
    pub config: Config,
}

// ─────────────────────────────────────────────────────────────────────────────
// Server entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Starts the in-enclave TCP HTTP server loop, blocking the main thread.
///
/// # Concurrency
/// Accepts incoming TCP connections and dispatches each stream to [`router::handle_connection`]
/// inside a spawned OS thread.
pub fn start_server(state: Arc<EnclaveState>) {
    let addr = format!("0.0.0.0:{}", state.config.port);
    let listener = TcpListener::bind(&addr).unwrap_or_else(|e| panic!("Cannot bind {addr}: {e}"));

    log::info!("Enclave HTTP server listening on http://{addr}");
    log::warn!("NOTE: TLS should be terminated by a TLS proxy in front of the enclave (e.g. rustls via stunnel or nginx). This server speaks plain HTTP for local dev.");

    for stream_result in listener.incoming() {
        match stream_result {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(e) = router::handle_connection(stream, state) {
                        log::error!("Request error: {e}");
                    }
                });
            }
            Err(e) => log::error!("Accept error: {e}"),
        }
    }
}
