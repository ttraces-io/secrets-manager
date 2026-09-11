//! Host Attestation Route Definitions.
//!
//! Exposes endpoints for querying and verifying Intel SGX attestation measurements.

use axum::{routing::get, Router};

/// Constructs the Axum sub-router for `/v1/attest` routes.
pub fn router() -> Router {
    Router::new().route("/", get(|| async { "Get attestation" }))
}
