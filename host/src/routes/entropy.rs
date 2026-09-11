//! Host Entropy Telemetry Route Definitions.
//!
//! Exposes health and audit endpoints for the hardware entropy source.

use axum::{routing::get, Router};

/// Constructs the Axum sub-router for `/v1/entropy` routes.
pub fn router() -> Router {
    Router::new().route("/health", get(|| async { "Entropy health" }))
}
