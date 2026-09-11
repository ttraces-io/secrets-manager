//! Host Secret Management Gateway Route Definitions.
//!
//! Exposes administrative routing for secret listing and creation.

use axum::{
    routing::{get, post},
    Router,
};

/// Constructs the Axum sub-router for `/v1/secrets` routes.
pub fn router() -> Router {
    Router::new()
        .route("/", get(|| async { "List secrets" }))
        .route("/", post(|| async { "Create secret" }))
}
