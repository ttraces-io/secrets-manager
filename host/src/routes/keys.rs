//! Host Asymmetric and Symmetric Key Route Definitions.
//!
//! Exposes administrative routing for key generation and metadata queries.

use axum::{
    routing::{get, post},
    Router,
};

/// Constructs the Axum sub-router for `/v1/keys` routes.
pub fn router() -> Router {
    Router::new()
        .route("/", get(|| async { "List keys" }))
        .route("/", post(|| async { "Create key" }))
}
