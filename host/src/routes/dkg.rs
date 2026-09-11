//! Host Distributed Key Generation (DKG) Route Definitions.
//!
//! Exposes endpoints for managing DKG cluster topology and node registries.

use axum::{
    routing::{get, post},
    Router,
};

/// Constructs the Axum sub-router for `/v1/dkg` routes.
pub fn router() -> Router {
    Router::new()
        .route("/setup", post(|| async { "Setup DKG" }))
        .route("/nodes", get(|| async { "Get nodes" }))
}
