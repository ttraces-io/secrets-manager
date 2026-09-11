//! Host Token Registry Route Definitions.
//!
//! Exposes administrative endpoints for listing host-tracked tokens.

use axum::{routing::get, Router};

/// Constructs the Axum sub-router for `/v1/tokens` routes.
pub fn router() -> Router {
    Router::new().route("/", get(|| async { "List tokens" }))
}
