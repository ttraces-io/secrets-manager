//! Host Key Lifecycle and Sanitization Route Definitions.
//!
//! Exposes administrative routes for triggering key state transitions and media sanitization.

use axum::{routing::post, Router};

/// Constructs the Axum sub-router for `/v1/lifecycle` routes.
pub fn router() -> Router {
    Router::new()
        .route("/transition", post(|| async { "Transition state" }))
        .route("/shred", post(|| async { "Shred state" }))
}
