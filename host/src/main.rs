//! Untrusted Host Proxy and Management Gateway.
//!
//! # Architecture and TCB Boundary
//! The `traces-sm-host` process runs in the untrusted host OS user space outside the SGX Enclave.
//! Its primary responsibilities include:
//! - **Static Asset Hosting**: Serves the compiled Web GUI frontend bundle (`gui/dist`).
//! - **Administrative Metadata Storage**: Manages the local SQLite database (`metadata.db`) configured
//!   with Write-Ahead Logging (WAL) and concurrency timeouts.
//! - **API Reverse Proxy & Routing**: Routes external REST requests to internal enclave communication channels.
//! - **Telemetry & Audit Forwarding**: Emits structured logs and audit telemetry via [`tracing`].

use axum::{routing::get, Router};
use std::net::SocketAddr;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};

mod db;
mod routes;

/// Entrypoint for the host proxy service.
///
/// # Boot Lifecycle
/// 1. Initializes structured console logging with [`tracing_subscriber`].
/// 2. Initializes SQLite schema and WAL mode pragmas via [`db::init_db`].
/// 3. Assembles Axum router tree with CORS, tracing middleware, and static asset fallback.
/// 4. Binds to `0.0.0.0:8080` and begins asynchronous Tokio event loop.
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Initialize DB
    db::init_db().expect("Failed to initialize database");

    let app = Router::new()
        .nest("/v1/secrets", routes::secrets::router())
        .nest("/v1/keys", routes::keys::router())
        .nest("/v1/tokens", routes::tokens::router())
        .nest("/v1/attest", routes::attest::router())
        .nest("/v1/lifecycle", routes::lifecycle::router())
        .nest("/v1/dkg", routes::dkg::router())
        .nest("/v1/entropy", routes::entropy::router())
        .route("/health", get(|| async { "OK" }))
        .nest_service("/", ServeDir::new("gui/dist"))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
