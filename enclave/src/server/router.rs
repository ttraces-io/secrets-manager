//! In-Enclave HTTP/1.1 Request Router and Protocol Engine.
//!
//! # Purpose and Protocol Handling
//! This module implements a zero-external-dependency HTTP/1.1 wire protocol parser and
//! REST API request dispatcher, parsing raw TCP streams using [`httparse`] and mapping
//! URI paths and HTTP verbs to their corresponding cryptographically isolated handler functions.
//!
//! # Security and Invariants
//! - **Request Buffer Limit**: Caps incoming raw HTTP request buffers at $64\,\text{KiB}$
//!   to prevent unbounded memory allocation inside the restricted Enclave Page Cache (EPC).
//! - **Standardized JSON Envelope**: All successful responses return a JSON envelope `{"success": true, "data": ...}`
//!   and error responses return `ApiResponse::err(code, message)` with appropriate HTTP status codes.
//! - **Header Hardening**: Injects `X-Enclave: traces-sm-enclave-v{version}` and explicit `Content-Length`
//!   on all outgoing responses.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use crate::error::{http_status, EnclaveError};
use crate::models::ApiResponse;
use crate::server::handlers;
use crate::server::EnclaveState;

// ─────────────────────────────────────────────────────────────────────────────
// Minimal HTTP request / response structures
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal in-enclave representation of an incoming HTTP/1.1 request.
pub struct HttpRequest {
    /// HTTP request method in uppercase (e.g., `"GET"`, `"POST"`, `"PUT"`, `"DELETE"`).
    pub method: String,
    /// Request URI target path (e.g., `"/v1/secrets"`).
    pub path: String,
    /// List of HTTP request header key-value pairs.
    pub headers: Vec<(String, String)>,
    /// Raw HTTP request body bytes.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Retrieves a header value by case-insensitive name match.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }

    /// Extracts Bearer token from the `Authorization: Bearer <jwt>` request header.
    pub fn bearer_token(&self) -> Option<&str> {
        self.header("Authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection handler
// ─────────────────────────────────────────────────────────────────────────────

/// Handles an active client TCP stream: reads bytes, parses HTTP request, dispatches to handler, and transmits response.
///
/// # Invariants
/// - Buffers at most $64\,\text{KiB}$ from the stream.
/// - Guarantees stream flush and close upon completion.
pub fn handle_connection(
    mut stream: TcpStream,
    state: Arc<EnclaveState>,
) -> Result<(), EnclaveError> {
    // Read up to 64 KiB
    let mut buf = vec![0u8; 65536];
    let n = stream
        .read(&mut buf)
        .map_err(|e| EnclaveError::Storage(e.to_string()))?;
    buf.truncate(n);

    let req = parse_request(&buf)?;
    let response = dispatch(&req, state);
    stream
        .write_all(response.as_bytes())
        .map_err(|e| EnclaveError::Storage(e.to_string()))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Request parsing (minimal HTTP/1.1)
// ─────────────────────────────────────────────────────────────────────────────

/// Parses a raw byte slice into an [`HttpRequest`] using [`httparse`].
fn parse_request(raw: &[u8]) -> Result<HttpRequest, EnclaveError> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);

    let status = req
        .parse(raw)
        .map_err(|e| EnclaveError::BadRequest(format!("HTTP parse error: {e}")))?;

    let method = req.method.unwrap_or("GET").to_string();
    let path = req.path.unwrap_or("/").to_string();

    let header_list: Vec<(String, String)> = req
        .headers
        .iter()
        .filter(|h| !h.name.is_empty())
        .map(|h| {
            (
                h.name.to_string(),
                String::from_utf8_lossy(h.value).to_string(),
            )
        })
        .collect();

    let body_start = match status {
        httparse::Status::Complete(n) => n,
        httparse::Status::Partial => {
            return Err(EnclaveError::BadRequest("incomplete HTTP request".into()));
        }
    };

    let body = raw[body_start..].to_vec();

    Ok(HttpRequest {
        method,
        path,
        headers: header_list,
        body,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatcher
// ─────────────────────────────────────────────────────────────────────────────

/// Routes an [`HttpRequest`] to the appropriate domain handler based on HTTP verb and path segments.
fn dispatch(req: &HttpRequest, state: Arc<EnclaveState>) -> String {
    // Segment the path: "/v1/secrets/some-id" → ["v1", "secrets", "some-id"]
    let segments: Vec<&str> = req
        .path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    let result: Result<serde_json::Value, EnclaveError> = match (
        req.method.as_str(),
        segments.as_slice(),
    ) {
        // ── Health ────────────────────────────────────────────────────────────
        ("GET", ["health"]) => {
            Ok(serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
        }

        // ── Secrets ───────────────────────────────────────────────────────────
        ("POST", ["v1", "secrets"]) => handlers::secrets::create(req, &state),
        ("GET", ["v1", "secrets"]) => handlers::secrets::list(req, &state),
        ("GET", ["v1", "secrets", id]) => handlers::secrets::get(req, &state, id),
        ("PUT", ["v1", "secrets", id]) => handlers::secrets::update(req, &state, id),
        ("DELETE", ["v1", "secrets", id]) => handlers::secrets::delete(req, &state, id),

        // ── Keys ──────────────────────────────────────────────────────────────
        ("POST", ["v1", "keys"]) => handlers::keys::generate(req, &state),
        ("GET", ["v1", "keys"]) => handlers::keys::list(req, &state),
        ("GET", ["v1", "keys", id, "public"]) => handlers::keys::public_key(req, &state, id),
        ("POST", ["v1", "keys", id, "sign"]) => handlers::keys::sign(req, &state, id),
        ("POST", ["v1", "keys", id, "verify"]) => handlers::keys::verify(req, &state, id),
        ("POST", ["v1", "keys", id, "encrypt"]) => handlers::keys::encrypt(req, &state, id),
        ("POST", ["v1", "keys", id, "decrypt"]) => handlers::keys::decrypt(req, &state, id),
        ("POST", ["v1", "keys", id, "rotate"]) => handlers::keys::rotate(req, &state, id),
        ("DELETE", ["v1", "keys", id]) => handlers::keys::delete(req, &state, id),

        // ── Tokens ────────────────────────────────────────────────────────────
        ("POST", ["v1", "tokens"]) => handlers::tokens::create(req, &state),
        ("GET", ["v1", "tokens"]) => handlers::tokens::list(req, &state),
        ("DELETE", ["v1", "tokens", id]) => handlers::tokens::revoke(req, &state, id),

        // ── ZKP ───────────────────────────────────────────────────────────────
        ("POST", ["v1", "zkp", "schnorr", "prove"]) => handlers::zkp::schnorr_prove(req, &state),
        ("POST", ["v1", "zkp", "schnorr", "verify"]) => handlers::zkp::schnorr_verify(req, &state),
        ("POST", ["v1", "zkp", "range", "prove"]) => handlers::zkp::range_prove(req, &state),
        ("POST", ["v1", "zkp", "range", "verify"]) => handlers::zkp::range_verify(req, &state),
        ("POST", ["v1", "zkp", "pedersen", "commit"]) => {
            handlers::zkp::pedersen_commit(req, &state)
        }
        ("POST", ["v1", "zkp", "he", "generate"]) => handlers::zkp::he_generate(req, &state),
        ("POST", ["v1", "zkp", "he", "encrypt"]) => handlers::zkp::he_encrypt(req, &state),
        ("POST", ["v1", "zkp", "he", "add"]) => handlers::zkp::he_add(req, &state),
        ("POST", ["v1", "zkp", "he", "decrypt"]) => handlers::zkp::he_decrypt(req, &state),

        // ── DKG / FROST ───────────────────────────────────────────────────────
        ("POST", ["v1", "dkg", "frost", "setup"]) => {
            handlers::dkg_handler::handle_frost_setup(req, &state)
        }
        ("POST", ["v1", "dkg", "frost", "commit"]) => {
            handlers::dkg_handler::handle_frost_commit(req, &state)
        }
        ("POST", ["v1", "dkg", "frost", "sign"]) => {
            handlers::dkg_handler::handle_frost_sign(req, &state)
        }
        ("POST", ["v1", "dkg", "frost", "aggregate"]) => {
            handlers::dkg_handler::handle_frost_aggregate(req, &state)
        }
        ("POST", ["v1", "dkg", "frost", "verify"]) => {
            handlers::dkg_handler::handle_frost_verify(req, &state)
        }

        // ── Entropy (NIST SP 800-90B) ──────────────────────────────────────────
        ("GET", ["v1", "entropy", "health"]) => {
            let status = crate::drbg::init_drbg_health_check();
            Ok(
                serde_json::json!({ "rct_passed": status.rct_passed, "apt_passed": status.apt_passed, "reseed_count": status.reseed_count, "source": "SGX_RDRAND_RDSEED" }),
            )
        }

        // ── Attestation ───────────────────────────────────────────────────────
        ("GET", ["v1", "attest", "quote"]) => handlers::attest::quote(req, &state),
        ("GET", ["v1", "attest", "measurements"]) => handlers::attest::measurements(req, &state),
        ("POST", ["v1", "attest", "verify"]) => handlers::attest::verify(req, &state),

        // ── 404 ───────────────────────────────────────────────────────────────
        _ => Err(EnclaveError::NotFound {
            id: req.path.clone(),
        }),
    };

    match result {
        Ok(body) => http_response(200, &serde_json::json!({ "success": true, "data": body })),
        Err(e) => {
            let status = http_status(&e);
            http_response(
                status,
                &ApiResponse::<()>::err(format!("{:?}", e), e.to_string()),
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Response formatting
// ─────────────────────────────────────────────────────────────────────────────

/// Formats a status code and serializable JSON payload into an RFC 7230 compliant HTTP/1.1 response string.
fn http_response(status: u16, body: &impl serde::Serialize) -> String {
    let json = serde_json::to_string_pretty(body)
        .unwrap_or_else(|_| r#"{"error":"serialization failed"}"#.to_string());
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Enclave: traces-sm-enclave-v{}\r\n\r\n{}",
        json.len(),
        env!("CARGO_PKG_VERSION"),
        json
    )
}
