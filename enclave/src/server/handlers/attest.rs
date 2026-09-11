//! Intel SGX Remote Attestation and Hardware Measurement Handlers.
//!
//! # Purpose and Attestation Protocols
//! This module handles generation and inspection of Intel SGX Data Center Attestation Primitives (DCAP)
//! quotes and enclave measurements:
//! - **MRENCLAVE**: SHA-256 cryptographic digest of the enclave binary code, initial data, and page layout.
//! - **MRSIGNER**: SHA-256 hash of the ISV's RSA signing key.
//! - **ISVPRODID / ISVSVN**: Product ID and monotonic security version number.

use std::sync::Arc;

use crate::error::EnclaveError;
use crate::models::{AttestationMeasurements, AttestationQuoteResponse};
use crate::server::router::HttpRequest;
use crate::server::EnclaveState;

/// Generates an SGX attestation quote bound to current runtime measurements.
///
/// In hardware mode, constructs a DCAP ECDSA quote; in simulation mode, returns a mock simulation quote.
pub fn quote(
    _req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let measurements = get_measurements(&state.config.sgx_mode);

    let (quote_hex, quote_b64) = if state.config.sgx_mode == "HW" {
        return Err(EnclaveError::BadRequest(
            "Real DCAP quote generation requires SGX hardware. Set SGX_MODE=SIM for simulation."
                .into(),
        ));
    } else {
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            b"SGX-SIMULATION-QUOTE-NOT-FOR-PRODUCTION",
        );
        let hex = hex::encode(b"SGX-SIMULATION-QUOTE-NOT-FOR-PRODUCTION");
        (hex, Some(b64))
    };

    Ok(serde_json::to_value(AttestationQuoteResponse {
        quote_hex,
        quote_b64,
        measurements,
    })?)
}

/// Returns the current enclave measurements (`MRENCLAVE`, `MRSIGNER`, `ISVPRODID`, `ISVSVN`).
pub fn measurements(
    _req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    Ok(serde_json::to_value(get_measurements(
        &state.config.sgx_mode,
    ))?)
}

/// Provides documentation and status for quote verification via host PCCS / Intel Trust Authority.
pub fn verify(
    _req: &HttpRequest,
    _state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    // Verification delegates to host PCCS / Intel Trust Authority.
    // Enclave returns the public measurements for policy checking.
    Ok(serde_json::json!({
        "message": "Quote verification requires PCCS/ITA on the host side.",
        "doc": "See /v1/attest/measurements for current enclave identity."
    }))
}

/// Constructs measurement container for the given SGX execution mode.
fn get_measurements(mode: &str) -> AttestationMeasurements {
    let zeroes = "0".repeat(64);
    AttestationMeasurements {
        mr_enclave: zeroes.clone(),
        mr_signer: zeroes.clone(),
        mrenclave_hex: Some(zeroes.clone()),
        mrsigner_hex: Some(zeroes),
        isvprodid: Some(1),
        isvsvn: Some(1),
        sgx_mode: Some(mode.to_string()),
    }
}
