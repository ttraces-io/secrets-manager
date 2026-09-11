//! Distributed Key Generation (DKG) and FROST Threshold Signature Handlers.
//!
//! # Protocol Overview
//! Implements multi-party threshold cryptographic endpoints:
//! - **Pedersen VSS**: Threshold secret sharing over $GF(256)$ with polynomial commitment verification.
//! - **FROST Ed25519**: Two-round threshold Schnorr signatures (IETF draft-irtf-cfrg-frost-15)
//!   supporting dealer keygen, Round 1 nonce generation, Round 2 signature share generation,
//!   aggregation into a standard 64-byte Ed25519 signature, and signature verification.

use crate::dkg::{split_secret_vss, SecretShare};
use crate::error::EnclaveError;
use crate::frost::{
    aggregate_signature, generate_dealer_keys, round1_commit, round2_sign_share, verify_signature,
};
use crate::models::{
    ApiResponse, DkgSetupRequest, FrostAggregateRequest, FrostCommitRequest, FrostDkgSetupRequest,
    FrostSignShareRequest, FrostVerifyRequest,
};
use crate::server::router::HttpRequest;
use crate::server::EnclaveState;
use crate::store::Store;
use std::sync::Arc;

/// Handles $(t, n)$ verifiable secret sharing split of an existing sealed secret.
pub fn handle_dkg_setup(
    store: Arc<Store>,
    req: DkgSetupRequest,
) -> Result<ApiResponse<Vec<SecretShare>>, EnclaveError> {
    let (_record, blob) = store.load(&req.secret_id)?;
    let secret_val = *blob.first().unwrap_or(&0);

    let (shares, _commitment) = split_secret_vss(secret_val, req.threshold, req.total);
    Ok(ApiResponse::ok(shares))
}

/// Handles trusted dealer key generation for FROST Ed25519 threshold signing.
pub fn handle_frost_setup(
    req: &HttpRequest,
    _state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: FrostDkgSetupRequest = serde_json::from_slice(&req.body)?;
    let output = generate_dealer_keys(body.max_signers, body.min_signers)?;
    Ok(serde_json::to_value(output)?)
}

/// Handles FROST Round 1: generates hiding and binding nonces $(d_i, e_i)$ and public commitments $(D_i, E_i)$.
pub fn handle_frost_commit(
    req: &HttpRequest,
    _state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: FrostCommitRequest = serde_json::from_slice(&req.body)?;
    let output = round1_commit(&body.key_package_json)?;
    Ok(serde_json::to_value(output)?)
}

/// Handles FROST Round 2: computes signature share $z_i = d_i + (e_i \cdot \rho_i) + \lambda_i \cdot s_i \cdot c$.
pub fn handle_frost_sign(
    req: &HttpRequest,
    _state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: FrostSignShareRequest = serde_json::from_slice(&req.body)?;
    let msg_bytes = hex::decode(&body.message_hex)
        .map_err(|e| EnclaveError::BadRequest(format!("Invalid message hex: {}", e)))?;
    let share_json = round2_sign_share(
        &body.key_package_json,
        &body.nonces_json,
        &body.commitments_map_json,
        &msg_bytes,
    )?;
    Ok(serde_json::json!({ "signature_share_json": share_json }))
}

/// Handles aggregation of threshold signature shares into a valid standard Ed25519 signature $(R, z)$.
pub fn handle_frost_aggregate(
    req: &HttpRequest,
    _state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: FrostAggregateRequest = serde_json::from_slice(&req.body)?;
    let msg_bytes = hex::decode(&body.message_hex)
        .map_err(|e| EnclaveError::BadRequest(format!("Invalid message hex: {}", e)))?;
    let sig_hex = aggregate_signature(
        &body.public_key_package_json,
        &body.commitments_map_json,
        &body.signature_shares_json,
        &msg_bytes,
    )?;
    Ok(serde_json::json!({ "signature_hex": sig_hex }))
}

/// Verifies a composite FROST threshold signature against the group public key.
pub fn handle_frost_verify(
    req: &HttpRequest,
    _state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: FrostVerifyRequest = serde_json::from_slice(&req.body)?;
    let msg_bytes = hex::decode(&body.message_hex)
        .map_err(|e| EnclaveError::BadRequest(format!("Invalid message hex: {}", e)))?;
    let valid = verify_signature(&body.group_public_key_hex, &body.signature_hex, &msg_bytes)?;
    Ok(serde_json::json!({ "valid": valid }))
}
