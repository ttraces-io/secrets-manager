//! Opaque Secret Management and Envelope Encryption Handlers.
//!
//! # Purpose and Operations
//! Handles CRUD lifecycle operations for opaque, arbitrary-length confidential payloads:
//! - Ingests Base64 plaintext from authenticated clients.
//! - Immediately derives a deterministic Schnorr commitment $Y = x \cdot G$ for ZKP verification.
//! - Seals plaintext into an authenticated AES-256-GCM ciphertext blob via [`crate::crypto::encrypt_secret`].
//! - Manages metadata versioning and soft-deletion.

use base64::Engine as _;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::crypto::{decrypt_secret, encrypt_secret};
use crate::error::EnclaveError;
use crate::models::{CreateSecretRequest, SecretMetadata, SecretResponse, UpdateSecretRequest};
use crate::server::router::HttpRequest;
use crate::server::EnclaveState;
use crate::store::SecretRecord;
use crate::zkp::schnorr::generate_commitment;

/// Creates and hardware-seals a new secret record, generating a Schnorr ZKP commitment.
pub fn create(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: CreateSecretRequest = serde_json::from_slice(&req.body)?;

    // Check for duplicate name
    if state.store.name_exists(&body.name) {
        return Err(EnclaveError::AlreadyExists {
            id: body.name.clone(),
        });
    }

    let value_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.plaintext_base64)
        .map_err(|_| EnclaveError::BadRequest("plaintext_base64 is not valid base64".into()))?;

    // Generate ZKP commitment for token possession proof
    let zkp_commitment = generate_commitment(&value_bytes).ok().map(|c| c.point_hex);

    // Encrypt the secret inside the enclave
    let blob = encrypt_secret(&value_bytes, "seal:secrets", state.provider.as_ref())?;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let secret_type = body
        .secret_type
        .unwrap_or(crate::models::SecretType::Opaque);
    let record = SecretRecord {
        id,
        name: body.name.clone(),
        secret_type: secret_type.clone(),
        version: 1,
        public_key_pem: None,
        algorithm: None,
        owner: body.owner.unwrap_or_else(|| "default".to_string()),
        tags: body.tags.unwrap_or_default(),
        created_at: now,
        updated_at: now,
        expires_at: body.expires_at,
        deleted_at: None,
        zkp_commitment,
    };

    state.store.save(&record, &blob)?;

    let meta = SecretMetadata {
        id: record.id,
        name: record.name.clone(),
        secret_type: record.secret_type.clone(),
        version: record.version,
        owner: record.owner.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
        expires_at: record.expires_at,
        tags: record.tags.clone(),
        lifecycle_state: Some(crate::nist::KeyLifecycleState::PreOperational),
    };

    Ok(serde_json::to_value(SecretResponse {
        id: record.id,
        name: record.name,
        plaintext_base64: None,
        version: record.version,
        metadata: Some(meta),
    })?)
}

/// Retrieves and decrypts a hardware-sealed secret record by UUID.
pub fn get(
    _req: &HttpRequest,
    state: &Arc<EnclaveState>,
    id: &str,
) -> Result<serde_json::Value, EnclaveError> {
    let uuid = Uuid::parse_str(id).map_err(|_| EnclaveError::BadRequest("invalid UUID".into()))?;
    let (record, blob) = state.store.load(&uuid)?;

    // Decrypt inside the enclave
    let plaintext = decrypt_secret(&blob, "seal:secrets", state.provider.as_ref())?;
    let value_b64 = base64::engine::general_purpose::STANDARD.encode(&plaintext);

    let meta = SecretMetadata {
        id: record.id,
        name: record.name.clone(),
        secret_type: record.secret_type.clone(),
        version: record.version,
        owner: record.owner.clone(),
        created_at: record.created_at,
        updated_at: record.updated_at,
        expires_at: record.expires_at,
        tags: record.tags.clone(),
        lifecycle_state: Some(crate::nist::KeyLifecycleState::Operational),
    };

    Ok(serde_json::to_value(SecretResponse {
        id: record.id,
        name: record.name,
        plaintext_base64: Some(value_b64),
        version: record.version,
        metadata: Some(meta),
    })?)
}

/// Lists administrative metadata for all active secret records.
pub fn list(
    _req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let records = state.store.list()?;
    let metas: Vec<SecretMetadata> = records
        .into_iter()
        .map(|r| SecretMetadata {
            id: r.id,
            name: r.name,
            secret_type: r.secret_type,
            version: r.version,
            owner: r.owner,
            created_at: r.created_at,
            updated_at: r.updated_at,
            expires_at: r.expires_at,
            tags: r.tags,
            lifecycle_state: Some(crate::nist::KeyLifecycleState::Operational),
        })
        .collect();
    Ok(serde_json::to_value(metas)?)
}

/// Updates the plaintext payload of an existing secret, rotating its version and re-sealing.
pub fn update(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
    id: &str,
) -> Result<serde_json::Value, EnclaveError> {
    let uuid = Uuid::parse_str(id).map_err(|_| EnclaveError::BadRequest("invalid UUID".into()))?;
    let body: UpdateSecretRequest = serde_json::from_slice(&req.body)?;

    let (mut record, _old_blob) = state.store.load(&uuid)?;

    let value_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body.plaintext_base64)
        .map_err(|_| EnclaveError::BadRequest("plaintext_base64 is not valid base64".into()))?;

    let new_blob = encrypt_secret(&value_bytes, "seal:secrets", state.provider.as_ref())?;
    record.version += 1;
    record.updated_at = Utc::now();
    record.zkp_commitment = generate_commitment(&value_bytes).ok().map(|c| c.point_hex);

    state.store.save(&record, &new_blob)?;
    Ok(
        serde_json::json!({ "id": uuid, "version": record.version, "updated_at": record.updated_at }),
    )
}

/// Soft-deletes a secret by populating its `deleted_at` timestamp.
pub fn delete(
    _req: &HttpRequest,
    state: &Arc<EnclaveState>,
    id: &str,
) -> Result<serde_json::Value, EnclaveError> {
    let uuid = Uuid::parse_str(id).map_err(|_| EnclaveError::BadRequest("invalid UUID".into()))?;
    state.store.soft_delete(&uuid)?;
    Ok(serde_json::json!({ "id": uuid, "deleted": true }))
}
