//! Asymmetric and Symmetric Key Lifecycle and Cryptographic Operation Handlers.
//!
//! # Capabilities
//! Handles in-enclave cryptographic operations:
//! - **Key Generation**: RSA (2048/4096), ECDSA (P-256/P-384), Ed25519, and FROST Ed25519.
//! - **Digital Signatures**: In-enclave signing with sealed private keys and public verification.
//! - **Envelope & RSA OAEP Encryption**: Public encryption and in-enclave hardware-sealed decryption.
//! - **Key Rotation & Destruction**: Versioned keypair rotation and hard deletion.

use base64::Engine as _;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::EnclaveError;
use crate::keygen;
use crate::models::SecretType;
use crate::models::{
    DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, GenerateKeyRequest,
    KeyAlgorithm, KeyResponse, SignRequest, SignResponse, VerifyRequest, VerifyResponse,
};
use crate::server::router::HttpRequest;
use crate::server::EnclaveState;
use crate::store::SecretRecord;

/// Handles generation of an asymmetric keypair, immediately sealing the private key to persistent storage.
pub fn generate(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: GenerateKeyRequest = serde_json::from_slice(&req.body)?;

    if state.store.name_exists(&body.name) {
        return Err(EnclaveError::AlreadyExists {
            id: body.name.clone(),
        });
    }

    // Generate inside the enclave — private key sealed immediately
    let (pub_pem, sealed_priv) =
        keygen::generate_keypair(body.algorithm.clone(), state.provider.as_ref())?;

    let id = Uuid::new_v4();
    let now = Utc::now();
    let record = SecretRecord {
        id,
        name: body.name.clone(),
        secret_type: SecretType::AsymmetricKey,
        version: 1,
        public_key_pem: Some(pub_pem.clone()),
        algorithm: Some(body.algorithm.to_string()),
        owner: "default".to_string(),
        tags: body.tags.clone().unwrap_or_default(),
        created_at: now,
        updated_at: now,
        expires_at: None,
        deleted_at: None,
        zkp_commitment: None,
    };

    state.store.save(&record, &sealed_priv)?;

    let metadata = crate::models::KeyMetadata {
        id,
        name: body.name.clone(),
        algorithm: body.algorithm,
        version: 1,
        owner: "default".to_string(),
        tags: body.tags.unwrap_or_default(),
        created_at: now,
        updated_at: now,
        expires_at: None,
        lifecycle_state: crate::nist::KeyLifecycleState::PreOperational,
    };
    Ok(serde_json::to_value(KeyResponse {
        id,
        name: body.name,
        public_key_pem: Some(pub_pem),
        metadata: Some(metadata),
    })?)
}

/// Lists all asymmetric key records stored in the enclave.
pub fn list(
    _req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let records = state
        .store
        .list()?
        .into_iter()
        .filter(|r| r.secret_type == SecretType::AsymmetricKey)
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "name": r.name,
                "algorithm": r.algorithm,
                "public_key_pem": r.public_key_pem,
                "created_at": r.created_at,
            })
        })
        .collect::<Vec<_>>();
    Ok(serde_json::Value::Array(records))
}

/// Exports the public key PEM for a given asymmetric key ID.
pub fn public_key(
    _req: &HttpRequest,
    state: &Arc<EnclaveState>,
    id: &str,
) -> Result<serde_json::Value, EnclaveError> {
    let uuid = Uuid::parse_str(id).map_err(|_| EnclaveError::BadRequest("bad UUID".into()))?;
    let record = state.store.load_meta(&uuid)?;
    Ok(serde_json::json!({ "id": uuid, "public_key_pem": record.public_key_pem }))
}

/// Computes a digital signature over a message using the hardware-sealed private key.
pub fn sign(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
    id: &str,
) -> Result<serde_json::Value, EnclaveError> {
    let uuid = Uuid::parse_str(id).map_err(|_| EnclaveError::BadRequest("bad UUID".into()))?;
    let body: SignRequest = serde_json::from_slice(&req.body)?;
    let (record, sealed_priv) = state.store.load(&uuid)?;

    let message = base64::engine::general_purpose::STANDARD
        .decode(&body.data_base64)
        .map_err(|_| EnclaveError::BadRequest("bad data_base64".into()))?;

    let algorithm: KeyAlgorithm = serde_json::from_value(
        serde_json::to_value(record.algorithm.as_deref().unwrap_or("")).unwrap_or_default(),
    )
    .map_err(|_| EnclaveError::UnsupportedAlgorithm(record.algorithm.unwrap_or_default()))?;

    let sig = keygen::sign(
        algorithm.clone(),
        &sealed_priv,
        &message,
        state.provider.as_ref(),
    )?;
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

    Ok(serde_json::to_value(SignResponse {
        signature_base64: sig_b64,
        algorithm: Some(algorithm),
    })?)
}

/// Verifies a digital signature against the stored public key.
pub fn verify(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
    id: &str,
) -> Result<serde_json::Value, EnclaveError> {
    let uuid = Uuid::parse_str(id).map_err(|_| EnclaveError::BadRequest("bad UUID".into()))?;
    let body: VerifyRequest = serde_json::from_slice(&req.body)?;
    let record = state.store.load_meta(&uuid)?;

    let message = base64::engine::general_purpose::STANDARD
        .decode(&body.data_base64)
        .map_err(|_| EnclaveError::BadRequest("bad data_base64".into()))?;
    let signature = base64::engine::general_purpose::STANDARD
        .decode(&body.signature_base64)
        .map_err(|_| EnclaveError::BadRequest("bad signature_base64".into()))?;

    let algorithm: KeyAlgorithm = serde_json::from_value(
        serde_json::to_value(record.algorithm.as_deref().unwrap_or("")).unwrap_or_default(),
    )
    .map_err(|_| EnclaveError::UnsupportedAlgorithm(record.algorithm.unwrap_or_default()))?;

    let pub_pem = record.public_key_pem.ok_or(EnclaveError::Internal)?;
    let valid = keygen::verify_signature(algorithm, &pub_pem, &message, &signature)?;

    Ok(serde_json::to_value(VerifyResponse { valid })?)
}

/// Encrypts plaintext under an RSA public key using RSA-OAEP SHA-256.
pub fn encrypt(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
    id: &str,
) -> Result<serde_json::Value, EnclaveError> {
    let uuid = Uuid::parse_str(id).map_err(|_| EnclaveError::BadRequest("bad UUID".into()))?;
    let body: EncryptRequest = serde_json::from_slice(&req.body)?;
    let record = state.store.load_meta(&uuid)?;

    let plaintext = base64::engine::general_purpose::STANDARD
        .decode(&body.plaintext_base64)
        .map_err(|_| EnclaveError::BadRequest("bad plaintext_base64".into()))?;

    let pub_pem = record.public_key_pem.ok_or(EnclaveError::Internal)?;
    let ct = keygen::rsa_encrypt(&pub_pem, &plaintext)?;
    let ct_b64 = base64::engine::general_purpose::STANDARD.encode(&ct);

    Ok(serde_json::to_value(EncryptResponse {
        ciphertext_base64: ct_b64,
    })?)
}

/// Decrypts RSA-OAEP ciphertext inside the enclave using the hardware-sealed private key.
pub fn decrypt(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
    id: &str,
) -> Result<serde_json::Value, EnclaveError> {
    let uuid = Uuid::parse_str(id).map_err(|_| EnclaveError::BadRequest("bad UUID".into()))?;
    let body: DecryptRequest = serde_json::from_slice(&req.body)?;
    let (_, sealed_priv) = state.store.load(&uuid)?;

    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&body.ciphertext_base64)
        .map_err(|_| EnclaveError::BadRequest("bad ciphertext_base64".into()))?;

    let pt = keygen::rsa_decrypt(&sealed_priv, &ciphertext, state.provider.as_ref())?;
    let pt_b64 = base64::engine::general_purpose::STANDARD.encode(&pt);

    Ok(serde_json::to_value(DecryptResponse {
        plaintext_base64: pt_b64,
    })?)
}

/// Rotates an existing keypair by generating a new version and updating storage atomically.
pub fn rotate(
    _req: &HttpRequest,
    state: &Arc<EnclaveState>,
    id: &str,
) -> Result<serde_json::Value, EnclaveError> {
    let uuid = Uuid::parse_str(id).map_err(|_| EnclaveError::BadRequest("bad UUID".into()))?;
    let (mut record, _old_priv) = state.store.load(&uuid)?;

    let algorithm: KeyAlgorithm = serde_json::from_value(
        serde_json::to_value(record.algorithm.as_deref().unwrap_or("")).unwrap_or_default(),
    )
    .map_err(|_| {
        EnclaveError::UnsupportedAlgorithm(record.algorithm.clone().unwrap_or_default())
    })?;

    let (new_pub_pem, new_sealed_priv) =
        keygen::generate_keypair(algorithm, state.provider.as_ref())?;

    record.public_key_pem = Some(new_pub_pem.clone());
    record.version += 1;
    record.updated_at = Utc::now();

    state.store.save(&record, &new_sealed_priv)?;

    Ok(serde_json::json!({
        "id": uuid,
        "version": record.version,
        "public_key_pem": new_pub_pem,
        "rotated_at": record.updated_at,
    }))
}

/// Hard-deletes a keypair and its sealed private key blob from storage.
pub fn delete(
    _req: &HttpRequest,
    state: &Arc<EnclaveState>,
    id: &str,
) -> Result<serde_json::Value, EnclaveError> {
    let uuid = Uuid::parse_str(id).map_err(|_| EnclaveError::BadRequest("bad UUID".into()))?;
    state.store.hard_delete(&uuid)?;
    Ok(serde_json::json!({ "id": uuid, "deleted": true }))
}
