//! Enclave-wide Domain Error Types and HTTP Status Mappings.
//!
//! # Purpose and Scope
//! This module defines the centralized error enumeration [`EnclaveError`] spanning all
//! in-enclave cryptographic operations, hardware sealing/unsealing, zero-knowledge proofs,
//! homomorphic encryption, authentication/authorization, and storage I/O.
//!
//! # Security and Invariants
//! - **Information Leakage Prevention**: All error variants are strictly designed to be safe
//!   for transmission across the untrusted host boundary. Under NO circumstances may error
//!   strings or debug formats include raw cryptographic keys, secret plaintext bytes, PRNG states,
//!   or unmasked polynomial coefficients.
//! - **Timing Attack Mitigations**: Decryption tag mismatches ([`EnclaveError::AesGcmDecrypt`])
//!   and signature verification failures ([`EnclaveError::Verify`]) return constant-time generic
//!   errors rather than detailed failure offsets.

use thiserror::Error;

/// Master error enumeration for all in-enclave operations.
#[derive(Debug, Error)]
pub enum EnclaveError {
    // ------------------------------------------------------------------
    // Sealing / unsealing
    // ------------------------------------------------------------------
    /// Hardware or simulation sealing key derivation or encryption failure.
    #[error("sealing error: {msg}")]
    Sealing { msg: &'static str },

    /// Hardware or simulation unsealing decryption or authentication failure.
    #[error("unsealing error: {msg}")]
    Unsealing { msg: &'static str },

    // ------------------------------------------------------------------
    // Symmetric crypto
    // ------------------------------------------------------------------
    /// Authenticated encryption with AES-256-GCM failed.
    #[error("AES-GCM encryption failed")]
    AesGcmEncrypt,

    /// Authenticated decryption failed due to tag mismatch or ciphertext corruption.
    #[error("AES-GCM decryption failed (authentication tag mismatch)")]
    AesGcmDecrypt,

    /// Key derivation using HKDF-SHA256 failed.
    #[error("HKDF key derivation failed: {0}")]
    Hkdf(String),

    // ------------------------------------------------------------------
    // Asymmetric key operations
    // ------------------------------------------------------------------
    /// Asymmetric keypair generation failed.
    #[error("key generation failed: {0}")]
    KeyGen(String),

    /// Key generation failed during internal entropy extraction.
    #[error("key generation failed: {0}")]
    KeyGenFailed(String),

    /// Distributed Key Generation input validation error (threshold > total or index out of bounds).
    #[error("DKG invalid input: {0}")]
    DkgInvalidInput(String),

    /// Digital signature creation failed.
    #[error("signing failed: {0}")]
    Sign(String),

    /// Digital signature verification failed against the supplied public key.
    #[error("signature verification failed")]
    Verify,

    /// RSA OAEP encryption failed.
    #[error("RSA encryption failed: {0}")]
    RsaEncrypt(String),

    /// RSA OAEP decryption failed.
    #[error("RSA decryption failed: {0}")]
    RsaDecrypt(String),

    /// Requested cryptographic algorithm is unsupported by the enclave engine.
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Requested feature or algorithm stub is not yet implemented.
    #[error("functionality not implemented: {0}")]
    NotImplemented(String),

    // ------------------------------------------------------------------
    // ZKP
    // ------------------------------------------------------------------
    /// Zero-knowledge proof generation failed.
    #[error("ZKP proof generation failed: {0}")]
    ZkpProve(String),

    /// Zero-knowledge proof verification failed (invalid proof or mismatched commitment).
    #[error("ZKP proof verification failed")]
    ZkpVerify,

    /// Invalid parameters supplied to zero-knowledge proof generation or verification.
    #[error("ZKP invalid input: {0}")]
    ZkpInvalidInput(String),

    // ------------------------------------------------------------------
    // Homomorphic Encryption
    // ------------------------------------------------------------------
    /// Paillier PHE keypair generation failed.
    #[error("HE key generation failed: {0}")]
    HeKeyGen(String),

    /// Paillier PHE encryption failed.
    #[error("HE encryption failed: {0}")]
    HeEncrypt(String),

    /// Paillier PHE decryption failed.
    #[error("HE decryption failed: {0}")]
    HeDecrypt(String),

    /// Homomorphic addition or scalar multiplication failed.
    #[error("HE operation failed: {0}")]
    HeOperation(String),

    // ------------------------------------------------------------------
    // Storage
    // ------------------------------------------------------------------
    /// Storage file I/O error on sealed records or metadata files.
    #[error("storage I/O error: {0}")]
    Storage(String),

    /// Secret or key record with the specified ID was not found in the enclave store.
    #[error("secret not found: {id}")]
    NotFound { id: String },

    /// Secret or key record with the specified identifier or name already exists.
    #[error("secret already exists: {id}")]
    AlreadyExists { id: String },

    // ------------------------------------------------------------------
    // Authentication / authorization
    // ------------------------------------------------------------------
    /// Missing, malformed, or invalid authentication credentials.
    #[error("unauthorized")]
    Unauthorized,

    /// Authentication token expiration timestamp has passed.
    #[error("token expired")]
    TokenExpired,

    /// Authentication token JTI has been explicitly revoked via deny-list.
    #[error("token revoked")]
    TokenRevoked,

    /// Calling token lacks the required RBAC/ABAC scope.
    #[error("insufficient scope: required '{required}'")]
    InsufficientScope { required: String },

    // ------------------------------------------------------------------
    // HTTP / protocol
    // ------------------------------------------------------------------
    /// Malformed client request payload or JSON deserialization failure.
    #[error("bad request: {0}")]
    BadRequest(String),

    /// JSON serialization or formatting error.
    #[error("JSON serialization error: {0}")]
    Json(String),

    /// In-enclave TLS negotiation or transport error.
    #[error("TLS error: {0}")]
    Tls(String),

    // ------------------------------------------------------------------
    // Internal / catchall
    // ------------------------------------------------------------------
    /// Unspecified internal enclave runtime failure.
    #[error("internal error")]
    Internal,
}

impl From<serde_json::Error> for EnclaveError {
    fn from(e: serde_json::Error) -> Self {
        EnclaveError::Json(e.to_string())
    }
}

impl From<std::io::Error> for EnclaveError {
    fn from(e: std::io::Error) -> Self {
        EnclaveError::Storage(e.to_string())
    }
}

/// Maps an [`EnclaveError`] variant to its corresponding HTTP status code.
///
/// # Status Mappings
/// - `404 Not Found`: [`EnclaveError::NotFound`]
/// - `401 Unauthorized`: [`EnclaveError::Unauthorized`], [`EnclaveError::TokenExpired`], [`EnclaveError::TokenRevoked`]
/// - `403 Forbidden`: [`EnclaveError::InsufficientScope`]
/// - `400 Bad Request`: [`EnclaveError::BadRequest`]
/// - `409 Conflict`: [`EnclaveError::AlreadyExists`]
/// - `501 Not Implemented`: [`EnclaveError::NotImplemented`]
/// - `500 Internal Server Error`: All other internal or crypto fault variants.
pub fn http_status(e: &EnclaveError) -> u16 {
    match e {
        EnclaveError::NotFound { .. } => 404,
        EnclaveError::Unauthorized | EnclaveError::TokenExpired | EnclaveError::TokenRevoked => 401,
        EnclaveError::InsufficientScope { .. } => 403,
        EnclaveError::BadRequest(_) => 400,
        EnclaveError::NotImplemented(_) => 501,
        EnclaveError::AlreadyExists { .. } => 409,
        _ => 500,
    }
}
