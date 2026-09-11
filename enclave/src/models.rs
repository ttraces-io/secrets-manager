//! # In-Enclave Domain Models, Request/Response DTOs & Serialization Schemas
//!
//! This module defines the canonical domain models, cryptographic algorithm enumerations,
//! and wire request/response Data Transfer Objects (DTOs) used for inter-process communication
//! across the enclave boundary via JSON-RPC, REST, and mTLS endpoints.
//!
//! ## Invariants & Serialization Guarantees
//! - **Schema Stability**: All structs implement [`Serialize`] and [`Deserialize`].
//! - **Backwards Compatibility**: DTO fields use `#[serde(alias = "...")]` and `#[serde(default)]`
//!   to handle diverse client payloads across Rust CLI, Desktop GUI, Web GUI, and external SDKs.
//! - **Strict Typing**: Cryptographic algorithms and secret categories are strongly typed enums
//!   preventing ambiguous parameter parsing.

use serde::{Deserialize, Serialize};

/// Secret category classification for access policy and storage routing.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SecretType {
    /// Arbitrary opaque binary or text data.
    Opaque,
    /// Symmetric encryption key (e.g. AES, ChaCha20).
    SymmetricKey,
    /// Asymmetric key pair or private key (e.g. RSA, ECDSA, Ed25519).
    AsymmetricKey,
    /// X.509 Certificate bundle or CA chain.
    CertBundle,
    /// SSH private/public key pair.
    SshKeyPair,
}

/// Comprehensive enumeration of cryptographic algorithms supported by the enclave.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum KeyAlgorithm {
    // Classic Asymmetric
    /// RSA 2048-bit keypair (PKCS#1 / PKCS#8 OAEP).
    Rsa2048,
    /// RSA 4096-bit keypair (PKCS#1 / PKCS#8 OAEP).
    Rsa4096,
    /// NIST P-256 (secp256r1) elliptic curve.
    EcdsaP256,
    /// NIST P-384 (secp384r1) elliptic curve.
    EcdsaP384,
    /// NIST P-521 (secp521r1) elliptic curve.
    EcdsaP521,
    /// Bitcoin / Ethereum secp256k1 Koblitz curve.
    Secp256k1,
    /// Edwards-curve Digital Signature Algorithm over Curve25519 (RFC 8032).
    Ed25519,
    /// X25519 Diffie-Hellman key exchange (RFC 7748).
    X25519,
    // Post-Quantum (NIST FIPS 203/204/205)
    /// NIST FIPS 203 ML-KEM-512 (Kyber-512).
    MlKem512,
    /// NIST FIPS 203 ML-KEM-768 (Kyber-768).
    MlKem768,
    /// NIST FIPS 203 ML-KEM-1024 (Kyber-1024).
    MlKem1024,
    /// NIST FIPS 204 ML-DSA-3 (Dilithium-3).
    MlDsa3,
    /// NIST FIPS 204 ML-DSA-5 (Dilithium-5).
    MlDsa5,
    /// NIST FIPS 205 SLH-DSA (SPHINCS+).
    SlhDsa,
    // Symmetric & Key Wrap (SP 800-38F)
    /// AES-128 in Galois/Counter Mode.
    Aes128Gcm,
    /// AES-256 in Galois/Counter Mode.
    Aes256Gcm,
    /// AES-128 Key Wrap (NIST SP 800-38F).
    Aes128Kw,
    /// AES-256 Key Wrap (NIST SP 800-38F).
    Aes256Kw,
    /// HMAC using SHA-256 hash.
    HmacSha256,
    /// HMAC using SHA-512 hash.
    HmacSha512,
    /// ChaCha20-Poly1305 authenticated symmetric cipher (RFC 8439).
    ChaCha20Poly1305,
    // Threshold DKG
    /// FROST threshold signature scheme over Ed25519.
    FrostEd25519,
    /// Pedersen Verifiable Secret Sharing.
    PedersenVss,
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Rsa2048 => write!(f, "RSA-2048"),
            KeyAlgorithm::Rsa4096 => write!(f, "RSA-4096"),
            KeyAlgorithm::EcdsaP256 => write!(f, "ECDSA-P256"),
            KeyAlgorithm::EcdsaP384 => write!(f, "ECDSA-P384"),
            KeyAlgorithm::EcdsaP521 => write!(f, "ECDSA-P521"),
            KeyAlgorithm::Secp256k1 => write!(f, "Secp256k1"),
            KeyAlgorithm::Ed25519 => write!(f, "Ed25519"),
            KeyAlgorithm::X25519 => write!(f, "X25519"),
            KeyAlgorithm::MlKem512 => write!(f, "ML-KEM-512"),
            KeyAlgorithm::MlKem768 => write!(f, "ML-KEM-768"),
            KeyAlgorithm::MlKem1024 => write!(f, "ML-KEM-1024"),
            KeyAlgorithm::MlDsa3 => write!(f, "ML-DSA-3"),
            KeyAlgorithm::MlDsa5 => write!(f, "ML-DSA-5"),
            KeyAlgorithm::SlhDsa => write!(f, "SLH-DSA"),
            KeyAlgorithm::Aes128Gcm => write!(f, "AES-128-GCM"),
            KeyAlgorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
            KeyAlgorithm::Aes128Kw => write!(f, "AES-128-KW"),
            KeyAlgorithm::Aes256Kw => write!(f, "AES-256-KW"),
            KeyAlgorithm::HmacSha256 => write!(f, "HMAC-SHA256"),
            KeyAlgorithm::HmacSha512 => write!(f, "HMAC-SHA512"),
            KeyAlgorithm::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
            KeyAlgorithm::FrostEd25519 => write!(f, "FROST-Ed25519"),
            KeyAlgorithm::PedersenVss => write!(f, "Pedersen-VSS"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DkgSetupRequest {
    pub secret_id: uuid::Uuid,
    pub threshold: usize,
    pub total: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrostDkgSetupRequest {
    pub max_signers: u16,
    pub min_signers: u16,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrostCommitRequest {
    pub key_package_json: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrostSignShareRequest {
    pub key_package_json: String,
    pub nonces_json: String,
    pub commitments_map_json: std::collections::BTreeMap<String, String>,
    pub message_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrostAggregateRequest {
    pub public_key_package_json: String,
    pub commitments_map_json: std::collections::BTreeMap<String, String>,
    pub signature_shares_json: std::collections::BTreeMap<String, String>,
    pub message_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FrostVerifyRequest {
    pub group_public_key_hex: String,
    pub signature_hex: String,
    pub message_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TransitionStateRequest {
    pub new_state: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CryptoShredRequest {
    pub id: uuid::Uuid,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EntropyStatusResponse {
    pub rct_passed: bool,
    pub apt_passed: bool,
    pub reseed_count: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(reason: impl Into<String>, _msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(reason.into()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Handler DTOs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateSecretRequest {
    pub name: String,
    #[serde(default)]
    pub secret_type: Option<SecretType>,
    #[serde(alias = "value_b64")]
    pub plaintext_base64: String,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub tags: Option<std::collections::HashMap<String, String>>,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateSecretRequest {
    #[serde(alias = "value_b64")]
    pub plaintext_base64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretMetadata {
    pub id: uuid::Uuid,
    pub name: String,
    pub secret_type: SecretType,
    pub version: u32,
    pub owner: String,
    #[serde(default)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub tags: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub lifecycle_state: Option<crate::nist::KeyLifecycleState>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretResponse {
    pub id: uuid::Uuid,
    pub name: String,
    #[serde(alias = "value_b64")]
    pub plaintext_base64: Option<String>,
    pub version: u32,
    #[serde(default)]
    pub metadata: Option<SecretMetadata>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GenerateKeyRequest {
    pub name: String,
    pub algorithm: KeyAlgorithm,
    #[serde(default)]
    pub tags: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyMetadata {
    pub id: uuid::Uuid,
    pub name: String,
    pub algorithm: KeyAlgorithm,
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub tags: std::collections::HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub lifecycle_state: crate::nist::KeyLifecycleState,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyResponse {
    pub id: uuid::Uuid,
    pub name: String,
    #[serde(default)]
    pub public_key_pem: Option<String>,
    #[serde(default)]
    pub metadata: Option<KeyMetadata>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignRequest {
    #[serde(alias = "message_b64")]
    pub data_base64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignResponse {
    #[serde(alias = "signature_b64")]
    pub signature_base64: String,
    #[serde(default)]
    pub algorithm: Option<KeyAlgorithm>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyRequest {
    #[serde(alias = "message_b64")]
    pub data_base64: String,
    #[serde(alias = "signature_b64")]
    pub signature_base64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptRequest {
    #[serde(alias = "plaintext_b64")]
    pub plaintext_base64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptResponse {
    #[serde(alias = "ciphertext_b64")]
    pub ciphertext_base64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DecryptRequest {
    #[serde(alias = "ciphertext_b64")]
    pub ciphertext_base64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DecryptResponse {
    #[serde(alias = "plaintext_b64")]
    pub plaintext_base64: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CreateTokenRequest {
    pub subject: String,
    pub scopes: Vec<String>,
    #[serde(alias = "ttl_secs")]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenResponse {
    pub token: String,
    #[serde(default)]
    pub token_id: Option<String>,
    #[serde(default)]
    pub jwt: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationMeasurements {
    pub mr_enclave: String,
    pub mr_signer: String,
    #[serde(default)]
    pub mrenclave_hex: Option<String>,
    #[serde(default)]
    pub mrsigner_hex: Option<String>,
    #[serde(default)]
    pub isvprodid: Option<u16>,
    #[serde(default)]
    pub isvsvn: Option<u16>,
    #[serde(default)]
    pub sgx_mode: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationQuoteResponse {
    pub quote_hex: String,
    #[serde(default)]
    pub quote_b64: Option<String>,
    pub measurements: AttestationMeasurements,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZkpSchnorrProveRequest {
    pub secret_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZkpSchnorrVerifyRequest {
    #[serde(default)]
    pub secret_name: Option<String>,
    #[serde(default)]
    pub public_key_hex: Option<String>,
    pub proof_hex: String,
    #[serde(default)]
    pub challenge_hex: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZkpProofResponse {
    pub proof_hex: Option<String>,
    pub valid: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZkpRangeProveRequest {
    pub secret_name: String,
    pub min: u64,
    pub max: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZkpRangeVerifyRequest {
    pub proof_hex: String,
    pub commitment_hex: String,
    pub min: u64,
    pub max: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PedersenCommitRequest {
    pub value: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PedersenCommitResponse {
    pub commitment_hex: String,
    pub blinding_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HePaillierGenerateRequest {
    pub key_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HePaillierKeyResponse {
    pub key_name: String,
    pub n_hex: String,
    pub g_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeEncryptRequest {
    pub key_name: String,
    pub plaintext: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeEncryptResponse {
    pub ciphertext_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeAddRequest {
    pub key_name: String,
    pub ciphertext1_hex: String,
    pub ciphertext2_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeAddResponse {
    pub result_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeDecryptRequest {
    pub key_name: String,
    pub ciphertext_hex: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HeDecryptResponse {
    pub plaintext: String,
}
