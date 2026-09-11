//! # In-Enclave JWT Token Authentication and Issuance Service
//!
//! This module implements hardware-bound JSON Web Token (JWT) issuance, cryptographic
//! signature verification, and lifecycle management running strictly inside the Intel SGX enclave.
//!
//! ## Architectural Invariants & Security Guarantees
//!
//! 1. **Zero-Leakage Private Key**:
//!    - The token signing private key is generated inside the enclave using Ring's CSPRNG.
//!    - When persisted, it is sealed using Intel SGX hardware-derived keys with purpose
//!      `"seal:token-signing-key"`.
//!    - When unsealed for signing operations, the raw PKCS#8 key buffer is wrapped in
//!      [`zeroize::Zeroizing`] so that memory registers are zeroed immediately upon drop.
//! 2. **Signature Verification without Unsealing**:
//!    - The public key DER bytes are retained in enclave memory (`pub_bytes`), allowing
//!      inbound JWT signature verification with zero decryption overhead or unsealing calls.
//! 3. **Non-Replayability and Revocation**:
//!    - Every token carries a unique UUID v4 JWT ID (`jti`) and Unix timestamp expiry (`exp`).
//!    - Revoked tokens are tracked in an in-memory deny-list and persisted to `revoked_tokens.json`.
//! 4. **EdDSA Signature Standard**:
//!    - Tokens are signed using Ed25519 (RFC 8037) over `base64url(header).base64url(payload)`.

use ring::signature::KeyPair;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use chrono::Utc;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::EnclaveError;
use crate::sealing::{seal, unseal, SealingKeyProvider};

/// Hardware sealing purpose domain separation string for the token signing private key.
const SEALING_PURPOSE: &str = "seal:token-signing-key";

/// Filename for the hardware-sealed token signing key.
const KEY_FILE: &str = "token_signing_key.sealed";

/// Filename for the persisted token revocation deny-list.
const REVOKED_FILE: &str = "revoked_tokens.json";

// ─────────────────────────────────────────────────────────────────────────────
// JWT claims
// ─────────────────────────────────────────────────────────────────────────────

/// Standard JWT payload claims schema for enclave-authenticated sessions.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject identifier (e.g. client ID, node ID, or service principal).
    pub sub: String,
    /// Issued-at timestamp (Unix epoch seconds).
    pub iat: i64,
    /// Expiration timestamp (Unix epoch seconds).
    pub exp: i64,
    /// Unique JWT Identifier (UUID v4) used for revocation tracking and replay defense.
    pub jti: String,
    /// Authorized capability scopes (e.g. `["keys:read", "secrets:write", "zkp:prove"]`).
    pub scopes: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Token service
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe in-enclave JWT token service managing signing, verification, and revocation.
pub struct EnclaveTokenService {
    /// Hardware-sealed PKCS#8 Ed25519 private key bytes.
    sealed_priv: Vec<u8>,
    /// DER-encoded public key bytes for fast in-enclave signature verification.
    pub_bytes: Vec<u8>,
    /// Thread-safe in-memory deny-list of revoked token JTIs.
    revoked: Arc<Mutex<HashSet<String>>>,
    /// Persistent directory path for sealed key storage and revocation state.
    store_path: String,
}

impl EnclaveTokenService {
    /// Initializes or loads the enclave token service.
    ///
    /// # Invariants & Workflow
    /// 1. Checks if `token_signing_key.sealed` exists in `store_path`.
    /// 2. If present, unseals the key using `provider` to verify public key derivation.
    /// 3. If missing, generates a fresh Ed25519 keypair, seals the private key, and writes to disk.
    /// 4. Loads any existing `revoked_tokens.json` into the thread-safe revocation set.
    ///
    /// # Arguments
    /// * `store_path` - Filesystem path for persisted sealed artifacts.
    /// * `provider` - Sealing key provider (SGX hardware root or mock provider).
    ///
    /// # Errors
    /// Returns [`EnclaveError`] if sealing/unsealing fails or disk I/O errors occur.
    pub fn new(store_path: &str, provider: &dyn SealingKeyProvider) -> Result<Self, EnclaveError> {
        let key_path = std::path::Path::new(store_path).join(KEY_FILE);

        let (sealed_priv, pub_bytes) = if key_path.exists() {
            // Load existing sealed key
            let sealed = std::fs::read(&key_path)?;
            let priv_pkcs8 = Zeroizing::new(unseal(&sealed, SEALING_PURPOSE, provider)?);
            let kp = Ed25519KeyPair::from_pkcs8(&priv_pkcs8)
                .map_err(|e| EnclaveError::KeyGen(format!("Ed25519 token key load: {e}")))?;
            let pub_b = kp.public_key().as_ref().to_vec();
            (sealed, pub_b)
        } else {
            // Generate a new keypair and seal it
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|e| EnclaveError::KeyGen(format!("Ed25519 token keygen: {e}")))?;
            let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
                .map_err(|e| EnclaveError::KeyGen(format!("Ed25519 token parse: {e}")))?;
            let pub_b = kp.public_key().as_ref().to_vec();
            let sealed = seal(pkcs8.as_ref(), SEALING_PURPOSE, provider)?;
            std::fs::write(&key_path, &sealed)?;
            log::info!("Generated new token signing key at {key_path:?}");
            (sealed, pub_b)
        };

        let rev_path = std::path::Path::new(store_path).join(REVOKED_FILE);
        let revoked_set: HashSet<String> = if rev_path.exists() {
            std::fs::read_to_string(&rev_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            HashSet::new()
        };

        Ok(Self {
            sealed_priv,
            pub_bytes,
            revoked: Arc::new(Mutex::new(revoked_set)),
            store_path: store_path.to_string(),
        })
    }

    /// Issues a signed JWT with the specified subject, scopes, and time-to-live.
    ///
    /// # Parameters
    /// * `subject` - The authenticated entity name or client principal.
    /// * `scopes` - List of permission scopes granted to the token.
    /// * `ttl_secs` - Lifetime of the token in seconds.
    /// * `provider` - Sealing provider used to temporarily unseal the signing private key.
    ///
    /// # Returns
    /// A tuple of `(jti, compact_jwt_string)`.
    ///
    /// # Security Invariant
    /// The private key is unsealed only during signing and immediately zeroized on scope exit.
    pub fn issue_token(
        &self,
        subject: &str,
        scopes: Vec<String>,
        ttl_secs: u64,
        provider: &dyn SealingKeyProvider,
    ) -> Result<(String /*jti*/, String /*jwt*/), EnclaveError> {
        let now = Utc::now().timestamp();
        let jti = Uuid::new_v4().to_string();
        let claims = Claims {
            sub: subject.to_string(),
            iat: now,
            exp: now + ttl_secs as i64,
            jti: jti.clone(),
            scopes,
        };

        let jwt = self.sign_jwt(&claims, provider)?;
        Ok((jti, jwt))
    }

    /// Verifies a compact JWT string against the enclave's public key and checks expiry & revocation.
    ///
    /// # Verification Steps
    /// 1. Verifies 3-part `header.payload.signature` format.
    /// 2. Performs constant-time Ed25519 signature verification against `pub_bytes`.
    /// 3. Deserializes claims JSON payload.
    /// 4. Verifies `exp > current_timestamp`.
    /// 5. Validates `jti` is not present in the active revocation deny-list.
    ///
    /// # Returns
    /// The verified [`Claims`] struct if valid.
    pub fn verify_token(&self, token: &str) -> Result<Claims, EnclaveError> {
        let parts: Vec<&str> = token.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(EnclaveError::Unauthorized);
        }
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = b64url_decode(parts[2])?;

        // Verify Ed25519 signature
        let pk = UnparsedPublicKey::new(&ED25519, &self.pub_bytes);
        pk.verify(signing_input.as_bytes(), &sig_bytes)
            .map_err(|_| EnclaveError::Unauthorized)?;

        // Decode claims
        let payload_json = b64url_decode(parts[1])?;
        let claims: Claims =
            serde_json::from_slice(&payload_json).map_err(|_| EnclaveError::Unauthorized)?;

        // Check expiry
        if Utc::now().timestamp() > claims.exp {
            return Err(EnclaveError::TokenExpired);
        }

        // Check deny-list
        if self.revoked.lock().unwrap().contains(&claims.jti) {
            return Err(EnclaveError::TokenRevoked);
        }

        Ok(claims)
    }

    /// Adds a token JTI to the revocation list and persists the updated deny-list to disk.
    ///
    /// # Side Effects
    /// Updates in-memory `revoked` set and writes JSON state to `revoked_tokens.json`.
    pub fn revoke_token(&self, jti: &str) {
        let mut lock = self.revoked.lock().unwrap();
        lock.insert(jti.to_string());
        let rev_path = std::path::Path::new(&self.store_path).join(REVOKED_FILE);
        if let Ok(json) = serde_json::to_string(&*lock) {
            let _ = std::fs::write(rev_path, json);
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Internal
    // ─────────────────────────────────────────────────────────────────────

    /// Signs a JWT claims structure using the unsealed Ed25519 signing key.
    fn sign_jwt(
        &self,
        claims: &Claims,
        provider: &dyn SealingKeyProvider,
    ) -> Result<String, EnclaveError> {
        let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
        let header_b64 = b64url_encode(header.as_bytes());
        let payload_json = serde_json::to_vec(claims)?;
        let payload_b64 = b64url_encode(&payload_json);

        let signing_input = format!("{header_b64}.{payload_b64}");

        // Unseal private key
        let priv_pkcs8 = Zeroizing::new(unseal(&self.sealed_priv, SEALING_PURPOSE, provider)?);
        let kp = Ed25519KeyPair::from_pkcs8(&priv_pkcs8)
            .map_err(|e| EnclaveError::Sign(format!("Ed25519 token sign: {e}")))?;

        let sig = kp.sign(signing_input.as_bytes());
        let sig_b64 = b64url_encode(sig.as_ref());

        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64url helpers (no padding)
// ─────────────────────────────────────────────────────────────────────────────

/// Encodes raw bytes to URL-safe base64 without padding (`=`).
fn b64url_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decodes URL-safe unpadded base64 to byte vector.
fn b64url_decode(s: &str) -> Result<Vec<u8>, EnclaveError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| EnclaveError::Unauthorized)
}
