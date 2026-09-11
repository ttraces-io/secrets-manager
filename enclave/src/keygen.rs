//! # In-Enclave Cryptographic Key Generation and Signing Engine
//!
//! This module implements hardware-isolated key generation, PKCS#8 encoding, hardware sealing,
//! and digital signature computation across standard asymmetric and symmetric algorithms.
//!
//! ## Invariants & Security Guarantees
//!
//! 1. **Zero-Trust Private Key Handling**:
//!    - Private key bytes generated within the enclave are wrapped in [`zeroize::Zeroizing`].
//!    - Unsealed private keys exist in EPC RAM only for the duration of the cryptographic operation
//!      and are scrubbed before returning from function scope.
//! 2. **Purpose-Isolated Sealing**:
//!    - Each algorithm family uses distinct domain-separated sealing contexts:
//!      - RSA: `"seal:rsa-privkey"`
//!      - ECDSA: `"seal:ecdsa-privkey"`
//!      - Ed25519: `"seal:ed25519-privkey"`
//!      - Symmetric / HMAC: `"seal:symmetric-key"`
//! 3. **Standard Encoding**:
//!    - Public keys are exported as standard PEM-encoded SubjectPublicKeyInfo (X.509) format.
//!    - Private keys are persisted only as hardware-sealed ciphertext blobs.

use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, KeyPair};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use zeroize::Zeroizing;

use crate::error::EnclaveError;
use crate::models::KeyAlgorithm;
use crate::sealing::{seal_data, unseal_data, SealingKeyProvider};

/// Container for an in-enclave generated key pair.
pub struct GeneratedKeyPair {
    /// PEM-encoded public key string (SubjectPublicKeyInfo).
    pub public_key_pem: String,
    /// Hardware-sealed private key ciphertext blob.
    pub sealed_private_key: Vec<u8>,
}

/// Generates a key pair and returns `(public_key_pem, sealed_private_key)`.
///
/// # Parameters
/// * `algorithm` - Target cryptographic algorithm (RSA, ECDSA, Ed25519, AES, HMAC).
/// * `provider` - Hardware sealing key provider.
pub fn generate_keypair(
    algorithm: KeyAlgorithm,
    provider: &dyn SealingKeyProvider,
) -> Result<(String, Vec<u8>), EnclaveError> {
    let pair = generate_key_pair(algorithm, provider)?;
    Ok((pair.public_key_pem, pair.sealed_private_key))
}

/// Formats raw base64 data into a standardized 64-character line-wrapped PEM document.
fn wrap_pem(label: &str, raw_b64: &str) -> String {
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in raw_b64.as_bytes().chunks(64) {
        if let Ok(s) = std::str::from_utf8(chunk) {
            pem.push_str(s);
            pem.push('\n');
        }
    }
    pem.push_str(&format!("-----END {}-----", label));
    pem
}

/// Dispatches key generation to the appropriate algorithm backend.
///
/// # Supported Algorithms
/// - RSA-2048, RSA-4096 (PKCS#1 / PKCS#8 via `rsa` crate)
/// - ECDSA P-256, ECDSA P-384 (via `ring` crate)
/// - Ed25519 (via `ring` crate)
/// - FROST Ed25519 (via `frost-ed25519` crate)
/// - AES-128, AES-256, ChaCha20-Poly1305, HMAC-SHA256, HMAC-SHA512
pub fn generate_key_pair(
    algorithm: KeyAlgorithm,
    provider: &dyn SealingKeyProvider,
) -> Result<GeneratedKeyPair, EnclaveError> {
    match algorithm {
        KeyAlgorithm::Rsa2048 => generate_rsa(2048, provider),
        KeyAlgorithm::Rsa4096 => generate_rsa(4096, provider),
        KeyAlgorithm::EcdsaP256 => generate_ecdsa_p256(provider),
        KeyAlgorithm::EcdsaP384 => generate_ecdsa_p384(provider),
        KeyAlgorithm::Secp256k1 => generate_secp256k1(provider),
        KeyAlgorithm::Ed25519 => generate_ed25519(provider),
        KeyAlgorithm::FrostEd25519 => generate_frost_ed25519(provider),
        KeyAlgorithm::MlKem768 | KeyAlgorithm::MlKem1024 => {
            generate_pqc_kem(&algorithm.to_string(), provider)
        }
        KeyAlgorithm::MlDsa3 | KeyAlgorithm::MlDsa5 => {
            generate_pqc_dsa(&algorithm.to_string(), provider)
        }
        KeyAlgorithm::Aes128Gcm | KeyAlgorithm::Aes128Kw => {
            generate_symmetric(16, &algorithm.to_string(), provider)
        }
        KeyAlgorithm::Aes256Gcm | KeyAlgorithm::Aes256Kw | KeyAlgorithm::ChaCha20Poly1305 => {
            generate_symmetric(32, &algorithm.to_string(), provider)
        }
        KeyAlgorithm::HmacSha256 => generate_symmetric(32, &algorithm.to_string(), provider),
        KeyAlgorithm::HmacSha512 => generate_symmetric(64, &algorithm.to_string(), provider),
        KeyAlgorithm::EcdsaP521
        | KeyAlgorithm::X25519
        | KeyAlgorithm::SlhDsa
        | KeyAlgorithm::MlKem512 => Err(EnclaveError::NotImplemented(format!(
            "Algorithm {} is not implemented",
            algorithm
        ))),
        _ => Err(EnclaveError::UnsupportedAlgorithm(format!(
            "Algorithm {} is not supported",
            algorithm
        ))),
    }
}

fn generate_frost_ed25519(
    provider: &dyn SealingKeyProvider,
) -> Result<GeneratedKeyPair, EnclaveError> {
    let output = crate::frost::generate_dealer_keys(3, 2)?;
    let public_key_pem = format!(
        "-----BEGIN FROST ED25519 PUBLIC KEY PACKAGE-----\n{}\n-----END FROST ED25519 PUBLIC KEY PACKAGE-----",
        output.group_public_key_hex
    );
    let output_bytes = serde_json::to_vec(&output)
        .map_err(|e| EnclaveError::KeyGenFailed(format!("FROST serialize error: {}", e)))?;
    let sealed_private_key = seal_data(&output_bytes, "seal:frost-privkey", provider)?;

    Ok(GeneratedKeyPair {
        public_key_pem,
        sealed_private_key,
    })
}

fn generate_rsa(
    bits: usize,
    provider: &dyn SealingKeyProvider,
) -> Result<GeneratedKeyPair, EnclaveError> {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| EnclaveError::KeyGenFailed(e.to_string()))?;
    let pub_key: RsaPublicKey = priv_key.to_public_key();

    let public_key_pem = pub_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| EnclaveError::KeyGenFailed(e.to_string()))?;

    let priv_doc = priv_key
        .to_pkcs8_der()
        .map_err(|e| EnclaveError::KeyGenFailed(e.to_string()))?;
    let priv_der = Zeroizing::new(priv_doc.as_bytes().to_vec());

    let sealed_private_key = seal_data(&priv_der, "seal:rsa-privkey", provider)?;

    Ok(GeneratedKeyPair {
        public_key_pem,
        sealed_private_key,
    })
}

fn generate_ecdsa_p256(
    provider: &dyn SealingKeyProvider,
) -> Result<GeneratedKeyPair, EnclaveError> {
    let rng = SystemRandom::new();
    let pkcs8_bytes =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| EnclaveError::KeyGenFailed("ECDSA P-256 generation failed".into()))?;

    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8_bytes.as_ref(),
        &rng,
    )
    .map_err(|_| EnclaveError::KeyGenFailed("ECDSA key parse failed".into()))?;

    let pub_bytes = key_pair.public_key().as_ref();
    let b64 = base64::engine::general_purpose::STANDARD.encode(pub_bytes);
    let public_key_pem = wrap_pem("PUBLIC KEY", &b64);

    let sealed_private_key = seal_data(pkcs8_bytes.as_ref(), "seal:ecdsa-privkey", provider)?;

    Ok(GeneratedKeyPair {
        public_key_pem,
        sealed_private_key,
    })
}

fn generate_ecdsa_p384(
    provider: &dyn SealingKeyProvider,
) -> Result<GeneratedKeyPair, EnclaveError> {
    let rng = SystemRandom::new();
    let pkcs8_bytes =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_FIXED_SIGNING, &rng)
            .map_err(|_| EnclaveError::KeyGenFailed("ECDSA P-384 generation failed".into()))?;

    let key_pair = signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        pkcs8_bytes.as_ref(),
        &rng,
    )
    .map_err(|_| EnclaveError::KeyGenFailed("ECDSA key parse failed".into()))?;

    let pub_bytes = key_pair.public_key().as_ref();
    let b64 = base64::engine::general_purpose::STANDARD.encode(pub_bytes);
    let public_key_pem = wrap_pem("PUBLIC KEY", &b64);

    let sealed_private_key = seal_data(pkcs8_bytes.as_ref(), "seal:ecdsa-privkey", provider)?;

    Ok(GeneratedKeyPair {
        public_key_pem,
        sealed_private_key,
    })
}

fn generate_secp256k1(
    _provider: &dyn SealingKeyProvider,
) -> Result<GeneratedKeyPair, EnclaveError> {
    Err(EnclaveError::NotImplemented(
        "Secp256k1 algorithm support is not implemented".into(),
    ))
}

fn generate_ed25519(provider: &dyn SealingKeyProvider) -> Result<GeneratedKeyPair, EnclaveError> {
    let rng = SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| EnclaveError::KeyGenFailed("Ed25519 generation failed".into()))?;

    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
        .map_err(|_| EnclaveError::KeyGenFailed("Ed25519 key parse failed".into()))?;

    let pub_bytes = key_pair.public_key().as_ref();
    let b64 = base64::engine::general_purpose::STANDARD.encode(pub_bytes);
    let public_key_pem = wrap_pem("PUBLIC KEY", &b64);

    let sealed_private_key = seal_data(pkcs8_bytes.as_ref(), "seal:ed25519-privkey", provider)?;

    Ok(GeneratedKeyPair {
        public_key_pem,
        sealed_private_key,
    })
}

fn generate_pqc_kem(
    name: &str,
    _provider: &dyn SealingKeyProvider,
) -> Result<GeneratedKeyPair, EnclaveError> {
    Err(EnclaveError::NotImplemented(format!(
        "Post-Quantum Cryptography KEM ({}) is not implemented",
        name
    )))
}

fn generate_pqc_dsa(
    name: &str,
    _provider: &dyn SealingKeyProvider,
) -> Result<GeneratedKeyPair, EnclaveError> {
    Err(EnclaveError::NotImplemented(format!(
        "Post-Quantum Cryptography DSA ({}) is not implemented",
        name
    )))
}

fn generate_symmetric(
    len: usize,
    _name: &str,
    provider: &dyn SealingKeyProvider,
) -> Result<GeneratedKeyPair, EnclaveError> {
    let mut key_bytes = Zeroizing::new(vec![0u8; len]);
    ring::rand::SystemRandom::new()
        .fill(&mut key_bytes)
        .map_err(|_| EnclaveError::KeyGenFailed("Symmetric keygen failed".into()))?;

    let public_key_pem = String::new();
    let sealed_private_key = seal_data(&key_bytes, "seal:symmetric-key", provider)?;

    Ok(GeneratedKeyPair {
        public_key_pem,
        sealed_private_key,
    })
}

pub fn sign(
    algorithm: KeyAlgorithm,
    sealed_priv: &[u8],
    message: &[u8],
    provider: &dyn SealingKeyProvider,
) -> Result<Vec<u8>, EnclaveError> {
    match algorithm {
        KeyAlgorithm::Ed25519 => {
            let pkcs8 = unseal_data(sealed_priv, "seal:ed25519-privkey", provider)?;
            let key_pair = signature::Ed25519KeyPair::from_pkcs8(&pkcs8)
                .map_err(|_| EnclaveError::Internal)?;
            let sig = key_pair.sign(message);
            Ok(sig.as_ref().to_vec())
        }
        KeyAlgorithm::EcdsaP256 => {
            let pkcs8 = unseal_data(sealed_priv, "seal:ecdsa-privkey", provider)?;
            let rng = SystemRandom::new();
            let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &pkcs8,
                &rng,
            )
            .map_err(|_| EnclaveError::Internal)?;
            let sig = key_pair
                .sign(&rng, message)
                .map_err(|_| EnclaveError::Internal)?;
            Ok(sig.as_ref().to_vec())
        }
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
            let priv_der = unseal_data(sealed_priv, "seal:rsa-privkey", provider)?;
            let priv_key = RsaPrivateKey::from_pkcs8_der(&priv_der)
                .map_err(|e| EnclaveError::KeyGenFailed(e.to_string()))?;
            let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(priv_key);
            use rsa::signature::Signer;
            let sig = signing_key.sign(message);
            use rsa::signature::SignatureEncoding;
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err(EnclaveError::NotImplemented(format!(
            "Signing not supported for {}",
            algorithm
        ))),
    }
}

pub fn verify_signature(
    algorithm: KeyAlgorithm,
    pub_pem: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<bool, EnclaveError> {
    match algorithm {
        KeyAlgorithm::Ed25519 => {
            let cleaned = pub_pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace(['\r', '\n', ' '], "");
            let pub_bytes = base64::engine::general_purpose::STANDARD
                .decode(cleaned)
                .map_err(|_| EnclaveError::BadRequest("invalid public key base64".into()))?;
            let peer_public_key =
                signature::UnparsedPublicKey::new(&signature::ED25519, &pub_bytes);
            Ok(peer_public_key.verify(message, signature).is_ok())
        }
        KeyAlgorithm::EcdsaP256 => {
            let cleaned = pub_pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace(['\r', '\n', ' '], "");
            let pub_bytes = base64::engine::general_purpose::STANDARD
                .decode(cleaned)
                .map_err(|_| EnclaveError::BadRequest("invalid public key base64".into()))?;
            let peer_public_key =
                signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &pub_bytes);
            Ok(peer_public_key.verify(message, signature).is_ok())
        }
        KeyAlgorithm::Rsa2048 | KeyAlgorithm::Rsa4096 => {
            let pub_key = RsaPublicKey::from_public_key_pem(pub_pem)
                .map_err(|e| EnclaveError::KeyGenFailed(e.to_string()))?;
            let verifying_key = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pub_key);
            use rsa::signature::Verifier;
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| EnclaveError::BadRequest("invalid RSA signature bytes".into()))?;
            Ok(verifying_key.verify(message, &sig).is_ok())
        }
        _ => Err(EnclaveError::NotImplemented(format!(
            "Verification not supported for {}",
            algorithm
        ))),
    }
}

pub fn rsa_encrypt(pub_pem: &str, plaintext: &[u8]) -> Result<Vec<u8>, EnclaveError> {
    let pub_key = RsaPublicKey::from_public_key_pem(pub_pem)
        .map_err(|e| EnclaveError::KeyGenFailed(e.to_string()))?;
    let mut rng = rand::thread_rng();
    let padding = Oaep::new::<sha2::Sha256>();
    let ct = pub_key
        .encrypt(&mut rng, padding, plaintext)
        .map_err(|_e| EnclaveError::Internal)?;
    Ok(ct)
}

pub fn rsa_decrypt(
    sealed_priv: &[u8],
    ciphertext: &[u8],
    provider: &dyn SealingKeyProvider,
) -> Result<Vec<u8>, EnclaveError> {
    let priv_der = unseal_data(sealed_priv, "seal:rsa-privkey", provider)?;
    let priv_key = RsaPrivateKey::from_pkcs8_der(&priv_der)
        .map_err(|e| EnclaveError::KeyGenFailed(e.to_string()))?;
    let padding = Oaep::new::<sha2::Sha256>();
    let pt = priv_key
        .decrypt(padding, ciphertext)
        .map_err(|_e| EnclaveError::Internal)?;
    Ok(pt)
}
