//! Post-Quantum Cryptography (PQC) Migration Roadmap and Type Definitions.
//!
//! # Standards and Transition Strategy
//! This module defines the API contracts and data structures for NIST Post-Quantum Cryptography
//! standards scheduled for production enclave enablement:
//! - **NIST FIPS 203 (ML-KEM)**: Module-Lattice-Based Key-Encapsulation Mechanism (formerly CRYSTALS-Kyber).
//!   Provides quantum-resistant asymmetric key establishment at Security Categories 3 (ML-KEM-768)
//!   and 5 (ML-KEM-1024).
//! - **NIST FIPS 204 (ML-DSA)**: Module-Lattice-Based Digital Signature Algorithm (formerly CRYSTALS-Dilithium).
//!   Provides quantum-resistant digital signatures at Security Categories 2 (ML-DSA-44), 3 (ML-DSA-65),
//!   and 5 (ML-DSA-87).
//!
//! # Implementation Status
//! The functions in this module currently define the stable external trait interface and
//! serialization contracts for future drop-in liboqs/rust-pqcrypto backends. All operational calls
//! return [`EnclaveError::NotImplemented`] in the current build.

use crate::error::EnclaveError;

/// ML-KEM post-quantum key encapsulation keypair container.
#[derive(Debug, Clone)]
pub struct MlKemKeyPair {
    /// Public encapsulation key bytes (NIST FIPS 203 format).
    pub public_key: Vec<u8>,
    /// Secret decapsulation key bytes (must be zeroized on drop).
    pub secret_key: Vec<u8>,
}

/// ML-DSA post-quantum digital signature keypair container.
#[derive(Debug, Clone)]
pub struct MlDsaKeyPair {
    /// Public signature verification key bytes (NIST FIPS 204 format).
    pub public_key: Vec<u8>,
    /// Private signing key bytes (must be zeroized on drop).
    pub secret_key: Vec<u8>,
}

/// Generates an ML-KEM-768 (NIST Category 3) keypair.
///
/// # Errors
/// Returns [`EnclaveError::NotImplemented`].
pub fn generate_ml_kem_768_keypair() -> Result<MlKemKeyPair, EnclaveError> {
    Err(EnclaveError::NotImplemented(
        "ML-KEM-768 key generation is not implemented".to_string(),
    ))
}

/// Generates an ML-KEM-1024 (NIST Category 5) keypair.
///
/// # Errors
/// Returns [`EnclaveError::NotImplemented`].
pub fn generate_ml_kem_1024_keypair() -> Result<MlKemKeyPair, EnclaveError> {
    Err(EnclaveError::NotImplemented(
        "ML-KEM-1024 key generation is not implemented".to_string(),
    ))
}

/// Encapsulates a shared secret under a recipient's ML-KEM public key.
///
/// # Returns
/// A tuple `(ciphertext, shared_secret)`.
///
/// # Errors
/// Returns [`EnclaveError::NotImplemented`].
pub fn ml_kem_encapsulate(_public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EnclaveError> {
    Err(EnclaveError::NotImplemented(
        "ML-KEM encapsulation is not implemented".to_string(),
    ))
}

/// Decapsulates a shared secret from an ML-KEM ciphertext using the private key.
///
/// # Errors
/// Returns [`EnclaveError::NotImplemented`].
pub fn ml_kem_decapsulate(_secret_key: &[u8], _ciphertext: &[u8]) -> Result<Vec<u8>, EnclaveError> {
    Err(EnclaveError::NotImplemented(
        "ML-KEM decapsulation is not implemented".to_string(),
    ))
}

/// Generates an ML-DSA-3 (Category 3 / ML-DSA-65) signing keypair.
///
/// # Errors
/// Returns [`EnclaveError::NotImplemented`].
pub fn generate_ml_dsa_3_keypair() -> Result<MlDsaKeyPair, EnclaveError> {
    Err(EnclaveError::NotImplemented(
        "ML-DSA-3 key generation is not implemented".to_string(),
    ))
}

/// Generates an ML-DSA-5 (Category 5 / ML-DSA-87) signing keypair.
///
/// # Errors
/// Returns [`EnclaveError::NotImplemented`].
pub fn generate_ml_dsa_5_keypair() -> Result<MlDsaKeyPair, EnclaveError> {
    Err(EnclaveError::NotImplemented(
        "ML-DSA-5 key generation is not implemented".to_string(),
    ))
}

/// Generates an ML-DSA-87 signing keypair (alias to Category 5).
///
/// # Errors
/// Returns [`EnclaveError::NotImplemented`].
pub fn generate_ml_dsa_87_keypair() -> Result<MlDsaKeyPair, EnclaveError> {
    generate_ml_dsa_5_keypair()
}

/// Signs a message using an ML-DSA private key.
///
/// # Errors
/// Returns [`EnclaveError::NotImplemented`].
pub fn ml_dsa_sign(_secret_key: &[u8], _message: &[u8]) -> Result<Vec<u8>, EnclaveError> {
    Err(EnclaveError::NotImplemented(
        "ML-DSA signing is not implemented".to_string(),
    ))
}

/// Verifies an ML-DSA signature against a message and public key.
///
/// # Errors
/// Returns [`EnclaveError::NotImplemented`].
pub fn ml_dsa_verify(
    _public_key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<bool, EnclaveError> {
    Err(EnclaveError::NotImplemented(
        "ML-DSA verification is not implemented".to_string(),
    ))
}

/// Verifies an ML-DSA-87 signature against a message and public key.
///
/// # Errors
/// Returns [`EnclaveError::NotImplemented`].
pub fn ml_dsa_87_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, EnclaveError> {
    ml_dsa_verify(public_key, message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_functions_return_not_implemented() {
        assert!(matches!(
            generate_ml_kem_768_keypair(),
            Err(EnclaveError::NotImplemented(_))
        ));
        assert!(matches!(
            generate_ml_kem_1024_keypair(),
            Err(EnclaveError::NotImplemented(_))
        ));
        assert!(matches!(
            ml_kem_encapsulate(&[]),
            Err(EnclaveError::NotImplemented(_))
        ));
        assert!(matches!(
            ml_kem_decapsulate(&[], &[]),
            Err(EnclaveError::NotImplemented(_))
        ));
        assert!(matches!(
            generate_ml_dsa_3_keypair(),
            Err(EnclaveError::NotImplemented(_))
        ));
        assert!(matches!(
            generate_ml_dsa_5_keypair(),
            Err(EnclaveError::NotImplemented(_))
        ));
        assert!(matches!(
            generate_ml_dsa_87_keypair(),
            Err(EnclaveError::NotImplemented(_))
        ));
        assert!(matches!(
            ml_dsa_sign(&[], &[]),
            Err(EnclaveError::NotImplemented(_))
        ));
        assert!(matches!(
            ml_dsa_verify(&[], &[], &[]),
            Err(EnclaveError::NotImplemented(_))
        ));
        assert!(matches!(
            ml_dsa_87_verify(&[], &[], &[]),
            Err(EnclaveError::NotImplemented(_))
        ));
    }
}
