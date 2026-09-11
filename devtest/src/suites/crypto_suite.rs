//! Cryptographic Algorithms and Primitives Verification Suite.

use super::FixedKeyProvider;
use anyhow::{bail, Result};
use traces_sm_enclave::crypto::{decrypt_secret, encrypt_secret};
use traces_sm_enclave::keygen::{
    generate_key_pair, rsa_decrypt, rsa_encrypt, sign, verify_signature,
};
use traces_sm_enclave::models::KeyAlgorithm;
use traces_sm_enclave::pqc::generate_ml_kem_768_keypair;

/// Executes comprehensive cryptography and algorithm tests.
pub fn run_suite() -> Result<()> {
    let provider = FixedKeyProvider::new(0x42);

    // 1. AES-256-GCM Envelope Encryption / Decryption
    let plaintext = b"SGX_ENCLAVE_SECRET_PLAINTEXT_DATA_4096_BITS";
    let purpose = "purpose:devtest:crypto:aes256";
    let blob = encrypt_secret(plaintext, purpose, &provider)
        .map_err(|e| anyhow::anyhow!("encrypt_secret failed: {:?}", e))?;
    let decrypted = decrypt_secret(&blob, purpose, &provider)
        .map_err(|e| anyhow::anyhow!("decrypt_secret failed: {:?}", e))?;
    if decrypted != plaintext {
        bail!("AES-256-GCM decrypted plaintext mismatch");
    }

    // 2. Domain Separation / Purpose Isolation Test
    let wrong_purpose = "purpose:devtest:crypto:wrong";
    if decrypt_secret(&blob, wrong_purpose, &provider).is_ok() {
        bail!("decrypt_secret should fail with incorrect purpose domain");
    }

    // 3. Ed25519 Keygen, Sign, and Verify
    let ed_pair = generate_key_pair(KeyAlgorithm::Ed25519, &provider)
        .map_err(|e| anyhow::anyhow!("Ed25519 keygen failed: {:?}", e))?;
    let message = b"Confidential enclave attestation message";
    let ed_sig = sign(KeyAlgorithm::Ed25519, &ed_pair.sealed_private_key, message, &provider)
        .map_err(|e| anyhow::anyhow!("Ed25519 sign failed: {:?}", e))?;
    let ed_valid = verify_signature(KeyAlgorithm::Ed25519, &ed_pair.public_key_pem, message, &ed_sig)
        .map_err(|e| anyhow::anyhow!("Ed25519 verify failed: {:?}", e))?;
    if !ed_valid {
        bail!("Ed25519 signature verification returned false for valid signature");
    }

    // Ed25519 Tampered Message Negative Test
    let tampered_message = b"Tampered unauthentic message";
    let tampered_valid = verify_signature(KeyAlgorithm::Ed25519, &ed_pair.public_key_pem, tampered_message, &ed_sig)
        .unwrap_or(false);
    if tampered_valid {
        bail!("Ed25519 verification unexpectedly accepted tampered message");
    }

    // 4. ECDSA P-256 Keygen, Sign, and Verify
    let ecdsa_pair = generate_key_pair(KeyAlgorithm::EcdsaP256, &provider)
        .map_err(|e| anyhow::anyhow!("ECDSA P-256 keygen failed: {:?}", e))?;
    let ecdsa_sig = sign(KeyAlgorithm::EcdsaP256, &ecdsa_pair.sealed_private_key, message, &provider)
        .map_err(|e| anyhow::anyhow!("ECDSA P-256 sign failed: {:?}", e))?;
    let ecdsa_valid = verify_signature(KeyAlgorithm::EcdsaP256, &ecdsa_pair.public_key_pem, message, &ecdsa_sig)
        .map_err(|e| anyhow::anyhow!("ECDSA P-256 verify failed: {:?}", e))?;
    if !ecdsa_valid {
        bail!("ECDSA P-256 signature verification returned false for valid signature");
    }

    // 5. RSA-2048 Keygen, OAEP Encryption/Decryption, and PKCS#1 v1.5 Sign/Verify
    let rsa_pair = generate_key_pair(KeyAlgorithm::Rsa2048, &provider)
        .map_err(|e| anyhow::anyhow!("RSA-2048 keygen failed: {:?}", e))?;
    let rsa_ciphertext = rsa_encrypt(&rsa_pair.public_key_pem, plaintext)
        .map_err(|e| anyhow::anyhow!("RSA-OAEP encrypt failed: {:?}", e))?;
    let rsa_decrypted = rsa_decrypt(&rsa_pair.sealed_private_key, &rsa_ciphertext, &provider)
        .map_err(|e| anyhow::anyhow!("RSA-OAEP decrypt failed: {:?}", e))?;
    if rsa_decrypted != plaintext {
        bail!("RSA-OAEP decrypted plaintext mismatch");
    }

    let rsa_sig = sign(KeyAlgorithm::Rsa2048, &rsa_pair.sealed_private_key, message, &provider)
        .map_err(|e| anyhow::anyhow!("RSA-2048 sign failed: {:?}", e))?;
    let rsa_valid = verify_signature(KeyAlgorithm::Rsa2048, &rsa_pair.public_key_pem, message, &rsa_sig)
        .map_err(|e| anyhow::anyhow!("RSA-2048 verify failed: {:?}", e))?;
    if !rsa_valid {
        bail!("RSA-2048 signature verification failed for valid signature");
    }

    // 6. Symmetric Keygen (AES-128, AES-256, ChaCha20-Poly1305)
    for algo in [KeyAlgorithm::Aes128Gcm, KeyAlgorithm::Aes256Gcm, KeyAlgorithm::ChaCha20Poly1305] {
        let sym_pair = generate_key_pair(algo.clone(), &provider)
            .map_err(|e| anyhow::anyhow!("Symmetric keygen {:?} failed: {:?}", algo, e))?;
        if sym_pair.sealed_private_key.is_empty() {
            bail!("Symmetric keygen {:?} produced empty sealed key", algo);
        }
    }

    // 7. PQC Stub Verification (NIST FIPS 203/204 Interface)
    match generate_ml_kem_768_keypair() {
        Err(traces_sm_enclave::error::EnclaveError::NotImplemented(_)) => {
            // Expected stub status
        }
        other => bail!("Expected NotImplemented for ML-KEM-768 stub, got: {:?}", other),
    }

    Ok(())
}
