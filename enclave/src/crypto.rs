//! # Enclave Envelope Encryption and Cryptographic Primitives
//!
//! This module implements envelope encryption for arbitrary secret payloads inside the SGX enclave.
//!
//! ## Cryptographic Design & Wire Format
//!
//! To avoid encrypting large data payloads under the master sealing key directly, `traces-sm` employs
//! a two-tier envelope encryption scheme:
//! 1. **Data Encryption Key (DEK)**: A fresh, ephemeral 256-bit symmetric key generated via CSPRNG
//!    for each secret write.
//! 2. **Key Encryption Key (KEK / Master Sealing Key)**: The enclave's hardware-bound root sealing key
//!    derives purpose-isolated keys to seal the ephemeral DEK.
//!
//! ### Wire Format Layout
//! ```text
//! ┌──────────────────────────────────────────────┬───────────┬────────────────────────────────────────┐
//! │ Sealed DEK (60 Bytes)                        │ Sep (0x00)│ Ciphertext Payload                     │
//! │ 12B Nonce || 32B Sealed DEK || 16B Auth Tag   │ 1 Byte    │ 12B Nonce || Data Ciphertext || 16B Tag│
//! └──────────────────────────────────────────────┴───────────┴────────────────────────────────────────┘
//! ```
//!
//! ## Memory Safety & Invariants
//! - The plaintext DEK is wrapped in [`zeroize::Zeroizing<[u8; 32]>`] to guarantee that raw key bytes
//!   are scrubbed from stack/heap memory on function return.
//! - AEAD nonces are strictly 96 bits generated from a cryptographically secure RNG.

use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN,
};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::error::EnclaveError;
use crate::sealing::{seal, unseal, SealingKeyProvider};

/// Length in bytes of the hardware-sealed DEK blob: 12 (nonce) + 32 (DEK) + 16 (GCM tag) = 60 bytes.
const SEALED_DEK_LEN: usize = NONCE_LEN + 32 + 16;

/// Delimiter byte (0x00) separating the sealed DEK header from the encrypted payload.
const SEPARATOR: u8 = 0x00;

/// A single-use AEAD nonce sequence provider enforcing non-repeatable nonces in Ring.
struct OneTimeNonce(Option<[u8; NONCE_LEN]>);

impl NonceSequence for OneTimeNonce {
    /// Advances and consumes the one-time nonce.
    ///
    /// # Invariant
    /// Returns [`ring::error::Unspecified`] if called more than once on the same instance,
    /// preventing nonce reuse under identical encryption keys.
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.0
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(ring::error::Unspecified)
    }
}

/// Encrypts `plaintext` using a fresh ephemeral DEK, then seals the DEK under the hardware master key.
///
/// # Invariants & Execution Flow
/// 1. Generates a 256-bit random DEK in zeroized memory.
/// 2. Seals the DEK with `purpose` domain separation via [`crate::sealing::seal`].
/// 3. Generates a distinct 96-bit random nonce for the payload.
/// 4. Encrypts `plaintext` in-place using AES-256-GCM and appends a 128-bit authentication tag.
/// 5. Assembles and returns the envelope binary blob.
///
/// # Parameters
/// * `plaintext` - Raw unencrypted secret bytes.
/// * `purpose` - Domain separation context string bound to the sealed key.
/// * `provider` - Hardware sealing key provider.
///
/// # Errors
/// Returns [`EnclaveError::AesGcmEncrypt`] if encryption or nonce generation fails.
pub fn encrypt_secret(
    plaintext: &[u8],
    purpose: &str,
    provider: &dyn SealingKeyProvider,
) -> Result<Vec<u8>, EnclaveError> {
    let rng = SystemRandom::new();

    // 1. Generate a fresh random 256-bit DEK
    let mut dek = Zeroizing::new([0u8; 32]);
    rng.fill(dek.as_mut())
        .map_err(|_| EnclaveError::AesGcmEncrypt)?;

    // 2. Seal the DEK using the master key
    let sealed_dek = seal(dek.as_ref(), purpose, provider)?;
    debug_assert_eq!(sealed_dek.len(), SEALED_DEK_LEN, "sealed DEK size mismatch");

    // 3. Encrypt the plaintext with the DEK
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| EnclaveError::AesGcmEncrypt)?;

    let unbound =
        UnboundKey::new(&AES_256_GCM, dek.as_ref()).map_err(|_| EnclaveError::AesGcmEncrypt)?;
    let mut sk = SealingKey::new(unbound, OneTimeNonce(Some(nonce_bytes)));

    let mut ciphertext = plaintext.to_vec();
    sk.seal_in_place_append_tag(Aad::empty(), &mut ciphertext)
        .map_err(|_| EnclaveError::AesGcmEncrypt)?;

    // 4. Pack: sealed_dek || 0x00 || nonce || ciphertext_with_tag
    let mut blob = Vec::with_capacity(SEALED_DEK_LEN + 1 + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&sealed_dek);
    blob.push(SEPARATOR);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend(ciphertext);
    Ok(blob)
}

/// Decrypts a self-contained envelope blob produced by [`encrypt_secret`].
///
/// # Invariants & Decryption Steps
/// 1. Verifies minimum blob length (`SEALED_DEK_LEN + 1 + NONCE_LEN + 16`).
/// 2. Validates the 0x00 separator boundary.
/// 3. Unseals the ephemeral 256-bit DEK under the matching `purpose` context.
/// 4. Decrypts the payload ciphertext in-place and validates the 128-bit GCM tag.
/// 5. Automatically zeroizes the recovered DEK when leaving function scope.
///
/// # Parameters
/// * `blob` - Full concatenated envelope blob.
/// * `purpose` - Context string that must match the encryption purpose exactly.
/// * `provider` - Hardware sealing key provider.
///
/// # Errors
/// Returns [`EnclaveError::AesGcmDecrypt`] or [`EnclaveError::Unsealing`] if the blob is
/// truncated, the tag is invalid, or the purpose context does not match.
pub fn decrypt_secret(
    blob: &[u8],
    purpose: &str,
    provider: &dyn SealingKeyProvider,
) -> Result<Vec<u8>, EnclaveError> {
    if blob.len() < SEALED_DEK_LEN + 1 + NONCE_LEN + 16 {
        return Err(EnclaveError::AesGcmDecrypt);
    }

    // 1. Split the blob
    let sealed_dek = &blob[..SEALED_DEK_LEN];
    if blob[SEALED_DEK_LEN] != SEPARATOR {
        return Err(EnclaveError::AesGcmDecrypt);
    }
    let rest = &blob[SEALED_DEK_LEN + 1..];
    let (nonce_bytes_slice, ciphertext_with_tag) = rest.split_at(NONCE_LEN);

    // 2. Unseal the DEK
    let dek_bytes = unseal(sealed_dek, purpose, provider)?;
    if dek_bytes.len() != 32 {
        return Err(EnclaveError::Unsealing {
            msg: "DEK wrong length after unseal",
        });
    }
    let dek = Zeroizing::new({
        let mut a = [0u8; 32];
        a.copy_from_slice(&dek_bytes);
        a
    });

    // 3. Decrypt with the DEK
    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(nonce_bytes_slice);

    let unbound =
        UnboundKey::new(&AES_256_GCM, dek.as_ref()).map_err(|_| EnclaveError::AesGcmDecrypt)?;
    let mut ok = OpeningKey::new(unbound, OneTimeNonce(Some(nonce_bytes)));

    let mut in_out = ciphertext_with_tag.to_vec();
    let decrypted = ok
        .open_in_place(Aad::empty(), &mut in_out)
        .map_err(|_| EnclaveError::AesGcmDecrypt)?;
    Ok(decrypted.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealing::SimSealingProvider;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let provider = SimSealingProvider::new("/tmp/sm-test-crypto");
        let plaintext = b"very secret password 1234";
        let blob = encrypt_secret(plaintext, "test:crypto", &provider).unwrap();
        let recovered = decrypt_secret(&blob, "test:crypto", &provider).unwrap();
        assert_eq!(&recovered, plaintext);
    }

    #[test]
    fn wrong_purpose_fails() {
        let provider = SimSealingProvider::new("/tmp/sm-test-crypto-b");
        let blob = encrypt_secret(b"data", "purpose:A", &provider).unwrap();
        assert!(decrypt_secret(&blob, "purpose:B", &provider).is_err());
    }
}
