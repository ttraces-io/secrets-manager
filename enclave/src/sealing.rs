//! Intel SGX Hardware and Simulation Sealing Engine.
//!
//! # Architecture and Threat Model
//! Sealing is the process by which an SGX enclave encrypts data at rest using a key
//! derived directly from hardware-fused CPU root keys, binding persistent data to either
//! the specific enclave build measurement (`KEYPOLICY_MRENCLAVE`) or the enclave signer's
//! public key and security version number (`KEYPOLICY_MRSIGNER` + `ISVSVN`).
//!
//! # Sealed Blob Binary Layout
//! Every sealed ciphertext payload conforms to the deterministic binary layout:
//! ```text
//! ┌──────────────────────┬──────────────────────────────────┬──────────────────────┐
//! │  AES-GCM Nonce (IV)  │            Ciphertext            │ Authenticated Tag    │
//! │       12 bytes       │             N bytes              │ 16 bytes             │
//! └──────────────────────┴──────────────────────────────────┴──────────────────────┘
//! ```
//!
//! # Key Derivation Hierarchy
//! ```text
//!          Hardware CPU Master Key (EGETKEY with KEYPOLICY_MRSIGNER)
//!                                     │
//!                                     ▼
//!                 HKDF-Extract(salt = "traces-sm-enclave-v1")
//!                                     │
//!                                     ▼
//!                              Pseudorandom Key (PRK)
//!                                     │
//!                                     ▼
//!             HKDF-Expand(info = purpose_label, len = 32 bytes)
//!                                     │
//!                                     ▼
//!             32-Byte Purpose-Scoped Data Encryption Key (DEK)
//!                                     │
//!                                     ▼
//!                         AES-256-GCM AEAD Encryption
//! ```
//!
//! # Zeroization and Memory Invariants
//! All intermediate master keys and derived DEKs are strictly wrapped in [`zeroize::Zeroizing`]
//! buffers, guaranteeing that stack and heap allocations are wiped with zeroes immediately
//! upon drop or scope exit.

use std::fs;
use std::path::Path;

use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM, NONCE_LEN,
};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::error::EnclaveError;

// ─────────────────────────────────────────────────────────────────────────────
// Trait
// ─────────────────────────────────────────────────────────────────────────────

/// Abstraction over the SGX sealing key source.
///
/// Implementations must be `Send + Sync` so that state can be shared across the
/// in-enclave multi-threaded HTTP server thread pool.
pub trait SealingKeyProvider: Send + Sync {
    /// Returns the 32-byte master root sealing key wrapped in a zeroizing container.
    ///
    /// # Hardware Mode (`HW`)
    /// Invokes the hardware `EGETKEY` instruction configured with `KEYPOLICY_MRSIGNER`
    /// and current `ISVSVN`, returning a 128-bit key expanded via SHA-256 to 256 bits.
    ///
    /// # Simulation Mode (`SIM`)
    /// Reads or generates a 256-bit CSPRNG key persisted with `0o600` file permissions.
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, EnclaveError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Simulation provider (dev / CI — no real SGX)
// ─────────────────────────────────────────────────────────────────────────────

/// Simulation sealing key provider for non-SGX host platforms, development, and unit testing.
pub struct SimSealingProvider {
    key_path: std::path::PathBuf,
}

impl SimSealingProvider {
    /// Constructs a new [`SimSealingProvider`] rooted at `store_path/.sim_master_key`.
    pub fn new(store_path: &str) -> Self {
        fs::create_dir_all(store_path).expect("Cannot create store directory");
        Self {
            key_path: Path::new(store_path).join(".sim_master_key"),
        }
    }
}

impl SealingKeyProvider for SimSealingProvider {
    /// Reads the simulation master key or generates a new 256-bit CSPRNG seed on disk.
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, EnclaveError> {
        if self.key_path.exists() {
            let bytes = fs::read(&self.key_path).map_err(|_e| EnclaveError::Sealing {
                msg: "cannot read sim key",
            })?;
            if bytes.len() < 32 {
                return Err(EnclaveError::Sealing {
                    msg: "sim key file too short",
                });
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&bytes[..32]);
            Ok(key)
        } else {
            let rng = SystemRandom::new();
            let mut raw = Zeroizing::new([0u8; 32]);
            rng.fill(raw.as_mut()).map_err(|_| EnclaveError::Sealing {
                msg: "RNG failure during key gen",
            })?;
            fs::write(&self.key_path, raw.as_ref()).map_err(|_| EnclaveError::Sealing {
                msg: "cannot write sim key",
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&self.key_path, fs::Permissions::from_mode(0o600));
            }
            log::info!(
                "Simulation master sealing key created at {:?}",
                self.key_path
            );
            Ok(raw)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hardware provider (real Intel SGX — requires sgx-hw feature)
// ─────────────────────────────────────────────────────────────────────────────

/// Real Intel SGX hardware sealing key provider utilizing CPU `EGETKEY` instructions.
pub struct HwSealingProvider;

impl SealingKeyProvider for HwSealingProvider {
    /// Executes `EGETKEY` with `KEYPOLICY_MRSIGNER`, returning an expanded 32-byte zeroized key.
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, EnclaveError> {
        #[cfg(feature = "sgx-hw")]
        {
            use sgx_isa::{Keyname, Keypolicy, Keyrequest};

            let mut req = Keyrequest::default();
            req.keyname = Keyname::Seal as u16;
            // MRSIGNER policy: key survives code updates, locked to signing identity + SVN
            req.keypolicy = Keypolicy::MRSIGNER;
            req.isvsvn = env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(1);

            let raw16 = req.egetkey().map_err(|_| EnclaveError::Sealing {
                msg: "EGETKEY failed",
            })?;

            // EGETKEY returns 16 bytes; expand to 32 via SHA-256
            let expanded = ring::digest::digest(&ring::digest::SHA256, &raw16);
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(expanded.as_ref());
            Ok(key)
        }
        #[cfg(not(feature = "sgx-hw"))]
        {
            Err(EnclaveError::Sealing {
                msg: "SGX hardware feature not compiled in",
            })
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Nonce wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// Single-use nonce sequence wrapper enforcing exactly-once nonce consumption for ring's `BoundKey` API.
struct OneTimeNonce(Option<[u8; NONCE_LEN]>);

impl NonceSequence for OneTimeNonce {
    /// Advances the sequence by yielding the 96-bit nonce exactly once, returning `Unspecified` on subsequent calls.
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.0
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(ring::error::Unspecified)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Key derivation
// ─────────────────────────────────────────────────────────────────────────────

/// Derives a 32-byte purpose-scoped Data Encryption Key (DEK) from the master sealing key using HKDF-SHA256.
///
/// # Invariants
/// - `purpose` MUST be a distinct, unique ASCII identifier for each operational domain
///   (e.g., `"seal:secrets"`, `"seal:paillier-priv"`, `"seal:token-key"`).
fn derive_dek(master: &[u8; 32], purpose: &str) -> Result<Zeroizing<[u8; 32]>, EnclaveError> {
    // HKDF: Extract → expand
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"traces-sm-enclave-v1");
    let prk = salt.extract(master.as_ref());
    let info = [purpose.as_bytes()];
    let okm = prk
        .expand(&info, &AES_256_GCM)
        .map_err(|_| EnclaveError::Hkdf(format!("expand failed for purpose={purpose}")))?;

    let mut dek = Zeroizing::new([0u8; 32]);
    okm.fill(dek.as_mut())
        .map_err(|_| EnclaveError::Hkdf("fill failed".into()))?;
    Ok(dek)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Seals `plaintext` under a purpose-scoped DEK derived from the master key using AES-256-GCM.
///
/// # Binary Output Structure
/// Returns a byte vector containing `[nonce(12 bytes) | ciphertext | tag(16 bytes)]`.
///
/// # Parameters
/// - `plaintext`: Raw bytes to be encrypted and sealed.
/// - `purpose`: Domain separation label for HKDF key derivation.
/// - `provider`: Sealing key provider instance ([`HwSealingProvider`] or [`SimSealingProvider`]).
pub fn seal(
    plaintext: &[u8],
    purpose: &str,
    provider: &dyn SealingKeyProvider,
) -> Result<Vec<u8>, EnclaveError> {
    let master = provider.master_key()?;
    let dek = derive_dek(&master, purpose)?;

    // Generate random nonce
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| EnclaveError::AesGcmEncrypt)?;

    let unbound =
        UnboundKey::new(&AES_256_GCM, dek.as_ref()).map_err(|_| EnclaveError::AesGcmEncrypt)?;
    let mut sealing_key = SealingKey::new(unbound, OneTimeNonce(Some(nonce_bytes)));

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut in_out)
        .map_err(|_| EnclaveError::AesGcmEncrypt)?;

    // Prepend nonce to output
    let mut blob = Vec::with_capacity(NONCE_LEN + in_out.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend(in_out);
    Ok(blob)
}

/// Unseals a sealed blob previously produced by [`seal`].
///
/// # Verification and Security
/// Verifies the 128-bit authentication tag before returning decrypted plaintext. Any
/// tampering or corruption returns [`EnclaveError::AesGcmDecrypt`].
///
/// # Parameters
/// - `blob`: The sealed payload `[nonce(12) | ciphertext | tag(16)]`.
/// - `purpose`: Domain separation string used during sealing.
/// - `provider`: Sealing key provider instance.
pub fn unseal(
    blob: &[u8],
    purpose: &str,
    provider: &dyn SealingKeyProvider,
) -> Result<Vec<u8>, EnclaveError> {
    // Minimum: 12-byte nonce + 16-byte tag (empty plaintext would be 28 bytes)
    if blob.len() < NONCE_LEN + 16 {
        return Err(EnclaveError::Unsealing {
            msg: "blob too short",
        });
    }

    let master = provider.master_key()?;
    let dek = derive_dek(&master, purpose)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&blob[..NONCE_LEN]);

    let unbound =
        UnboundKey::new(&AES_256_GCM, dek.as_ref()).map_err(|_| EnclaveError::AesGcmDecrypt)?;
    let mut opening_key = OpeningKey::new(unbound, OneTimeNonce(Some(nonce_bytes)));

    let mut in_out = blob[NONCE_LEN..].to_vec();
    let decrypted = opening_key
        .open_in_place(Aad::empty(), &mut in_out)
        .map_err(|_| EnclaveError::AesGcmDecrypt)?;
    Ok(decrypted.to_vec())
}

pub use seal as seal_data;
pub use unseal as unseal_data;


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    struct MockProvider([u8; 32]);
    impl SealingKeyProvider for MockProvider {
        fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, EnclaveError> {
            Ok(Zeroizing::new(self.0))
        }
    }

    #[test]
    fn seal_unseal_roundtrip() {
        let p = MockProvider([0xAB; 32]);
        let msg = b"top secret value 42!";
        let blob = seal(msg, "test:roundtrip", &p).unwrap();
        let recovered = unseal(&blob, "test:roundtrip", &p).unwrap();
        assert_eq!(&recovered, msg);
    }

    #[test]
    fn wrong_purpose_fails() {
        let p = MockProvider([0x12; 32]);
        let blob = seal(b"data", "purpose:A", &p).unwrap();
        // Different purpose → different DEK → tag mismatch
        assert!(unseal(&blob, "purpose:B", &p).is_err());
    }

    #[test]
    fn test_high_concurrency_sealing() {
        let provider = Arc::new(MockProvider([0x42; 32]));
        let mut handles = Vec::new();

        for thread_idx in 0..16 {
            let p = Arc::clone(&provider);
            let handle = thread::spawn(move || {
                for iter in 0..50 {
                    let secret = format!("concurrent-secret-{}-{}", thread_idx, iter);
                    let purpose = format!("purpose-{}", thread_idx % 4);
                    let sealed = seal(secret.as_bytes(), &purpose, p.as_ref())
                        .expect("seal failed under concurrency");
                    let unsealed = unseal(&sealed, &purpose, p.as_ref())
                        .expect("unseal failed under concurrency");
                    assert_eq!(unsealed, secret.as_bytes());
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle
                .join()
                .expect("thread panicked during concurrency test");
        }
    }
}
