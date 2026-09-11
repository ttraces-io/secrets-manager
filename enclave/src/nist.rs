//! # NIST SP 800-57 Key Lifecycle State Machine & NIST SP 800-108 KDF
//!
//! This module implements key lifecycle state transitions adhering to NIST SP 800-57 Part 1 Rev. 5,
//! cryptoperiod volume tracking, and NIST SP 800-108 Key Derivation in Counter Mode using HMAC-SHA256.
//!
//! ## Key Lifecycle State Invariants (NIST SP 800-57 §8)
//!
//! ```text
//! ┌────────────────┐      Generate      ┌─────────────┐
//! │ PreOperational │ ─────────────────> │ Operational │
//! └────────────────┘                    └──────┬──────┘
//!                                              │ Deactivate / Retire
//!                                              ▼
//! ┌───────────┐      Crypto-Shred       ┌─────────────┐
//! │ Destroyed │ <────────────────────── │ Deactivated │
//! └───────────┘                         └─────────────┘
//! ```
//!
//! ### Permission Matrix
//! | State | Encrypt | Decrypt (Historical) | Sign | Verify |
//! | :--- | :--- | :--- | :--- | :--- |
//! | `PreOperational` | ❌ No | ❌ No | ❌ No | ❌ No |
//! | `Operational` | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
//! | `Deactivated` | ❌ No | ✅ Yes | ❌ No | ✅ Yes |
//! | `Destroyed` | ❌ No | ❌ No | ❌ No | ❌ No |

use ring::hmac;
use serde::{Deserialize, Serialize};

/// NIST SP 800-57 4-phase key lifecycle state machine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyLifecycleState {
    /// Key generated or pre-allocated, not yet authorized for active crypto operations.
    PreOperational,
    /// Active for encryption, signing, key wrapping, and verification.
    Operational,
    /// Retired from active origination; authorized only for historical decryption and verification.
    Deactivated,
    /// Key validity window expired.
    Expired,
    /// Explicitly revoked due to compromise or retirement.
    Revoked,
    /// Crypto-shredded; all key material permanently zeroized and unrecoverable.
    Destroyed,
}

impl KeyLifecycleState {
    /// Whether the key can be used for new encryption or key wrapping operations.
    pub fn can_encrypt(&self) -> bool {
        matches!(self, KeyLifecycleState::Operational)
    }

    /// Whether the key can be used to decrypt historically encrypted data.
    pub fn can_decrypt_historical(&self) -> bool {
        matches!(
            self,
            KeyLifecycleState::Operational | KeyLifecycleState::Deactivated
        )
    }

    /// Whether the key can be used to generate digital signatures or authentication tags.
    pub fn can_sign(&self) -> bool {
        matches!(self, KeyLifecycleState::Operational)
    }

    /// Whether the key can be used to verify existing signatures or tokens.
    pub fn can_verify(&self) -> bool {
        matches!(
            self,
            KeyLifecycleState::Operational | KeyLifecycleState::Deactivated
        )
    }

    /// Whether the key is in the active operational state.
    pub fn is_active(&self) -> bool {
        matches!(self, KeyLifecycleState::Operational)
    }
}

/// Bitmask-style capability permissions governing allowed cryptographic actions for a key.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct KeyUsage {
    pub sign: bool,
    pub verify: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub key_wrap: bool,
    pub derive_key: bool,
    pub authenticate: bool,
}

pub use zeroize::Zeroizing;

/// Derives keying material using the NIST SP 800-108 KDF in Counter Mode with HMAC-SHA256.
///
/// # Formula (NIST SP 800-108 §5.1)
/// $$K(i) = \text{HMAC}(K_I, [i]_2 \parallel \text{Label} \parallel 0x00 \parallel \text{Context} \parallel [L]_2)$$
///
/// # Parameters
/// * `ki` - Key derivation input secret key material.
/// * `label` - Domain separation label.
/// * `context` - Environmental context data.
/// * `l` - Target derived key length in bytes.
///
/// # Returns
/// A [`Zeroizing<Vec<u8>>`] container that automatically scrubs derived keys from memory on drop.
pub fn sp800_108_kdf(ki: &[u8], label: &[u8], context: &[u8], l: usize) -> Zeroizing<Vec<u8>> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, ki);
    let mut okm = Vec::with_capacity(l);
    let mut counter = 1u32;

    while okm.len() < l {
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&counter.to_be_bytes());
        ctx.update(label);
        ctx.update(&[0x00]);
        ctx.update(context);
        ctx.update(&(l as u32 * 8).to_be_bytes());

        let tag = ctx.sign();
        let chunk = tag.as_ref();
        let to_copy = std::cmp::min(chunk.len(), l - okm.len());
        okm.extend_from_slice(&chunk[..to_copy]);
        counter += 1;
    }
    Zeroizing::new(okm)
}

/// Tracks volumetric throughput against the NIST SP 800-57 cryptoperiod maximum threshold.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CryptoPeriod {
    /// Total bytes processed under the active key instance.
    pub bytes_processed: u64,
    /// Maximum allowed bytes before mandatory retirement (default $2^{32} = 4\text{ GB}$).
    pub max_bytes: u64,
}

impl Default for CryptoPeriod {
    fn default() -> Self {
        Self {
            bytes_processed: 0,
            max_bytes: 4_294_967_296, // 2^32
        }
    }
}

impl CryptoPeriod {
    /// Increments the volumetric counter. Returns `true` if within limit, or `false` if expired.
    pub fn process(&mut self, bytes: u64) -> bool {
        let new_total = self.bytes_processed.saturating_add(bytes);
        if new_total <= self.max_bytes {
            self.bytes_processed = new_total;
            true
        } else {
            false
        }
    }
}

