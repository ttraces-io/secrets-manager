//! Sealing and envelope-encryption conformance tests.
//!
//! Spec references (docs/TECHNICAL_SPECIFICATION.md):
//!   §6.1 "Output: Sealed blob formatted as [ Nonce (12B) || Ciphertext || Tag (16B) ]"
//!   §6   "Sealed DEK (60B)"
//!   §3.1 "Unencrypted private key bytes ... never leave EPC memory."
//!
//! STATUS: TC-SEAL-001 and everything in the envelope section are expected to
//! FAIL. `sealing::unseal` returns `in_out.to_vec()` instead of the
//! `decrypted` slice returned by `open_in_place`, so every unseal appends the
//! 16-byte GCM tag to the plaintext. See issue ENC-010.

mod common;

use common::FixedKeyProvider;
use traces_sm_enclave::crypto::{decrypt_secret, encrypt_secret};
use traces_sm_enclave::sealing::{seal, unseal};

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const SEALED_DEK_LEN: usize = NONCE_LEN + 32 + TAG_LEN; // 60 bytes, per §6

// ─────────────────────────────────────────────────────────────────────────────
// Sealing
// ─────────────────────────────────────────────────────────────────────────────

/// TC-SEAL-001 — seal/unseal must be a lossless round-trip.
///
/// This is the test that catches ENC-010. `enclave/src/sealing.rs` already
/// contains a `#[cfg(test)]` version of this assertion, which proves the
/// in-file unit tests have never been executed: CI runs `cargo build` only.
#[test]
fn tc_seal_001_roundtrip_is_lossless() {
    let p = FixedKeyProvider::new(0xAB);
    let msg = b"top secret value 42!";

    let blob = seal(msg, "test:roundtrip", &p).expect("seal");
    let recovered = unseal(&blob, "test:roundtrip", &p).expect("unseal");

    assert_eq!(
        recovered.len(),
        msg.len(),
        "unseal returned {} bytes for a {}-byte plaintext — the {TAG_LEN}-byte \
         GCM tag is being returned as plaintext (issue ENC-010)",
        recovered.len(),
        msg.len()
    );
    assert_eq!(recovered, msg, "unsealed plaintext does not match input");
}

/// TC-SEAL-002 — the empty plaintext must round-trip.
#[test]
fn tc_seal_002_empty_plaintext_roundtrips() {
    let p = FixedKeyProvider::new(0x01);
    let blob = seal(b"", "test:empty", &p).expect("seal");
    assert_eq!(
        blob.len(),
        NONCE_LEN + TAG_LEN,
        "empty seal must be 28 bytes"
    );
    assert_eq!(unseal(&blob, "test:empty", &p).expect("unseal"), b"");
}

/// TC-SEAL-003 — blob layout must match §6.1: nonce || ciphertext || tag.
#[test]
fn tc_seal_003_blob_layout_matches_spec() {
    let p = FixedKeyProvider::new(0x02);
    let msg = b"0123456789";
    let blob = seal(msg, "test:layout", &p).expect("seal");
    assert_eq!(
        blob.len(),
        NONCE_LEN + msg.len() + TAG_LEN,
        "sealed blob must be nonce(12) || ciphertext(n) || tag(16)"
    );
}

/// TC-SEAL-004 — a 32-byte DEK must seal to exactly 60 bytes (§6).
///
/// `crypto.rs` encodes this constant as a `debug_assert_eq!`, which is a
/// no-op in release builds. This test enforces it in every profile.
#[test]
fn tc_seal_004_sealed_dek_is_60_bytes() {
    let p = FixedKeyProvider::new(0x03);
    let dek = [0x5Au8; 32];
    let sealed = seal(&dek, "seal:dek", &p).expect("seal");
    assert_eq!(sealed.len(), SEALED_DEK_LEN, "sealed DEK must be 60 bytes");
}

/// TC-SEAL-005 — domain separation: a blob sealed under one purpose must not
/// unseal under another.
#[test]
fn tc_seal_005_purpose_is_domain_separated() {
    let p = FixedKeyProvider::new(0x12);
    let blob = seal(b"data", "purpose:A", &p).expect("seal");
    assert!(
        unseal(&blob, "purpose:B", &p).is_err(),
        "a different HKDF purpose must yield a different DEK and fail the tag check"
    );
}

/// TC-SEAL-006 — a blob sealed under one master key must not unseal under another.
#[test]
fn tc_seal_006_master_key_is_binding() {
    let blob = seal(b"data", "p", &FixedKeyProvider::new(0xAA)).expect("seal");
    assert!(
        unseal(&blob, "p", &FixedKeyProvider::new(0xBB)).is_err(),
        "unsealing succeeded under a foreign master key"
    );
}

/// TC-SEAL-007 — AEAD integrity: any single-bit flip must be rejected.
#[test]
fn tc_seal_007_tamper_is_detected() {
    let p = FixedKeyProvider::new(0x04);
    let blob = seal(b"integrity-protected payload", "test:tamper", &p).expect("seal");

    for idx in [0usize, NONCE_LEN, blob.len() - 1] {
        let mut bad = blob.clone();
        bad[idx] ^= 0x01;
        assert!(
            unseal(&bad, "test:tamper", &p).is_err(),
            "a flipped bit at offset {idx} was not detected by AES-256-GCM"
        );
    }
}

/// TC-SEAL-008 — truncated blobs must be rejected, not panic.
#[test]
fn tc_seal_008_short_blob_is_rejected() {
    let p = FixedKeyProvider::new(0x05);
    for len in 0..(NONCE_LEN + TAG_LEN) {
        assert!(
            unseal(&vec![0u8; len], "test:short", &p).is_err(),
            "a {len}-byte blob must be rejected as too short"
        );
    }
}

/// TC-SEAL-009 — nonces must never repeat across seals of the same plaintext.
///
/// AES-GCM nonce reuse under a fixed key is catastrophic (it leaks the
/// XOR of the plaintexts and the authentication subkey).
#[test]
fn tc_seal_009_nonce_is_unique_per_seal() {
    let p = FixedKeyProvider::new(0x06);
    let mut nonces = Vec::new();
    for _ in 0..256 {
        let blob = seal(b"same plaintext every time", "test:nonce", &p).expect("seal");
        nonces.push(blob[..NONCE_LEN].to_vec());
    }
    let before = nonces.len();
    nonces.sort_unstable();
    nonces.dedup();
    assert_eq!(
        before,
        nonces.len(),
        "AES-GCM nonce reuse detected under a fixed key"
    );
}

/// TC-SEAL-010 — the simulation master key file must not be world-readable.
///
/// `SimSealingProvider` writes `.sim_master_key` with `fs::write`, which uses
/// mode 0666 & ~umask — typically 0644. On a shared host every local user can
/// read the key that protects every sealed secret. See issue ENC-011.
#[cfg(unix)]
#[test]
fn tc_seal_010_sim_master_key_is_owner_only() {
    use crate::common::TempStore;
    use std::os::unix::fs::PermissionsExt;
    use traces_sm_enclave::sealing::{SealingKeyProvider, SimSealingProvider};

    let tmp = TempStore::new("simkey");
    let provider = SimSealingProvider::new(tmp.path());
    provider.master_key().expect("generate sim key");

    let key_file = tmp.0.join(".sim_master_key");
    let mode = std::fs::metadata(&key_file)
        .expect("sim key file exists")
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(
        mode, 0o600,
        "master sealing key is mode {mode:o}; must be 0600 (issue ENC-011)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Envelope encryption
// ─────────────────────────────────────────────────────────────────────────────

/// TC-ENV-001 — envelope encrypt/decrypt must round-trip.
///
/// Blocked by ENC-010: `decrypt_secret` unseals the DEK, gets 48 bytes back
/// (32-byte DEK + 16-byte tag), and rejects it with "DEK wrong length after
/// unseal". Every secret written through the API is therefore unreadable.
#[test]
fn tc_env_001_roundtrip_is_lossless() {
    let p = FixedKeyProvider::new(0x21);
    let plaintext = b"very secret password 1234";

    let blob = encrypt_secret(plaintext, "test:crypto", &p).expect("encrypt");
    let recovered = decrypt_secret(&blob, "test:crypto", &p)
        .expect("decrypt — fails today because unseal returns DEK||tag (ENC-010)");

    assert_eq!(recovered, plaintext);
}

/// TC-ENV-002 — every secret must get a fresh DEK.
///
/// Encrypting the same plaintext twice must produce different sealed DEKs,
/// otherwise the "per-secret random DEK" claim in crypto.rs is false.
#[test]
fn tc_env_002_dek_is_unique_per_secret() {
    let p = FixedKeyProvider::new(0x22);
    let a = encrypt_secret(b"payload", "test:dek", &p).expect("encrypt");
    let b = encrypt_secret(b"payload", "test:dek", &p).expect("encrypt");
    assert_ne!(
        a[..SEALED_DEK_LEN],
        b[..SEALED_DEK_LEN],
        "two secrets shared a data encryption key"
    );
}

/// TC-ENV-003 — the plaintext must not appear anywhere in the blob.
#[test]
fn tc_env_003_plaintext_not_present_in_ciphertext() {
    let p = FixedKeyProvider::new(0x23);
    let needle = b"CANARY-0f3a9c-DO-NOT-LEAK";
    let blob = encrypt_secret(needle, "test:leak", &p).expect("encrypt");
    assert!(
        !blob.windows(needle.len()).any(|w| w == needle),
        "plaintext appears verbatim inside the sealed blob"
    );
}

/// TC-ENV-004 — a malformed separator byte must be rejected in every profile.
///
/// `decrypt_secret` checks the separator with `debug_assert_eq!`, which is
/// compiled out of release builds. In release, a blob with a corrupt
/// separator is parsed anyway. Input arriving from the host is untrusted and
/// must be validated unconditionally. See issue ENC-012.
#[test]
fn tc_env_004_corrupt_separator_is_rejected() {
    let p = FixedKeyProvider::new(0x24);
    let mut blob = encrypt_secret(b"payload", "test:sep", &p).expect("encrypt");
    blob[SEALED_DEK_LEN] = 0xFF; // separator must be 0x00
    assert!(
        decrypt_secret(&blob, "test:sep", &p).is_err(),
        "a corrupt separator byte was accepted (issue ENC-012)"
    );
}

/// TC-ENV-005 — truncated blobs must be rejected without panicking.
#[test]
fn tc_env_005_truncated_blob_is_rejected() {
    let p = FixedKeyProvider::new(0x25);
    let blob = encrypt_secret(b"payload", "test:trunc", &p).expect("encrypt");
    for cut in [0, 1, SEALED_DEK_LEN, SEALED_DEK_LEN + 1, blob.len() - 1] {
        assert!(
            decrypt_secret(&blob[..cut], "test:trunc", &p).is_err(),
            "a blob truncated to {cut} bytes was accepted"
        );
    }
}
