//! Hardware & Simulation Sealed Storage and Tamper Resistance Verification Suite.

use super::TestStoreDir;
use anyhow::{bail, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use traces_sm_enclave::crypto::{decrypt_secret, encrypt_secret};
use traces_sm_enclave::models::SecretType;
use traces_sm_enclave::sealing::{SealingKeyProvider, SimSealingProvider};
use traces_sm_enclave::store::{SecretRecord, Store};
use uuid::Uuid;

/// Executes sealed storage, CRUD, and ciphertext tamper detection tests.
pub fn run_suite() -> Result<()> {
    let temp_store = TestStoreDir::new("sealing-store");
    let provider = SimSealingProvider::new(temp_store.path());

    // 1. SimSealingProvider Determinism & Key Persistence
    let key1 = provider
        .master_key()
        .map_err(|e| anyhow::anyhow!("master_key() failed: {:?}", e))?;
    let provider_reload = SimSealingProvider::new(temp_store.path());
    let key2 = provider_reload
        .master_key()
        .map_err(|e| anyhow::anyhow!("reloaded master_key() failed: {:?}", e))?;
    if key1.as_slice() != key2.as_slice() {
        bail!("SimSealingProvider failed to reload persistent master key deterministically");
    }

    // 2. Store Save & Load
    let store = Store::new(temp_store.path());
    let id = Uuid::new_v4();
    let record = SecretRecord {
        id,
        name: "test-database-api-credential".to_string(),
        secret_type: SecretType::Opaque,
        version: 1,
        public_key_pem: None,
        algorithm: None,
        owner: "devtest-service-principal".to_string(),
        tags: {
            let mut t = HashMap::new();
            t.insert("env".to_string(), "development-sandbox".to_string());
            t
        },
        created_at: Utc::now(),
        updated_at: Utc::now(),
        expires_at: None,
        deleted_at: None,
        zkp_commitment: None,
    };

    let plaintext = b"DATABASE_SUPERUSER_PASSWORD_SECURE_987654";
    let blob = encrypt_secret(plaintext, "seal:secret", &provider)
        .map_err(|e| anyhow::anyhow!("encrypt_secret failed: {:?}", e))?;

    store
        .save(&record, &blob)
        .map_err(|e| anyhow::anyhow!("store.save failed: {:?}", e))?;

    let (loaded_record, loaded_blob) = store
        .load(&id)
        .map_err(|e| anyhow::anyhow!("store.load failed: {:?}", e))?;

    if loaded_record.name != record.name {
        bail!("Loaded record metadata name mismatch");
    }
    if loaded_blob != blob {
        bail!("Loaded record sealed blob mismatch");
    }

    let decrypted = decrypt_secret(&loaded_blob, "seal:secret", &provider)
        .map_err(|e| anyhow::anyhow!("decrypt_secret failed: {:?}", e))?;
    if decrypted != plaintext {
        bail!("Decrypted payload from store mismatch");
    }

    // 3. Ciphertext Tamper Resistance Verification
    let blob_path = std::path::Path::new(temp_store.path()).join(format!("{id}.blob"));
    let mut tampered_bytes = fs::read(&blob_path)
        .map_err(|e| anyhow::anyhow!("failed to read blob for tampering: {:?}", e))?;
    let last_idx = tampered_bytes.len() - 1;
    tampered_bytes[last_idx] ^= 0xFF; // Invert last byte of authentication tag
    fs::write(&blob_path, &tampered_bytes)
        .map_err(|e| anyhow::anyhow!("failed to write tampered blob: {:?}", e))?;

    let (_, corrupt_blob) = store
        .load(&id)
        .map_err(|e| anyhow::anyhow!("load tampered blob failed: {:?}", e))?;
    if decrypt_secret(&corrupt_blob, "seal:secret", &provider).is_ok() {
        bail!("Tampered ciphertext unexpectedly passed AEAD authentication tag validation!");
    }

    // 4. Media Sanitization & Crypto-Shredding Verification
    store
        .crypto_shred(&id)
        .map_err(|e| anyhow::anyhow!("crypto_shred failed: {:?}", e))?;
    if store.exists(&id) {
        bail!("Record still exists after crypto_shred");
    }

    Ok(())
}
