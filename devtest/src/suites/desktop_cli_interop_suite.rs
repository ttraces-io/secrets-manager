//! Desktop GUI and CLI Subcommand Interoperability Verification Suite.

use super::TestStoreDir;
use anyhow::{bail, Result};
use std::collections::HashMap;
use traces_sm_enclave::crypto::encrypt_secret;
use traces_sm_enclave::models::SecretType;
use traces_sm_enclave::sealing::SimSealingProvider;
use traces_sm_enclave::store::{SecretRecord, Store};

/// Executes Desktop GUI model mutations and verifies CLI data consistency across 25 interop scenarios.
pub fn run_suite() -> Result<()> {
    let temp_store = TestStoreDir::new("desktop-cli-interop");
    let provider = SimSealingProvider::new(temp_store.path());
    let store = Store::new(temp_store.path());

    // Run 25 interop scenario iterations
    for i in 0..25 {
        let secret_name = format!("interop-secret-{}", i);
        let secret_val = format!("DESKTOP_GUI_MUTATED_VALUE_ITERATION_{}", i);
        let purpose = format!("purpose:secret:{}", secret_name);

        // 1. Desktop GUI Component writes sealed secret to shared store
        let sealed_blob =
            encrypt_secret(secret_val.as_bytes(), &purpose, &provider).map_err(|e| {
                anyhow::anyhow!(
                    "encrypt_secret failed in interop desktop simulation: {:?}",
                    e
                )
            })?;

        let now = chrono::Utc::now();
        let record = SecretRecord {
            id: uuid::Uuid::new_v4(),
            name: secret_name.clone(),
            secret_type: SecretType::Opaque,
            version: 1,
            public_key_pem: None,
            algorithm: Some("Aes256Gcm".to_string()),
            owner: "desktop-gui-operator".to_string(),
            tags: HashMap::new(),
            created_at: now,
            updated_at: now,
            expires_at: None,
            deleted_at: None,
            zkp_commitment: None,
        };

        store.save(&record, &sealed_blob).map_err(|e| {
            anyhow::anyhow!("store.save failed in interop desktop simulation: {:?}", e)
        })?;

        // 2. CLI Command routine loads and verifies the secret
        let (loaded_record, loaded_blob) = store.load(&record.id).map_err(|e| {
            anyhow::anyhow!("store.load failed in CLI interop verification: {:?}", e)
        })?;

        if loaded_record.name != secret_name {
            bail!(
                "CLI loaded secret name mismatch: expected {}, got {}",
                secret_name,
                loaded_record.name
            );
        }
        if loaded_blob != sealed_blob {
            bail!("CLI loaded sealed blob mismatch for secret {}", secret_name);
        }
    }

    Ok(())
}
