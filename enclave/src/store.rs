//! Persistent Hardware-Sealed Blob Storage and Lifecycle Engine.
//!
//! # Storage Architecture and File Layout
//! Every secret, keypair, or confidential artifact persisted by the enclave is partitioned into
//! two dedicated files under the base directory `store_path/`:
//! 1. `{uuid}.meta.json`: Plaintext JSON metadata containing administrative attributes (name,
//!    secret type, version, ownership, tags, timestamps, public keys, and ZKP commitments).
//!    **Invariant**: This file MUST NEVER contain plaintext secret or private key bytes.
//! 2. `{uuid}.blob`: Hardware-sealed AES-256-GCM ciphertext payload `[nonce(12) | ciphertext | tag(16)]`.
//!
//! # Filesystem Security and Permissions
//! - On POSIX systems, all created metadata and blob files are explicitly set to `0o600`
//!   (owner read/write only) via [`std::os::unix::fs::PermissionsExt`].
//! - Deletion lifecycle supports soft-delete (marking `deleted_at` timestamp in metadata for audit retention)
//!   and hard-delete.
//! - Hard sanitization is performed via [`Store::crypto_shred`], complying with NIST SP 800-88
//!   Guidelines for Media Sanitization by overwriting on-disk storage blocks with CSPRNG entropy
//!   and executing synchronous filesystem flushes (`sync_all()`) prior to unlinking.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::EnclaveError;
use crate::models::SecretType;

// ─────────────────────────────────────────────────────────────────────────────
// Persisted metadata (stored in plaintext — no secret values here)
// ─────────────────────────────────────────────────────────────────────────────

/// Plaintext administrative metadata stored on disk in `{id}.meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    /// Globally unique record identifier (UUIDv4).
    pub id: Uuid,
    /// Unique human-readable name of the secret or key.
    pub name: String,
    /// Category of secret payload ([`SecretType`]).
    pub secret_type: SecretType,
    /// Monotonically increasing version counter.
    pub version: u32,
    /// PEM-encoded public key (for asymmetric keypair records).
    pub public_key_pem: Option<String>,
    /// Algorithm label (e.g., `"RSA-4096"`, `"Ed25519"`, `"AES-256-GCM"`).
    pub algorithm: Option<String>,
    /// Principal identifier or IAM identity of the record creator.
    pub owner: String,
    /// Arbitrary user-defined key-value metadata tags.
    pub tags: HashMap<String, String>,
    /// UTC timestamp of creation.
    pub created_at: DateTime<Utc>,
    /// UTC timestamp of last metadata or version update.
    pub updated_at: DateTime<Utc>,
    /// Optional UTC timestamp when the record expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional UTC timestamp when the record was soft-deleted.
    pub deleted_at: Option<DateTime<Utc>>,
    /// Hex-encoded compressed Ristretto255 public point for Schnorr zero-knowledge proof verification.
    pub zkp_commitment: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Store
// ─────────────────────────────────────────────────────────────────────────────

/// Persistent hardware-sealed file repository.
pub struct Store {
    base: PathBuf,
}

impl Store {
    /// Initializes a new [`Store`] instance rooted at the specified directory path.
    ///
    /// Creates the directory tree recursively if it does not already exist.
    pub fn new(store_path: &str) -> Self {
        let base = PathBuf::from(store_path);
        fs::create_dir_all(&base).expect("Cannot create store directory");
        Self { base }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Returns the absolute path to `{id}.meta.json`.
    fn meta_path(&self, id: &Uuid) -> PathBuf {
        self.base.join(format!("{id}.meta.json"))
    }

    /// Returns the absolute path to `{id}.blob`.
    fn blob_path(&self, id: &Uuid) -> PathBuf {
        self.base.join(format!("{id}.blob"))
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Persists a new or updated secret record metadata alongside its hardware-sealed blob.
    ///
    /// # Security Invariant
    /// Enforces `0o600` file permissions on both written files on POSIX systems.
    pub fn save(&self, record: &SecretRecord, blob: &[u8]) -> Result<(), EnclaveError> {
        let meta_json = serde_json::to_vec_pretty(record)?;
        let m_path = self.meta_path(&record.id);
        let b_path = self.blob_path(&record.id);
        fs::write(&m_path, &meta_json)?;
        fs::write(&b_path, blob)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&m_path, fs::Permissions::from_mode(0o600));
            let _ = fs::set_permissions(&b_path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Updates only the plaintext metadata JSON file (e.g., during tag update or soft-deletion).
    pub fn save_meta(&self, record: &SecretRecord) -> Result<(), EnclaveError> {
        let meta_json = serde_json::to_vec_pretty(record)?;
        let m_path = self.meta_path(&record.id);
        fs::write(&m_path, &meta_json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&m_path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// Loads a secret record metadata and its sealed ciphertext blob by UUID.
    ///
    /// # Errors
    /// Returns [`EnclaveError::NotFound`] if the record does not exist or has been soft-deleted.
    pub fn load(&self, id: &Uuid) -> Result<(SecretRecord, Vec<u8>), EnclaveError> {
        let meta_path = self.meta_path(id);
        if !meta_path.exists() {
            return Err(EnclaveError::NotFound { id: id.to_string() });
        }
        let meta_bytes = fs::read(&meta_path)?;
        let record: SecretRecord = serde_json::from_slice(&meta_bytes)?;

        if record.deleted_at.is_some() {
            return Err(EnclaveError::NotFound { id: id.to_string() });
        }

        let blob = fs::read(self.blob_path(id))?;
        Ok((record, blob))
    }

    /// Loads only the metadata for a record by UUID without performing blob I/O.
    pub fn load_meta(&self, id: &Uuid) -> Result<SecretRecord, EnclaveError> {
        let meta_path = self.meta_path(id);
        if !meta_path.exists() {
            return Err(EnclaveError::NotFound { id: id.to_string() });
        }
        let meta_bytes = fs::read(&meta_path)?;
        let record: SecretRecord = serde_json::from_slice(&meta_bytes)?;
        Ok(record)
    }

    /// Finds an active (non-deleted) record by human-readable name.
    ///
    /// # Errors
    /// Returns [`EnclaveError::NotFound`] if no active secret matches `name`.
    pub fn find_by_name(&self, name: &str) -> Result<SecretRecord, EnclaveError> {
        self.list_all()?
            .into_iter()
            .find(|r| r.name == name && r.deleted_at.is_none())
            .ok_or_else(|| EnclaveError::NotFound {
                id: name.to_string(),
            })
    }

    // ── List ──────────────────────────────────────────────────────────────────

    /// Lists all active (non-deleted) secret records, sorted chronologically by creation timestamp.
    pub fn list(&self) -> Result<Vec<SecretRecord>, EnclaveError> {
        Ok(self
            .list_all()?
            .into_iter()
            .filter(|r| r.deleted_at.is_none())
            .collect())
    }

    /// Reads all records from disk including soft-deleted entries.
    fn list_all(&self) -> Result<Vec<SecretRecord>, EnclaveError> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.base)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let bytes = fs::read(&path)?;
                let record = serde_json::from_slice::<SecretRecord>(&bytes)?;
                records.push(record);
            }
        }
        records.sort_by_key(|a| a.created_at);
        Ok(records)
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    /// Soft-deletes a secret by populating its `deleted_at` timestamp.
    ///
    /// The encrypted blob remains intact on disk for audit compliance until explicitly hard-deleted or shredded.
    pub fn soft_delete(&self, id: &Uuid) -> Result<(), EnclaveError> {
        let mut record = self.load_meta(id)?;
        record.deleted_at = Some(Utc::now());
        self.save_meta(&record)
    }

    /// Hard-deletes a secret by immediately removing both `.meta.json` and `.blob` files from disk.
    pub fn hard_delete(&self, id: &Uuid) -> Result<(), EnclaveError> {
        let m = self.meta_path(id);
        let b = self.blob_path(id);
        if m.exists() {
            fs::remove_file(&m)?;
        }
        if b.exists() {
            fs::remove_file(&b)?;
        }
        Ok(())
    }

    // ── Existence check ───────────────────────────────────────────────────────

    /// Checks if a record exists on disk with the given UUID.
    pub fn exists(&self, id: &Uuid) -> bool {
        self.meta_path(id).exists()
    }

    /// Checks if an active (non-deleted) record exists with the given name.
    pub fn name_exists(&self, name: &str) -> bool {
        self.find_by_name(name).is_ok()
    }

    /// Sanitizes and destroys on-disk record files according to NIST SP 800-88 Guidelines for Media Sanitization.
    ///
    /// # Overwrite Protocol
    /// 1. Reads file physical size $L$.
    /// 2. Fills a buffer with $L$ bytes from the hardware CSPRNG [`SystemRandom`].
    /// 3. Overwrites disk sectors with the random buffer.
    /// 4. Issues [`std::fs::File::sync_all`] to flush storage drive write caches.
    /// 5. Unlinks the file from the filesystem.
    pub fn crypto_shred(&self, id: &Uuid) -> Result<(), EnclaveError> {
        let m = self.meta_path(id);
        let b = self.blob_path(id);

        if !m.exists() && !b.exists() {
            return Err(EnclaveError::NotFound { id: id.to_string() });
        }

        use ring::rand::{SecureRandom, SystemRandom};
        use std::fs::OpenOptions;
        use std::io::Write;

        let rng = SystemRandom::new();

        for path in [&m, &b] {
            if path.exists() {
                let metadata = fs::metadata(path)?;
                let len = metadata.len() as usize;
                let mut file = OpenOptions::new().write(true).open(path)?;
                let mut buf = vec![0u8; len];
                rng.fill(&mut buf).map_err(|_| EnclaveError::Internal)?;
                file.write_all(&buf)?;
                file.sync_all()?;
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}

