//! DevTest Test Suites Registry and Shared Test Utilities.

pub mod auth_token_suite;
pub mod crypto_suite;
pub mod desktop_cli_interop_suite;
pub mod dkg_frost_suite;
pub mod drbg_entropy_suite;
pub mod environment_suite;
pub mod he_paillier_suite;
pub mod host_db_suite;
pub mod http_live_server_suite;
pub mod lifecycle_suite;
pub mod p2p_sharing_suite;
pub mod policy_zeroize_suite;
pub mod sealing_store_suite;
pub mod zkp_suite;

use std::path::PathBuf;
use traces_sm_enclave::error::EnclaveError;
use traces_sm_enclave::sealing::SealingKeyProvider;
use zeroize::Zeroizing;

/// Fixed deterministic sealing provider for in-memory and isolated test execution.
pub struct FixedKeyProvider(pub [u8; 32]);

impl FixedKeyProvider {
    pub fn new(byte: u8) -> Self {
        Self([byte; 32])
    }
}

impl SealingKeyProvider for FixedKeyProvider {
    fn master_key(&self) -> Result<Zeroizing<[u8; 32]>, EnclaveError> {
        Ok(Zeroizing::new(self.0))
    }
}

/// A unique temporary directory per test suite, cleaned up on drop.
pub struct TestStoreDir(pub PathBuf);

impl TestStoreDir {
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "traces-sm-devtest-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp store dir");
        Self(dir)
    }

    pub fn path(&self) -> &str {
        self.0.to_str().expect("utf-8 temp path")
    }
}

impl Drop for TestStoreDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Calculates Shannon entropy in bits per byte across a buffer.
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}
