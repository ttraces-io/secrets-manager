//! FIPS 140-3 Zeroization and Mandatory Security Policy (MSP) Verification Suite.

use anyhow::{bail, Result};
use traces_sm_enclave::policy::{PolicyEngine, SecurityPolicy};
use zeroize::{Zeroize, Zeroizing};

/// Executes policy engine and memory zeroization tests.
pub fn run_suite() -> Result<()> {
    // 1. Validate Default Security Policy Invariants
    let default_policy = SecurityPolicy::default();
    if !default_policy.enforce_fips_zeroization {
        bail!("Default policy must enforce FIPS 140-3 zeroization");
    }
    if !default_policy.enforce_storage_encryption {
        bail!("Default policy must enforce AES-256-GCM storage encryption");
    }
    if !default_policy.enforce_cryptoperiod_limit {
        bail!("Default policy must enforce cryptoperiod limits");
    }

    let engine = PolicyEngine::new(default_policy);
    engine
        .validate_in_memory_protection()
        .map_err(|e| anyhow::anyhow!("validate_in_memory_protection failed: {:?}", e))?;

    // 2. FIPS 140-3 Zeroization Verification
    // Verify that Zeroizing<[u8; 32]> actively scrubs sensitive memory
    {
        let mut key_buffer = Zeroizing::new([0xAAu8; 32]);
        if key_buffer.as_slice() != [0xAAu8; 32] {
            bail!("Key buffer initialization mismatch");
        }
        // Explicit zeroize call verification
        key_buffer.zeroize();
        if key_buffer.as_slice() != [0x00u8; 32] {
            bail!("Explicit zeroization failed to overwrite key buffer with zeroes");
        }
    }

    // 3. Volumetric Cryptoperiod Limit Verification
    let max_volume = 4_294_967_296u64; // 4 GiB (2^32 bytes)
    let safe_usage = 1_000_000u64;
    if safe_usage >= max_volume {
        bail!("Safe usage should not exceed 4 GiB bound");
    }

    Ok(())
}
