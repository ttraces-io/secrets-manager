//! NIST SP 800-57 Key Lifecycle and SP 800-108 KDF Verification Suite.

use anyhow::{bail, Result};
use traces_sm_enclave::nist::{sp800_108_kdf, KeyLifecycleState};

/// Executes NIST SP 800-57 key lifecycle and KDF tests.
pub fn run_suite() -> Result<()> {
    // 1. NIST SP 800-57 Permission Matrix Checks
    let pre_op = KeyLifecycleState::PreOperational;
    if pre_op.can_encrypt()
        || pre_op.can_decrypt_historical()
        || pre_op.can_sign()
        || pre_op.can_verify()
    {
        bail!("PreOperational key should have zero operational permissions");
    }

    let operational = KeyLifecycleState::Operational;
    if !operational.can_encrypt()
        || !operational.can_decrypt_historical()
        || !operational.can_sign()
        || !operational.can_verify()
    {
        bail!("Operational key must have full encrypt, decrypt, sign, and verify permissions");
    }

    let deactivated = KeyLifecycleState::Deactivated;
    if deactivated.can_encrypt()
        || !deactivated.can_decrypt_historical()
        || deactivated.can_sign()
        || !deactivated.can_verify()
    {
        bail!("Deactivated key must allow historical decrypt/verify only, with zero new encryption/signing");
    }

    let destroyed = KeyLifecycleState::Destroyed;
    if destroyed.can_encrypt()
        || destroyed.can_decrypt_historical()
        || destroyed.can_sign()
        || destroyed.can_verify()
    {
        bail!("Destroyed key must have zero permissions");
    }

    // 2. NIST SP 800-108 KDF Counter Mode Verification
    let ki = b"master_derivation_key_32_bytes!!";
    let label1 = b"enclave_session_key_encryption";
    let label2 = b"enclave_session_mac_validation";
    let context = b"session_id_49201938501234";

    let derived_key1 = sp800_108_kdf(ki, label1, context, 32);
    let derived_key2 = sp800_108_kdf(ki, label2, context, 32);
    let derived_key1_repeat = sp800_108_kdf(ki, label1, context, 32);

    if derived_key1.len() != 32 || derived_key2.len() != 32 {
        bail!("Derived keys must match requested 32-byte length");
    }

    if derived_key1.as_slice() != derived_key1_repeat.as_slice() {
        bail!("SP 800-108 KDF must be strictly deterministic under identical inputs");
    }

    if derived_key1.as_slice() == derived_key2.as_slice() {
        bail!("SP 800-108 KDF must produce distinct outputs under different labels");
    }

    Ok(())
}
