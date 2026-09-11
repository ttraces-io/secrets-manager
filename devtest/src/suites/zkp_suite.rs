//! Zero-Knowledge Proof (ZKP) Protocols Verification Suite.

use anyhow::{bail, Result};
use traces_sm_enclave::zkp::bulletproof::{prove_range, verify_range_proof, SerializedRangeProof};
use traces_sm_enclave::zkp::pedersen::{add_commitments, commit, verify_opening};
use traces_sm_enclave::zkp::schnorr::{generate_commitment, prove_knowledge, verify_proof};

/// Executes ZKP Schnorr, Bulletproofs, and Pedersen commitment tests.
pub fn run_suite() -> Result<()> {
    // 1. Schnorr Sigma Protocol PoK (Proof of Knowledge of Discrete Log)
    let secret_seed = b"super_secret_master_password_98765";
    let commitment = generate_commitment(secret_seed)
        .map_err(|e| anyhow::anyhow!("generate_commitment failed: {:?}", e))?;
    let challenge_nonce = b"random_nonce_12345";

    let proof = prove_knowledge(secret_seed, challenge_nonce)
        .map_err(|e| anyhow::anyhow!("schnorr prove_knowledge failed: {:?}", e))?;

    let is_valid = verify_proof(&commitment, &proof, challenge_nonce)
        .map_err(|e| anyhow::anyhow!("schnorr verify_proof failed: {:?}", e))?;
    if !is_valid {
        bail!("Schnorr proof verification returned false for valid witness");
    }

    // Negative Schnorr test (tampered challenge nonce)
    let tampered_valid = verify_proof(&commitment, &proof, b"wrong_nonce").unwrap_or(false);
    if tampered_valid {
        bail!("Schnorr verification unexpectedly passed with mismatched challenge nonce");
    }

    // 2. Bulletproofs Range Proof (Zero-Knowledge 32-bit Range Proof)
    let committed_value = 50_000u64;
    let min_bound = 10_000u64;
    let max_bound = 100_000u64;

    let range_proof = prove_range(committed_value, min_bound, max_bound)
        .map_err(|e| anyhow::anyhow!("prove_range failed: {:?}", e))?;

    let range_valid = verify_range_proof(&range_proof)
        .map_err(|e| anyhow::anyhow!("verify_range_proof failed: {:?}", e))?;
    if !range_valid {
        bail!("Bulletproofs range proof verification returned false for valid range");
    }

    // Negative Range Proof test (out-of-range bounds)
    let bad_range_proof = SerializedRangeProof {
        proof_hex: range_proof.proof_hex.clone(),
        commitment_hex: range_proof.commitment_hex.clone(),
        min: 60_000,
        max: 100_000,
    };
    let wrong_bounds_valid = verify_range_proof(&bad_range_proof).unwrap_or(false);
    if wrong_bounds_valid {
        bail!("Bulletproofs verification unexpectedly passed for wrong range bounds");
    }

    // 3. Pedersen Commitments & Homomorphic Addition
    let val1 = 150u64;
    let val2 = 350u64;
    let (c1, open1) = commit(val1).map_err(|e| anyhow::anyhow!("commit(val1) failed: {:?}", e))?;
    let (c2, _open2) = commit(val2).map_err(|e| anyhow::anyhow!("commit(val2) failed: {:?}", e))?;

    let valid_open1 = verify_opening(&c1, &open1)
        .map_err(|e| anyhow::anyhow!("verify_opening(c1) failed: {:?}", e))?;
    if !valid_open1 {
        bail!("Pedersen commitment opening failed for c1");
    }

    let c_sum = add_commitments(&c1, &c2)
        .map_err(|e| anyhow::anyhow!("add_commitments failed: {:?}", e))?;
    if c_sum.point_hex.is_empty() {
        bail!("Homomorphic sum commitment point is empty");
    }

    Ok(())
}
