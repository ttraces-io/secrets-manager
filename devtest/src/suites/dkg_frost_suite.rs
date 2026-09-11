//! Distributed Key Generation (DKG) and FROST Threshold Signatures Verification Suite.

use anyhow::{bail, Result};
use std::collections::BTreeMap;
use traces_sm_enclave::dkg::{reconstruct_secret_bytes, split_secret_bytes};
use traces_sm_enclave::frost::{
    aggregate_signature, generate_dealer_keys, round1_commit, round2_sign_share, verify_signature,
};

/// Executes Shamir secret sharing and FROST threshold signature tests.
pub fn run_suite() -> Result<()> {
    // 1. Shamir Multi-Byte Secret Sharing (3-of-5)
    let secret_master_key = b"NIST_PQC_TRANSITION_ROOT_KEY_32B";
    let threshold = 3usize;
    let total_shares = 5usize;

    let shares = split_secret_bytes(secret_master_key, threshold, total_shares);
    if shares.len() != total_shares {
        bail!(
            "Expected {} Shamir shares, got {}",
            total_shares,
            shares.len()
        );
    }

    // Reconstruct with exact threshold (shares 0, 2, 4)
    let subset_3 = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
    let reconstructed = reconstruct_secret_bytes(&subset_3, threshold)
        .map_err(|e| anyhow::anyhow!("Reconstruction failed: {:?}", e))?;
    if reconstructed.as_slice() != secret_master_key {
        bail!("Reconstructed Shamir secret mismatch");
    }

    // Insufficient shares (2 shares when threshold is 3) should fail
    let subset_2 = vec![shares[1].clone(), shares[3].clone()];
    if reconstruct_secret_bytes(&subset_2, threshold).is_ok() {
        bail!("Reconstruction with 2 shares unexpectedly succeeded when threshold is 3");
    }

    // 2. FROST Ed25519 Threshold Signing (2-of-3)
    let max_signers = 3u16;
    let min_signers = 2u16;

    let keygen_output = generate_dealer_keys(max_signers, min_signers)
        .map_err(|e| anyhow::anyhow!("FROST generate_dealer_keys failed: {:?}", e))?;

    if keygen_output.key_packages.len() != 3 {
        bail!("FROST key packages count mismatch");
    }

    // Select signer 1 and signer 2
    let mut iter = keygen_output.key_packages.into_iter();
    let (id1, pkg1) = iter.next().unwrap();
    let (id2, pkg2) = iter.next().unwrap();

    // Round 1: Commitments & Nonces
    let r1_p1 =
        round1_commit(&pkg1).map_err(|e| anyhow::anyhow!("round1_commit p1 failed: {:?}", e))?;
    let r1_p2 =
        round1_commit(&pkg2).map_err(|e| anyhow::anyhow!("round1_commit p2 failed: {:?}", e))?;

    let mut commitments_map = BTreeMap::new();
    commitments_map.insert(id1.clone(), r1_p1.commitments_json);
    commitments_map.insert(id2.clone(), r1_p2.commitments_json);

    // Round 2: Signature Shares
    let message = b"FROST_ENCLAVE_THRESHOLD_AUTHENTICATED_TRANSACTION_PAYLOAD";
    let share1 = round2_sign_share(&pkg1, &r1_p1.nonces_json, &commitments_map, message)
        .map_err(|e| anyhow::anyhow!("round2_sign_share p1 failed: {:?}", e))?;
    let share2 = round2_sign_share(&pkg2, &r1_p2.nonces_json, &commitments_map, message)
        .map_err(|e| anyhow::anyhow!("round2_sign_share p2 failed: {:?}", e))?;

    let mut shares_map = BTreeMap::new();
    shares_map.insert(id1, share1);
    shares_map.insert(id2, share2);

    // Aggregation
    let signature_hex = aggregate_signature(
        &keygen_output.public_key_package,
        &commitments_map,
        &shares_map,
        message,
    )
    .map_err(|e| anyhow::anyhow!("aggregate_signature failed: {:?}", e))?;

    // Verification
    let is_valid = verify_signature(&keygen_output.group_public_key_hex, &signature_hex, message)
        .map_err(|e| anyhow::anyhow!("verify_signature failed: {:?}", e))?;
    if !is_valid {
        bail!("Aggregated FROST threshold signature verification returned false");
    }

    // Negative verification on tampered message
    let tampered_valid = verify_signature(
        &keygen_output.group_public_key_hex,
        &signature_hex,
        b"Tampered message content",
    )
    .unwrap_or(false);
    if tampered_valid {
        bail!("FROST signature verification unexpectedly succeeded on tampered message");
    }

    Ok(())
}
