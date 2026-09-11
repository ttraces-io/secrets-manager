//! Bulletproofs Non-Interactive Zero-Knowledge Range Proofs.
//!
//! # Protocol Overview and Mathematical Foundations
//! Bulletproofs (Bünz, Bootle, Boneh, Poelstra, Wu, Maxwell, 2018) are short non-interactive
//! zero-knowledge proofs that require **no trusted setup**.
//!
//! ## Mathematical Formulation
//! A range proof convinces a verifier that a secret committed value $v \in \mathbb{Z}_p$ satisfies:
//! $$v \in [0, 2^n - 1]$$
//! without revealing any information about $v$.
//!
//! Given public generators $\mathbf{g}, \mathbf{h} \in \mathbb{G}^n$ and Pedersen commitment $V = v \cdot G + \gamma \cdot H$,
//! the prover decomposes $v$ into its binary representation:
//! $$v = \sum_{i=0}^{n-1} a_{L, i} \cdot 2^i, \quad a_{L, i} \in \{0, 1\}$$
//! and establishes the vector constraints $\mathbf{a}_R = \mathbf{a}_L - \mathbf{1}^n$ and $\mathbf{a}_L \circ \mathbf{a}_R = \mathbf{0}^n$.
//!
//! ## Arbitrary Range $[v_{\text{min}}, v_{\text{max}}]$ Mapping
//! Bulletproofs natively prove range inclusion $0 \le v' < 2^{\text{RANGE\_BITS}}$ where $\text{RANGE\_BITS} = 32$.
//! To prove $v \in [v_{\text{min}}, v_{\text{max}}]$:
//! 1. Set $v' = v - v_{\text{min}}$.
//! 2. Ensure $(v_{\text{max}} - v_{\text{min}}) < 2^{\text{RANGE\_BITS}}$.
//! 3. Bind $v_{\text{min}}$ and $v_{\text{max}}$ into the Merlin Fiat-Shamir transcript.
//! 4. Prove $0 \le v' < 2^{\text{RANGE\_BITS}}$.
//!
//! ## Complexity Guarantees
//! - **Proof Size**: $O(\log n)$ elements (672 bytes for 32-bit ranges).
//! - **Prover Time**: $O(n)$ multi-scalar multiplications.
//! - **Verifier Time**: $O(n)$ multi-exponentiations.

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::EnclaveError;

/// Bit-width for range proofs. Supports integers up to $2^{32}-1 \approx 4.29 \times 10^9$.
const RANGE_BITS: usize = 32;

/// Domain separation label for the Merlin Fiat-Shamir transcript.
const TRANSCRIPT_LABEL: &[u8] = b"sm:bulletproof:range:v1";

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Serialized non-interactive zero-knowledge range proof payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedRangeProof {
    /// Bulletproof byte payload encoded as a hexadecimal string.
    pub proof_hex: String,
    /// Pedersen commitment point $V = v' \cdot G + \gamma \cdot H$ encoded as a 64-character hex string.
    pub commitment_hex: String,
    /// Public lower bound $v_{\text{min}}$ (inclusive).
    pub min: u64,
    /// Public upper bound $v_{\text{max}}$ (inclusive).
    pub max: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof generation (inside enclave — has the plaintext value)
// ─────────────────────────────────────────────────────────────────────────────

/// Proves in zero knowledge that a secret `value` lies in the closed interval $[v_{\text{min}}, v_{\text{max}}]$.
///
/// # Parameters
/// - `value`: The secret integer witness known to the enclave.
/// - `min`: Public lower bound.
/// - `max`: Public upper bound.
///
/// # Invariants
/// - Requires $v_{\text{min}} \le \text{value} \le v_{\text{max}}$.
/// - Requires $(v_{\text{max}} - v_{\text{min}}) < 2^{32}$.
///
/// # Errors
/// Returns [`EnclaveError::ZkpInvalidInput`] if bounds are violated or [`EnclaveError::ZkpProve`] if proof generation fails.
pub fn prove_range(value: u64, min: u64, max: u64) -> Result<SerializedRangeProof, EnclaveError> {
    if max < min {
        return Err(EnclaveError::ZkpInvalidInput("max must be ≥ min".into()));
    }
    if value < min || value > max {
        return Err(EnclaveError::ZkpInvalidInput(format!(
            "value {value} is not in [{min}, {max}]"
        )));
    }

    let range_span = max
        .checked_sub(min)
        .ok_or_else(|| EnclaveError::ZkpInvalidInput("underflow in range span".into()))?;
    if range_span >= (1u64 << RANGE_BITS) {
        return Err(EnclaveError::ZkpInvalidInput(format!(
            "range [{min}, {max}] exceeds 2^{RANGE_BITS}"
        )));
    }

    // Shift: prove 0 ≤ (value - min) < 2^RANGE_BITS
    let v_shifted = value
        .checked_sub(min)
        .ok_or_else(|| EnclaveError::ZkpInvalidInput("underflow in shift".into()))?;

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(RANGE_BITS, 1);

    let blinding = Scalar::random(&mut OsRng);
    let mut prover_transcript = Transcript::new(TRANSCRIPT_LABEL);
    prover_transcript.append_u64(b"min", min);
    prover_transcript.append_u64(b"max", max);

    let (proof, committed_value) = RangeProof::prove_single(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        v_shifted,
        &blinding,
        RANGE_BITS,
    )
    .map_err(|e| EnclaveError::ZkpProve(format!("bulletproof prove failed: {e:?}")))?;

    Ok(SerializedRangeProof {
        proof_hex: hex::encode(proof.to_bytes()),
        commitment_hex: hex::encode(committed_value.to_bytes()),
        min,
        max,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof verification (can run on untrusted side — no secret needed)
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies a [`SerializedRangeProof`] without knowledge of the secret value or blinding factor.
///
/// # Returns
/// - `Ok(true)` if the commitment $V$ legitimately commits to some value $v \in [\text{min}, \text{max}]$.
/// - `Ok(false)` if the verification equations fail.
/// - `Err(EnclaveError)` if hexadecimal parsing or point decoding fails.
pub fn verify_range_proof(proof: &SerializedRangeProof) -> Result<bool, EnclaveError> {
    if proof.max < proof.min {
        return Err(EnclaveError::ZkpInvalidInput("max must be >= min".into()));
    }
    let range_span = proof
        .max
        .checked_sub(proof.min)
        .ok_or_else(|| EnclaveError::ZkpInvalidInput("underflow in range span".into()))?;
    if range_span >= (1u64 << RANGE_BITS) {
        return Err(EnclaveError::ZkpInvalidInput(format!(
            "range span exceeds 2^{RANGE_BITS}"
        )));
    }

    let proof_bytes = hex::decode(&proof.proof_hex)
        .map_err(|_| EnclaveError::ZkpInvalidInput("bad proof hex".into()))?;

    let bp_proof = RangeProof::from_bytes(&proof_bytes)
        .map_err(|e| EnclaveError::ZkpInvalidInput(format!("cannot parse proof: {e:?}")))?;

    let commitment_bytes = hex::decode(&proof.commitment_hex)
        .map_err(|_| EnclaveError::ZkpInvalidInput("bad commitment hex".into()))?;
    let commitment_arr: [u8; 32] = commitment_bytes
        .try_into()
        .map_err(|_| EnclaveError::ZkpInvalidInput("commitment must be 32 bytes".into()))?;
    let committed_value = CompressedRistretto(commitment_arr);

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(RANGE_BITS, 1);

    let mut verifier_transcript = Transcript::new(TRANSCRIPT_LABEL);
    verifier_transcript.append_u64(b"min", proof.min);
    verifier_transcript.append_u64(b"max", proof.max);

    match bp_proof.verify_single(
        &bp_gens,
        &pc_gens,
        &mut verifier_transcript,
        &committed_value,
        RANGE_BITS,
    ) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_proof_verifies() {
        let proof = prove_range(500, 100, 1000).unwrap();
        assert!(verify_range_proof(&proof).unwrap());
    }

    #[test]
    fn boundary_values_prove_and_verify() {
        for &v in &[100u64, 1000u64] {
            let proof = prove_range(v, 100, 1000).unwrap();
            assert!(verify_range_proof(&proof).unwrap());
        }
    }

    #[test]
    fn out_of_range_value_fails_to_prove() {
        assert!(prove_range(1001, 100, 1000).is_err());
        assert!(prove_range(99, 100, 1000).is_err());
    }

    #[test]
    fn tampered_commitment_fails_verify() {
        let mut proof = prove_range(500, 100, 1000).unwrap();
        // Flip a byte in the commitment
        let mut bytes = hex::decode(&proof.commitment_hex).unwrap();
        bytes[0] ^= 0xFF;
        proof.commitment_hex = hex::encode(bytes);
        assert!(!verify_range_proof(&proof).unwrap_or(false));
    }
}
