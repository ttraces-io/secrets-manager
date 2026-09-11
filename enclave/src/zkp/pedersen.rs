//! Additively Homomorphic Pedersen Commitments over Ristretto255.
//!
//! # Mathematical Foundations and Homomorphic Properties
//! A Pedersen commitment scheme over a prime-order group $\mathbb{G}$ of order $p$ maps a value
//! $v \in \mathbb{Z}_p$ and a secret blinding scalar $r \in \mathbb{Z}_p$ to a group element $C \in \mathbb{G}$:
//! $$C = \text{commit}(v, r) = v \cdot G + r \cdot H$$
//! where:
//! - $G \in \mathbb{G}$ is the standard Ristretto255 canonical basepoint generator.
//! - $H \in \mathbb{G}$ is a second generator whose discrete logarithm $\log_G(H)$ is unknown.
//!
//! ## Nothing-Up-My-Sleeve Generator Construction
//! $H$ is derived via standard hash-to-curve utilizing SHA-512 and the Elligator2 map:
//! $$H = \text{hash\_to\_ristretto}(\text{"sm:pedersen:H:v1"})$$
//! Because finding $\alpha$ such that $H = \alpha \cdot G$ requires solving the discrete logarithm
//! problem over Ristretto255, the scheme is **computationally binding**.
//!
//! ## Information-Theoretic Privacy (Perfect Hiding)
//! For any value $v$, the commitment $C = v \cdot G + r \cdot H$ is uniformly distributed in $\mathbb{G}$
//! when $r \xleftarrow{\$} \mathbb{Z}_p$. Even an adversary with unbounded computational power cannot
//! extract $v$ from $C$.
//!
//! ## Additive Homomorphism
//! Given two commitments $C_1 = v_1 \cdot G + r_1 \cdot H$ and $C_2 = v_2 \cdot G + r_2 \cdot H$:
//! $$C_1 + C_2 = (v_1 \cdot G + r_1 \cdot H) + (v_2 \cdot G + r_2 \cdot H) = (v_1 + v_2) \cdot G + (r_1 + r_2) \cdot H = \text{commit}(v_1 + v_2, r_1 + r_2)$$
//! Scalar multiplication by constant $k \in \mathbb{Z}_p$:
//! $$k \cdot C = (k \cdot v) \cdot G + (k \cdot r) \cdot H = \text{commit}(k \cdot v, k \cdot r)$$

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::EnclaveError;

// ─────────────────────────────────────────────────────────────────────────────
// Generator H (hash-to-point, nothing-up-my-sleeve)
// ─────────────────────────────────────────────────────────────────────────────

/// Derives the second independent Pedersen generator $H \in \mathbb{G}$ via Elligator2 map on SHA-512 uniform bytes.
///
/// # Security Invariant
/// Computes $H = \text{from\_uniform\_bytes}(\text{SHA-512}(\text{"sm:pedersen:H:v1"}))$.
/// The discrete log $\log_G(H)$ is provably unknown under random oracle assumptions.
pub fn pedersen_h() -> RistrettoPoint {
    use ring::digest;
    let label = b"sm:pedersen:H:v1";
    let mut state = digest::Context::new(&digest::SHA512);
    state.update(label);
    let hash = state.finish();
    let bytes: [u8; 64] = hash.as_ref().try_into().expect("SHA-512 is 64 bytes");
    RistrettoPoint::from_uniform_bytes(&bytes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Public Pedersen commitment $C = v \cdot G + r \cdot H$.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    /// 32-byte compressed Ristretto255 group element encoded as a 64-character lowercase hex string.
    pub point_hex: String,
}

/// Secret opening tuple $(v, r)$ required to reveal and verify a Pedersen commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenOpening {
    /// Committed integer value $v \in [0, 2^{64}-1]$.
    pub value: u64,
    /// 32-byte secret blinding scalar $r \in \mathbb{Z}_p$ encoded as a 64-character hex string.
    pub blinding_hex: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Commitment
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a Pedersen commitment for `value` with a fresh CSPRNG blinding scalar $r \xleftarrow{\$} \mathbb{Z}_p$.
///
/// # Returns
/// A tuple containing the public [`PedersenCommitment`] and private [`PedersenOpening`].
pub fn commit(value: u64) -> Result<(PedersenCommitment, PedersenOpening), EnclaveError> {
    let r = Scalar::random(&mut OsRng);
    let c = commit_with_blinding(value, &r)?;
    Ok((
        c,
        PedersenOpening {
            value,
            blinding_hex: hex::encode(r.to_bytes()),
        },
    ))
}

/// Generates a Pedersen commitment using an explicitly supplied blinding scalar $r$.
///
/// Computes $C = v \cdot G + r \cdot H$.
pub fn commit_with_blinding(
    value: u64,
    blinding: &Scalar,
) -> Result<PedersenCommitment, EnclaveError> {
    let g = &RISTRETTO_BASEPOINT_TABLE;
    let h = pedersen_h();
    let v_scalar = Scalar::from(value);
    let c = (*g * &v_scalar) + (h * blinding);
    Ok(PedersenCommitment {
        point_hex: hex::encode(c.compress().to_bytes()),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification (open a commitment)
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that a public commitment $C$ legitimately opens to $(v, r)$.
///
/// Computes $C' = v \cdot G + r \cdot H$ and checks $C' \stackrel{?}{=} C$.
pub fn verify_opening(
    commitment: &PedersenCommitment,
    opening: &PedersenOpening,
) -> Result<bool, EnclaveError> {
    let blinding_bytes = hex::decode(&opening.blinding_hex)
        .map_err(|_| EnclaveError::ZkpInvalidInput("bad blinding hex".into()))?;
    let b_arr: [u8; 32] = blinding_bytes
        .try_into()
        .map_err(|_| EnclaveError::ZkpInvalidInput("blinding must be 32 bytes".into()))?;
    let blinding = Scalar::from_bytes_mod_order(b_arr);

    let expected = commit_with_blinding(opening.value, &blinding)?;
    Ok(expected.point_hex == commitment.point_hex)
}

// ─────────────────────────────────────────────────────────────────────────────
// Homomorphic operations
// ─────────────────────────────────────────────────────────────────────────────

/// Adds two Pedersen commitments homomorphically: $C_{\text{sum}} = C_1 + C_2$.
///
/// Corresponds to $\text{commit}(v_1 + v_2, r_1 + r_2)$.
pub fn add_commitments(
    c1: &PedersenCommitment,
    c2: &PedersenCommitment,
) -> Result<PedersenCommitment, EnclaveError> {
    let p1 = decompress(c1)?;
    let p2 = decompress(c2)?;
    let sum = p1 + p2;
    Ok(PedersenCommitment {
        point_hex: hex::encode(sum.compress().to_bytes()),
    })
}

/// Verifies that the homomorphic sum of a sequence of commitments $\sum_{i=1}^n C_i$ equals `claimed_total`.
pub fn verify_sum(
    commitments: &[PedersenCommitment],
    claimed_total: &PedersenCommitment,
    combined_blinding_hex: &str,
) -> Result<bool, EnclaveError> {
    let homomorphic_sum = commitments
        .iter()
        .try_fold(None::<RistrettoPoint>, |acc, c| {
            let p = decompress(c)?;
            Ok::<_, EnclaveError>(Some(acc.map(|a| a + p).unwrap_or(p)))
        })?
        .ok_or_else(|| EnclaveError::ZkpInvalidInput("empty commitment list".into()))?;

    let claimed = decompress(claimed_total)?;
    if homomorphic_sum.compress() != claimed.compress() {
        return Ok(false);
    }

    let blinding_bytes = hex::decode(combined_blinding_hex)
        .map_err(|_| EnclaveError::ZkpInvalidInput("bad combined blinding hex".into()))?;
    let b_arr: [u8; 32] = blinding_bytes
        .try_into()
        .map_err(|_| EnclaveError::ZkpInvalidInput("blinding must be 32 bytes".into()))?;
    let blinding = Scalar::from_bytes_mod_order(b_arr);
    let _ = blinding;
    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

/// Decompresses a 32-byte hex string into a validated [`RistrettoPoint`].
fn decompress(c: &PedersenCommitment) -> Result<RistrettoPoint, EnclaveError> {
    let bytes = hex::decode(&c.point_hex)
        .map_err(|_| EnclaveError::ZkpInvalidInput("bad commitment hex".into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EnclaveError::ZkpInvalidInput("commitment must be 32 bytes".into()))?;
    CompressedRistretto(arr).decompress().ok_or_else(|| {
        EnclaveError::ZkpInvalidInput("commitment is not a valid Ristretto point".into())
    })
}


// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_and_verify() {
        let (c, o) = commit(42).unwrap();
        assert!(verify_opening(&c, &o).unwrap());
    }

    #[test]
    fn wrong_value_fails() {
        let (c, o) = commit(42).unwrap();
        let bad_opening = PedersenOpening {
            value: 99,
            blinding_hex: o.blinding_hex,
        };
        assert!(!verify_opening(&c, &bad_opening).unwrap());
    }

    #[test]
    fn homomorphic_addition() {
        let r1 = Scalar::from(7u64);
        let r2 = Scalar::from(11u64);
        let c1 = commit_with_blinding(10, &r1).unwrap();
        let c2 = commit_with_blinding(20, &r2).unwrap();
        let c_sum = add_commitments(&c1, &c2).unwrap();
        let r_sum = r1 + r2;
        let expected = commit_with_blinding(30, &r_sum).unwrap();
        assert_eq!(c_sum.point_hex, expected.point_hex);
    }
}
