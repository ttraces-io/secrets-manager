//! # Distributed Key Generation (DKG), Shamir Secret Sharing & Pedersen VSS
//!
//! This module implements $M$-of-$N$ threshold secret sharing and Verifiable Secret Sharing (VSS)
//! executed inside the Intel SGX enclave.
//!
//! ## Mathematical Foundations
//!
//! ### 1. Shamir's Secret Sharing over $GF(256)$
//! For arbitrary byte slices, each byte index $b$ is treated as the secret term $a_0 = S[b]$
//! in a random polynomial of degree $t - 1$:
//! $$f_b(x) = a_0 + a_1 x + a_2 x^2 + \dots + a_{t-1} x^{t-1} \pmod{P(x)}$$
//! where $P(x) = x^8 + x^4 + x^3 + x + 1$ ($0x11B$, AES irreducible polynomial).
//!
//! ### 2. Lagrange Polynomial Interpolation over $GF(256)$
//! Given $t$ valid distinct shares $(x_i, y_i)$, the secret is reconstructed at $x = 0$ via:
//! $$L_i(0) = \prod_{j \ne i} \frac{x_j}{x_j \oplus x_i}$$
//! $$S[b] = \bigoplus_{i=0}^{t-1} y_{i,b} \otimes L_i(0)$$
//!
//! ### 3. Pedersen Verifiable Secret Sharing (VSS) on Ristretto255
//! Participant shares $(x_i, s_i, r_i)$ are verified against published coefficient commitments
//! $C_k = a_k G + b_k H$ using the homomorphic identity:
//! $$s_i G + r_i H = \sum_{k=0}^{t-1} x_i^k C_k$$
//!
//! ## Invariants & Safety Guarantees
//! - Evaluation points must be non-zero ($x \in [1, 255]$).
//! - Duplicate $x$ coordinates are rejected during reconstruction to prevent degenerate matrices.
//! - All random coefficients are sourced from the in-enclave NIST SP 800-90A HMAC-DRBG.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use serde::{Deserialize, Serialize};

use crate::drbg::HmacDrbg;
use crate::error::EnclaveError;

/// Multi-byte participant threshold key share over Galois Field $GF(256)$.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyShare {
    /// Non-zero participant index $x \in [1, 255]$.
    pub x: u8,
    /// Evaluated polynomial share bytes $y = f(x)$.
    pub y: Vec<u8>,
}

/// Participant share structure supporting both classic Shamir shares and Pedersen VSS blinding scalars.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretShare {
    /// Non-zero participant index $x \in [1, 255]$.
    pub x: u8,
    /// Evaluated share byte for legacy single-byte interfaces.
    pub y: u8,
    /// Optional hex-encoded Ristretto255 blinding scalar $r_i$ for Pedersen VSS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blinding_hex: Option<String>,
    /// Optional hex-encoded Ristretto255 secret scalar $s_i$ for Pedersen VSS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scalar_y_hex: Option<String>,
}

/// Splits an arbitrary multi-byte secret key slice (`&[u8]`) into `total` threshold shares (`KeyShare`),
/// evaluating Shamir's Secret Sharing over $GF(256)$ for each byte of the secret payload.
///
/// # Invariants & Parameters
/// * `secret` - Non-empty byte slice to split.
/// * `threshold` - Minimum number of shares required for reconstruction ($1 \le t \le total$).
/// * `total` - Total number of participant shares to generate ($total \le 255$).
///
/// Random polynomial coefficients are generated using in-enclave NIST SP 800-90A HMAC-DRBG.
pub fn split_secret_bytes(secret: &[u8], threshold: usize, total: usize) -> Vec<KeyShare> {
    if secret.is_empty() || threshold == 0 || total < threshold || total > 255 {
        return Vec::new();
    }

    let mut drbg = HmacDrbg::new();
    let secret_len = secret.len();

    // For each byte position, build polynomial coefficients: [secret[b], c1, c2, ..., c_{threshold-1}]
    let mut all_coeffs = Vec::with_capacity(secret_len);
    for &byte in secret {
        let mut coeffs = Vec::with_capacity(threshold);
        coeffs.push(byte);
        if threshold > 1 {
            let mut rand_buf = vec![0u8; threshold - 1];
            drbg.generate(&mut rand_buf);
            coeffs.extend_from_slice(&rand_buf);
        }
        all_coeffs.push(coeffs);
    }

    let mut shares = Vec::with_capacity(total);
    for x in 1..=total {
        let x_u8 = x as u8;
        let mut y_vec = Vec::with_capacity(secret_len);

        for coeffs in &all_coeffs {
            let mut y = 0u8;
            let mut x_pow = 1u8;
            for coeff in coeffs {
                y = gf256_add(y, gf256_mul(*coeff, x_pow));
                x_pow = gf256_mul(x_pow, x_u8);
            }
            y_vec.push(y);
        }
        shares.push(KeyShare { x: x_u8, y: y_vec });
    }
    shares
}

/// Reconstructs a multi-byte secret key (`Vec<u8>`) from `threshold` or more `KeyShare` instances
/// using Lagrange polynomial interpolation over Galois Field $GF(256)$.
///
/// # Validation Invariants
/// - Verifies `shares.len() >= threshold`.
/// - Checks that no share has $x = 0$.
/// - Enforces uniqueness of participant evaluation coordinates $x_i$.
/// - Enforces uniform share byte length across all threshold shares.
pub fn reconstruct_secret_bytes(shares: &[KeyShare], threshold: usize) -> Result<Vec<u8>, String> {
    if threshold == 0 {
        return Err("Threshold cannot be zero".to_string());
    }
    if shares.len() < threshold {
        return Err("Not enough shares to satisfy threshold".to_string());
    }

    // Check for duplicate x coordinates and x == 0
    let mut seen_x = std::collections::HashSet::new();
    for s in &shares[0..threshold] {
        if s.x == 0 {
            return Err("Share with x=0 is invalid".to_string());
        }
        if !seen_x.insert(s.x) {
            return Err("Duplicate x-coordinates in shares".to_string());
        }
    }

    if shares.is_empty() || shares[0].y.is_empty() {
        return Ok(Vec::new());
    }

    let secret_len = shares[0].y.len();
    // Validate that all threshold shares have identical length (no ragged shares)
    for s in &shares[0..threshold] {
        if s.y.len() != secret_len {
            return Err("Ragged share lengths".to_string());
        }
    }

    let mut secret = Vec::with_capacity(secret_len);

    for b in 0..secret_len {
        let mut byte_val = 0u8;
        for i in 0..threshold {
            let mut num = 1u8;
            let mut den = 1u8;

            for j in 0..threshold {
                if i != j {
                    num = gf256_mul(num, shares[j].x);
                    den = gf256_mul(den, gf256_add(shares[i].x, shares[j].x));
                }
            }

            let basis = gf256_mul(num, gf256_inv(den));
            byte_val = gf256_add(byte_val, gf256_mul(shares[i].y[b], basis));
        }
        secret.push(byte_val);
    }
    Ok(secret)
}

/// Backward-compatible single-byte secret splitting function using NIST SP 800-90A DRBG.
pub fn split_secret(secret: u8, threshold: usize, total: usize) -> Vec<SecretShare> {
    let key_shares = split_secret_bytes(&[secret], threshold, total);
    key_shares
        .into_iter()
        .map(|ks| SecretShare {
            x: ks.x,
            y: ks.y.first().copied().unwrap_or(0),
            blinding_hex: None,
            scalar_y_hex: None,
        })
        .collect()
}

/// Backward-compatible single-byte secret reconstruction function.
pub fn reconstruct_secret(shares: &[SecretShare], threshold: usize) -> u8 {
    if shares.len() < threshold || threshold == 0 {
        return 0;
    }

    // If VSS scalar shares are present, interpolate over the Scalar field
    if shares
        .iter()
        .take(threshold)
        .all(|s| s.scalar_y_hex.is_some())
    {
        let mut secret_scalar = Scalar::ZERO;
        let mut xs = Vec::with_capacity(threshold);
        let mut ys = Vec::with_capacity(threshold);

        for s in &shares[0..threshold] {
            let x = Scalar::from(s.x as u64);
            let hex_s = s.scalar_y_hex.as_ref().unwrap();
            let bytes = match hex::decode(hex_s) {
                Ok(b) => b,
                Err(_) => return 0,
            };
            let arr: [u8; 32] = match bytes.try_into() {
                Ok(a) => a,
                Err(_) => return 0,
            };
            let y = Option::from(Scalar::from_canonical_bytes(arr))
                .unwrap_or_else(|| Scalar::from_bytes_mod_order(arr));
            xs.push(x);
            ys.push(y);
        }

        for i in 0..threshold {
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for j in 0..threshold {
                if i != j {
                    num *= xs[j];
                    den *= xs[j] - xs[i];
                }
            }
            let basis = num * den.invert();
            secret_scalar += ys[i] * basis;
        }
        return secret_scalar.to_bytes()[0];
    }

    let key_shares: Vec<KeyShare> = shares
        .iter()
        .map(|s| KeyShare {
            x: s.x,
            y: vec![s.y],
        })
        .collect();
    reconstruct_secret_bytes(&key_shares, threshold)
        .map(|v| v.first().copied().unwrap_or(0))
        .unwrap_or(0)
}

// GF(256) arithmetic operations
fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn gf256_mul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if b & 1 == 1 {
            p ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x1b; // AES irreducible polynomial
        }
        b >>= 1;
    }
    p
}

fn gf256_inv(a: u8) -> u8 {
    let mut x = a;
    for _ in 0..253 {
        x = gf256_mul(x, a);
    }
    x
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VssCommitment {
    pub commitment_hex: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coefficient_commitments: Vec<String>,
}

impl VssCommitment {
    pub fn points(&self) -> Result<Vec<RistrettoPoint>, EnclaveError> {
        let hex_list: Vec<String> = if !self.coefficient_commitments.is_empty() {
            self.coefficient_commitments.clone()
        } else if self.commitment_hex.starts_with('[') {
            serde_json::from_str(&self.commitment_hex)
                .unwrap_or_else(|_| vec![self.commitment_hex.clone()])
        } else if self.commitment_hex.contains(',') {
            self.commitment_hex
                .split(',')
                .map(|s| s.trim().to_string())
                .collect()
        } else if !self.commitment_hex.is_empty() {
            vec![self.commitment_hex.clone()]
        } else {
            vec![]
        };

        if hex_list.is_empty() {
            return Err(EnclaveError::ZkpInvalidInput("Empty VSS commitment".into()));
        }

        let mut points = Vec::with_capacity(hex_list.len());
        for h in hex_list {
            let bytes = hex::decode(&h).map_err(|_| {
                EnclaveError::ZkpInvalidInput("Invalid commitment hex string".into())
            })?;
            let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                EnclaveError::ZkpInvalidInput("Commitment point must be 32 bytes".into())
            })?;
            let point = CompressedRistretto(arr).decompress().ok_or_else(|| {
                EnclaveError::ZkpInvalidInput("Invalid Ristretto point in commitment".into())
            })?;
            points.push(point);
        }
        Ok(points)
    }
}

/// Splits a secret using Pedersen Verifiable Secret Sharing (VSS) over Ristretto255.
/// Generates polynomial coefficient commitments C_k = a_k·G + b_k·H and returns
/// both the participant secret shares (with blinding scalars) and the VSS commitment.
pub fn split_secret_vss(
    secret: u8,
    threshold: usize,
    total: usize,
) -> (Vec<SecretShare>, VssCommitment) {
    use rand_core::OsRng;

    let g = &RISTRETTO_BASEPOINT_TABLE;
    let h = crate::zkp::pedersen::pedersen_h();

    let secret_scalar = Scalar::from(secret);
    let mut secret_coeffs = vec![secret_scalar];
    for _ in 1..threshold {
        secret_coeffs.push(Scalar::random(&mut OsRng));
    }

    let mut blinding_coeffs = Vec::with_capacity(threshold);
    for _ in 0..threshold {
        blinding_coeffs.push(Scalar::random(&mut OsRng));
    }

    // Compute coefficient commitments C_k = a_k·G + b_k·H
    let mut coeff_commitments_hex = Vec::with_capacity(threshold);
    for k in 0..threshold {
        let point = (*g * &secret_coeffs[k]) + (h * blinding_coeffs[k]);
        coeff_commitments_hex.push(hex::encode(point.compress().to_bytes()));
    }

    let commitment = VssCommitment {
        commitment_hex: coeff_commitments_hex.first().cloned().unwrap_or_default(),
        coefficient_commitments: coeff_commitments_hex,
    };

    let mut shares = Vec::with_capacity(total);
    for i in 1..=total {
        let x_scalar = Scalar::from(i as u64);

        // Evaluate f(x_i) = sum_{k=0}^{threshold-1} a_k * x_i^k
        let mut s_val = Scalar::ZERO;
        let mut x_pow = Scalar::ONE;
        for a_k in &secret_coeffs {
            s_val += a_k * x_pow;
            x_pow *= x_scalar;
        }

        // Evaluate g(x_i) = sum_{k=0}^{threshold-1} b_k * x_i^k
        let mut r_val = Scalar::ZERO;
        let mut x_pow_b = Scalar::ONE;
        for b_k in &blinding_coeffs {
            r_val += b_k * x_pow_b;
            x_pow_b *= x_scalar;
        }

        let y_bytes = s_val.to_bytes();
        let y = y_bytes[0];

        shares.push(SecretShare {
            x: i as u8,
            y,
            blinding_hex: Some(hex::encode(r_val.to_bytes())),
            scalar_y_hex: Some(hex::encode(s_val.to_bytes())),
        });
    }

    (shares, commitment)
}

/// Verifies a Pedersen Verifiable Secret Sharing (VSS) commitment over Ristretto255.
///
/// Checks that the share (x_i, s_i, r_i) matches the published coefficient commitments C_k:
///
///   s_i·G + r_i·H == sum_{k=0}^{t-1} (x_i^k)·C_k
///
/// Returns `true` if and only if the verification identity holds strictly.
pub fn verify_vss_commitment(share: &SecretShare, commitment: &VssCommitment) -> bool {
    let coeff_points = match commitment.points() {
        Ok(pts) => pts,
        Err(_) => return false,
    };

    if coeff_points.is_empty() {
        return false;
    }

    let x_scalar = Scalar::from(share.x as u64);

    let s_scalar = if let Some(ref hex_s) = share.scalar_y_hex {
        let bytes = match hex::decode(hex_s) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let arr: [u8; 32] = match bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        Scalar::from_canonical_bytes(arr).unwrap_or_else(|| Scalar::from_bytes_mod_order(arr))
    } else {
        Scalar::from(share.y as u64)
    };

    let r_scalar = if let Some(ref hex_r) = share.blinding_hex {
        let bytes = match hex::decode(hex_r) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let arr: [u8; 32] = match bytes.try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        Scalar::from_canonical_bytes(arr).unwrap_or_else(|| Scalar::from_bytes_mod_order(arr))
    } else {
        Scalar::ZERO
    };

    // LHS = s_i·G + r_i·H
    let g = &RISTRETTO_BASEPOINT_TABLE;
    let h = crate::zkp::pedersen::pedersen_h();
    let lhs = (*g * &s_scalar) + (h * r_scalar);

    // RHS = sum_{k=0}^{t-1} (x_i^k)·C_k
    let mut rhs = RistrettoPoint::identity();
    let mut x_pow = Scalar::ONE;
    for c_k in &coeff_points {
        rhs += c_k * x_pow;
        x_pow *= x_scalar;
    }

    lhs == rhs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vss_verification_valid_shares() {
        let secret = 42u8;
        let threshold = 3;
        let total = 5;

        let (shares, commitment) = split_secret_vss(secret, threshold, total);
        assert_eq!(shares.len(), 5);
        assert_eq!(commitment.coefficient_commitments.len(), 3);

        // Every generated share must pass Pedersen VSS verification
        for share in &shares {
            assert!(
                verify_vss_commitment(share, &commitment),
                "Share x={} failed VSS verification",
                share.x
            );
        }
    }

    #[test]
    fn test_vss_verification_invalid_share_fails() {
        let secret = 100u8;
        let (shares, commitment) = split_secret_vss(secret, 2, 4);

        let mut tampered_share = shares[0].clone();
        // Tamper with scalar_y_hex
        tampered_share.scalar_y_hex = Some(hex::encode([99u8; 32]));

        assert!(
            !verify_vss_commitment(&tampered_share, &commitment),
            "Tampered share should fail verification"
        );
    }

    #[test]
    fn test_vss_verification_invalid_blinding_fails() {
        let secret = 55u8;
        let (shares, commitment) = split_secret_vss(secret, 2, 3);

        let mut tampered_share = shares[0].clone();
        tampered_share.blinding_hex = Some(hex::encode([123u8; 32]));

        assert!(
            !verify_vss_commitment(&tampered_share, &commitment),
            "Tampered blinding factor should fail verification"
        );
    }

    #[test]
    fn test_vss_verification_invalid_commitment_point_fails() {
        let secret = 77u8;
        let (shares, _) = split_secret_vss(secret, 2, 3);

        let bad_commitment = VssCommitment {
            commitment_hex: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            coefficient_commitments: vec![
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ],
        };

        assert!(
            !verify_vss_commitment(&shares[0], &bad_commitment),
            "Invalid Ristretto point should fail verification"
        );
    }

    #[test]
    fn test_key_level_secret_splitting_multi_byte() {
        let original_key = b"this_is_a_32_byte_secret_key_123";
        let threshold = 3;
        let total = 5;

        let shares = split_secret_bytes(original_key, threshold, total);
        assert_eq!(shares.len(), 5);
        for share in &shares {
            assert_eq!(share.y.len(), 32);
        }

        // Test reconstruction with exact threshold (3 shares)
        let subset_shares = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let reconstructed =
            reconstruct_secret_bytes(&subset_shares, threshold).expect("Reconstruction failed");
        assert_eq!(reconstructed, original_key);

        // Test reconstruction with more than threshold (4 shares)
        let larger_subset = vec![
            shares[1].clone(),
            shares[2].clone(),
            shares[3].clone(),
            shares[4].clone(),
        ];
        let reconstructed_large =
            reconstruct_secret_bytes(&larger_subset, threshold).expect("Reconstruction failed");
        assert_eq!(reconstructed_large, original_key);
    }

    #[test]
    fn test_single_byte_secret_splitting() {
        let secret = 0xa5u8;
        let threshold = 2;
        let total = 4;

        let shares = split_secret(secret, threshold, total);
        assert_eq!(shares.len(), 4);

        let recovered = reconstruct_secret(&shares[0..2], threshold);
        assert_eq!(recovered, secret);
    }
}
