//! Zero-Knowledge Proof (ZKP) and Cryptographic Commitment Subsystem.
//!
//! # Proof Systems and Mathematical Foundations
//! This module re-exports three complementary zero-knowledge proof and commitment systems:
//! - [`schnorr`]: Non-interactive Schnorr Proofs of Knowledge (PoK) over the prime-order
//!   Ristretto255 group. Enables a client or enclave to prove possession of a secret or private
//!   key without disclosing the secret itself.
//! - [`pedersen`]: Perfectly hiding, computationally binding Pedersen commitments over Ristretto255
//!   ($C = v \cdot G + r \cdot H$) with additive homomorphism ($C_1 + C_2 = (v_1+v_2)G + (r_1+r_2)H$).
//! - [`bulletproof`]: Short, non-interactive zero-knowledge Bulletproof range proofs (Bünz et al., 2018)
//!   proving $v \in [\text{min}, \text{max}]$ in $O(\log n)$ proof size without requiring a trusted setup.

pub mod bulletproof;
pub mod pedersen;
pub mod schnorr;
