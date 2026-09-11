//! Homomorphic Encryption Subsystem.
//!
//! # Purpose and Capabilities
//! This module exports Partially Homomorphic Encryption (PHE) capabilities:
//! - [`paillier`]: The Paillier Cryptosystem (Paillier, 1999) providing additive homomorphism
//!   over $\mathbb{Z}_n$ ($D(E(m_1) \cdot E(m_2) \bmod n^2) = (m_1 + m_2) \bmod n$) and scalar multiplication
//!   ($D(E(m)^k \bmod n^2) = (k \cdot m) \bmod n$).

pub mod paillier;
