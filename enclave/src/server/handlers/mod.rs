//! In-Enclave Domain Request Handlers.
//!
//! # Handler Submodules
//! - [`attest`]: Intel SGX Remote Attestation quote generation, measurements, and verification delegation.
//! - [`dkg_handler`]: Distributed Key Generation (Pedersen VSS) and FROST Ed25519 threshold signatures.
//! - [`keys`]: Asymmetric & symmetric keypair generation, public export, signing, and decryption.
//! - [`lifecycle`]: NIST SP 800-57 lifecycle transitions, NIST SP 800-88 cryptographic shredding, and entropy status.
//! - [`secrets`]: Hardware-sealed secret CRUD and envelope encryption/decryption.
//! - [`tokens`]: In-enclave Ed25519-signed JWT token issuance and revocation.
//! - [`zkp`]: Schnorr PoK, Bulletproofs range proofs, Pedersen commitments, and Paillier PHE operations.

pub mod attest;
pub mod dkg_handler;
pub mod keys;
pub mod lifecycle;
pub mod secrets;
pub mod tokens;
pub mod zkp;
