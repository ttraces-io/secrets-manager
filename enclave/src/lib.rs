//! # `traces-sm-enclave` — Hardware-Enforced SGX Cryptographic Enclave Engine
//!
//! This crate contains the in-enclave core of `traces-sm`, engineered to run inside
//! an Intel SGX Enclave Page Cache (EPC) using the Fortanix Enclave Development Platform
//! (`x86_64-fortanix-unknown-sgx`).
//!
//! ## Core Architectural Invariants
//!
//! 1. **Zero-Trust Host Boundary**:
//!    - The untrusted host OS and hypervisor cannot read or modify enclave memory.
//!    - All plaintexts, unsealed keys, DRBG states, and MPC polynomial shares reside
//!      strictly within CPU-encrypted EPC RAM.
//! 2. **Memory Zeroization on Drop**:
//!    - Sensitive byte buffers (private keys, secret shares, DRBG internal state) are
//!      wrapped in [`zeroize::Zeroizing`] to ensure volatile memory overwrites prior to deallocation.
//! 3. **Constant-Time Cryptographic Primitives**:
//!    - MAC verification, token signature validation, and symmetric tag checks use
//!      constant-time comparison routines ([`subtle::ConstantTimeEq`]) to prevent timing side channels.
//! 4. **Hardware-Sealed Persistence**:
//!    - Secrets persisted outside EPC RAM are encrypted via hardware-derived keys using
//!      AES-256-GCM authenticated encryption bound to the enclave's measurement ([`crate::sealing`]).
//! 5. **NIST SP 800-57 Key Lifecycle**:
//!    - Cryptographic keys strictly follow state transitions:
//!      `PreOperational -> Operational -> Deactivated -> Destroyed`.
//!
//! ## Module Organization
//!
//! - [`auth`]: In-enclave JWT authentication, Ed25519 token issuance, and JTI revocation.
//! - [`config`]: Enclave runtime configuration and environmental parameters.
//! - [`crypto`]: Symmetric encryption (AES-256-GCM, ChaCha20-Poly1305), HKDF, and constant-time utilities.
//! - [`dkg`]: Distributed Key Generation ($M$-of-$N$ threshold), Shamir Secret Sharing, and Pedersen VSS.
//! - [`drbg`]: NIST SP 800-90A HMAC-DRBG with NIST SP 800-90B continuous entropy health testing.
//! - [`error`]: Unified error types and domain-specific error handling.
//! - [`frost`]: FROST (Flexible Round-Optimized Schnorr Threshold) signature scheme.
//! - [`he`]: Homomorphic encryption primitives (Paillier cryptosystem).
//! - [`keygen`]: In-enclave asymmetric (RSA, ECDSA, Ed25519) and symmetric key generation.
//! - [`models`]: Core data structures, request/response DTOs, and serialization schemas.
//! - [`nist`]: NIST SP 800-57 key lifecycle management state machine.
//! - [`policy`]: Mandatory Security Policy (MSP) engine and Entri Safe Mode quarantine triggers.
//! - [`pqc`]: Post-Quantum Cryptography (PQC) stubs and migration interfaces.
//! - [`sealing`]: Intel SGX hardware root key sealing and unsealing.
//! - [`server`]: Embedded mTLS/TCP server, dispatch router, and endpoint handlers.
//! - [`store`]: Hardware-sealed storage engine for keys and secrets.
//! - [`zkp`]: Zero-Knowledge Proof protocols (Schnorr $\Sigma$-protocol, Bulletproofs, Pedersen commitments).

pub mod auth;
pub mod config;
pub mod crypto;
pub mod dkg;
pub mod drbg;
pub mod error;
pub mod frost;
pub mod he;
pub mod keygen;
pub mod models;
pub mod nist;
pub mod policy;
pub mod pqc;
pub mod sealing;
pub mod server;
pub mod store;
pub mod zkp;
