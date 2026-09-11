//! Schnorr Zero-Knowledge Proof-of-Knowledge (PoK) Protocol.
//!
//! # Protocol Overview and Mathematical Foundations
//! This module implements a non-interactive zero-knowledge Proof-of-Knowledge (PoK) of a
//! discrete logarithm over the prime-order Ristretto255 group $\mathbb{G}$ of order $p = 2^{252} + 27742317777372353535851937790883648493$.
//!
//! ## Mathematical Relation
//! Given a secret seed $s \in \{0,1\}^*$, the prover computes a deterministic scalar $x = \text{SHA-512}(s)[0..32] \pmod p$
//! and establishes the public commitment (verification key):
//! $$Y = x \cdot G \in \mathbb{G}$$
//! where $G$ is the standard Ristretto255 basepoint generator.
//!
//! ## Non-Interactive $\Sigma$-Protocol (Fiat-Shamir via Merlin Transcript)
//! 1. **Commitment**: Prover chooses ephemeral nonce $k \xleftarrow{\$} \mathbb{Z}_p$ and computes $R = k \cdot G$.
//! 2. **Challenge**: Challenge $e = H(\text{transcript} \mathbin{\Vert} Y \mathbin{\Vert} R \mathbin{\Vert} \text{challenge\_nonce}) \in \mathbb{Z}_p$
//!    is derived via Merlin transcript binding.
//! 3. **Response**: Prover computes scalar response $z = k + e \cdot x \pmod p$.
//! 4. **Verification**: Verifier checks that:
//!    $$z \cdot G \stackrel{?}{=} R + e \cdot Y$$
//!
//! # Invariants and Security Properties
//! - **Completeness**: An honest prover holding $s$ will always produce a proof verifying against $Y = x \cdot G$.
//! - **Special Soundness**: From two valid transcripts $(R, e, z)$ and $(R, e', z')$ with $e \neq e'$,
//!   the witness $x = (z - z')(e - e')^{-1} \pmod p$ can be extracted in polynomial time.
//! - **Zero-Knowledge**: The verifier learns nothing about $s$ or $x$ beyond knowledge validity.
//! - **Replay Protection**: The `challenge_nonce` is bound into the Merlin transcript context `"sm:zkp:schnorr:v1"`.

use schnorrkel::{ExpansionMode, MiniSecretKey, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::EnclaveError;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Public Schnorr commitment stored alongside a secret in the enclave repository.
///
/// Corresponds to the 32-byte compressed Ristretto255 public point $Y = x \cdot G$.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrCommitment {
    /// 32-byte compressed Ristretto255 point encoded as a 64-character lowercase hex string.
    pub point_hex: String,
}

/// A non-interactive zero-knowledge Schnorr proof-of-knowledge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrProof {
    /// 64-byte Schnorr signature $(R, z)$ encoded as a 128-character lowercase hex string.
    pub signature_hex: String,
    /// Domain separation context label bound into the Merlin transcript (default: `"sm:zkp:schnorr:v1"`).
    pub context: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Commitment generation (stored when a secret is created)
// ─────────────────────────────────────────────────────────────────────────────

/// Derives a deterministic Ristretto255 public commitment $Y = x \cdot G$ from arbitrary secret bytes.
///
/// # Security Invariant
/// The resulting commitment is safe for untrusted public storage and verifier distribution;
/// computing the discrete logarithm $x$ from $Y$ is computationally infeasible under the DLP on Ristretto255.
pub fn generate_commitment(secret_bytes: &[u8]) -> Result<SchnorrCommitment, EnclaveError> {
    let mini = derive_mini_secret(secret_bytes)?;
    let kp = mini.expand_to_keypair(ExpansionMode::Ed25519);
    Ok(SchnorrCommitment {
        point_hex: hex::encode(kp.public.to_bytes()),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof generation (runs INSIDE the enclave — has access to the secret)
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a Schnorr Proof-of-Knowledge for the given `secret_bytes` bound to `challenge_nonce`.
///
/// # Parameters
/// - `secret_bytes`: The secret plaintext witness known to the enclave.
/// - `challenge_nonce`: Verifier-supplied challenge or record UUID bound into transcript to prevent replay attacks.
///
/// # Errors
/// Returns [`EnclaveError::ZkpProve`] if cryptographic key expansion or signing fails.
pub fn prove_knowledge(
    secret_bytes: &[u8],
    challenge_nonce: &[u8],
) -> Result<SchnorrProof, EnclaveError> {
    let mini = derive_mini_secret(secret_bytes)?;
    let kp = mini.expand_to_keypair(ExpansionMode::Ed25519);

    // Sign the challenge nonce with the key derived from the secret.
    // The signature IS the proof: it can only be created by someone who
    // knows the secret (and hence the private key).
    let ctx = schnorrkel::signing_context(b"sm:zkp:schnorr:v1");
    let sig = kp.sign(ctx.bytes(challenge_nonce));

    Ok(SchnorrProof {
        signature_hex: hex::encode(sig.to_bytes()),
        context: "sm:zkp:schnorr:v1".to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Proof verification (verifier only needs the commitment)
// ─────────────────────────────────────────────────────────────────────────────

/// Verifies that `proof` was produced by an entity with knowledge of the secret witness behind `commitment`.
///
/// # Parameters
/// - `commitment`: The public commitment point $Y = x \cdot G$.
/// - `proof`: The Schnorr signature proof $(R, z)$.
/// - `challenge_nonce`: The exact challenge nonce bound during proof generation.
///
/// # Returns
/// - `Ok(true)` if $z \cdot G = R + e \cdot Y$.
/// - `Ok(false)` if signature verification fails.
/// - `Err(EnclaveError)` if hexadecimal decoding or point decompression fails.
pub fn verify_proof(
    commitment: &SchnorrCommitment,
    proof: &SchnorrProof,
    challenge_nonce: &[u8],
) -> Result<bool, EnclaveError> {
    let pubkey_bytes = hex::decode(&commitment.point_hex)
        .map_err(|_| EnclaveError::ZkpInvalidInput("bad commitment hex".into()))?;

    let pubkey = PublicKey::from_bytes(&pubkey_bytes).map_err(|_| {
        EnclaveError::ZkpInvalidInput("cannot parse commitment as Ristretto point".into())
    })?;

    let sig_bytes = hex::decode(&proof.signature_hex)
        .map_err(|_| EnclaveError::ZkpInvalidInput("bad proof hex".into()))?;

    let sig = Signature::from_bytes(&sig_bytes)
        .map_err(|_| EnclaveError::ZkpInvalidInput("cannot parse Schnorr signature".into()))?;

    let ctx = schnorrkel::signing_context(b"sm:zkp:schnorr:v1");
    Ok(pubkey.verify(ctx.bytes(challenge_nonce), &sig).is_ok())
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Deterministically derives a [`MiniSecretKey`] from arbitrary-length bytes via SHA-512.
fn derive_mini_secret(bytes: &[u8]) -> Result<MiniSecretKey, EnclaveError> {
    use ring::digest;
    let hash = digest::digest(&digest::SHA512, bytes);
    // Take the first 32 bytes of SHA-512 output
    let seed: [u8; 32] = hash.as_ref()[..32]
        .try_into()
        .map_err(|_| EnclaveError::ZkpProve("SHA-512 output too short".into()))?;
    MiniSecretKey::from_bytes(&seed)
        .map_err(|_| EnclaveError::ZkpProve("cannot create MiniSecretKey from seed".into()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"my-super-secret-api-token-value-xyz";
    const NONCE: &[u8] = b"random-challenge-nonce-12345";

    #[test]
    fn commitment_is_deterministic() {
        let c1 = generate_commitment(SECRET).unwrap();
        let c2 = generate_commitment(SECRET).unwrap();
        assert_eq!(c1.point_hex, c2.point_hex);
    }

    #[test]
    fn proof_verifies_with_correct_secret() {
        let commitment = generate_commitment(SECRET).unwrap();
        let proof = prove_knowledge(SECRET, NONCE).unwrap();
        assert!(verify_proof(&commitment, &proof, NONCE).unwrap());
    }

    #[test]
    fn proof_fails_with_wrong_secret() {
        let commitment = generate_commitment(SECRET).unwrap();
        let wrong_proof = prove_knowledge(b"different-secret", NONCE).unwrap();
        assert!(!verify_proof(&commitment, &wrong_proof, NONCE).unwrap());
    }

    #[test]
    fn proof_fails_with_wrong_nonce() {
        let commitment = generate_commitment(SECRET).unwrap();
        let proof = prove_knowledge(SECRET, NONCE).unwrap();
        assert!(!verify_proof(&commitment, &proof, b"different-nonce").unwrap());
    }
}
