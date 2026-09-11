//! Zero-Knowledge Proofs (ZKP) and Partially Homomorphic Encryption (PHE) Handlers.
//!
//! # Capabilities
//! Exposes cryptographic endpoints for advanced privacy-preserving computing:
//! - **Schnorr PoK**: Non-interactive proof of knowledge generation and verification over Ristretto255.
//! - **Bulletproofs Range Proofs**: Proves value intervals $v \in [\text{min}, \text{max}]$ without revealing secrets.
//! - **Pedersen Commitments**: Perfectly hiding additively homomorphic value commitments.
//! - **Paillier PHE**: Partially homomorphic 2048-bit keygen, ciphertext addition, and sealed decryption.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::EnclaveError;
use crate::he::paillier;
use crate::models::*;
use crate::server::router::HttpRequest;
use crate::server::EnclaveState;
use crate::zkp::{bulletproof, pedersen, schnorr};
use num_bigint::BigUint;

// ─────────────────────────────────────────────────────────────────────────────
// Schnorr PoK
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a Schnorr Proof-of-Knowledge for a named secret stored inside the enclave.
pub fn schnorr_prove(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: ZkpSchnorrProveRequest = serde_json::from_slice(&req.body)?;
    let record = state.store.find_by_name(&body.secret_name)?;

    // The commitment must have been generated when the secret was created
    let _commitment_hex = record.zkp_commitment.ok_or_else(|| {
        EnclaveError::ZkpInvalidInput("no ZKP commitment stored for this secret".into())
    })?;

    // Load and decrypt the secret to generate the proof
    let uuid = record.id;
    let (_, blob) = state.store.load(&uuid)?;
    let plaintext = crate::crypto::decrypt_secret(&blob, "seal:secrets", state.provider.as_ref())?;

    // Use a random nonce embedded in the request body (caller provides it for non-interactive PoK)
    let nonce = uuid.as_bytes(); // Use the secret UUID as the nonce for determinism
    let proof = schnorr::prove_knowledge(&plaintext, nonce)?;

    Ok(serde_json::to_value(ZkpProofResponse {
        proof_hex: Some(proof.signature_hex),
        valid: None,
    })?)
}

/// Verifies a Schnorr Proof-of-Knowledge against either a stored secret's commitment or an explicit public point.
pub fn schnorr_verify(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: ZkpSchnorrVerifyRequest = serde_json::from_slice(&req.body)?;

    let (commitment_hex, nonce_bytes) = if let Some(ref name) = body.secret_name {
        let record = state.store.find_by_name(name)?;
        let c_hex = record.zkp_commitment.ok_or_else(|| {
            EnclaveError::ZkpInvalidInput("no ZKP commitment stored for this secret".into())
        })?;
        (c_hex, record.id.as_bytes().to_vec())
    } else if let Some(ref pk_hex) = body.public_key_hex {
        let nonce = if let Some(ref ch) = body.challenge_hex {
            hex::decode(ch).unwrap_or_else(|_| ch.as_bytes().to_vec())
        } else {
            b"sm:zkp:schnorr:v1".to_vec()
        };
        (pk_hex.clone(), nonce)
    } else {
        return Err(EnclaveError::ZkpInvalidInput(
            "either secret_name or public_key_hex must be provided".into(),
        ));
    };

    let commitment = schnorr::SchnorrCommitment {
        point_hex: commitment_hex,
    };
    let proof = schnorr::SchnorrProof {
        signature_hex: body.proof_hex,
        context: "sm:zkp:schnorr:v1".to_string(),
    };
    let valid = schnorr::verify_proof(&commitment, &proof, &nonce_bytes)?;

    Ok(serde_json::to_value(ZkpProofResponse {
        proof_hex: None,
        valid: Some(valid),
    })?)
}

// ─────────────────────────────────────────────────────────────────────────────
// Bulletproof range proof
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a Bulletproofs zero-knowledge range proof for an integer value stored inside the enclave.
pub fn range_prove(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: ZkpRangeProveRequest = serde_json::from_slice(&req.body)?;

    // Decrypt secret (must be a u64 stored as little-endian bytes or decimal string)
    let record = state.store.find_by_name(&body.secret_name)?;
    let (_, blob) = state.store.load(&record.id)?;
    let plaintext = crate::crypto::decrypt_secret(&blob, "seal:secrets", state.provider.as_ref())?;

    // Interpret the secret as a UTF-8 decimal number
    let value_str = String::from_utf8(plaintext)
        .map_err(|_| EnclaveError::ZkpInvalidInput("secret is not valid UTF-8".into()))?;
    let value: u64 = value_str
        .trim()
        .parse()
        .map_err(|_| EnclaveError::ZkpInvalidInput("secret is not a valid u64 integer".into()))?;

    let proof = bulletproof::prove_range(value, body.min, body.max)?;
    Ok(serde_json::to_value(&proof)?)
}

/// Verifies a Bulletproofs range proof without knowledge of the secret plaintext integer.
pub fn range_verify(
    req: &HttpRequest,
    _state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: ZkpRangeVerifyRequest = serde_json::from_slice(&req.body)?;
    let proof = bulletproof::SerializedRangeProof {
        proof_hex: body.proof_hex,
        commitment_hex: body.commitment_hex,
        min: body.min,
        max: body.max,
    };
    let valid = bulletproof::verify_range_proof(&proof)?;
    Ok(serde_json::json!({ "valid": valid }))
}

// ─────────────────────────────────────────────────────────────────────────────
// Pedersen commitments
// ─────────────────────────────────────────────────────────────────────────────

/// Computes a Pedersen commitment $C = v \cdot G + r \cdot H$ and returns $(C, r)$.
pub fn pedersen_commit(
    req: &HttpRequest,
    _state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: PedersenCommitRequest = serde_json::from_slice(&req.body)?;
    let (commitment, opening) = pedersen::commit(body.value)?;
    Ok(serde_json::to_value(PedersenCommitResponse {
        commitment_hex: commitment.point_hex,
        blinding_hex: opening.blinding_hex,
    })?)
}

// ─────────────────────────────────────────────────────────────────────────────
// Paillier PHE
// ─────────────────────────────────────────────────────────────────────────────

/// Generates a 2048-bit Paillier keypair, hardware-seals the private key, and stores public parameters.
pub fn he_generate(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: HePaillierGenerateRequest = serde_json::from_slice(&req.body)?;

    // Generate 2048-bit Paillier key pair inside the enclave
    let kp = paillier::generate_keypair(2048).map_err(|e| EnclaveError::HeKeyGen(e.to_string()))?;

    let n_hex = hex::encode(kp.public.n.to_bytes_be());
    let g_hex = hex::encode(kp.public.g.to_bytes_be());

    // Seal the private key and store it
    let sk_serial = paillier::PaillierPrivateKeySerial::from_key(&kp.private);
    let sk_json = serde_json::to_vec(&sk_serial)?;
    let sealed_sk = crate::sealing::seal(&sk_json, "seal:paillier-priv", state.provider.as_ref())?;

    // Store as a secret record with public key in metadata
    let id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now();
    let record = crate::store::SecretRecord {
        id,
        name: body.key_name.clone(),
        secret_type: crate::models::SecretType::AsymmetricKey,
        version: 1,
        public_key_pem: Some(format!("n={n_hex},g={g_hex}")),
        algorithm: Some("Paillier-2048".to_string()),
        owner: "default".to_string(),
        tags: HashMap::new(),
        created_at: now,
        updated_at: now,
        expires_at: None,
        deleted_at: None,
        zkp_commitment: None,
    };
    state.store.save(&record, &sealed_sk)?;

    Ok(serde_json::to_value(HePaillierKeyResponse {
        key_name: body.key_name,
        n_hex,
        g_hex,
    })?)
}

/// Encrypts an integer under a Paillier public key: $c = g^m \cdot r^n \bmod n^2$.
pub fn he_encrypt(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: HeEncryptRequest = serde_json::from_slice(&req.body)?;
    let pk = load_paillier_pk(state, &body.key_name)?;
    let m = BigUint::parse_bytes(body.plaintext.as_bytes(), 10)
        .ok_or_else(|| EnclaveError::HeEncrypt("plaintext must be a decimal integer".into()))?;
    let ct = paillier::encrypt(&pk, &m)?;
    Ok(serde_json::to_value(HeEncryptResponse {
        ciphertext_hex: hex::encode(ct.to_bytes_be()),
    })?)
}

/// Computes homomorphic addition of two Paillier ciphertexts: $c_3 = c_1 \cdot c_2 \bmod n^2$.
pub fn he_add(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: HeAddRequest = serde_json::from_slice(&req.body)?;
    let pk = load_paillier_pk(state, &body.key_name)?;
    let c1 = BigUint::from_bytes_be(
        &hex::decode(&body.ciphertext1_hex)
            .map_err(|_| EnclaveError::HeOperation("bad ciphertext1 hex".into()))?,
    );
    let c2 = BigUint::from_bytes_be(
        &hex::decode(&body.ciphertext2_hex)
            .map_err(|_| EnclaveError::HeOperation("bad ciphertext2 hex".into()))?,
    );
    let result = paillier::add_ciphertexts(&pk, &c1, &c2);
    Ok(serde_json::to_value(HeAddResponse {
        result_hex: hex::encode(result.to_bytes_be()),
    })?)
}

/// Decrypts a Paillier ciphertext using the hardware-sealed private key inside the enclave.
pub fn he_decrypt(
    req: &HttpRequest,
    state: &Arc<EnclaveState>,
) -> Result<serde_json::Value, EnclaveError> {
    let body: HeDecryptRequest = serde_json::from_slice(&req.body)?;
    let record = state.store.find_by_name(&body.key_name)?;
    let (_, sealed_sk) = state.store.load(&record.id)?;
    let sk_json =
        crate::sealing::unseal(&sealed_sk, "seal:paillier-priv", state.provider.as_ref())?;
    let sk_serial: paillier::PaillierPrivateKeySerial = serde_json::from_slice(&sk_json)?;
    let sk = sk_serial.to_key()?;
    let ct = BigUint::from_bytes_be(
        &hex::decode(&body.ciphertext_hex)
            .map_err(|_| EnclaveError::HeDecrypt("bad ciphertext hex".into()))?,
    );
    let pt = paillier::decrypt(&sk, &ct)?;
    Ok(serde_json::to_value(HeDecryptResponse {
        plaintext: pt.to_string(),
    })?)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parses and loads a stored Paillier public key from metadata.
fn load_paillier_pk(
    state: &Arc<EnclaveState>,
    key_name: &str,
) -> Result<paillier::PaillierPublicKey, EnclaveError> {
    let record = state.store.find_by_name(key_name)?;
    let pub_str = record
        .public_key_pem
        .ok_or_else(|| EnclaveError::NotFound {
            id: key_name.to_string(),
        })?;
    // Parse "n=<hex>,g=<hex>"
    let mut n_hex = String::new();
    let mut g_hex = String::new();
    for part in pub_str.split(',') {
        if let Some(v) = part.strip_prefix("n=") {
            n_hex = v.to_string();
        }
        if let Some(v) = part.strip_prefix("g=") {
            g_hex = v.to_string();
        }
    }
    let n = BigUint::from_bytes_be(&hex::decode(&n_hex).map_err(|_| EnclaveError::Internal)?);
    let g = BigUint::from_bytes_be(&hex::decode(&g_hex).map_err(|_| EnclaveError::Internal)?);
    let n_sq = &n * &n;
    Ok(paillier::PaillierPublicKey { n, g, n_sq })
}
