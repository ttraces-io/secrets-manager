//! Paillier Partially Homomorphic Encryption (PHE) Verification Suite.

use anyhow::{bail, Result};
use num_bigint::BigUint;
use traces_sm_enclave::he::paillier::{
    add_ciphertexts, decrypt, encrypt, generate_keypair, multiply_ciphertext_by_scalar,
};

/// Executes Paillier homomorphic encryption, addition, and scalar multiplication tests.
pub fn run_suite() -> Result<()> {
    // 1. Generate Paillier 512-bit Keypair for fast deterministic test execution
    let keypair =
        generate_keypair(512).map_err(|e| anyhow::anyhow!("Paillier keygen failed: {:?}", e))?;

    let m1 = BigUint::from(42u32);
    let m2 = BigUint::from(58u32);

    // 2. Encrypt plaintexts
    let c1 = encrypt(&keypair.public, &m1)
        .map_err(|e| anyhow::anyhow!("Paillier encrypt m1 failed: {:?}", e))?;
    let c2 = encrypt(&keypair.public, &m2)
        .map_err(|e| anyhow::anyhow!("Paillier encrypt m2 failed: {:?}", e))?;

    // 3. Direct Decryption Verification
    let dec1 = decrypt(&keypair.private, &c1)
        .map_err(|e| anyhow::anyhow!("Paillier decrypt c1 failed: {:?}", e))?;
    let dec2 = decrypt(&keypair.private, &c2)
        .map_err(|e| anyhow::anyhow!("Paillier decrypt c2 failed: {:?}", e))?;

    if dec1 != m1 || dec2 != m2 {
        bail!("Paillier decrypted values do not match original plaintexts");
    }

    // 4. Additive Homomorphism: Enc(m1 + m2) = Enc(m1) * Enc(m2) mod n^2
    let c_sum = add_ciphertexts(&keypair.public, &c1, &c2);
    let dec_sum = decrypt(&keypair.private, &c_sum)
        .map_err(|e| anyhow::anyhow!("Paillier decrypt c_sum failed: {:?}", e))?;

    let expected_sum = &m1 + &m2; // 100
    if dec_sum != expected_sum {
        bail!(
            "Homomorphic addition mismatch: got {}, expected {}",
            dec_sum,
            expected_sum
        );
    }

    // 5. Scalar Multiplication: Enc(k * m1) = Enc(m1)^k mod n^2
    let k = BigUint::from(5u32);
    let c_prod = multiply_ciphertext_by_scalar(&keypair.public, &c1, &k);
    let dec_prod = decrypt(&keypair.private, &c_prod)
        .map_err(|e| anyhow::anyhow!("Paillier decrypt c_prod failed: {:?}", e))?;

    let expected_prod = &m1 * &k; // 210
    if dec_prod != expected_prod {
        bail!(
            "Homomorphic scalar multiplication mismatch: got {}, expected {}",
            dec_prod,
            expected_prod
        );
    }

    Ok(())
}
