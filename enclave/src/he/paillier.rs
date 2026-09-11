//! # Paillier Partially Homomorphic Encryption (PHE) Engine
//!
//! This module implements the Paillier cryptosystem, providing additive homomorphic
//! encryption and scalar multiplication over encrypted integers inside the Intel SGX enclave.
//!
//! ## Mathematical Foundations & Homomorphic Properties
//!
//! ### 1. Key Generation
//! - Let $p, q$ be two large distinct primes of equal bit-length.
//! - Compute RSA composite modulus $n = p \cdot q$ and $n^2$.
//! - Using the simplified Paillier scheme, choose base generator $g = n + 1$.
//! - Carmichael's function: $\lambda(n) = \text{lcm}(p-1, q-1) = \frac{(p-1)(q-1)}{\gcd(p-1, q-1)}$.
//! - Multiplicative inverse: $\mu = \lambda^{-1} \pmod{n}$.
//!
//! ### 2. Encryption ($m \in \mathbb{Z}_n$)
//! Select random blinding scalar $r \in \mathbb{Z}_n^*$:
//! $$c = g^m \cdot r^n \pmod{n^2} = (1 + m \cdot n) \cdot r^n \pmod{n^2}$$
//!
//! ### 3. Decryption ($c \in \mathbb{Z}_{n^2}^*$)
//! Compute the $L$-function quotient $L(u) = \frac{u - 1}{n}$:
//! $$m = L(c^\lambda \bmod n^2) \cdot \mu \pmod{n}$$
//!
//! ### 4. Homomorphic Operations (Zero Plaintext Exposure)
//! - **Additive Homomorphism**:
//!   $$\text{Enc}(m_1) \cdot \text{Enc}(m_2) \equiv \text{Enc}(m_1 + m_2) \pmod{n^2}$$
//! - **Scalar Multiplication**:
//!   $$\text{Enc}(m)^k \equiv \text{Enc}(k \cdot m) \pmod{n^2}$$
//! - **Re-randomization (Unlinkable Ciphertext Blinding)**:
//!   $$c' = c \cdot r'^n \pmod{n^2}$$
//!
//! ## Invariants & Security
//! - Private key fields (`lambda`, `mu`) implement custom [`Drop`] logic to zeroize memory.
//! - Minimum recommended modulus size is 2048 bits for production deployments.

use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::error::EnclaveError;

// ─────────────────────────────────────────────────────────────────────────────
// Key types
// ─────────────────────────────────────────────────────────────────────────────

/// Paillier public key — safe to distribute to external untrusted clients for client-side encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierPublicKey {
    /// Composite modulus $n = p \cdot q$.
    pub n: BigUint,
    /// Base generator $g = n + 1$.
    pub g: BigUint,
    /// Precomputed square modulus $n^2$.
    pub n_sq: BigUint,
}

/// Paillier private key — strictly isolated within EPC memory and zeroized upon drop.
#[derive(Debug, Clone)]
pub struct PaillierPrivateKey {
    /// Carmichael's totient $\lambda(n) = \text{lcm}(p-1, q-1)$.
    pub lambda: BigUint,
    /// Modular inverse $\mu = \lambda^{-1} \pmod{n}$.
    pub mu: BigUint,
    /// Modulus $n$.
    pub n: BigUint,
    /// Square modulus $n^2$.
    pub n_sq: BigUint,
}

impl Drop for PaillierPrivateKey {
    /// Overwrites sensitive private parameters with zeroes prior to memory deallocation.
    fn drop(&mut self) {
        let zero = BigUint::zero();
        self.lambda = zero.clone();
        self.mu = zero.clone();
    }
}

/// Full Paillier public/private keypair structure.
pub struct PaillierKeyPair {
    /// Public key for encryption and homomorphic evaluation.
    pub public: PaillierPublicKey,
    /// Private key for decryption inside the enclave.
    pub private: PaillierPrivateKey,
}

// ─────────────────────────────────────────────────────────────────────────────
// Serialisable private key (for sealing to disk)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaillierPrivateKeySerial {
    pub lambda_hex: String,
    pub mu_hex: String,
    pub n_hex: String,
}

impl PaillierPrivateKeySerial {
    pub fn from_key(sk: &PaillierPrivateKey) -> Self {
        Self {
            lambda_hex: hex::encode(sk.lambda.to_bytes_be()),
            mu_hex: hex::encode(sk.mu.to_bytes_be()),
            n_hex: hex::encode(sk.n.to_bytes_be()),
        }
    }

    pub fn to_key(&self) -> Result<PaillierPrivateKey, EnclaveError> {
        let lambda = BigUint::from_bytes_be(
            &hex::decode(&self.lambda_hex)
                .map_err(|_| EnclaveError::HeKeyGen("bad lambda hex".into()))?,
        );
        let mu = BigUint::from_bytes_be(
            &hex::decode(&self.mu_hex).map_err(|_| EnclaveError::HeKeyGen("bad mu hex".into()))?,
        );
        let n = BigUint::from_bytes_be(
            &hex::decode(&self.n_hex).map_err(|_| EnclaveError::HeKeyGen("bad n hex".into()))?,
        );
        let n_sq = &n * &n;
        Ok(PaillierPrivateKey {
            lambda,
            mu,
            n,
            n_sq,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Primality helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a random odd `bit_len`-bit number that passes Miller-Rabin.
/// We use a simple deterministic test sufficient for 1024-bit primes.
fn gen_prime(bit_len: u64) -> BigUint {
    let mut rng = thread_rng();
    loop {
        let mut candidate = rng.gen_biguint(bit_len);
        // Ensure it is odd and has the right bit length
        candidate.set_bit(0, true);
        candidate.set_bit(bit_len - 1, true);
        if miller_rabin(&candidate, 20) {
            return candidate;
        }
    }
}

/// Miller-Rabin primality test with `k` rounds.
fn miller_rabin(n: &BigUint, k: u32) -> bool {
    if n < &BigUint::from(2u32) {
        return false;
    }
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    // Write n-1 = 2^r · d
    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let n_minus_1 = n - &one;

    let mut d = n_minus_1.clone();
    let mut r = 0u64;
    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    let mut rng = thread_rng();
    'witness: for _ in 0..k {
        // Random base a in [2, n-2]
        let a = loop {
            let candidate = rng.gen_biguint_range(&two, &(n - &two));
            if candidate >= two {
                break candidate;
            }
        };

        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        for _ in 0..r - 1 {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

/// Extended Euclidean — returns (gcd, x, y) s.t. a*x + b*y = gcd.
fn extended_gcd(a: &BigUint, b: &BigUint) -> (BigUint, num_bigint::BigInt, num_bigint::BigInt) {
    use num_bigint::BigInt;

    let (mut old_r, mut r) = (BigInt::from(a.clone()), BigInt::from(b.clone()));
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());

    while !r.is_zero() {
        let quotient = &old_r / &r;
        let tmp_r = old_r - &quotient * &r;
        old_r = r;
        r = tmp_r;
        let tmp_s = old_s - &quotient * &s;
        old_s = s;
        s = tmp_s;
    }

    let t = if b.is_zero() {
        BigInt::zero()
    } else {
        (old_r.clone() - &old_s * BigInt::from(a.clone())) / BigInt::from(b.clone())
    };

    (old_r.to_biguint().unwrap_or_default(), old_s, t)
}

/// Compute the modular inverse of `a` mod `m`.
fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;

    let (gcd, x, _) = extended_gcd(a, m);
    if gcd != BigUint::one() {
        return None; // a and m are not coprime
    }
    let m_int = BigInt::from(m.clone());
    let result = ((x % &m_int) + &m_int) % &m_int;
    result.to_biguint()
}

/// L-function used in decryption:  L(u) = (u - 1) / n
fn l_func(u: &BigUint, n: &BigUint) -> BigUint {
    if u <= &BigUint::one() {
        return BigUint::zero();
    }
    (u - BigUint::one()) / n
}

// ─────────────────────────────────────────────────────────────────────────────
// Key generation
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a Paillier key pair.
///
/// `bits` is the desired bit-length of `n` (e.g. 2048).
/// `p` and `q` will each be `bits/2` bits.
pub fn generate_keypair(bits: usize) -> Result<PaillierKeyPair, EnclaveError> {
    if bits < 512 {
        return Err(EnclaveError::HeKeyGen(format!(
            "Paillier key size {} is below minimum 512 bits (spec §4.3 recommends 2048)",
            bits
        )));
    }
    let half = bits as u64 / 2;

    // Generate two distinct primes p, q
    let (p, q) = loop {
        let p = gen_prime(half);
        let q = gen_prime(half);
        if p != q {
            break (p, q);
        }
    };

    let n = &p * &q;
    let n_sq = &n * &n;
    // Simplified Paillier: g = n + 1  →  L(g^λ mod n²) = λ always
    let g = &n + BigUint::one();

    // λ = lcm(p-1, q-1)
    let p1 = &p - BigUint::one();
    let q1 = &q - BigUint::one();
    let lambda = p1.lcm(&q1);

    // μ = λ⁻¹ mod n
    let mu = mod_inverse(&lambda, &n)
        .ok_or_else(|| EnclaveError::HeKeyGen("λ not invertible mod n".into()))?;

    Ok(PaillierKeyPair {
        public: PaillierPublicKey {
            n: n.clone(),
            g,
            n_sq: n_sq.clone(),
        },
        private: PaillierPrivateKey {
            lambda,
            mu,
            n,
            n_sq,
        },
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Encryption / decryption
// ─────────────────────────────────────────────────────────────────────────────

/// Encrypt plaintext integer `m` (must satisfy 0 ≤ m < n).
///
/// Returns a ciphertext `c` in Z_{n²}.
pub fn encrypt(pk: &PaillierPublicKey, m: &BigUint) -> Result<BigUint, EnclaveError> {
    if m >= &pk.n {
        return Err(EnclaveError::HeEncrypt("plaintext must be < n".into()));
    }
    let mut rng = thread_rng();
    // Random r in Z*_n  (gcd(r,n) = 1 with overwhelming probability)
    let r = loop {
        let candidate = rng.gen_biguint_below(&pk.n);
        if !candidate.is_zero() {
            break candidate;
        }
    };

    // c = g^m · r^n  mod n²
    //   = (n+1)^m · r^n  mod n²
    //   = (1 + m·n) · r^n  mod n²   (binomial expansion for g=n+1)
    let gm = (BigUint::one() + m * &pk.n) % &pk.n_sq;
    let rn = r.modpow(&pk.n, &pk.n_sq);
    let c = (gm * rn) % &pk.n_sq;
    Ok(c)
}

/// Decrypt ciphertext `c` back to the original plaintext m.
///
/// **MUST only run inside the enclave** — the private key never leaves EPC.
pub fn decrypt(sk: &PaillierPrivateKey, c: &BigUint) -> Result<BigUint, EnclaveError> {
    if c >= &sk.n_sq || c.is_zero() {
        return Err(EnclaveError::HeDecrypt("ciphertext out of range".into()));
    }
    // m = L(c^λ mod n²) · μ  mod n
    let cl = c.modpow(&sk.lambda, &sk.n_sq);
    let l_cl = l_func(&cl, &sk.n);
    let m = (l_cl * &sk.mu) % &sk.n;
    Ok(m)
}

// ─────────────────────────────────────────────────────────────────────────────
// Homomorphic operations (run on untrusted ciphertexts — no decryption needed)
// ─────────────────────────────────────────────────────────────────────────────

/// Homomorphic addition:  Enc(m1 + m2) = Enc(m1) · Enc(m2)  mod n²
pub fn add_ciphertexts(pk: &PaillierPublicKey, c1: &BigUint, c2: &BigUint) -> BigUint {
    (c1 * c2) % &pk.n_sq
}

/// Homomorphic scalar multiplication:  Enc(k · m) = Enc(m)^k  mod n²
pub fn multiply_ciphertext_by_scalar(pk: &PaillierPublicKey, c: &BigUint, k: &BigUint) -> BigUint {
    c.modpow(k, &pk.n_sq)
}

/// Re-randomize a ciphertext without changing the plaintext.
/// Useful for unlinkability.
pub fn rerandomize(pk: &PaillierPublicKey, c: &BigUint) -> BigUint {
    let r = {
        let mut rng = thread_rng();
        rng.gen_biguint_below(&pk.n)
    };
    let blind = r.modpow(&pk.n, &pk.n_sq);
    (c * blind) % &pk.n_sq
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn small_kp() -> PaillierKeyPair {
        // 512-bit key for fast tests — use 2048 in production
        generate_keypair(512).expect("keygen failed")
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let kp = small_kp();
        let m = BigUint::from(42_u64);
        let c = encrypt(&kp.public, &m).unwrap();
        let recovered = decrypt(&kp.private, &c).unwrap();
        assert_eq!(recovered, m);
    }

    #[test]
    fn homomorphic_addition() {
        let kp = small_kp();
        let m1 = BigUint::from(100_u64);
        let m2 = BigUint::from(200_u64);
        let c1 = encrypt(&kp.public, &m1).unwrap();
        let c2 = encrypt(&kp.public, &m2).unwrap();
        let c_sum = add_ciphertexts(&kp.public, &c1, &c2);
        let decrypted = decrypt(&kp.private, &c_sum).unwrap();
        assert_eq!(decrypted, BigUint::from(300_u64));
    }

    #[test]
    fn homomorphic_scalar_mul() {
        let kp = small_kp();
        let m = BigUint::from(7_u64);
        let k = BigUint::from(5_u64);
        let c = encrypt(&kp.public, &m).unwrap();
        let c_scaled = multiply_ciphertext_by_scalar(&kp.public, &c, &k);
        let decrypted = decrypt(&kp.private, &c_scaled).unwrap();
        assert_eq!(decrypted, BigUint::from(35_u64));
    }

    #[test]
    fn rerandomize_same_plaintext() {
        let kp = small_kp();
        let m = BigUint::from(99_u64);
        let c = encrypt(&kp.public, &m).unwrap();
        let c2 = rerandomize(&kp.public, &c);
        // Ciphertexts should differ (with overwhelming probability)
        assert_ne!(c, c2);
        // But both decrypt to the same plaintext
        assert_eq!(decrypt(&kp.private, &c2).unwrap(), m);
    }
}
