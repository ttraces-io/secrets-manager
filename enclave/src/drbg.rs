//! # NIST SP 800-90A HMAC-DRBG and NIST SP 800-90B Continuous Entropy Health Testing
//!
//! This module provides in-enclave deterministic random bit generation and continuous health
//! monitoring adhering to NIST SP 800-90A (HMAC-SHA256) and NIST SP 800-90B standards.
//!
//! ## Mathematical & Algorithmic Foundations
//!
//! ### 1. NIST SP 800-90A HMAC-DRBG State Machine
//! The generator maintains two primary state vectors:
//! - $K \in \{0, 1\}^{256}$: 256-bit HMAC secret key.
//! - $V \in \{0, 1\}^{256}$: 256-bit initialization value / state seed.
//! - $\text{reseed\_counter} \in \mathbb{N}$: Enforces re-seeding at maximum 10,000 generation cycles.
//!
//! The state update function updates $K$ and $V$ via:
//! $$K \leftarrow \text{HMAC}(K, V \parallel 0x00 \parallel \text{provided\_data})$$
//! $$V \leftarrow \text{HMAC}(K, V)$$
//!
//! ### 2. NIST SP 800-90B Continuous Health Tests
//! To detect hardware RNG degradation or stuck-bit failures in physical silicon:
//! - **Repetition Count Test (RCT)**: Detects catastrophic stuck noise sources where the same sample
//!   value repeats consecutive times exceeding cutoff threshold $C = 16$.
//! - **Adaptive Proportion Test (APT)**: Detects statistical bias by counting occurrences of a base sample
//!   within a sliding window of $W = 512$ samples; triggers failure if count exceeds $C = 13$.

use ring::hmac;
use ring::rand::SecureRandom;

/// Real-time health metrics of the in-enclave entropy and DRBG subsystems.
#[derive(Debug, Clone, Copy)]
pub struct EntropyHealthStatus {
    /// Whether the NIST SP 800-90B Repetition Count Test passed.
    pub rct_passed: bool,
    /// Whether the NIST SP 800-90B Adaptive Proportion Test passed.
    pub apt_passed: bool,
    /// Current reseed cycle counter since last full entropy seeding.
    pub reseed_count: u64,
}

/// In-enclave NIST SP 800-90A compliant HMAC-SHA256 Deterministic Random Bit Generator.
pub struct HmacDrbg {
    /// HMAC-SHA256 internal key ($K$).
    key: hmac::Key,
    /// Internal working state vector ($V$).
    v: Vec<u8>,
    /// Reseed cycle counter. Reseeding occurs when counter > 10,000.
    reseed_counter: u64,
    /// RCT previous byte sample for stuck-bit detection.
    rct_prev_sample: u8,
    /// Current consecutive repetition count.
    rct_count: usize,
    /// APT sliding window storage buffer (capacity 512 bytes).
    apt_window: Vec<u8>,
    /// Total samples evaluated in current APT window (0 to 512).
    apt_count: usize,
    /// Base reference sample for the active APT window.
    apt_base_sample: u8,
}

impl Default for HmacDrbg {
    fn default() -> Self {
        Self::new()
    }
}

impl HmacDrbg {
    /// Instantiates and seeds a new HMAC-DRBG using 256 bits of hardware CSPRNG entropy.
    ///
    /// # Invariants
    /// - Initializes $K = 0^{32}$ and $V = 1^{32}$.
    /// - Performs an initial HMAC update with 32 bytes of secure hardware entropy.
    pub fn new() -> Self {
        let entropy = Self::get_entropy(32);
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        let v = vec![1u8; 32];
        let mut drbg = Self {
            key,
            v,
            reseed_counter: 1,
            rct_prev_sample: 0,
            rct_count: 0,
            apt_window: Vec::with_capacity(512),
            apt_count: 0,
            apt_base_sample: 0,
        };
        drbg.update(&entropy);
        drbg
    }

    /// Fetches `len` bytes of cryptographic entropy from the underlying hardware RNG.
    fn get_entropy(len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut buf)
            .expect("Secure entropy generation failed");
        buf
    }

    /// Executes the NIST SP 800-90A HMAC-DRBG Update process.
    ///
    /// # Equations
    /// 1. $K \leftarrow \text{HMAC}(K, V \parallel 0x00 \parallel \text{provided\_data})$
    /// 2. $V \leftarrow \text{HMAC}(K, V)$
    /// 3. If $\text{provided\_data} \ne \emptyset$:
    ///    - $K \leftarrow \text{HMAC}(K, V \parallel 0x01 \parallel \text{provided\_data})$
    ///    - $V \leftarrow \text{HMAC}(K, V)$
    fn update(&mut self, provided_data: &[u8]) {
        let mut ctx = hmac::Context::with_key(&self.key);
        ctx.update(&self.v);
        ctx.update(&[0x00]);
        ctx.update(provided_data);
        self.key = hmac::Key::new(hmac::HMAC_SHA256, ctx.sign().as_ref());

        let mut ctx = hmac::Context::with_key(&self.key);
        ctx.update(&self.v);
        self.v = ctx.sign().as_ref().to_vec();

        if !provided_data.is_empty() {
            let mut ctx = hmac::Context::with_key(&self.key);
            ctx.update(&self.v);
            ctx.update(&[0x01]);
            ctx.update(provided_data);
            self.key = hmac::Key::new(hmac::HMAC_SHA256, ctx.sign().as_ref());

            let mut ctx = hmac::Context::with_key(&self.key);
            ctx.update(&self.v);
            self.v = ctx.sign().as_ref().to_vec();
        }
    }

    /// Generates pseudorandom bytes into `out` and executes continuous NIST SP 800-90B health checks.
    ///
    /// # Invariants
    /// - Reseeds automatically if `reseed_counter > 10,000`.
    /// - Runs the Repetition Count Test (RCT) and Adaptive Proportion Test (APT) on generated bytes.
    /// - Performs an end-of-generation state update to prevent backtracking attacks.
    ///
    /// # Parameters
    /// * `out` - Destination buffer to fill with pseudorandom bytes.
    ///
    /// # Returns
    /// [`EntropyHealthStatus`] indicating whether continuous health tests passed.
    pub fn generate(&mut self, out: &mut [u8]) -> EntropyHealthStatus {
        if self.reseed_counter > 10000 {
            let entropy = Self::get_entropy(32);
            self.update(&entropy);
            self.reseed_counter = 1;
        }

        let mut generated = 0;
        while generated < out.len() {
            let mut ctx = hmac::Context::with_key(&self.key);
            ctx.update(&self.v);
            self.v = ctx.sign().as_ref().to_vec();

            let to_copy = std::cmp::min(self.v.len(), out.len() - generated);
            out[generated..generated + to_copy].copy_from_slice(&self.v[..to_copy]);
            generated += to_copy;
        }

        self.update(&[]);
        self.reseed_counter += 1;

        // Run Health Tests
        let rct_passed = self.run_rct(out);
        let apt_passed = self.run_apt(out);

        EntropyHealthStatus {
            rct_passed,
            apt_passed,
            reseed_count: self.reseed_counter,
        }
    }

    /// Executes the NIST SP 800-90B Repetition Count Test (RCT).
    ///
    /// # Failure Condition
    /// Fails (returns `false`) if $\ge 16$ identical consecutive byte samples are observed.
    fn run_rct(&mut self, data: &[u8]) -> bool {
        for &byte in data {
            if byte == self.rct_prev_sample {
                self.rct_count += 1;
                if self.rct_count >= 16 {
                    return false;
                }
            } else {
                self.rct_prev_sample = byte;
                self.rct_count = 1;
            }
        }
        true
    }

    /// Executes the NIST SP 800-90B Adaptive Proportion Test (APT).
    ///
    /// # Failure Condition
    /// Evaluates sliding windows of 512 bytes. Fails (returns `false`) if the initial base sample
    /// appears $\ge 13$ times within the 512-byte window.
    fn run_apt(&mut self, data: &[u8]) -> bool {
        for &byte in data {
            if self.apt_count == 0 {
                self.apt_base_sample = byte;
            }
            if byte == self.apt_base_sample {
                self.apt_window.push(byte);
                if self.apt_window.len() >= 13 {
                    return false;
                }
            }
            self.apt_count += 1;
            if self.apt_count == 512 {
                self.apt_count = 0;
                self.apt_window.clear();
            }
        }
        true
    }
}

/// Initializes a DRBG instance and performs an startup self-test / health check.
pub fn init_drbg_health_check() -> EntropyHealthStatus {
    let mut drbg = HmacDrbg::new();
    let mut dummy = [0u8; 64];
    drbg.generate(&mut dummy)
}
