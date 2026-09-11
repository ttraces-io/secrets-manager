//! NIST SP 800-90A/B DRBG and Continuous Entropy Health Testing Suite.

use super::calculate_shannon_entropy;
use anyhow::{bail, Result};
use traces_sm_enclave::drbg::{init_drbg_health_check, HmacDrbg};

/// Executes DRBG and TRNG continuous entropy health tests.
pub fn run_suite() -> Result<()> {
    // 1. Initialise and verify NIST SP 800-90B continuous health check
    let status = init_drbg_health_check();
    if !status.rct_passed {
        bail!("NIST SP 800-90B Repetition Count Test (RCT) failed");
    }
    if !status.apt_passed {
        bail!("NIST SP 800-90B Adaptive Proportion Test (APT) failed");
    }

    // 2. Instantiate HMAC-DRBG and generate pseudorandom stream
    let mut drbg = HmacDrbg::new();
    let mut stream = Vec::with_capacity(2048);
    let mut block = [0u8; 32];
    for _ in 0..64 {
        let health = drbg.generate(&mut block);
        if !health.rct_passed || !health.apt_passed {
            bail!("Continuous health test failed during stream generation");
        }
        stream.extend_from_slice(&block);
    }

    // 3. Statistical Shannon Entropy Evaluation (must be >= 7.6 bits/byte)
    let entropy = calculate_shannon_entropy(&stream);
    if entropy < 7.6 {
        bail!(
            "Insufficient Shannon entropy in DRBG output: {:.4} bits/byte (expected >= 7.6)",
            entropy
        );
    }

    // 4. Distribution uniformity check (distinct byte diversity)
    let mut seen = [false; 256];
    for &b in &stream {
        seen[b as usize] = true;
    }
    let distinct_count = seen.iter().filter(|&&s| s).count();
    if distinct_count < 230 {
        bail!(
            "Low distinct byte diversity in 2048-byte sample: {} distinct values (expected >= 230)",
            distinct_count
        );
    }

    Ok(())
}
