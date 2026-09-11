//! Authentication Token and Role-Based Access Control (RBAC) Verification Suite.

use super::TestStoreDir;
use anyhow::{bail, Result};
use traces_sm_enclave::auth::EnclaveTokenService;
use traces_sm_enclave::error::EnclaveError;
use traces_sm_enclave::sealing::SimSealingProvider;

/// Executes authentication token lifecycle and negative security tests.
pub fn run_suite() -> Result<()> {
    let temp_store = TestStoreDir::new("auth-token-suite");
    let provider = SimSealingProvider::new(temp_store.path());

    // 1. Initialize EnclaveTokenService
    let token_service = EnclaveTokenService::new(temp_store.path(), &provider)
        .map_err(|e| anyhow::anyhow!("EnclaveTokenService::new failed: {:?}", e))?;

    // 2. Standard Token Issuance and Validation
    let sub = "operator@traces-sm.internal";
    let scopes = vec![
        "admin".to_string(),
        "secrets:read".to_string(),
        "keys:manage".to_string(),
    ];
    let ttl_secs = 3600;

    let (jti, token) = token_service
        .issue_token(sub, scopes.clone(), ttl_secs, &provider)
        .map_err(|e| anyhow::anyhow!("issue_token failed: {:?}", e))?;

    if token.is_empty() || jti.is_empty() {
        bail!("Issued JWT token string cannot be empty");
    }

    let claims = token_service
        .verify_token(&token)
        .map_err(|e| anyhow::anyhow!("verify_token failed for valid token: {:?}", e))?;

    if claims.sub != sub {
        bail!(
            "Claims subject mismatch: expected {}, got {}",
            sub,
            claims.sub
        );
    }
    if claims.scopes != scopes {
        bail!("Claims scopes mismatch");
    }

    // 3. Negative Test: Revocation
    token_service.revoke_token(&jti);
    match token_service.verify_token(&token) {
        Err(EnclaveError::TokenRevoked) => {
            // Expected
        }
        other => bail!(
            "Expected TokenRevoked error after revoking token, got: {:?}",
            other
        ),
    }

    // 4. Negative Test: Tampered Signature
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 3 {
        let tampered_token = format!("{}.{}.dGFtcGVyZWRfc2lnbmF0dXJl", parts[0], parts[1]);
        if token_service.verify_token(&tampered_token).is_ok() {
            bail!("Tampered token unexpectedly passed verification");
        }
    }

    Ok(())
}
