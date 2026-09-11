//! Live In-Enclave HTTP/1.1 REST API Integration Verification Suite.

use super::TestStoreDir;
use anyhow::{bail, Result};
use base64::Engine;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use traces_sm_enclave::auth::EnclaveTokenService;
use traces_sm_enclave::config::Config;
use traces_sm_enclave::sealing::{SealingKeyProvider, SimSealingProvider};
use traces_sm_enclave::server::EnclaveState;
use traces_sm_enclave::store::Store;

/// Executes live HTTP endpoint integration tests against a live in-enclave HTTP listener.
pub async fn run_suite() -> Result<()> {
    let temp_store = TestStoreDir::new("http-live");
    let provider: Arc<dyn SealingKeyProvider> =
        Arc::new(SimSealingProvider::new(temp_store.path()));
    let store = Arc::new(Store::new(temp_store.path()));
    let token_service = Arc::new(
        EnclaveTokenService::new(temp_store.path(), provider.as_ref())
            .map_err(|e| anyhow::anyhow!("token service init failed: {:?}", e))?,
    );

    let config = Config {
        port: 0,
        store_path: temp_store.path().to_string(),
        sgx_mode: "SIMULATION".to_string(),
        jwt_validity_secs: 3600,
    };

    let state = Arc::new(EnclaveState {
        store,
        provider,
        token_service,
        config,
    });

    // Bind on ephemeral port 127.0.0.1:0
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| anyhow::anyhow!("failed to bind ephemeral listener: {:?}", e))?;
    let port = listener.local_addr()?.port();
    let base_url = format!("http://127.0.0.1:{}", port);

    // Spawn server background accept thread
    let server_state = Arc::clone(&state);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let st = Arc::clone(&server_state);
            thread::spawn(move || {
                let _ = traces_sm_enclave::server::router::handle_connection(stream, st);
            });
        }
    });

    let client = reqwest::Client::new();

    // 1. Health Endpoint: GET /health
    let res = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("GET /health network error: {:?}", e))?;
    if !res.status().is_success() {
        bail!("GET /health returned status {}", res.status());
    }
    let body: serde_json::Value = res.json().await?;
    if body["data"]["status"] != "ok" {
        bail!("Unexpected /health response: {:?}", body);
    }

    // 2. Entropy Health Endpoint: GET /v1/entropy/health
    let res = client
        .get(format!("{}/v1/entropy/health", base_url))
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    if body["data"]["rct_passed"] != true || body["data"]["apt_passed"] != true {
        bail!("Entropy health test failed in HTTP response: {:?}", body);
    }

    // 3. Attestation Quote & Measurements: GET /v1/attest/quote
    let res = client
        .get(format!("{}/v1/attest/quote", base_url))
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    if body["data"]["measurements"]["mr_enclave"].is_null() {
        bail!("Missing MRENCLAVE measurement in attestation quote response");
    }

    // 4. Token Issuance: POST /v1/tokens
    let token_req = serde_json::json!({
        "subject": "devtest-operator",
        "scopes": ["secrets:read", "secrets:write", "keys:manage"],
        "ttl_seconds": 3600
    });
    let res = client
        .post(format!("{}/v1/tokens", base_url))
        .json(&token_req)
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    let jwt_token = body["data"]["token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing token in response"))?;
    let auth_header = format!("Bearer {}", jwt_token);

    // 5. Create Secret: POST /v1/secrets
    let secret_payload = "SUPER_CONFIDENTIAL_DATABASE_CREDENTIAL_9999";
    let b64_secret = base64::engine::general_purpose::STANDARD.encode(secret_payload);
    let secret_req = serde_json::json!({
        "name": "db-prod-password",
        "plaintext_base64": b64_secret,
        "owner": "devtest"
    });
    let res = client
        .post(format!("{}/v1/secrets", base_url))
        .header("Authorization", &auth_header)
        .json(&secret_req)
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    let secret_id = body["data"]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing secret id in create response"))?;

    // 6. Get Secret: GET /v1/secrets/{id}
    let res = client
        .get(format!("{}/v1/secrets/{}", base_url, secret_id))
        .header("Authorization", &auth_header)
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    let retrieved_b64 = body["data"]["plaintext_base64"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing plaintext_base64 in get secret response"))?;
    let retrieved_bytes = base64::engine::general_purpose::STANDARD.decode(retrieved_b64)?;
    if retrieved_bytes.as_slice() != secret_payload.as_bytes() {
        bail!("Retrieved secret plaintext does not match original value");
    }

    // 7. Generate Key: POST /v1/keys
    let key_req = serde_json::json!({
        "name": "ed25519-primary-signing-key",
        "algorithm": "Ed25519"
    });
    let res = client
        .post(format!("{}/v1/keys", base_url))
        .header("Authorization", &auth_header)
        .json(&key_req)
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    let key_id = body["data"]["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing key id in key generation response"))?;

    // 8. Sign with Key: POST /v1/keys/{id}/sign
    let sign_msg = "ENCLAVE_TRANSACTION_PAYLOAD_SIGNING_TEST";
    let b64_msg = base64::engine::general_purpose::STANDARD.encode(sign_msg);
    let sign_req = serde_json::json!({
        "data_base64": b64_msg
    });
    let res = client
        .post(format!("{}/v1/keys/{}/sign", base_url, key_id))
        .header("Authorization", &auth_header)
        .json(&sign_req)
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    let sig_b64 = body["data"]["signature_base64"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing signature in sign response"))?;

    // 9. Verify Signature: POST /v1/keys/{id}/verify
    let verify_req = serde_json::json!({
        "data_base64": b64_msg,
        "signature_base64": sig_b64
    });
    let res = client
        .post(format!("{}/v1/keys/{}/verify", base_url, key_id))
        .header("Authorization", &auth_header)
        .json(&verify_req)
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    if body["data"]["valid"] != true {
        bail!("Live HTTP signature verification returned valid=false");
    }

    // 10. ZKP Pedersen Commitment: POST /v1/zkp/pedersen/commit
    let pedersen_req = serde_json::json!({ "value": 750 });
    let res = client
        .post(format!("{}/v1/zkp/pedersen/commit", base_url))
        .json(&pedersen_req)
        .send()
        .await?;
    let body: serde_json::Value = res.json().await?;
    if body["data"]["commitment_hex"].is_null() {
        bail!("Missing commitment_hex in pedersen response");
    }

    // 11. Cleanup: DELETE /v1/secrets/{id} and DELETE /v1/keys/{id}
    let res = client
        .delete(format!("{}/v1/secrets/{}", base_url, secret_id))
        .header("Authorization", &auth_header)
        .send()
        .await?;
    if !res.status().is_success() {
        bail!("Failed to delete secret via HTTP DELETE");
    }

    let res = client
        .delete(format!("{}/v1/keys/{}", base_url, key_id))
        .header("Authorization", &auth_header)
        .send()
        .await?;
    if !res.status().is_success() {
        bail!("Failed to delete key via HTTP DELETE");
    }

    Ok(())
}
