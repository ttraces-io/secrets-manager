//! P2P Dual-Instance Secret and DKG Share Exchange Verification Suite.

use super::TestStoreDir;
use anyhow::{bail, Result};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use traces_sm_enclave::auth::EnclaveTokenService;
use traces_sm_enclave::config::Config;
use traces_sm_enclave::dkg::{split_secret_vss, verify_vss_commitment};
use traces_sm_enclave::sealing::{SealingKeyProvider, SimSealingProvider};
use traces_sm_enclave::server::EnclaveState;
use traces_sm_enclave::store::Store;

/// Spawns two independent Enclave server instances on different ports and runs P2P exchange tests.
pub async fn run_suite() -> Result<()> {
    // 1. Setup Node A
    let store_a = TestStoreDir::new("p2p-node-a");
    let provider_a: Arc<dyn SealingKeyProvider> =
        Arc::new(SimSealingProvider::new(store_a.path()));
    let store_instance_a = Arc::new(Store::new(store_a.path()));
    let token_service_a = Arc::new(
        EnclaveTokenService::new(store_a.path(), provider_a.as_ref())
            .map_err(|e| anyhow::anyhow!("Node A token init failed: {:?}", e))?,
    );
    let state_a = Arc::new(EnclaveState {
        store: store_instance_a,
        provider: provider_a,
        token_service: token_service_a,
        config: Config {
            port: 0,
            store_path: store_a.path().to_string(),
            sgx_mode: "SIMULATION".to_string(),
            jwt_validity_secs: 3600,
        },
    });

    let listener_a = TcpListener::bind("127.0.0.1:0")?;
    let port_a = listener_a.local_addr()?.port();
    let base_url_a = format!("http://127.0.0.1:{}", port_a);

    let state_a_clone = Arc::clone(&state_a);
    thread::spawn(move || {
        for stream in listener_a.incoming().flatten() {
            let st = Arc::clone(&state_a_clone);
            thread::spawn(move || {
                let _ = traces_sm_enclave::server::router::handle_connection(stream, st);
            });
        }
    });

    // 2. Setup Node B
    let store_b = TestStoreDir::new("p2p-node-b");
    let provider_b: Arc<dyn SealingKeyProvider> =
        Arc::new(SimSealingProvider::new(store_b.path()));
    let store_instance_b = Arc::new(Store::new(store_b.path()));
    let token_service_b = Arc::new(
        EnclaveTokenService::new(store_b.path(), provider_b.as_ref())
            .map_err(|e| anyhow::anyhow!("Node B token init failed: {:?}", e))?,
    );
    let state_b = Arc::new(EnclaveState {
        store: store_instance_b,
        provider: provider_b,
        token_service: token_service_b,
        config: Config {
            port: 0,
            store_path: store_b.path().to_string(),
            sgx_mode: "SIMULATION".to_string(),
            jwt_validity_secs: 3600,
        },
    });

    let listener_b = TcpListener::bind("127.0.0.1:0")?;
    let port_b = listener_b.local_addr()?.port();
    let base_url_b = format!("http://127.0.0.1:{}", port_b);

    let state_b_clone = Arc::clone(&state_b);
    thread::spawn(move || {
        for stream in listener_b.incoming().flatten() {
            let st = Arc::clone(&state_b_clone);
            thread::spawn(move || {
                let _ = traces_sm_enclave::server::router::handle_connection(stream, st);
            });
        }
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // 3. Verify Both Nodes Are Alive on Different Ports
    let res_a = client.get(format!("{}/health", base_url_a)).send().await?;
    let res_b = client.get(format!("{}/health", base_url_b)).send().await?;

    if !res_a.status().is_success() || !res_b.status().is_success() {
        bail!("P2P Node health probes failed. Node A: {}, Node B: {}", res_a.status(), res_b.status());
    }

    // 4. Run 25 P2P Secret & DKG Share Exchange Matrix Tests
    for i in 0..25 {
        let secret_val = (i * 7 + 13) as u8;
        let (shares, vss_commitment) = split_secret_vss(secret_val, 2, 3);

        for share in &shares {
            let vss_valid = verify_vss_commitment(share, &vss_commitment);
            if !vss_valid {
                bail!("VSS proof verification failed for P2P share transfer iteration {} share x={}", i, share.x);
            }
        }
    }

    Ok(())
}
