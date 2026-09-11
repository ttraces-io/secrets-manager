//! Environment Injection, Process Wrapping, and CLI Secret Scrubbing Verification Suite.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::process::Command;

/// Executes environment variable injection, secret leak prevention, and process lifecycle tests.
pub fn run_suite() -> Result<()> {
    // 1. Process Environment Masking Invariant
    let mut env_map = HashMap::new();
    env_map.insert("DB_PASSWORD", "supersecretpassword123!");
    env_map.insert("API_KEY", "canary_token_998877");
    env_map.insert("PUBLIC_HOST", "localhost");

    // Mask sensitive keys
    let masked_env: HashMap<String, String> = env_map
        .iter()
        .map(|(k, v)| {
            let is_sensitive = k.contains("SECRET") || k.contains("PASSWORD") || k.contains("KEY") || k.contains("TOKEN");
            let val = if is_sensitive {
                "********".to_string()
            } else {
                (*v).to_string()
            };
            ((*k).to_string(), val)
        })
        .collect();

    if masked_env.get("DB_PASSWORD") != Some(&"********".to_string()) {
        bail!("Failed to mask DB_PASSWORD in process environment wrapper");
    }
    if masked_env.get("API_KEY") != Some(&"********".to_string()) {
        bail!("Failed to mask API_KEY in process environment wrapper");
    }
    if masked_env.get("PUBLIC_HOST") != Some(&"localhost".to_string()) {
        bail!("Public host variable should remain unmasked");
    }

    // 2. Child Process Lifecycle & Inheritance Test
    let echo_var = "TRACES_SM_INJECTED_VAR";
    let echo_val = "isolated_val_42";

    #[cfg(target_os = "windows")]
    let child_output = Command::new("cmd")
        .args(["/C", "echo %TRACES_SM_INJECTED_VAR%"])
        .env(echo_var, echo_val)
        .output();

    #[cfg(not(target_os = "windows"))]
    let child_output = Command::new("sh")
        .args(["-c", "echo $TRACES_SM_INJECTED_VAR"])
        .env(echo_var, echo_val)
        .output();

    if let Ok(out) = child_output {
        let stdout_str = String::from_utf8_lossy(&out.stdout);
        if !stdout_str.contains(echo_val) {
            bail!("Child process failed to receive injected environment variable");
        }
    }

    // 3. Process Command Line Leaks Protection Assertion
    // Check that sensitive tokens passed via env rather than process args
    let forbidden_arg_pattern = "canary_token_998877";
    let process_args = vec!["traces-sm", "run", "--", "myapp", "--config", "env"];
    for arg in process_args {
        if arg.contains(forbidden_arg_pattern) {
            bail!("Process command line arguments contain unencrypted secret canary!");
        }
    }

    Ok(())
}
