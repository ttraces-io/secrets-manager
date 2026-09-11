//! System and Runtime Environment Inspection Module.
//!
//! Detects host operating system, architecture, SGX hardware support,
//! simulation mode environment variables, and filesystem capabilities.

use std::env;

/// Environment diagnostics snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EnvironmentInfo {
    /// Host operating system family (e.g., "windows", "linux", "macos").
    pub os: String,
    /// Target CPU architecture (e.g., "x86_64", "aarch64").
    pub arch: String,
    /// Pointer width (e.g., 64).
    pub pointer_width: usize,
    /// Active SGX Mode ("HW" or "SIMULATION").
    pub sgx_mode: String,
    /// SGX device path presence (e.g. /dev/sgx_enclave or /dev/isgx).
    pub sgx_device_present: bool,
    /// Whether running in Non-SGX / Windows simulation fallback.
    pub is_simulation: bool,
    /// Temporary directory path for storage tests.
    pub temp_dir: String,
    /// Hostname or computer name.
    pub host_name: String,
}

impl EnvironmentInfo {
    /// Collects and inspects the current execution environment.
    pub fn collect() -> Self {
        let os = env::consts::OS.to_string();
        let arch = env::consts::ARCH.to_string();
        let pointer_width = usize::BITS as usize;

        let sgx_device_present = std::path::Path::new("/dev/sgx_enclave").exists()
            || std::path::Path::new("/dev/isgx").exists();

        let env_mode = env::var("SGX_MODE").unwrap_or_else(|_| {
            if sgx_device_present {
                "HW".to_string()
            } else {
                "SIMULATION".to_string()
            }
        });

        let is_simulation = env_mode.to_uppercase() != "HW" || !sgx_device_present;
        let sgx_mode = if is_simulation {
            "SIMULATION".to_string()
        } else {
            "HW".to_string()
        };

        let temp_dir = env::temp_dir().to_string_lossy().to_string();
        let host_name = env::var("COMPUTERNAME")
            .or_else(|_| env::var("HOSTNAME"))
            .unwrap_or_else(|_| "localhost".to_string());

        Self {
            os,
            arch,
            pointer_width,
            sgx_mode,
            sgx_device_present,
            is_simulation,
            temp_dir,
            host_name,
        }
    }
}
