//! `traces-sm` CLI Entry Point and Command-Line Interface.
//!
//! # Architecture & Operator Model
//! The `traces-sm` binary provides a command-line interface for operators and administrators
//! interacting with the untrusted host gateway and Intel SGX cryptographic enclave backend.
//!
//! # Responsibilities
//! - **Command-Line Parsing**: Leverages `clap` v4 with derive macros for type-safe CLI routing.
//! - **HTTP/REST Client Delegation**: Dispatches parsed commands through [`client::ApiClient`]
//!   to the configured host service URL (default: `http://localhost:8080`).
//! - **ANSI Color Terminal Formatting**: Renders ASCII art banners and colored status badges
//!   (`green` for success, `cyan` for metadata, `yellow` for telemetry/signatures, `red` for shredding).
//! - **Domain Workflows**:
//!   - Sealed secrets CRUD (`secret`)
//!   - In-enclave asymmetric/symmetric keypair generation and signing (`key`)
//!   - NIST SP 800-57 lifecycle transitions & SP 800-88 cryptographic shredding (`lifecycle`)
//!   - DKG threshold cluster node status (`dkg`)
//!   - NIST SP 800-90B DRBG continuous entropy health telemetry (`entropy`)
//!   - Zero-Knowledge proofs & Homomorphic Encryption (`zkp`)
//!   - Intel SGX DCAP remote attestation quotes (`attest`)
//!   - Service liveness/readiness health probes (`health`)

use clap::{Parser, Subcommand};
use colored::*;

mod client;

/// Generates the stylized ASCII key banner displayed upon CLI invocation.
///
/// Returns a multi-line formatted string styled with ANSI color codes.
fn get_ascii_key_banner() -> String {
    format!(
        "{}\n{}\n{}\n{}\n{}\n",
        r#"  .-""""-."#.yellow().bold(),
        r#" /  ____  \"#.yellow().bold(),
        format!(
            "|  |'  '|  |====|===\\__/\\____/\\____[ {} ]====|",
            "TRACES-SM".cyan().bold()
        )
        .yellow(),
        r#" \  \__/  /                              │ │ │"#.yellow(),
        r#"  '-....-'                               ╵ ╵ ╵"#.yellow()
    )
}

/// Root command-line parser for `traces-sm`.
#[derive(Parser)]
#[command(
    name = "traces-sm",
    author = "traces-sm team",
    version = "0.1.0",
    about = "100% Rust-Native NIST SP 800-57 Compliant SGX Secrets & Key Management CLI",
    before_help = "  .-\"\"\"\"-.\n /  ____  \\\n|  |'  '|  |====|===\\__/\\____/\\____[ TRACES-SM ]====|\n \\  \\__/  /                              │ │ │\n  '-....-'                               ╵ ╵ ╵\n",
    long_about = "  .-\"\"\"\"-.\n /  ____  \\\n|  |'  '|  |====|===\\__/\\____/\\____[ TRACES-SM ]====|\n \\  \\__/  /                              │ │ │\n  '-....-'                               ╵ ╵ ╵\n\ntraces-sm is a 100% Rust-Native CLI tool for managing Intel SGX enclave-sealed secrets, NIST SP 800-57 key lifecycles, Post-Quantum Cryptography (ML-KEM/ML-DSA), DKG threshold nodes, ZK proofs, and SP 800-90B DRBG health status.",
    help_template = "{before-help}\n{bin} {version}\n{author-with-newline}{about-section}\n\n{usage-heading} {usage}\n\n{all-args}{after-help}"
)]
struct Cli {
    /// Command subcommand to execute.
    #[command(subcommand)]
    command: Commands,

    /// Server endpoint URL (default: http://localhost:8080)
    #[arg(
        short = 's',
        long,
        global = true,
        default_value = "http://localhost:8080"
    )]
    server: String,

    /// Enable verbose debug diagnostic logging output
    #[arg(short = 'd', long, global = true)]
    debug: bool,
}

/// Top-level subcommands supported by the `traces-sm` CLI binary.
#[derive(Subcommand)]
enum Commands {
    /// Manage sealed secrets (create, read, update, delete, list).
    Secret {
        #[command(subcommand)]
        action: SecretCommands,
    },
    /// In-enclave Key Generation & Cryptographic Operations.
    Key {
        #[command(subcommand)]
        action: KeyCommands,
    },
    /// NIST SP 800-57 Key Lifecycle Management & Crypto-Shredding.
    Lifecycle {
        #[command(subcommand)]
        action: LifecycleCommands,
    },
    /// Distributed Key Generation (DKG) & Node Topology.
    Dkg {
        #[command(subcommand)]
        action: DkgCommands,
    },
    /// NIST SP 800-90B DRBG Entropy Health Monitoring.
    Entropy {
        #[command(subcommand)]
        action: EntropyCommands,
    },
    /// Zero-Knowledge Proofs & Homomorphic Encryption (Schnorr, Bulletproofs, Paillier).
    Zkp {
        #[command(subcommand)]
        action: ZkpCommands,
    },
    /// Inspect Intel DCAP Remote Attestation Quotes.
    Attest {
        #[command(subcommand)]
        action: AttestCommands,
    },
    /// Check system health and enclave connectivity.
    Health,
}

/// Secret management subcommands.
#[derive(Subcommand)]
enum SecretCommands {
    /// Create and seal a new secret inside the SGX enclave.
    Create {
        /// Secret identifier / name
        #[arg(short, long)]
        name: String,
        /// Plaintext secret value
        #[arg(short, long)]
        value: String,
        /// Secret payload type (opaque, symmetric-key, asymmetric-key, cert-bundle)
        #[arg(short = 't', long, default_value = "opaque")]
        secret_type: String,
        /// Time-To-Live in seconds
        #[arg(long, default_value = "86400")]
        ttl: u64,
    },
    /// Retrieve metadata for a sealed secret.
    Get {
        /// Secret identifier / name
        #[arg(short, long)]
        name: String,
    },
    /// List sealed secret records.
    List,
}

/// Key management and cryptographic operation subcommands.
#[derive(Subcommand)]
enum KeyCommands {
    /// Generate a new keypair inside SGX EPC memory (RSA, ECDSA, Ed25519, ML-KEM, ML-DSA-3, ML-DSA-87).
    Generate {
        /// Key alias / identifier
        #[arg(short, long)]
        name: String,
        /// Key algorithm (rsa-4096, rsa-2048, ecdsa-p256, ecdsa-p384, ed25519, ml-kem-768, ml-dsa-3, ml-dsa-87, aes-256-kw)
        #[arg(short, long, default_value = "rsa-4096")]
        algorithm: String,
    },
    /// Export public key PEM format.
    Public {
        /// Key alias / identifier
        #[arg(short, long)]
        name: String,
    },
    /// Sign a message hash inside the SGX enclave.
    Sign {
        /// Key alias / identifier
        #[arg(short, long)]
        name: String,
        /// Message text to sign
        #[arg(short, long)]
        message: String,
    },
    /// Verify a signature against a message and key alias.
    Verify {
        /// Key alias / identifier
        #[arg(short, long)]
        name: String,
        /// Message text that was signed
        #[arg(short, long)]
        message: String,
        /// Hex-encoded signature string
        #[arg(short, long)]
        signature: String,
    },
}

/// NIST SP 800-57 key lifecycle and SP 800-88 sanitization subcommands.
#[derive(Subcommand)]
enum LifecycleCommands {
    /// Transition key lifecycle state (PreOperational, Operational, Deactivated, Expired, Revoked).
    Transition {
        /// Target key ID
        #[arg(short, long)]
        id: String,
        /// Target NIST lifecycle state
        #[arg(short, long)]
        state: String,
    },
    /// Execute NIST SP 800-88 Crypto-Shredding (overwrite storage sectors before delete).
    Shred {
        /// Target key ID to crypto-shred
        #[arg(short, long)]
        id: String,
    },
}

/// Distributed Key Generation cluster management subcommands.
#[derive(Subcommand)]
enum DkgCommands {
    /// List DKG threshold peer nodes and RA-TLS connection status.
    Nodes,
}

/// Entropy health telemetry subcommands.
#[derive(Subcommand)]
enum EntropyCommands {
    /// Check NIST SP 800-90B DRBG continuous health status (APT & RCT tests).
    Health,
}

/// Zero-Knowledge proof generation subcommands.
#[derive(Subcommand)]
enum ZkpCommands {
    /// Generate Schnorr Proof-of-Knowledge for a secret token.
    Prove {
        /// Secret token string
        #[arg(short, long)]
        token: String,
    },
}

/// Remote attestation inspection subcommands.
#[derive(Subcommand)]
enum AttestCommands {
    /// Inspect raw Intel DCAP Quote (MRENCLAVE, MRSIGNER, ISVSVN).
    Quote,
}

/// CLI main asynchronous entry point.
///
/// Dispatches the user-specified subcommand to the remote host gateway via HTTP client.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    println!("{}", get_ascii_key_banner());

    if cli.debug || std::env::var("TRACES_SM_DEBUG").is_ok() {
        println!("{}", "  ⚡ [DEBUG MODE ACTIVE] Verbose telemetry, latency metrics, and raw RPC payloads enabled.\n".magenta().bold());
    }

    let client = client::ApiClient::new(&cli.server);

    match cli.command {
        Commands::Secret { action } => match action {
            SecretCommands::Create {
                name,
                value,
                secret_type,
                ttl,
            } => {
                let payload = serde_json::json!({
                    "name": name,
                    "value": value,
                    "secret_type": secret_type,
                    "ttl": ttl
                });
                let res: serde_json::Value = client.post("/v1/secrets", &payload).await?;
                println!(
                    "{}",
                    format!("✓ Secret '{}' sealed in SGX enclave: {}", name, res).green()
                );
            }
            SecretCommands::Get { name } => {
                let res: serde_json::Value =
                    client.get(&format!("/v1/secrets?name={}", name)).await?;
                println!(
                    "{}",
                    format!("Secret Metadata for '{}': {}", name, res).cyan()
                );
            }
            SecretCommands::List => {
                let res: serde_json::Value = client.get("/v1/secrets").await?;
                println!("{}", format!("Sealed Secret Vault List: {}", res).cyan());
            }
        },
        Commands::Key { action } => match action {
            KeyCommands::Generate { name, algorithm } => {
                let payload = serde_json::json!({ "name": name, "algorithm": algorithm });
                let res: serde_json::Value = client.post("/v1/keys", &payload).await?;
                println!(
                    "{}",
                    format!(
                        "✓ Key '{}' ({}) generated inside SGX enclave: {}",
                        name, algorithm, res
                    )
                    .green()
                );
            }
            KeyCommands::Public { name } => {
                let res: serde_json::Value = client.get(&format!("/v1/keys?name={}", name)).await?;
                println!(
                    "{}",
                    format!("Public Key PEM for '{}': {}", name, res).cyan()
                );
            }
            KeyCommands::Sign { name, message } => {
                let payload = serde_json::json!({ "name": name, "message": message });
                let res: serde_json::Value = client.post("/v1/keys/sign", &payload).await?;
                println!("{}", format!("Signature Output: {}", res).yellow());
            }
            KeyCommands::Verify {
                name,
                message,
                signature,
            } => {
                let payload =
                    serde_json::json!({ "name": name, "message": message, "signature": signature });
                let res: serde_json::Value = client.post("/v1/keys/verify", &payload).await?;
                println!("{}", format!("Signature Verification: {}", res).green());
            }
        },
        Commands::Lifecycle { action } => match action {
            LifecycleCommands::Transition { id, state } => {
                let res: serde_json::Value = client
                    .post(
                        "/v1/lifecycle/transition",
                        &serde_json::json!({ "key_id": id, "target_state": state }),
                    )
                    .await?;
                println!(
                    "{}",
                    format!("✓ Key {} transitioned to state {}: {}", id, state, res).green()
                );
            }
            LifecycleCommands::Shred { id } => {
                let res: serde_json::Value = client
                    .post(
                        "/v1/lifecycle/shred",
                        &serde_json::json!({ "key_id": id, "confirmation": id }),
                    )
                    .await?;
                println!(
                    "{}",
                    format!("✓ Key {} crypto-shredded (SP 800-88): {}", id, res).red()
                );
            }
        },
        Commands::Dkg { action } => match action {
            DkgCommands::Nodes => {
                let res: serde_json::Value = client.get("/v1/dkg/nodes").await?;
                println!("{}", format!("DKG Threshold Peer Nodes: {}", res).cyan());
            }
        },
        Commands::Entropy { action } => match action {
            EntropyCommands::Health => {
                let res: serde_json::Value = client.get("/v1/entropy/health").await?;
                println!(
                    "{}",
                    format!("NIST SP 800-90B DRBG Health (APT & RCT): {}", res).yellow()
                );
            }
        },
        Commands::Zkp { action } => match action {
            ZkpCommands::Prove { token } => {
                let payload = serde_json::json!({ "token": token });
                let res: serde_json::Value = client.post("/v1/zkp/prove", &payload).await?;
                println!(
                    "{}",
                    format!("Schnorr Proof-of-Knowledge: {}", res).magenta()
                );
            }
        },
        Commands::Attest { action } => match action {
            AttestCommands::Quote => {
                let res: serde_json::Value = client.get("/v1/attest/quote").await?;
                println!(
                    "{}",
                    format!("Intel DCAP Attestation Quote: {}", res)
                        .bold()
                        .blue()
                );
            }
        },
        Commands::Health => {
            let res: serde_json::Value = client.get("/health").await?;
            println!("{}", format!("System Status: {}", res).bold().green());
        }
    }

    Ok(())
}
