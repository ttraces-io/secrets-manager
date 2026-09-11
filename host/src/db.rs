//! Host Administrative Metadata and Audit SQLite Storage Engine.
//!
//! # Purpose and Concurrency Model
//! Manages the host-side SQLite database (`metadata.db`) used for administrative indexing,
//! issued token tracking, DKG node statuses, and audit trail logs.
//!
//! # Database Invariants
//! - **Write-Ahead Logging (WAL)**: `PRAGMA journal_mode = WAL;` is enabled to allow concurrent
//!   readers without blocking writers.
//! - **Busy Timeout**: `PRAGMA busy_timeout = 5000;` prevents `SQLITE_BUSY` errors during concurrent bursts.
//! - **Synchronous Mode**: `PRAGMA synchronous = NORMAL;` provides durability against application crashes.
//! - **Foreign Key Constraints**: `PRAGMA foreign_keys = ON;` guarantees relational integrity.

use once_cell::sync::Lazy;
use rusqlite::{Connection, Result};
use std::sync::Mutex;

/// Global thread-safe SQLite connection pool wrapped in a mutex.
pub static DB_CONN: Lazy<Mutex<Connection>> = Lazy::new(|| {
    let conn = Connection::open("metadata.db").expect("Failed to open DB");
    // Enable Write-Ahead Logging (WAL) and busy timeout to avoid database lock errors under concurrency
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;",
    )
    .expect("Failed to apply SQLite PRAGMAs");
    Mutex::new(conn)
});

/// Initializes the SQLite database schema and verifies table existence.
///
/// # Tables Created
/// - `secrets_metadata`: Unencrypted index of secret identifiers, names, and creation timestamps.
/// - `audit_logs`: Append-only audit record of administrative actions and timestamps.
/// - `tokens`: Issued token registry and host-tracked revocation flags.
/// - `dkg_nodes`: Distributed Key Generation participant registry and connectivity status.
/// - `entropy_audits`: Audit records of NIST SP 800-90B continuous health verification runs.
pub fn init_db() -> Result<()> {
    let conn = DB_CONN.lock().unwrap();
    // Ensure WAL PRAGMAs are active
    let _ = conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA synchronous = NORMAL;",
    );

    conn.execute(
        "CREATE TABLE IF NOT EXISTS secrets_metadata (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS tokens (
            token_id TEXT PRIMARY KEY,
            revoked INTEGER DEFAULT 0
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS dkg_nodes (
            node_id TEXT PRIMARY KEY,
            status TEXT NOT NULL
        )",
        [],
    )?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS entropy_audits (
            audit_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )",
        [],
    )?;

    Ok(())
}
