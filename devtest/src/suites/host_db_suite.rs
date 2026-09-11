//! Untrusted Host SQLite Database, WAL Mode, and Concurrency Verification Suite.

use super::TestStoreDir;
use anyhow::{bail, Result};
use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use std::thread;

/// Executes host database connection, WAL pragma, and concurrent isolation tests.
pub fn run_suite() -> Result<()> {
    let store_dir = TestStoreDir::new("host-db");
    let db_path = store_dir.0.join("metadata.db");

    // 1. Connection & Pragma Initialization
    let conn = Connection::open(&db_path)
        .map_err(|e| anyhow::anyhow!("SQLite Connection::open failed: {:?}", e))?;

    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;",
    )
    .map_err(|e| anyhow::anyhow!("Failed to set SQLite WAL pragmas: {:?}", e))?;

    // Verify WAL journal mode setting
    let journal_mode: String = conn.query_row("PRAGMA journal_mode;", [], |row| row.get(0))?;
    if journal_mode.to_lowercase() != "wal" {
        bail!("Expected journal_mode = WAL, got: {}", journal_mode);
    }

    // 2. Schema Table Creation
    conn.execute(
        "CREATE TABLE IF NOT EXISTS secret_metadata (
            id TEXT PRIMARY KEY,
            purpose TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );",
        [],
    )?;

    // Insert test record
    conn.execute(
        "INSERT INTO secret_metadata (id, purpose, created_at) VALUES (?1, ?2, ?3);",
        ("sec-101", "purpose:devtest:host_db", 1700000000i64),
    )?;

    let count: i64 = conn.query_row("SELECT COUNT(*) FROM secret_metadata;", [], |row| row.get(0))?;
    if count != 1 {
        bail!("Expected 1 record in secret_metadata, found {}", count);
    }

    // 3. Multi-Threaded Concurrent Read/Write Contention Audit
    let conn_arc = Arc::new(Mutex::new(conn));
    let mut threads = vec![];

    for i in 0..5 {
        let conn_clone = Arc::clone(&conn_arc);
        let handle = thread::spawn(move || -> Result<()> {
            let conn = conn_clone.lock().map_err(|_| anyhow::anyhow!("Mutex lock poisoned"))?;
            conn.execute(
                "INSERT INTO secret_metadata (id, purpose, created_at) VALUES (?1, ?2, ?3);",
                (format!("sec-concurrent-{i}"), "purpose:concurrent", 1700000000i64 + i),
            )?;
            Ok(())
        });
        threads.push(handle);
    }

    for t in threads {
        t.join().map_err(|_| anyhow::anyhow!("Thread panicked"))??;
    }

    let final_conn = conn_arc.lock().map_err(|_| anyhow::anyhow!("Lock error"))?;
    let total_records: i64 = final_conn.query_row("SELECT COUNT(*) FROM secret_metadata;", [], |row| row.get(0))?;
    if total_records != 6 {
        bail!("Expected 6 total records after concurrent inserts, found {}", total_records);
    }

    Ok(())
}
