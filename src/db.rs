use rusqlite::{Connection, Result};

use crate::utils::now;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        Ok(Database { conn })
    }

    pub fn init(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                iv TEXT NOT NULL,
                url TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                last_accessed TEXT NOT NULL
            )",
            [],
        )?;

        Ok(())
    }

    pub fn store_master_password(&self, hash: &str, salt: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO master_password (id, hash, salt, last_accessed) VALUES (1, ?, ?, ?)",
            [hash, salt, &now()],
        )?;
        Ok(())
    }

    pub fn get_master_salt_and_hash(&self) -> Result<(String, String)> {
        self.conn.query_row(
            "SELECT salt, hash FROM master_password WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
    }

    pub fn get_last_access(&self) -> Result<String> {
        self.conn.query_row(
            "SELECT last_accessed FROM master_password WHERE id = 1",
            [],
            |row| row.get(0),
        )
    }

    pub fn update_last_access(&self) -> Result<()> {
        self.conn.execute(
            "UPDATE master_password SET last_accessed = ? WHERE id = 1",
            [now()],
        )?;
        Ok(())
    }

    pub fn add_password() {}

    pub fn list_passwords() {}

    pub fn get_password() {}

    pub fn update_password() {}

    pub fn delete_password() {}

    pub fn update_master_password() {}

    pub fn reset_database() {}
}
