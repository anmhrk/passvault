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
                website_name TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                iv TEXT NOT NULL,
                website_url TEXT,
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

    pub fn check_if_initialized(&self) -> bool {
        let result = self.conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='master_password'",
            [],
            |row| row.get::<_, i32>(0),
        );

        matches!(result, Ok(1))
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

    pub fn add_password(
        &self,
        website_name: &str,
        username: &str,
        password: &str,
        iv: &str,
        website_url: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO passwords (website_name, username, encrypted_password, iv, website_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [website_name, username, password, iv, website_url, &now(), &now()],
        )?;
        Ok(())
    }

    pub fn list_passwords(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT website_name FROM passwords")?;
        let website_names = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<String>>>()?;
        Ok(website_names)
    }

    pub fn get_password(&self, website_name: &str) -> Result<(String, String, String)> {
        self.conn.query_row(
            "SELECT username, encrypted_password, iv FROM passwords WHERE website_name = ?",
            [website_name],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
    }

    pub fn update_password() {}

    pub fn delete_password() {}

    pub fn update_master_password() {}

    pub fn reset_database() {}
}
