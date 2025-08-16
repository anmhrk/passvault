use anyhow::Result;
use rusqlite::Connection;
use std::fs;

#[derive(Debug)]
pub struct PasswordEntry {
    pub name: String,
    pub username: Option<String>,
    pub encrypted_password: String,
    pub url: Option<String>,
    pub nonce: String,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new() -> Result<Self> {
        let home_dir = dirs
            ::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Unable to find home directory"))?;
        let vault_dir = home_dir.join(".passvault");

        if !vault_dir.exists() {
            fs::create_dir_all(&vault_dir)?;
        }

        let db_path = vault_dir.join("passvault.db");
        let conn = Connection::open(db_path)?;

        let db = Self { conn };
        db.initialize_schema()?;
        Ok(db)
    }

    fn initialize_schema(&self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            []
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS password_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                username TEXT,
                encrypted_password TEXT NOT NULL,
                url TEXT,
                nonce TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            []
        )?;

        Ok(())
    }

    pub fn has_master_password(&self) -> Result<bool> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM master_password")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count > 0)
    }

    pub fn set_master_password(&self, password_hash: &str, salt: &str) -> Result<()> {
        self.conn.execute("DELETE FROM master_password", [])?;

        self.conn.execute("INSERT INTO master_password (password_hash, salt) VALUES (?1, ?2)", [
            password_hash,
            salt,
        ])?;

        Ok(())
    }

    pub fn update_master_password(&self, password_hash: &str, salt: &str) -> Result<()> {
        self.conn.execute("UPDATE master_password SET password_hash = ?1, salt = ?2", [
            password_hash,
            salt,
        ])?;
        Ok(())
    }

    pub fn get_master_password_hash(&self) -> Result<Option<(String, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT password_hash, salt FROM master_password LIMIT 1"
        )?;

        let result = stmt.query_row([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        });

        match result {
            Ok((hash, salt)) => Ok(Some((hash, salt))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn insert_password_entry(
        &self,
        name: &str,
        username: Option<&str>,
        encrypted_password: &str,
        url: Option<&str>,
        nonce: &str
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO password_entries (name, username, encrypted_password, url, nonce, updated_at) 
             VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)",
            rusqlite::params![name, username, encrypted_password, url, nonce]
        )?;
        Ok(())
    }

    pub fn get_password_entry(&self, name: &str) -> Result<Option<PasswordEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, username, encrypted_password, url, nonce FROM password_entries WHERE name = ?1"
        )?;

        let result = stmt.query_row([name], |row| {
            Ok(PasswordEntry {
                name: row.get(0)?,
                username: row.get(1)?,
                encrypted_password: row.get(2)?,
                url: row.get(3)?,
                nonce: row.get(4)?,
            })
        });

        match result {
            Ok(entry) => Ok(Some(entry)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_password_entries(&self) -> Result<Vec<PasswordEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, username, encrypted_password, url, nonce FROM password_entries ORDER BY name"
        )?;

        let entries = stmt.query_map([], |row| {
            Ok(PasswordEntry {
                name: row.get(0)?,
                username: row.get(1)?,
                encrypted_password: row.get(2)?,
                url: row.get(3)?,
                nonce: row.get(4)?,
            })
        })?;

        let mut result = Vec::new();
        for entry in entries {
            result.push(entry?);
        }

        Ok(result)
    }

    pub fn update_password_entry(
        &self,
        name: &str,
        username: Option<&str>,
        encrypted_password: Option<&str>,
        url: Option<&str>,
        nonce: Option<&str>
    ) -> Result<bool> {
        let existing = self.get_password_entry(name)?;
        if existing.is_none() {
            return Ok(false);
        }

        let existing = existing.unwrap();

        let new_username = username.or(existing.username.as_deref());
        let new_encrypted_password = encrypted_password.unwrap_or(&existing.encrypted_password);
        let new_url = url.or(existing.url.as_deref());
        let new_nonce = nonce.unwrap_or(&existing.nonce);

        self.conn.execute(
            "UPDATE password_entries SET username = ?1, encrypted_password = ?2, url = ?3, nonce = ?4, updated_at = CURRENT_TIMESTAMP WHERE name = ?5",
            rusqlite::params![new_username, new_encrypted_password, new_url, new_nonce, name]
        )?;

        Ok(true)
    }

    pub fn delete_password_entry(&self, name: &str) -> Result<bool> {
        self.conn.execute("DELETE FROM password_entries WHERE name = ?1", [name])?;

        Ok(true)
    }
}
