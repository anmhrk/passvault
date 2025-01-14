use rusqlite::{types::ToSql, Connection, Result};
use std::path::PathBuf;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(path: &PathBuf) -> Result<Self> {
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
                iv TEXT NOT NULL
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS master_password (
                id INTEGER PRIMARY KEY,
                hash TEXT NOT NULL,
                salt TEXT NOT NULL
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
            "INSERT INTO master_password (id, hash, salt) VALUES (1, ?, ?)",
            [hash, salt],
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

    pub fn check_if_password_exists(&self, website_name: &str) -> bool {
        let result = self.conn.query_row(
            "SELECT COUNT(*) FROM passwords WHERE website_name = ?",
            [website_name],
            |row| row.get::<_, i32>(0),
        );

        matches!(result, Ok(1))
    }

    pub fn add_password(
        &self,
        website_name: &str,
        username: &str,
        password: &str,
        iv: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO passwords (
                website_name, 
                username, 
                encrypted_password, 
                iv
            ) VALUES (?, ?, ?, ?)",
            [website_name, username, password, iv],
        )?;

        Ok(())
    }

    pub fn list_passwords(
        &self,
        website_name: Option<&str>,
    ) -> Result<Vec<(String, String, String, String)>> {
        if let Some(website_name) = website_name {
            let mut stmt = self.conn.prepare(
                "SELECT website_name, username, encrypted_password, iv FROM passwords 
                WHERE LOWER(website_name) LIKE LOWER(?)",
            )?;

            let pattern = format!("%{}%", website_name);
            let results = stmt.query_map([pattern], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;

            results.collect()
        } else {
            let mut stmt = self
                .conn
                .prepare("SELECT website_name, username, encrypted_password, iv FROM passwords")?;
            let results = stmt.query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;

            results.collect()
        }
    }

    pub fn update_password(
        &self,
        website_name: &str,
        username: Option<&str>,
        password: Option<&str>,
        iv: Option<&str>,
    ) -> Result<()> {
        let mut set_clauses = Vec::new();
        let mut params: Vec<Box<dyn ToSql>> = Vec::new();

        if let Some(username) = username {
            set_clauses.push("username = ?");
            params.push(Box::new(username.to_string()));
        }
        if let Some(password) = password {
            set_clauses.push("encrypted_password = ?");
            params.push(Box::new(password.to_string()));
        }
        if let Some(iv) = iv {
            set_clauses.push("iv = ?");
            params.push(Box::new(iv.to_string()));
        }

        let joined_clauses = set_clauses.join(", ");
        let mut query = String::from("UPDATE passwords SET ");
        query.push_str(&joined_clauses);
        query.push_str(" WHERE website_name = ?");
        params.push(Box::new(website_name.to_string()));

        let param_refs: Vec<&dyn ToSql> = params.iter().map(|p| p.as_ref()).collect();
        self.conn.execute(&query, param_refs.as_slice())?;
        Ok(())
    }

    pub fn delete_password(&self, website_name: &str) -> Result<()> {
        self.conn.execute(
            "DELETE FROM passwords WHERE website_name = ?",
            [website_name],
        )?;

        Ok(())
    }

    pub fn reset_database(&self) -> Result<()> {
        self.conn.execute("DROP TABLE IF EXISTS passwords", [])?;
        self.conn
            .execute("DROP TABLE IF EXISTS master_password", [])?;

        Ok(())
    }
}
