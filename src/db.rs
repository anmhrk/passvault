use rusqlite::{Connection, Result};

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        Ok(Database { conn })
    }
}
