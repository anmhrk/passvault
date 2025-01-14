use argon2::password_hash::SaltString;
use dirs::home_dir;
use std::io;
use std::path::PathBuf;

use crate::errors::PassvaultError;

pub fn get_salt_string(salt: &str) -> Result<SaltString, PassvaultError> {
    SaltString::from_b64(salt).map_err(|_| PassvaultError::CryptoError)
}

pub fn read_line() -> Result<String, PassvaultError> {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|_| PassvaultError::ReadInputError)?;
    Ok(input.trim().to_string())
}

pub fn get_db_path() -> Result<PathBuf, PassvaultError> {
    let mut path = home_dir().expect("Failed to get home directory");
    path.push(".passvault");
    std::fs::create_dir_all(&path).expect("Failed to create directory");
    path.push("passvault.db");
    Ok(path)
}
