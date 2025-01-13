use argon2::password_hash::SaltString;
use chrono::{DateTime, Utc};
use std::io;

use crate::errors::PassmanError;

pub fn now() -> String {
    let now: DateTime<Utc> = Utc::now();
    now.to_rfc3339()
}

pub fn get_salt_string(salt: &str) -> Result<SaltString, PassmanError> {
    SaltString::from_b64(salt).map_err(|_| PassmanError::CryptoError)
}

pub fn read_line() -> Result<String, PassmanError> {
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|_| PassmanError::ReadInputError)?;
    Ok(input.trim().to_string())
}
