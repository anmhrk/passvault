use argon2::password_hash::SaltString;
use std::io;

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
