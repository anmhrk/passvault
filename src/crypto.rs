use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};

use crate::errors::PassmanError;

pub struct Crypto {
    argon2: Argon2<'static>,
}

impl Crypto {
    pub fn new() -> Self {
        Crypto {
            argon2: Argon2::default(),
        }
    }

    pub fn hash_password(&self, password: &str) -> Result<(String, String), PassmanError> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| PassmanError::HashPasswordError)?;

        Ok((password_hash.to_string(), salt.to_string()))
    }
}
