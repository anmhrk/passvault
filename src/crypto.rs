use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{rand_core::RngCore, PasswordHasher, SaltString},
    Argon2,
};
use base64::prelude::*;

use crate::errors::PassvaultError;
use crate::utils::get_salt_string;

pub struct Crypto {
    pub argon2: Argon2<'static>,
}

impl Crypto {
    pub fn new() -> Self {
        Crypto {
            argon2: Argon2::default(),
        }
    }

    pub fn hash_password(&self, password: &str) -> Result<(String, String), PassvaultError> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| PassvaultError::CryptoError)?;

        Ok((password_hash.to_string(), salt.to_string()))
    }

    pub fn encrypt_password(
        &self,
        password: &str,
        key: &[u8],
    ) -> Result<(String, String), PassvaultError> {
        // key is derived from master password
        // generate random iv
        // init cipher
        // encrypt password into ciphertext
        // return ciphertext and iv

        let mut iv = [0u8; 12];
        OsRng.fill_bytes(&mut iv);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&iv), password.as_bytes())
            .map_err(|_| PassvaultError::CryptoError)?;

        Ok((
            BASE64_STANDARD.encode(ciphertext),
            BASE64_STANDARD.encode(iv),
        ))
    }

    pub fn decrypt_password(
        &self,
        ciphertext: &str,
        iv: &str,
        key: &[u8],
    ) -> Result<String, PassvaultError> {
        // decode ciphertext and iv
        // init cipher
        // decrypt password from ciphertext
        // convert password from bytes to string
        // return password

        let ciphertext = BASE64_STANDARD
            .decode(ciphertext)
            .map_err(|_| PassvaultError::CryptoError)?;
        let iv = BASE64_STANDARD
            .decode(iv)
            .map_err(|_| PassvaultError::CryptoError)?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let password = cipher
            .decrypt(Nonce::from_slice(&iv), ciphertext.as_ref())
            .map_err(|_| PassvaultError::CryptoError)?;

        Ok(String::from_utf8(password).map_err(|_| PassvaultError::CryptoError)?)
    }

    pub fn derive_key(&self, master_password: &str, salt: &str) -> Result<Vec<u8>, PassvaultError> {
        // get salt from db
        // convert to salt string
        // hash master password with salt
        // return key as vec

        let salt = get_salt_string(salt)?;
        let mut key = [0u8; 32];
        self.argon2
            .hash_password_into(
                master_password.as_bytes(),
                salt.as_str().as_bytes(),
                &mut key,
            )
            .map_err(|_| PassvaultError::CryptoError)?;

        Ok(key.to_vec())
    }
}
