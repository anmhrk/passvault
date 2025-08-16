use aes_gcm::{ aead::{ Aead, AeadCore, KeyInit, OsRng }, Aes256Gcm, Key, Nonce };
use anyhow::Result;
use argon2::{
    Argon2,
    PasswordHash,
    PasswordHasher as ArgonPasswordHasher,
    PasswordVerifier,
    password_hash::SaltString,
};
use base64::prelude::*;

pub struct PasswordHasher {
    argon2: Argon2<'static>,
}

impl PasswordHasher {
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }

    pub fn hash_password(&self, password: &str) -> Result<(String, String)> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = ArgonPasswordHasher::hash_password(
            &self.argon2,
            password.as_bytes(),
            &salt
        ).map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

        Ok((password_hash.to_string(), salt.to_string()))
    }

    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash).map_err(|e|
            anyhow::anyhow!("Failed to parse password hash: {}", e)
        )?;

        match self.argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

pub struct PasswordCrypto {
    cipher: Aes256Gcm,
}

impl PasswordCrypto {
    pub fn new(master_password: &str, salt: &str) -> Result<Self> {
        let key = derive_key_from_master(master_password, salt)?;
        let cipher = Aes256Gcm::new(&key);
        Ok(Self { cipher })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<(String, String)> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let encrypted_base64 = BASE64_STANDARD.encode(&ciphertext);
        let nonce_base64 = BASE64_STANDARD.encode(nonce);

        Ok((encrypted_base64, nonce_base64))
    }

    pub fn decrypt(&self, encrypted_base64: &str, nonce_base64: &str) -> Result<String> {
        let ciphertext = BASE64_STANDARD.decode(encrypted_base64).map_err(|e|
            anyhow::anyhow!("Failed to decode ciphertext: {}", e)
        )?;

        let nonce_bytes = BASE64_STANDARD.decode(nonce_base64).map_err(|e|
            anyhow::anyhow!("Failed to decode nonce: {}", e)
        )?;

        if nonce_bytes.len() != 12 {
            return Err(anyhow::anyhow!("Invalid nonce length"));
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = self.cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        String::from_utf8(plaintext).map_err(|e|
            anyhow::anyhow!("Failed to convert decrypted data to string: {}", e)
        )
    }
}

fn derive_key_from_master(password: &str, salt: &str) -> Result<Key<Aes256Gcm>> {
    let mut key = [0u8; 32];
    argon2::Argon2
        ::default()
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key)
        .map_err(|e| anyhow::anyhow!("Failed to derive key: {}", e))?;

    Ok(*Key::<Aes256Gcm>::from_slice(&key))
}
