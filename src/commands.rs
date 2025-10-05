use anyhow::{ Result };
use serde::{ Deserialize, Serialize };
use std::fs;
use crate::db::Database;
use crate::crypto::{ PasswordCrypto, PasswordHasher };
use crate::utils::{ prompt_password, prompt_input };
use passwords::PasswordGenerator;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordEntry {
    pub name: String,
    pub username: Option<String>,
    pub password: String,
}
pub struct PasswordVault {
    db: Database,
    crypto: Option<PasswordCrypto>,
}

impl PasswordVault {
    pub fn new() -> Result<Self> {
        let db = Database::new()?;
        Ok(Self {
            db,
            crypto: None,
        })
    }

    pub fn is_initialized(&self) -> Result<bool> {
        self.db.has_master_password()
    }

    pub fn initialize(&mut self) -> Result<()> {
        if self.db.has_master_password()? {
            return Err(anyhow::anyhow!("Passvault is already initialized"));
        }

        println!("Setting up your master password...");
        let new_master_password = prompt_password("Enter your master password")?;
        let hasher = PasswordHasher::new();
        let (hash, salt) = hasher.hash_password(&new_master_password)?;
        self.db.set_master_password(&hash, &salt)?;
        println!("Master password created successfully!");
        println!("Passvault has been initialized.");
        Ok(())
    }

    pub fn authenticate(&mut self) -> Result<bool> {
        let master_password = prompt_password("Enter your master password")?;
        if let Some((stored_hash, salt)) = self.db.get_master_password_hash()? {
            let hasher = PasswordHasher::new();
            if hasher.verify_password(&master_password, &stored_hash)? {
                self.crypto = Some(PasswordCrypto::new(&master_password, &salt)?);
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Err(anyhow::anyhow!("Master password verification failed"))
        }
    }

    pub fn list(&self) -> Result<Vec<PasswordEntry>> {
        let crypto = self.crypto.as_ref().ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;
        let db_entries = self.db.list_password_entries()?;

        let mut entries = Vec::new();
        for db_entry in db_entries {
            let decrypted_password = crypto.decrypt(&db_entry.encrypted_password, &db_entry.nonce)?;
            entries.push(PasswordEntry {
                name: db_entry.name,
                username: db_entry.username,
                password: decrypted_password,
            });
        }

        Ok(entries)
    }

    pub fn get(&self, name: &str) -> Result<Option<PasswordEntry>> {
        let crypto = self.crypto.as_ref().ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

        if let Some(db_entry) = self.db.get_password_entry(name)? {
            let decrypted_password = crypto.decrypt(&db_entry.encrypted_password, &db_entry.nonce)?;
            Ok(
                Some(PasswordEntry {
                    name: db_entry.name,
                    username: db_entry.username,
                    password: decrypted_password,
                })
            )
        } else {
            Ok(None)
        }
    }

    pub fn add(&self, entry: PasswordEntry) -> Result<()> {
        let crypto = self.crypto.as_ref().ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

        let (encrypted_password, nonce) = crypto.encrypt(&entry.password)?;
        self.db.insert_password_entry(
            &entry.name,
            entry.username.as_deref(),
            &encrypted_password,
            None,
            &nonce
        )?;

        Ok(())
    }

    pub fn update(
        &self,
        name: &str,
        username: Option<String>,
        password: Option<String>
    ) -> Result<bool> {
        let crypto = self.crypto.as_ref().ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

        let (encrypted_password, nonce) = if let Some(ref pwd) = password {
            let (enc, n) = crypto.encrypt(pwd)?;
            (Some(enc), Some(n))
        } else {
            (None, None)
        };

        self.db.update_password_entry(
            name,
            username.as_deref(),
            encrypted_password.as_deref(),
            None,
            nonce.as_deref()
        )
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        self.db.delete_password_entry(name)
    }

    pub fn export(&self, output_path: &str, format: &str) -> Result<()> {
        let entries = self.list()?;

        match format.to_lowercase().as_str() {
            "json" => {
                let content = serde_json::to_string_pretty(&entries)?;
                std::fs::write(output_path, content)?;
            }
            "csv" => {
                let mut writer = csv::Writer::from_path(output_path)?;
                writer.write_record(["name", "username", "password"])?;

                for entry in entries {
                    writer.write_record([
                        &entry.name,
                        entry.username.as_deref().unwrap_or(""),
                        &entry.password,
                    ])?;
                }
                writer.flush()?;
            }
            _ => {
                return Err(anyhow::anyhow!("Unsupported format: {}", format));
            }
        }
        Ok(())
    }

    pub fn change_master_password(&mut self, new_master_password: &str) -> Result<()> {
        // Get all password entries first (while we still have access to decrypt them)
        let entries = self.list()?;

        // Hash the new master password and update the database
        let hasher = PasswordHasher::new();
        let (new_hash, new_salt) = hasher.hash_password(new_master_password)?;
        self.db.update_master_password(&new_hash, &new_salt)?;

        // Create new crypto instance with the new master password
        let new_crypto = PasswordCrypto::new(new_master_password, &new_salt)?;

        // Re-encrypt all existing passwords with the new master password
        for entry in entries {
            let (encrypted_password, nonce) = new_crypto.encrypt(&entry.password)?;
            self.db.insert_password_entry(
                &entry.name,
                entry.username.as_deref(),
                &encrypted_password,
                None,
                &nonce
            )?;
        }

        self.crypto = Some(new_crypto);

        Ok(())
    }

    pub fn reset(&self) -> Result<()> {
        let home_dir = dirs
            ::home_dir()
            .ok_or_else(|| anyhow::anyhow!("Unable to find home directory"))?;
        let vault_dir = home_dir.join(".passvault");

        if vault_dir.exists() {
            fs::remove_dir_all(&vault_dir)?;
            println!("Passvault database has been reset. Run 'passvault init' to reinitialize.");
        } else {
            return Err(anyhow::anyhow!("Passvault directory not found."));
        }

        Ok(())
    }

    pub fn prompt_generate_password(&self) -> Result<Option<String>> {
        let response = prompt_input("Generate a password? (y/n)")?;

        if response.to_lowercase() != "y" {
            return Ok(None);
        }

        let password = self.generate_password()?;
        println!("\nGenerated password: {}", password);

        Ok(Some(password))
    }

    fn generate_password(&self) -> Result<String> {
        // Use sane defaults: 20 characters with uppercase, lowercase, numbers, and symbols
        let pg = PasswordGenerator {
            length: 20,
            numbers: true,
            lowercase_letters: true,
            uppercase_letters: true,
            symbols: true,
            spaces: false,
            exclude_similar_characters: true,
            strict: true,
        };

        let password = pg
            .generate_one()
            .map_err(|e| anyhow::anyhow!("Failed to generate password: {}", e))?;

        Ok(password)
    }
}
