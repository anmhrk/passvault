use argon2::password_hash::PasswordHasher;
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use keyring::Entry;
use rpassword::read_password;
use serde::{Deserialize, Serialize};

use crate::crypto::Crypto;
use crate::db::Database;
use crate::errors::PassmanError;
use crate::utils::{get_salt_string, is_session_expired, read_line};

#[derive(Serialize, Deserialize)]
struct CachedKey {
    key: Vec<u8>,
    timestamp: DateTime<Utc>,
}

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add,
    List {
        website_name: Option<String>, // if not provided, list all
    },
    // add copy, delete, update, export, reset, update master password
}

pub struct CliHandler {
    db: Database,
    crypto: Crypto,
    keyring: Entry,
}

impl CliHandler {
    pub fn new(db_path: &str) -> Result<Self, PassmanError> {
        let db = Database::new(db_path).map_err(|_| PassmanError::InitDbError)?;
        let crypto = Crypto::new();
        let keyring =
            Entry::new("passman", "cached_key").map_err(|_| PassmanError::SessionCacheError)?;

        Ok(CliHandler {
            db,
            crypto,
            keyring,
        })
    }

    pub fn handle_command(&self, cli: Cli) -> Result<(), PassmanError> {
        // first check if db is initialized before running any commands
        // also once initialized, don't allow init command
        if !self.db.check_if_initialized() && !matches!(cli.command, Commands::Init) {
            return Err(PassmanError::DbNotInitializedError);
        } else if self.db.check_if_initialized() && matches!(cli.command, Commands::Init) {
            return Err(PassmanError::DbAlreadyInitializedError);
        }

        let mut key = Vec::new();

        if !matches!(cli.command, Commands::Init) {
            key = self.get_cached_key()?;
        }

        match cli.command {
            Commands::Init => self.handle_init(),
            Commands::Add => self.handle_add(&key),
            Commands::List { .. } => self.handle_list(&cli, &key),
        }
    }

    fn handle_init(&self) -> Result<(), PassmanError> {
        println!("Welcome to Passman!");
        println!("Setup your master password: ");
        let master_password: String = read_password().map_err(|_| PassmanError::ReadInputError)?;
        println!("Confirm your master password: ");
        let master_password_confirm: String =
            read_password().map_err(|_| PassmanError::ReadInputError)?;

        if master_password != master_password_confirm {
            return Err(PassmanError::PasswordMismatchError);
        }

        // init db tables
        self.db.init().map_err(|_| PassmanError::InitDbError)?;

        let (hash, salt) = self.crypto.hash_password(&master_password)?;
        self.db
            .store_master_password(&hash, &salt)
            .map_err(|_| PassmanError::StoreDbError)?;

        println!("Master password has been set. Make sure to remember it!");
        println!("Run `passman add` to add your first password.");
        Ok(())
    }

    fn verify_master_password(&self) -> Result<Vec<u8>, PassmanError> {
        // get salt and hash from db
        // generate hash from input and salt
        // compare hash
        // return ok or error
        // update last access

        println!("Enter your master password first: ");
        let master_password: String = read_password().map_err(|_| PassmanError::ReadInputError)?;

        let (salt, stored_hash) = self
            .db
            .get_master_salt_and_hash()
            .map_err(|_| PassmanError::GetDbError)?;
        let salt_string = get_salt_string(&salt)?;
        let hash = self
            .crypto
            .argon2
            .hash_password(master_password.as_bytes(), &salt_string)
            .map_err(|_| PassmanError::CryptoError)?;

        if hash.to_string() != stored_hash {
            return Err(PassmanError::PasswordMismatchError);
        }

        // derive key and cache it. cached key will be used for all other commands until it expires
        // more on cache logic in get_cached_key()
        let key = self.crypto.derive_key(&master_password, &salt)?;
        let cached_key = CachedKey {
            key: key.clone(),
            timestamp: Utc::now(),
        };
        let cached_key_str =
            serde_json::to_string(&cached_key).map_err(|_| PassmanError::SessionCacheError)?;

        self.keyring
            .set_password(&cached_key_str)
            .map_err(|_| PassmanError::SessionCacheError)?;

        Ok(key)
    }

    fn get_cached_key(&self) -> Result<Vec<u8>, PassmanError> {
        // if cached key exists and is not expired, return it
        // if cached key is expired, run verify_master_password() which will update cached key

        match self.keyring.get_password() {
            Ok(cached_key_str) => {
                let cached_key: CachedKey = serde_json::from_str(&cached_key_str)
                    .map_err(|_| PassmanError::SessionCacheError)?;

                if !is_session_expired(&cached_key.timestamp) {
                    return Ok(cached_key.key);
                }
            }
            Err(_) => {}
        }

        // this will either make new cached key or update timestamp of existing cached key
        self.verify_master_password()
    }

    fn handle_add(&self, key: &Vec<u8>) -> Result<(), PassmanError> {
        println!("Website Name: ");
        let website_name: String = read_line().map_err(|_| PassmanError::ReadInputError)?;
        let website_name = website_name.trim().to_lowercase();

        println!("Website URL: (optional, press enter to skip)");
        let website_url: String = read_line().map_err(|_| PassmanError::ReadInputError)?;

        println!("Username: ");
        let username: String = read_line().map_err(|_| PassmanError::ReadInputError)?;

        println!("Password: ");
        let password: String = read_password().map_err(|_| PassmanError::ReadInputError)?;

        let (ciphertext, iv) = self.crypto.encrypt_password(&password, &key)?;
        self.db
            .add_password(&website_name, &username, &ciphertext, &iv, &website_url)
            .map_err(|_| PassmanError::StoreDbError)?;

        println!("Password added successfully.");
        Ok(())
    }

    fn handle_list(&self, cli: &Cli, key: &Vec<u8>) -> Result<(), PassmanError> {
        if let Commands::List { website_name } = &cli.command {
            if let Some(website_name) = website_name {
                let (username, ciphertext, iv) = self
                    .db
                    .get_password(&website_name)
                    .map_err(|_| PassmanError::WebsiteNotFoundError)?;
                let password = self.crypto.decrypt_password(&ciphertext, &iv, &key)?;

                println!("Website: {}", website_name);
                println!("Username: {}", username);
                println!("Password: {}", password);
            } else {
                let website_names = self
                    .db
                    .list_passwords()
                    .map_err(|_| PassmanError::GetDbError)?;

                if website_names.is_empty() {
                    println!("No websites found. Run `passman add` to add your first website.");
                } else {
                    println!("Here are all of your stored websites:");
                    for website_name in website_names {
                        println!("{}", website_name);
                    }

                    println!();
                    println!(
                        "Run `passman list <website_name>` to get the credentials for a specific website."
                    );
                }
            }
        }

        Ok(())
    }
}
