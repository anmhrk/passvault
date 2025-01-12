use argon2::password_hash::PasswordHasher;
use clap::{Parser, Subcommand};
use rpassword::read_password;

use crate::crypto::Crypto;
use crate::db::Database;
use crate::errors::PassmanError;
use crate::utils::{get_salt_string, is_session_expired, read_line};

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
        #[arg(short)]
        website_name: Option<String>, // if not provided, list all
    },
    // add copy, delete, update, export, reset, update master password
}

pub struct CliHandler {
    db: Database,
    crypto: Crypto,
}

impl CliHandler {
    pub fn new(db_name: &str) -> Result<Self, PassmanError> {
        let db = Database::new(db_name).map_err(|_| PassmanError::InitDbError)?;
        let crypto = Crypto::new();
        Ok(CliHandler { db, crypto })
    }

    pub fn handle_command(&self, cli: Cli) -> Result<(), PassmanError> {
        let mut key = None;

        // only verify master password if not initializing
        if !matches!(cli.command, Commands::Init) {
            if is_session_expired(
                &self
                    .db
                    .get_last_access()
                    .map_err(|_| PassmanError::GetDbError)?,
            ) {
                key = self.verify_master_password()?;
            }
        }

        match cli.command {
            Commands::Init => self.handle_init(),
            Commands::Add => self.handle_add(key),
            Commands::List { .. } => self.handle_list(),
        }
    }

    fn handle_init(&self) -> Result<(), PassmanError> {
        println!("Welcome to Passman!");

        // init db tables
        self.db.init().map_err(|_| PassmanError::InitDbError)?;

        println!("Setup your master password: ");
        let master_password: String = read_password().map_err(|_| PassmanError::ReadInputError)?;
        println!("Confirm your master password: ");
        let master_password_confirm: String =
            read_password().map_err(|_| PassmanError::ReadInputError)?;

        if master_password != master_password_confirm {
            return Err(PassmanError::PasswordMismatchError);
        }

        let (hash, salt) = self.crypto.hash_password(&master_password)?;
        self.db
            .store_master_password(&hash, &salt)
            .map_err(|_| PassmanError::StoreDbError)?;

        println!("Master password has been set. Make sure to remember it!");
        println!("Passman initialized successfully. Run `passman add` to add your first password.");
        Ok(())
    }

    fn verify_master_password(&self) -> Result<Option<Vec<u8>>, PassmanError> {
        // get salt and hash from db
        // generate hash from input and salt
        // compare hash
        // return ok or error
        // update last access
        // return derived key

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

        self.db
            .update_last_access()
            .map_err(|_| PassmanError::UpdateDbError)?;

        let key = self.crypto.derive_key(&master_password, &salt)?;
        Ok(Some(key))
    }

    fn handle_add(&self, key: Option<Vec<u8>>) -> Result<(), PassmanError> {
        println!("Title/Website Name: ");
        let title: String = read_line().map_err(|_| PassmanError::ReadInputError)?;

        println!("Website URL: (optional, press enter to skip)");
        let website_url: String = read_line().map_err(|_| PassmanError::ReadInputError)?;

        println!("Username: ");
        let username: String = read_line().map_err(|_| PassmanError::ReadInputError)?;

        println!("Password: ");
        let password: String = read_password().map_err(|_| PassmanError::ReadInputError)?;

        if let Some(key) = key {
            let (ciphertext, iv) = self.crypto.encrypt_password(&password, &key)?;
            self.db
                .add_password(&title, &username, &ciphertext, &iv, &website_url)
                .map_err(|_| PassmanError::StoreDbError)?;
        }

        println!("Password added successfully.");
        Ok(())
    }

    fn handle_list(&self) -> Result<(), PassmanError> {
        println!("Here are all of your stored passwords:");
        let passwords = self
            .db
            .list_passwords()
            .map_err(|_| PassmanError::GetDbError)?;

        for password in passwords {
            println!("{}", password);
        }

        println!();
        println!("Run `passman list <website_name>` to get the password for a specific website.");
        Ok(())
    }
}
