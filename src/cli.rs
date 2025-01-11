use argon2::password_hash::PasswordHasher;
use clap::{Parser, Subcommand};
use rpassword::read_password;

use crate::crypto::Crypto;
use crate::db::Database;
use crate::errors::PassmanError;
use crate::utils::{get_salt_string, is_session_expired};

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add {
        website_name: Option<String>,
    },
    List {
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
        // only verify master password if not initializing
        if !matches!(cli.command, Commands::Init) {
            if is_session_expired(
                &self
                    .db
                    .get_last_access()
                    .map_err(|_| PassmanError::GetDbError)?,
            ) {
                self.verify_master_password()?;
            }
        }

        match cli.command {
            Commands::Init => self.handle_init(),
            Commands::Add { .. } => self.handle_add(),
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

        println!("Passman initialized successfully. Run `passman add` to add your first password.");
        Ok(())
    }

    fn verify_master_password(&self) -> Result<(), PassmanError> {
        // get salt and hash from db
        // generate hash from input and salt
        // compare hash
        // return ok or error

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
            .map_err(|_| PassmanError::HashPasswordError)?;

        if hash.to_string() != stored_hash {
            return Err(PassmanError::PasswordMismatchError);
        }

        self.db
            .update_last_access()
            .map_err(|_| PassmanError::UpdateDbError)?;

        Ok(())
    }

    fn handle_add(&self) -> Result<(), PassmanError> {
        // add a new password
        Ok(())
    }

    fn handle_list(&self) -> Result<(), PassmanError> {
        // list all passwords or requested website
        Ok(())
    }
}
