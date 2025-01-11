use clap::{Parser, Subcommand};
use rpassword::read_password;

use crate::crypto::Crypto;
use crate::db::Database;
use crate::errors::PassmanError;

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add {
        website_name: String,
        website_url: Option<String>,
        username: String,
        password: String,
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
            self.verify_master_password()?;
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
        // verify master password
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
