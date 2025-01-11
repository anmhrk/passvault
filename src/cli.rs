use clap::{Parser, Subcommand};
use rpassword::read_password;

use crate::errors::PassmanError;
use crate::db::Database;
use crate::crypto::Crypto;

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
    // add copy, delete, update, export
}

pub struct CliHandler {
    db: Database,
    crypto: Crypto,
}

impl CliHandler {
    pub fn new(db_name: &str) -> Result<Self, PassmanError> {
        let db = Database::new(db_name).map_err(|_| PassmanError::DbError)?;
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
        println!("Setup your master password: ");
        let master_password: String = read_password().map_err(|_| PassmanError::ReadInputError)?;
        println!("Confirm your master password: ");
        let master_password_confirm: String = read_password().map_err(|_| PassmanError::ReadInputError)?;
    
        if master_password != master_password_confirm {
            return Err(PassmanError::PasswordMismatchError);
        }

        // hash and save pwd 

        println!("Setup database name: (press enter to use default: passman.db)");
        let mut db_name = String::new();

        std::io::stdin().read_line(&mut db_name).map_err(|_| PassmanError::ReadInputError)?;
        let db_name = db_name.trim();
        let db_name = if db_name.is_empty() {
            "passman.db"
        } else {
            db_name
        };
    
        // init database
        println!("Passman initialized successfully at {}", db_name);
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
