use clap::{Parser, Subcommand};
use rpassword::read_password;

use crate::errors::PassmanError;
use crate::db::Database;

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
}

impl CliHandler {
    pub fn new(db_path: &str) -> Result<Self, PassmanError> {
        let db = Database::new(db_path).map_err(|_| PassmanError::DbError)?;
        Ok(CliHandler { db })
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
        // init database
    
        println!("Welcome to Passman! Please setup your master password: ");
        let master_password: String = read_password().map_err(|_| PassmanError::AuthError)?;
        println!("Please confirm your master password: ");
        let master_password_confirm: String = read_password().map_err(|_| PassmanError::AuthError)?;
    
        if master_password != master_password_confirm {
            return Err(PassmanError::AuthError);
        }
    
        // hash and save pwd 
        println!("Passman initialized successfully");
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
