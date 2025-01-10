use clap::{Parser, Subcommand};
use rpassword::read_password;
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
    // add copy, delete, update, export
}

fn handle_init() -> Result<(), PassmanError> {
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
