use arboard::Clipboard;
use argon2::password_hash::PasswordHasher;
use clap::{Parser, Subcommand};
use dialoguer::{theme::ColorfulTheme, Select};
use rpassword::read_password;

use crate::crypto::Crypto;
use crate::db::Database;
use crate::errors::PassmanError;
use crate::utils::{get_salt_string, read_line};

#[derive(Parser)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Add,
    List { website_name: Option<String> },
    Reset,
    Export,
}
pub struct CliHandler {
    db: Database,
    crypto: Crypto,
}

impl CliHandler {
    pub fn new(db_path: &str) -> Result<Self, PassmanError> {
        let db = Database::new(db_path).map_err(|_| PassmanError::InitDbError)?;
        let crypto = Crypto::new();

        Ok(CliHandler { db, crypto })
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

        // verify master password if not init
        if !matches!(cli.command, Commands::Init) {
            key = self.verify_master_password()?;
        }

        match cli.command {
            Commands::Init => self.handle_init(),
            Commands::Add => self.handle_add(&key),
            Commands::List { .. } => self.handle_list(&cli, &key),
            Commands::Reset => self.handle_reset(&key),
            Commands::Export => self.handle_export(&key),
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
        // if match, derive key and return

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
            return Err(PassmanError::WrongMasterPasswordError);
        }

        let key = self.crypto.derive_key(&master_password, &salt)?;
        Ok(key)
    }

    fn handle_add(&self, key: &Vec<u8>) -> Result<(), PassmanError> {
        println!("Website Name: ");
        let website_name: String = read_line().map_err(|_| PassmanError::ReadInputError)?;

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

    fn display_website_names(
        &self,
        website_names: Vec<(String, String, String, String)>,
        key: &Vec<u8>,
        prompt: &str,
    ) -> Result<(String, String, String), PassmanError> {
        let names: Vec<&String> = website_names.iter().map(|(name, _, _, _)| name).collect();
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(&names)
            .default(0)
            .interact()
            .map_err(|_| PassmanError::ReadInputError)?;

        let (name, username, ciphertext, iv) = &website_names[selection];
        let password = self.crypto.decrypt_password(&ciphertext, &iv, &key)?;
        Ok((name.clone(), username.clone(), password))
    }

    fn handle_list_options(
        &self,
        website: &str,
        username: &str,
        password: &str,
        key: &Vec<u8>,
    ) -> Result<(), PassmanError> {
        let options = vec![
            "Display credentials",
            "Copy password to clipboard",
            "Update",
            "Delete",
            "Exit",
        ];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .items(&options)
            .default(0)
            .interact()
            .map_err(|_| PassmanError::ReadInputError)?;

        match selection {
            0 => {
                println!("Website: {}", website);
                println!("Username: {}", username);
                println!("Password: {}", password);
            }
            1 => {
                let mut clipboard = Clipboard::new().map_err(|_| PassmanError::ClipboardError)?;
                clipboard
                    .set_text(password)
                    .map_err(|_| PassmanError::ClipboardError)?;

                println!("Password copied to clipboard.");
                println!("Press enter to clear clipboard.");
                read_line().map_err(|_| PassmanError::ReadInputError)?;

                if let Ok(current_text) = clipboard.get_text() {
                    if current_text == password {
                        clipboard
                            .set_text("")
                            .map_err(|_| PassmanError::ClipboardError)?;
                        println!("Clipboard cleared.");
                    } else {
                        println!("Clipboard content has changed. Not clearing.");
                    }
                } else {
                    return Err(PassmanError::ClipboardError);
                }
            }
            2 => {
                // update
            }
            3 => {
                // delete
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_list(&self, cli: &Cli, key: &Vec<u8>) -> Result<(), PassmanError> {
        if let Commands::List { website_name } = &cli.command {
            if let Some(website_name) = website_name {
                let results = self
                    .db
                    .list_passwords(Some(&website_name))
                    .map_err(|_| PassmanError::GetDbError)?;

                if results.is_empty() {
                    return Err(PassmanError::WebsiteNotFoundError);
                }

                if results.len() == 1 {
                    let (website, username, ciphertext, iv) = results.first().unwrap();
                    let password = self.crypto.decrypt_password(&ciphertext, &iv, &key)?;
                    self.handle_list_options(&website, &username, &password, key)?;
                } else {
                    let (name, username, password) = self.display_website_names(
                        results,
                        key,
                        "Multiple matches found. Select one:",
                    )?;
                    self.handle_list_options(&name, &username, &password, key)?;
                }
            } else {
                let website_names = self
                    .db
                    .list_passwords(None)
                    .map_err(|_| PassmanError::GetDbError)?;

                if website_names.is_empty() {
                    println!("No websites found. Run `passman add` to add your first website.");
                } else {
                    let (name, username, password) = self.display_website_names(
                        website_names,
                        key,
                        "Here are all of your stored websites. Select one:",
                    )?;
                    self.handle_list_options(&name, &username, &password, key)?;
                }
            }
        }

        Ok(())
    }

    fn handle_reset(&self, key: &Vec<u8>) -> Result<(), PassmanError> {
        Ok(())
    }

    fn handle_export(&self, key: &Vec<u8>) -> Result<(), PassmanError> {
        Ok(())
    }
}
