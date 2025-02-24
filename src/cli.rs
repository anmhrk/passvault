use arboard::Clipboard;
use argon2::password_hash::PasswordHasher;
use clap::{Parser, Subcommand};
use csv::Writer;
use dialoguer::{theme::ColorfulTheme, Select};
use rpassword::read_password;
use std::fs::File;
use std::path::PathBuf;

use crate::crypto::Crypto;
use crate::db::Database;
use crate::errors::PassvaultError;
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
    pub fn new(db_path: &PathBuf) -> Result<Self, PassvaultError> {
        let db = Database::new(db_path).map_err(|_| PassvaultError::InitDbError)?;
        let crypto = Crypto::new();

        Ok(CliHandler { db, crypto })
    }

    pub fn handle_command(&self, cli: Cli) -> Result<(), PassvaultError> {
        // first check if db is initialized before running any commands
        // also once initialized, don't allow init command
        if !self.db.check_if_initialized() && !matches!(cli.command, Commands::Init) {
            return Err(PassvaultError::DbNotInitializedError);
        } else if self.db.check_if_initialized() && matches!(cli.command, Commands::Init) {
            return Err(PassvaultError::DbAlreadyInitializedError);
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
            Commands::Reset => self.handle_reset(),
            Commands::Export => self.handle_export(&key),
        }
    }

    fn handle_init(&self) -> Result<(), PassvaultError> {
        println!("Welcome to Passvault! 🔒");
        println!("Setup your master password: ");
        let master_password: String =
            read_password().map_err(|_| PassvaultError::ReadInputError)?;
        println!("Confirm your master password: ");
        let master_password_confirm: String =
            read_password().map_err(|_| PassvaultError::ReadInputError)?;

        if master_password != master_password_confirm {
            return Err(PassvaultError::PasswordMismatchError);
        }

        // init db tables
        self.db.init().map_err(|_| PassvaultError::InitDbError)?;

        let (hash, salt) = self.crypto.hash_password(&master_password)?;
        self.db
            .store_master_password(&hash, &salt)
            .map_err(|_| PassvaultError::StoreDbError)?;

        println!("Master password has been set. Make sure to remember it!");
        println!("Run `passvault add` to add your first password.");
        Ok(())
    }

    fn verify_master_password(&self) -> Result<Vec<u8>, PassvaultError> {
        // get salt and hash from db
        // generate hash from input and salt
        // compare hash
        // if match, derive key and return

        println!("Enter your master password first: ");
        let master_password: String =
            read_password().map_err(|_| PassvaultError::ReadInputError)?;

        let (salt, stored_hash) = self
            .db
            .get_master_salt_and_hash()
            .map_err(|_| PassvaultError::GetDbError)?;
        let salt_string = get_salt_string(&salt)?;
        let hash = self
            .crypto
            .argon2
            .hash_password(master_password.as_bytes(), &salt_string)
            .map_err(|_| PassvaultError::CryptoError)?;

        if hash.to_string() != stored_hash {
            return Err(PassvaultError::WrongMasterPasswordError);
        }

        let key = self.crypto.derive_key(&master_password, &salt)?;
        Ok(key)
    }

    fn handle_add(&self, key: &Vec<u8>) -> Result<(), PassvaultError> {
        println!("Website Name: ");
        let website_name: String = read_line().map_err(|_| PassvaultError::ReadInputError)?;

        if self.db.check_if_password_exists(&website_name) {
            return Err(PassvaultError::WebsiteAlreadyExistsError);
        }

        println!("Username: ");
        let username: String = read_line().map_err(|_| PassvaultError::ReadInputError)?;

        println!("Password: ");
        let password: String = read_password().map_err(|_| PassvaultError::ReadInputError)?;

        let (ciphertext, iv) = self.crypto.encrypt_password(&password, &key)?;
        self.db
            .add_password(&website_name, &username, &ciphertext, &iv)
            .map_err(|_| PassvaultError::StoreDbError)?;

        println!("Password added successfully.");
        Ok(())
    }

    fn display_website_names(
        &self,
        website_names: Vec<(String, String, String, String)>,
        key: &Vec<u8>,
        prompt: &str,
    ) -> Result<(String, String, String), PassvaultError> {
        let names: Vec<&String> = website_names.iter().map(|(name, _, _, _)| name).collect();
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt(prompt)
            .items(&names)
            .default(0)
            .interact()
            .map_err(|_| PassvaultError::ReadInputError)?;

        let (name, username, ciphertext, iv) = &website_names[selection];
        let password = self.crypto.decrypt_password(&ciphertext, &iv, &key)?;

        // return relevant info for list_options
        Ok((name.clone(), username.clone(), password))
    }

    fn handle_list_options(
        &self,
        website: &str,
        username: &str,
        password: &str,
        key: &Vec<u8>,
    ) -> Result<(), PassvaultError> {
        let options = vec![
            "Display credentials",
            "Copy password to clipboard",
            "Update credentials",
            "Delete password",
            "Exit",
        ];
        let selection = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("What would you like to do?")
            .items(&options)
            .default(0)
            .interact()
            .map_err(|_| PassvaultError::ReadInputError)?;

        match selection {
            0 => {
                println!("Website: {}", website);
                println!("Username: {}", username);
                println!("Password: {}", password);
            }
            1 => {
                let mut clipboard = Clipboard::new().map_err(|_| PassvaultError::ClipboardError)?;
                clipboard
                    .set_text(password)
                    .map_err(|_| PassvaultError::ClipboardError)?;

                println!("Password copied to clipboard.");
                println!("Press enter to clear clipboard.");
                read_line().map_err(|_| PassvaultError::ReadInputError)?;

                if let Ok(current_text) = clipboard.get_text() {
                    if current_text == password {
                        clipboard
                            .set_text("")
                            .map_err(|_| PassvaultError::ClipboardError)?;
                        println!("Successfully cleared clipboard.");
                    } else {
                        return Err(PassvaultError::ClipboardError);
                    }
                } else {
                    return Err(PassvaultError::ClipboardError);
                }
            }
            2 => {
                let update_selection = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("What would you like to update?")
                    .items(&["Username", "Password", "Exit"])
                    .default(0)
                    .interact()
                    .map_err(|_| PassvaultError::ReadInputError)?;

                match update_selection {
                    0 => {
                        println!("Enter new username: ");
                        let new_username: String =
                            read_line().map_err(|_| PassvaultError::ReadInputError)?;
                        self.db
                            .update_password(website, Some(&new_username), None, None)
                            .map_err(|_| PassvaultError::UpdateDbError)?;
                        println!("Username updated successfully.");
                    }
                    1 => {
                        println!("Enter new password: ");
                        let new_password: String =
                            read_password().map_err(|_| PassvaultError::ReadInputError)?;
                        let (ciphertext, iv) = self.crypto.encrypt_password(&new_password, &key)?;
                        self.db
                            .update_password(website, None, Some(&ciphertext), Some(&iv))
                            .map_err(|_| PassvaultError::UpdateDbError)?;
                        println!("Password updated successfully.");
                    }
                    _ => {}
                }
            }
            3 => {
                self.db
                    .delete_password(website)
                    .map_err(|_| PassvaultError::DeleteDbError)?;
                println!("Password deleted successfully.");
            }
            _ => {}
        }

        Ok(())
    }

    fn handle_list(&self, cli: &Cli, key: &Vec<u8>) -> Result<(), PassvaultError> {
        if let Commands::List { website_name } = &cli.command {
            if let Some(website_name) = website_name {
                let results = self
                    .db
                    .list_passwords(Some(&website_name))
                    .map_err(|_| PassvaultError::GetDbError)?;

                if results.is_empty() {
                    return Err(PassvaultError::WebsiteNotFoundError);
                }

                if results.len() == 1 {
                    let (website, username, ciphertext, iv) = results.first().unwrap();
                    let password = self.crypto.decrypt_password(&ciphertext, &iv, &key)?;
                    self.handle_list_options(&website, &username, &password, &key)?;
                } else {
                    let (name, username, password) = self.display_website_names(
                        results,
                        key,
                        "Multiple matches found. Select one:",
                    )?;
                    self.handle_list_options(&name, &username, &password, &key)?;
                }
            } else {
                let website_names = self
                    .db
                    .list_passwords(None)
                    .map_err(|_| PassvaultError::GetDbError)?;

                if website_names.is_empty() {
                    println!("No websites found. Run `passvault add` to add your first website.");
                } else {
                    let (name, username, password) = self.display_website_names(
                        website_names,
                        key,
                        "Here are all of your stored websites. Select one:",
                    )?;
                    self.handle_list_options(&name, &username, &password, &key)?;
                }
            }
        }

        Ok(())
    }

    fn handle_reset(&self) -> Result<(), PassvaultError> {
        println!("Are you sure you want to reset the database? This action is irreversible.");
        println!("Enter 'reset' to confirm: ");
        let confirmation: String = read_line().map_err(|_| PassvaultError::ReadInputError)?;

        if confirmation != "reset" {
            return Err(PassvaultError::ResetDbError);
        }

        self.db
            .reset_database()
            .map_err(|_| PassvaultError::ResetDbError)?;

        println!("Database reset successfully.");
        println!("Run `passvault init` to start over.");
        Ok(())
    }

    fn handle_export(&self, key: &Vec<u8>) -> Result<(), PassvaultError> {
        println!("Give your desired export file name: ");
        let export_file_name: String = read_line().map_err(|_| PassvaultError::ReadInputError)?;
        let export_file_path = format!("{}.csv", export_file_name);
        println!("Exporting passwords...");

        let file = File::create(&export_file_path).map_err(|_| PassvaultError::ExportFileError)?;
        let mut writer = Writer::from_writer(file);

        writer
            .write_record(&["Website", "Username", "Password"])
            .map_err(|_| PassvaultError::ExportFileError)?;

        let passwords = self
            .db
            .list_passwords(None)
            .map_err(|_| PassvaultError::GetDbError)?;

        for (website, username, ciphertext, iv) in passwords {
            let password = self.crypto.decrypt_password(&ciphertext, &iv, &key)?;
            writer
                .write_record(&[website, username, password])
                .map_err(|_| PassvaultError::ExportFileError)?;
        }

        writer
            .flush()
            .map_err(|_| PassvaultError::ExportFileError)?;

        println!("Passwords exported successfully.");
        println!(
            "File saved at: {} in the current directory.",
            &export_file_path
        );

        Ok(())
    }
}
