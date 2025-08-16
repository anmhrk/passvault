mod cli;
mod commands;
mod crypto;
mod db;

use anyhow::Result;
use arboard::Clipboard;
use clap::Parser;
use cli::{ Args, Commands };
use commands::{ PasswordEntry, PasswordVault, prompt_input, prompt_password };

fn main() -> Result<()> {
    let args = Args::parse();

    let mut vault = PasswordVault::new()?;

    match args.command {
        Commands::Init => {
            match vault.initialize() {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        }

        _ => {
            // Check if vault is initialized before running any other commands
            if !vault.is_initialized()? {
                eprintln!("Passvault has not been initialized. Please run 'passvault init'");
                std::process::exit(1);
            }

            // Authenticate user
            match vault.authenticate() {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!("Invalid master password!");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }

            // Now handle the actual commands
            match args.command {
                Commands::Init => unreachable!(), // Already handled above

                Commands::List => {
                    let entries = vault.list()?;
                    if entries.is_empty() {
                        println!("No password entries found.");
                    } else {
                        println!("Stored password entries:");
                        for entry in entries {
                            println!(
                                "  {} ({})",
                                entry.name,
                                entry.username.as_deref().unwrap_or("no username")
                            );
                        }
                    }

                    // TODO: Make this an interactive list where you can browse move up and down and select an entry
                    // to view the password. Also add search and filter capabilities.
                }

                Commands::Get { name, copy } => {
                    if let Some(entry) = vault.get(&name)? {
                        println!("Name: {}", entry.name);
                        if let Some(username) = &entry.username {
                            println!("Username: {}", username);
                        }
                        println!("Password: {}", entry.password);

                        if copy {
                            let mut clipboard = Clipboard::new()?;
                            clipboard.set_text(&entry.password)?;
                            println!("Password copied to clipboard.");
                        }
                    } else {
                        println!("Password entry '{}' not found.", name);
                    }
                }

                Commands::Add { name, username, password } => {
                    let username = if let Some(u) = username {
                        Some(u)
                    } else {
                        let input = prompt_input("Username (optional, press Enter to skip)")?;
                        if input.is_empty() {
                            None
                        } else {
                            Some(input)
                        }
                    };

                    let password = if let Some(p) = password {
                        p
                    } else {
                        prompt_password("Password")?
                    };

                    let entry = PasswordEntry {
                        name: name.clone(),
                        username,
                        password,
                    };

                    vault.add(entry)?;
                    println!("Password entry '{}' added successfully.", name);
                }

                Commands::Update { name, username, password } => {
                    let password = if password.is_some() {
                        password
                    } else {
                        Some(prompt_password("Enter new password")?)
                    };

                    if vault.update(&name, username, password)? {
                        println!("Password entry '{}' updated successfully.", name);
                    } else {
                        println!("Password entry '{}' not found.", name);
                    }
                }

                Commands::Delete { name } => {
                    if vault.delete(&name)? {
                        println!("Password entry '{}' deleted successfully.", name);
                    } else {
                        println!("Password entry '{}' not found.", name);
                    }
                }

                Commands::Export { output, format } => {
                    vault.export(&output, &format)?;
                    println!("Passwords exported to '{}' in {} format.", output, format);
                }

                Commands::ChangeMasterPassword => {
                    let new_master_password = prompt_password("Enter new master password")?;
                    vault.change_master_password(&new_master_password)?;
                    println!("Master password changed successfully!");
                }

                Commands::Reset => {
                    let input = prompt_input(
                        "Are you sure you want to reset Passvault and delete all your passwords? This action cannot be undone. (y/n)"
                    )?;
                    if input == "y" {
                        vault.reset()?;
                    } else {
                        println!("Reset cancelled.");
                    }
                }
            }
        }
    }

    Ok(())
}
