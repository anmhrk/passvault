use clap::{ Parser, Subcommand, ArgAction };

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "A minimal and secure password manager written in Rust",
    long_about = None
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    // Initialize the password vault
    Init,
    // List all stored passwords
    List,
    // Get a specific password entry
    Get {
        // Name of the password entry to retrieve
        name: String,
        // Copy the password to clipboard
        #[arg(short, long, action = ArgAction::SetTrue)]
        copy: bool,
    },
    // Add a new password entry
    Add {
        // Name for the password entry
        name: String,
        // Username for the entry
        #[arg(short, long)]
        username: Option<String>,
        // Password for the entry
        #[arg(short, long)]
        password: Option<String>,
    },
    // Update an existing password entry
    Update {
        // Name of the password entry to update
        name: String,
        // New username for the entry
        #[arg(short, long)]
        username: Option<String>,
        // New password for the entry
        #[arg(short, long)]
        password: Option<String>,
    },
    // Delete a password entry
    Delete {
        // Name of the password entry to delete
        name: String,
    },
    // Export passwords to a file
    Export {
        // Output file path
        #[arg(short, long)]
        output: String,
        // Export format (json, csv)
        #[arg(short, long, default_value = "json")]
        format: String,
    },
    // Change the master password
    ChangeMasterPassword,
    // Reset the database
    Reset,
}
