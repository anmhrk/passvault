# Passvault

Passvault is a minimal and secure CLI based password manager written in Rust. All passwords are securely encrypted and stored locally in a SQLite database.

## Key libraries/features

- Argon2 for password hashing and verification
- AES-GCM for password encryption and decryption using master password as key
- rpassword for secure password input
- clap library for the CLI
- rusqlite to interact with the SQLite database
- arboard for clipboard integration
- passwords for secure password generation
- zxcvbn for password strength checking

## Usage

### Pre-requisites

- Make sure you have [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) and [Rust](https://rust-lang.org/learn/get-started/) installed.

### Installation

```bash
cargo install passvault
```

### Local development

1. Clone the repository

```bash
git clone https://github.com/anmhrk/passvault.git
cd passvault
```

2. Install dependencies

```bash
cargo install --path .
```

3. Run the application

```bash
cargo run init # Initialize the password vault
```

### Commands available

```
passvault init                                  # Initialize the password vault
passvault list                                  # List all stored passwords
passvault get <name>                            # Get a specific password entry (optional -c flag to copy to clipboard)
passvault add <name> <username> <password>      # Add a new password entry
passvault update <name> <username> <password>   # Update an existing password entry
passvault delete <name>                         # Delete a password entry
passvault audit                                 # Audit all passwords and check their strength
passvault export <output> <format>              # Export passwords to a file
passvault change-master-password                # Change the master password
passvault reset                                 # Reset the database
```