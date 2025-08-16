# Passvault

Passvault is a minimal and secure password manager written in Rust. All passwords are securely encrypted and stored locally in a SQLite database.

## Key libraries

- Argon2 for password hashing and verification
- AES-GCM for password encryption and decryption using master password as key
- rpassword for secure password input
- clap library for the CLI
- rusqlite to interact with the SQLite database

## Installation

1. Make sure you have [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) installed.

2. Run `cargo install passvault` to install the binary.

## Commands available

| Command | Description |
|---------|-------------|
| `passvault init` | Initialize the password vault |
| `passvault list` | List all stored passwords |
| `passvault get <name>` | Get a specific password entry (optional --copy flag to copy to clipboard) |
| `passvault add <name> <username> <password>` | Add a new password entry |
| `passvault update <name> <username> <password>` | Update an existing password entry |
| `passvault delete <name>` | Delete a password entry |
| `passvault export <output> <format>` | Export passwords to a file |
| `passvault change-master-password` | Change the master password |
| `passvault reset` | Reset the database |
