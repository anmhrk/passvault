# Passvault

This is a fully featured CLI based password manager written in Rust. It’s fast, secure and runs completely local on your machine. I built this to learn Rust, and ended up also learning a good bit about cryptography in the process.

## Installation

```bash
cargo install passvault
```

## Usage

```bash
passvault
```

## Features

- Uses argon2 for password hashing with random salt
- AES-GCM for encrypting and decrypting passwords with master password as the key
- Uses rpassword for securely reading passwords from the terminal
- Master password is required to access the vault and decrypt passwords
- Encrypted passwords are stored in a local sqlite3 database which can be exported to a csv file

## Commands

- `passvault add` to add a new password
- `passvault list` to list all passwords. Has view, update, copy to clipboard and delete options
- `passvault list <website-name>` to search for a specific password
- `passvault reset` to reset the master password and database
- `passvault export` to export all passwords to a csv file

## Future improvements

- [ ] Add favorites to easily access and copy passwords to clipboard
- [ ] Cache master password key in memory to avoid re-prompting for a set amount of time until it expires
