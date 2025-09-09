# PassVault

A minimal and secure CLI-based password manager written in Go where you can store, retrieve, and manage your passwords locally with strong encryption.

## Features

- **🔐 Strong Encryption**: AES-256-GCM encryption with PBKDF2 key derivation (100,000 iterations)
- **🏠 Local Storage**: All data stored locally in a SQLite database (`~/.passvault/passvault.db`)
- **📋 Clipboard Integration**: Copy passwords directly to clipboard
- **👥 Multiple Accounts**: Support multiple accounts per service/website
- **📤 Export Functionality**: Export passwords to CSV or JSON format
- **🔄 Master Password Management**: Change master password with automatic re-encryption
- **🗑️ Complete Reset**: Securely wipe all stored data when needed
- **🛡️ Secure by Design**: Passwords hidden during input, secure memory handling

## Installation

```bash
go install github.com/anmhrk/passvault@latest
```

Run the application

```bash
passvault
```

## Building from Source

1. Clone the Repository

```bash
git clone https://github.com/anmhrk/passvault.git
cd passvault
```

2. Install Dependencies

```bash
go mod tidy
```

3. Build the Application

```bash
go build -o passvault .
```

4. Run the application

```bash
passvault
```

## Commands

### Core Password Management

#### `create`

Create a new password entry

```bash
passvault create
```

Prompts for service name, username/email, and password.

#### `get <service>`

Retrieve a password for a service

```bash
passvault get github
passvault get github --copy    # Copy to clipboard instead of displaying
passvault get github -c        # Short flag for copy
```

#### `list`

List all stored passwords with interactive viewing

```bash
passvault list
```

Shows all services and usernames, allows you to select entries to view decrypted passwords.

#### `update <service>`

Update an existing password entry

```bash
passvault update github
```

Allows you to update username and/or password for an existing service.

#### `delete <service>`

Delete a password entry

```bash
passvault delete github
```

Prompts for confirmation before deletion. If multiple accounts exist for a service, you'll be asked to select which one to delete.

### Data Management

#### `export`

Export all passwords to file

```bash
passvault export                   # Export to CSV (default)
passvault export --type csv        # Export to CSV
passvault export --type json       # Export to JSON
passvault export -t json           # Short flag
```

Creates timestamped export files: `passvault_export_YYYYMMDD_HHMMSS.csv/json`

### Vault Management

#### `change-master`

Change the master password

```bash
passvault change-master
```

Prompts for new master password and automatically re-encrypts all stored passwords.

#### `reset`

Completely wipe the password vault

```bash
passvault reset
```

### Help

#### `help`

Show help information

```bash
passvault help              # General help
passvault help create       # Help for specific command
```
