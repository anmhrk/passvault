package internal

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/term"
)

var (
	db             *sql.DB
	masterPassword string
)

const (
	dbDir  = ".passvault"
	dbFile = "passvault.db"
)

type PasswordEntry struct {
	Service   string
	Username  string
	CreatedAt string
	UpdatedAt string
}

func InitDB() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	dbPath := filepath.Join(homeDir, dbDir)
	if err := os.MkdirAll(dbPath, 0700); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	dbFullPath := filepath.Join(dbPath, dbFile)
	db, err = sql.Open("sqlite3", dbFullPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}

	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	return nil
}

func createTables() error {
	masterPasswordTable := `
	CREATE TABLE IF NOT EXISTS master_password (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`

	passwordsTable := `
	CREATE TABLE IF NOT EXISTS passwords (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		service TEXT NOT NULL,
		username TEXT,
		encrypted_password BLOB NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(service, username)
	);`

	if _, err := db.Exec(masterPasswordTable); err != nil {
		return fmt.Errorf("failed to create master_password table: %w", err)
	}

	if _, err := db.Exec(passwordsTable); err != nil {
		return fmt.Errorf("failed to create passwords table: %w", err)
	}

	return nil
}

func InitializeMasterPassword() error {
	exists, err := masterPasswordExists()
	if err != nil {
		return fmt.Errorf("failed to check master password existence: %w", err)
	}

	if exists {
		if err := promptAndVerifyMasterPassword(); err != nil {
			return fmt.Errorf("master password verification failed: %w", err)
		}
	} else {
		if err := createNewMasterPassword(); err != nil {
			return fmt.Errorf("failed to create master password: %w", err)
		}
	}

	return nil
}

func masterPasswordExists() (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM master_password").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func promptAndVerifyMasterPassword() error {
	var storedHash string
	err := db.QueryRow("SELECT password_hash FROM master_password ORDER BY created_at DESC LIMIT 1").Scan(&storedHash)
	if err != nil {
		return fmt.Errorf("failed to retrieve master password hash: %w", err)
	}

	fmt.Print("Enter master password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()

	password := string(passwordBytes)
	if len(password) == 0 {
		return fmt.Errorf("master password cannot be empty")
	}

	if err := VerifyMasterPassword(password, storedHash); err != nil {
		return fmt.Errorf("invalid master password")
	}

	masterPassword = password
	fmt.Println("Master password verified successfully!")
	return nil
}

func createNewMasterPassword() error {
	fmt.Println("No master password found. Let's create one.")

	fmt.Print("Enter new master password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	fmt.Println()

	password := string(passwordBytes)
	if len(password) == 0 {
		return fmt.Errorf("master password cannot be empty")
	}

	fmt.Print("Confirm master password: ")
	confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read confirmation password: %w", err)
	}
	fmt.Println()

	confirmPassword := string(confirmBytes)
	if password != confirmPassword {
		return fmt.Errorf("passwords do not match")
	}

	hashedPassword, err := HashMasterPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash master password: %w", err)
	}

	_, err = db.Exec("INSERT INTO master_password (password_hash) VALUES (?)", hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to store master password: %w", err)
	}

	masterPassword = password
	fmt.Println("Master password created successfully!")
	return nil
}

// GetMasterPassword returns the master password from memory
// If not initialized, it will initialize the master password first
func GetMasterPassword() (string, error) {
	if masterPassword == "" {
		if err := InitializeMasterPassword(); err != nil {
			return "", err
		}
	}
	return masterPassword, nil
}

// SetMasterPasswordInMemory updates the master password in memory
func SetMasterPasswordInMemory(newPassword string) error {
	if newPassword == "" {
		return fmt.Errorf("master password cannot be empty")
	}
	masterPassword = newPassword
	return nil
}

// UpdateMasterPassword updates the master password in the database
func UpdateMasterPassword(newPassword string) error {
	if newPassword == "" {
		return fmt.Errorf("new master password cannot be empty")
	}

	hashedPassword, err := HashMasterPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new master password: %w", err)
	}

	_, err = db.Exec("DELETE FROM master_password")
	if err != nil {
		return fmt.Errorf("failed to delete old master password: %w", err)
	}

	_, err = db.Exec("INSERT INTO master_password (password_hash) VALUES (?)", hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to store new master password: %w", err)
	}

	return nil
}

func GetDB() *sql.DB {
	return db
}

func CloseDB() error {
	if db != nil {
		return db.Close()
	}
	return nil
}

func AddPassword(service, username string, encryptedPassword []byte) error {
	query := `
		INSERT OR REPLACE INTO passwords (service, username, encrypted_password, updated_at)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
	`
	_, err := db.Exec(query, service, username, encryptedPassword)
	if err != nil {
		return fmt.Errorf("failed to add password: %w", err)
	}
	return nil
}

func GetPassword(service, username string) ([]byte, error) {
	var encryptedPassword []byte
	query := "SELECT encrypted_password FROM passwords WHERE service = ? AND username = ?"
	err := db.QueryRow(query, service, username).Scan(&encryptedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("password not found for service: %s, username: %s", service, username)
		}
		return nil, fmt.Errorf("failed to retrieve password: %w", err)
	}
	return encryptedPassword, nil
}

func GetPasswordEntriesByService(service string) ([]PasswordEntry, error) {
	query := "SELECT service, username, created_at, updated_at FROM passwords WHERE service = ? ORDER BY username"
	rows, err := db.Query(query, service)
	if err != nil {
		return nil, fmt.Errorf("failed to query passwords for service: %w", err)
	}
	defer rows.Close()

	var entries []PasswordEntry
	for rows.Next() {
		var entry PasswordEntry
		err := rows.Scan(&entry.Service, &entry.Username, &entry.CreatedAt, &entry.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan password entry: %w", err)
		}
		entries = append(entries, entry)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating password entries: %w", err)
	}

	return entries, nil
}

func ListPasswords() ([]PasswordEntry, error) {
	query := "SELECT service, username, created_at, updated_at FROM passwords ORDER BY service, username"
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query passwords: %w", err)
	}
	defer rows.Close()

	var entries []PasswordEntry
	for rows.Next() {
		var entry PasswordEntry
		err := rows.Scan(&entry.Service, &entry.Username, &entry.CreatedAt, &entry.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan password entry: %w", err)
		}
		entries = append(entries, entry)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating password entries: %w", err)
	}

	return entries, nil
}

func DeletePassword(service, username string) error {
	query := "DELETE FROM passwords WHERE service = ? AND username = ?"
	result, err := db.Exec(query, service, username)
	if err != nil {
		return fmt.Errorf("failed to delete password: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("password not found for service: %s, username: %s", service, username)
	}

	return nil
}
