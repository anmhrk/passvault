package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

const (
	SaltLength     = 32
	KeyLength      = 32
	IterationCount = 100000
	Cost           = 15
)

func HashMasterPassword(masterPassword string) (string, error) {
	if len(masterPassword) == 0 {
		return "", errors.New("master password cannot be empty")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(masterPassword), Cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash master password: %w", err)
	}

	return string(hash), nil
}

func VerifyMasterPassword(masterPassword, hash string) error {
	if len(masterPassword) == 0 {
		return errors.New("master password cannot be empty")
	}
	if len(hash) == 0 {
		return errors.New("hash cannot be empty")
	}

	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(masterPassword))
	if err != nil {
		return fmt.Errorf("invalid master password: %w", err)
	}

	return nil
}

// Derive an encryption key from the master password and salt
func deriveKey(masterPassword string, salt []byte) []byte {
	return pbkdf2.Key([]byte(masterPassword), salt, IterationCount, KeyLength, sha256.New)
}

func EncryptPassword(password, masterPassword string) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}
	if len(masterPassword) == 0 {
		return nil, errors.New("master password cannot be empty")
	}

	// Generate a random salt
	salt := make([]byte, SaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key := deriveKey(masterPassword, salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the password
	ciphertext := gcm.Seal(nil, nonce, []byte(password), nil)

	// Combine salt + nonce + ciphertext
	result := make([]byte, SaltLength+len(nonce)+len(ciphertext))
	copy(result[:SaltLength], salt)
	copy(result[SaltLength:SaltLength+len(nonce)], nonce)
	copy(result[SaltLength+len(nonce):], ciphertext)

	return result, nil
}

func DecryptPassword(encryptedData []byte, masterPassword string) (string, error) {
	if len(encryptedData) == 0 {
		return "", errors.New("encrypted data cannot be empty")
	}
	if len(masterPassword) == 0 {
		return "", errors.New("master password cannot be empty")
	}

	// Extract salt
	salt := encryptedData[:SaltLength]

	// Derive encryption key from master password
	key := deriveKey(masterPassword, salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(encryptedData) < SaltLength+nonceSize {
		return "", errors.New("encrypted data is too short to contain nonce")
	}

	nonce := encryptedData[SaltLength : SaltLength+nonceSize]
	ciphertext := encryptedData[SaltLength+nonceSize:]

	// Decrypt the password
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt password: %w", err)
	}

	return string(plaintext), nil
}
