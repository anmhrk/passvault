package cmd

import (
	"fmt"
	"os"
	"syscall"

	"github.com/anmhrk/passvault/internal"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var changeMasterCmd = &cobra.Command{
	Use:   "change-master",
	Short: "Change the master password",
	Long:  `Change the master password. All stored passwords will be re-encrypted with the new master password.`,
	Run:   changeMasterPassword,
}

func init() {
	rootCmd.AddCommand(changeMasterCmd)
}

// DecryptedPassword holds a temporarily decrypted password during migration
type DecryptedPassword struct {
	Service  string
	Username string
	Password string
}

func changeMasterPassword(cmd *cobra.Command, args []string) {
	currentMasterPassword, err := internal.GetMasterPassword()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print("Enter new master password: ")
	newPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Error reading new password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()

	newMasterPassword := string(newPasswordBytes)
	if len(newMasterPassword) == 0 {
		fmt.Println("Error: New master password cannot be empty")
		os.Exit(1)
	}

	fmt.Print("Confirm new master password: ")
	confirmPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Error reading confirmation password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()

	confirmPassword := string(confirmPasswordBytes)
	if newMasterPassword != confirmPassword {
		fmt.Println("Error: Passwords do not match")
		os.Exit(1)
	}

	if newMasterPassword == currentMasterPassword {
		fmt.Println("Error: New master password must be different from the current one")
		os.Exit(1)
	}

	// Migrate passwords now
	// Step 1: Get all password entries
	entries, err := internal.ListPasswords()
	if err != nil {
		fmt.Printf("\nError retrieving passwords: %v\n", err)
		os.Exit(1)
	}

	// Step 2: Decrypt all passwords with current master password
	var decryptedPasswords []DecryptedPassword
	for _, entry := range entries {
		encryptedPassword, err := internal.GetPassword(entry.Service, entry.Username)
		if err != nil {
			fmt.Printf("\nError retrieving password for %s (%s): %v\n", entry.Service, entry.Username, err)
			os.Exit(1)
		}

		decryptedPassword, err := internal.DecryptPassword(encryptedPassword, currentMasterPassword)
		if err != nil {
			fmt.Printf("\nError decrypting password for %s (%s): %v\n", entry.Service, entry.Username, err)
			os.Exit(1)
		}

		decryptedPasswords = append(decryptedPasswords, DecryptedPassword{
			Service:  entry.Service,
			Username: entry.Username,
			Password: decryptedPassword,
		})
	}

	// Step 3: Update master password in database
	err = internal.UpdateMasterPassword(newMasterPassword)
	if err != nil {
		fmt.Printf("\nError updating master password: %v\n", err)
		os.Exit(1)
	}

	// Step 4: Re-encrypt all passwords with new master password
	fmt.Print("4. Re-encrypting all passwords with new master password... ")
	for _, decrypted := range decryptedPasswords {
		newEncryptedPassword, err := internal.EncryptPassword(decrypted.Password, newMasterPassword)
		if err != nil {
			fmt.Printf("\nError encrypting password for %s (%s): %v\n", decrypted.Service, decrypted.Username, err)
			os.Exit(1)
		}

		err = internal.AddPassword(decrypted.Service, decrypted.Username, newEncryptedPassword)
		if err != nil {
			fmt.Printf("\nError storing re-encrypted password for %s (%s): %v\n", decrypted.Service, decrypted.Username, err)
			os.Exit(1)
		}
	}

	fmt.Printf("\nMaster password changed successfully!\n")
}
