package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/anmhrk/passvault/internal"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var updateCmd = &cobra.Command{
	Use:   "update <service>",
	Short: "Update an existing password entry",
	Long:  `Update username/email and/or password for an existing service. Both fields are optional.`,
	Args:  cobra.ExactArgs(1),
	Run:   updatePassword,
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func updatePassword(cmd *cobra.Command, args []string) {
	service := strings.TrimSpace(args[0])
	if service == "" {
		fmt.Println("Error: Service cannot be empty")
		os.Exit(1)
	}

	masterPassword, err := internal.GetMasterPassword()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	entries, err := internal.GetPasswordEntriesByService(service)
	if err != nil {
		fmt.Printf("Error retrieving passwords: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Printf("No password found for service: %s\n", service)
		os.Exit(1)
	}

	var selectedEntry internal.PasswordEntry
	if len(entries) == 1 {
		selectedEntry = entries[0]
		fmt.Printf("Updating password for %s (%s)\n", service, selectedEntry.Username)
	} else {
		fmt.Printf("Multiple accounts found for %s:\n", service)
		for i, entry := range entries {
			fmt.Printf("%d. %s\n", i+1, entry.Username)
		}

		var choice int
		fmt.Print("Select account to update (number): ")
		_, err := fmt.Scanf("%d", &choice)
		if err != nil || choice < 1 || choice > len(entries) {
			fmt.Println("Invalid selection")
			os.Exit(1)
		}
		selectedEntry = entries[choice-1]
		fmt.Printf("Updating password for %s (%s)\n", service, selectedEntry.Username)
	}

	reader := bufio.NewReader(os.Stdin)
	var changes []string
	newUsername := selectedEntry.Username
	var newEncryptedPassword []byte

	fmt.Printf("Current username: %s\n", selectedEntry.Username)
	fmt.Print("New username (press Enter to keep current): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading username: %v\n", err)
		os.Exit(1)
	}
	input = strings.TrimSpace(input)
	if input != "" {
		newUsername = input
		changes = append(changes, "username")
	}

	fmt.Print("New password (press Enter to keep current): ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()

	newPassword := string(passwordBytes)
	if newPassword != "" {
		newEncryptedPassword, err = internal.EncryptPassword(newPassword, masterPassword)
		if err != nil {
			fmt.Printf("Error encrypting password: %v\n", err)
			os.Exit(1)
		}
		changes = append(changes, "password")
	} else {
		newEncryptedPassword, err = internal.GetPassword(service, selectedEntry.Username)
		if err != nil {
			fmt.Printf("Error retrieving existing password: %v\n", err)
			os.Exit(1)
		}
	}

	if len(changes) == 0 {
		fmt.Println("No changes made.")
		return
	}

	if newUsername != selectedEntry.Username {
		err = internal.DeletePassword(service, selectedEntry.Username)
		if err != nil {
			fmt.Printf("Error deleting old entry: %v\n", err)
			os.Exit(1)
		}
	}

	err = internal.AddPassword(service, newUsername, newEncryptedPassword)
	if err != nil {
		fmt.Printf("Error updating password: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully updated %s for %s (%s)\n",
		strings.Join(changes, " and "), service, newUsername)
}
