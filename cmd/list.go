package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/anmhrk/passvault/internal"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all stored passwords",
	Long:  `List all stored password entries and interactively view decrypted passwords.`,
	Run:   listPasswords,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func listPasswords(cmd *cobra.Command, args []string) {
	masterPassword, err := internal.GetMasterPassword()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// For loop to keep the list running
	for {
		entries, err := internal.ListPasswords()
		if err != nil {
			fmt.Printf("Error retrieving passwords: %v\n", err)
			os.Exit(1)
		}

		if len(entries) == 0 {
			fmt.Println("No passwords stored.")
			return
		}

		fmt.Println("\n=== Stored Passwords ===")
		for i, entry := range entries {
			fmt.Printf("%d. %s (%s)\n", i+1, entry.Service, entry.Username)
		}
		fmt.Println("\nEnter number to view password, 'q' to quit:")

		var input string
		fmt.Print("> ")
		_, err = fmt.Scanln(&input)
		if err != nil {
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		input = strings.TrimSpace(strings.ToLower(input))

		if input == "q" || input == "quit" || input == "exit" {
			break
		}

		choice, err := strconv.Atoi(input)
		if err != nil {
			fmt.Println("Invalid input. Please enter a number, 'q' to quit.")
			continue
		}

		if choice < 1 || choice > len(entries) {
			fmt.Printf("Invalid choice. Please enter a number between 1 and %d.\n", len(entries))
			continue
		}

		selectedEntry := entries[choice-1]

		encryptedPassword, err := internal.GetPassword(selectedEntry.Service, selectedEntry.Username)
		if err != nil {
			fmt.Printf("Error retrieving password: %v\n", err)
			continue
		}

		decryptedPassword, err := internal.DecryptPassword(encryptedPassword, masterPassword)
		if err != nil {
			fmt.Printf("Error decrypting password: %v\n", err)
			continue
		}

		fmt.Printf("\n--- Password Details ---\n")
		fmt.Printf("Service: %s\n", selectedEntry.Service)
		fmt.Printf("Username: %s\n", selectedEntry.Username)
		fmt.Printf("Password: %s\n", decryptedPassword)
		fmt.Printf("Created: %s\n", selectedEntry.CreatedAt)
		fmt.Printf("Updated: %s\n", selectedEntry.UpdatedAt)
		fmt.Println("------------------------")

		fmt.Print("\nPress Enter to continue...")
		fmt.Scanln()
	}
}
