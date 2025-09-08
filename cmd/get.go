package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/anmhrk/passvault/internal"
	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"
)

var (
	copyToClipboard bool
)

var getCmd = &cobra.Command{
	Use:   "get <service>",
	Short: "Retrieve a password for a service",
	Long:  `Retrieve and display a password for the specified service. Use --copy flag to copy to clipboard instead.`,
	Args:  cobra.ExactArgs(1),
	Run:   getPassword,
}

func init() {
	getCmd.Flags().BoolVarP(&copyToClipboard, "copy", "c", false, "Copy password to clipboard instead of displaying")
	rootCmd.AddCommand(getCmd)
}

func getPassword(cmd *cobra.Command, args []string) {
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
	} else {
		fmt.Printf("Multiple accounts found for %s:\n", service)
		for i, entry := range entries {
			fmt.Printf("%d. %s\n", i+1, entry.Username)
		}

		var choice int
		fmt.Print("Select account (number): ")
		_, err := fmt.Scanf("%d", &choice)
		if err != nil || choice < 1 || choice > len(entries) {
			fmt.Println("Invalid selection")
			os.Exit(1)
		}
		selectedEntry = entries[choice-1]
	}

	encryptedPassword, err := internal.GetPassword(service, selectedEntry.Username)
	if err != nil {
		fmt.Printf("Error retrieving password: %v\n", err)
		os.Exit(1)
	}

	password, err := internal.DecryptPassword(encryptedPassword, masterPassword)
	if err != nil {
		fmt.Printf("Error decrypting password: %v\n", err)
		os.Exit(1)
	}

	if copyToClipboard {
		err = clipboard.WriteAll(password)
		if err != nil {
			fmt.Printf("Error copying to clipboard: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Password for %s (%s) copied to clipboard!\n", service, selectedEntry.Username)
	} else {
		fmt.Printf("Service: %s\n", service)
		fmt.Printf("Username: %s\n", selectedEntry.Username)
		fmt.Printf("Password: %s\n", password)
	}
}
