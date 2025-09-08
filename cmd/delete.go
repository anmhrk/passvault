package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/anmhrk/passvault/internal"
	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete <service>",
	Short: "Delete a password entry",
	Long:  `Delete a password entry for the specified service. Requires confirmation before deletion.`,
	Args:  cobra.ExactArgs(1),
	Run:   deletePassword,
}

func init() {
	rootCmd.AddCommand(deleteCmd)
}

func deletePassword(cmd *cobra.Command, args []string) {
	service := strings.TrimSpace(args[0])
	if service == "" {
		fmt.Println("Error: Service cannot be empty")
		os.Exit(1)
	}

	_, err := internal.GetMasterPassword()
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
		// Multiple entries - let user choose
		fmt.Printf("Multiple accounts found for %s:\n", service)
		for i, entry := range entries {
			fmt.Printf("%d. %s\n", i+1, entry.Username)
		}

		var choice int
		fmt.Print("Select account to delete (number): ")
		_, err := fmt.Scanf("%d", &choice)
		if err != nil || choice < 1 || choice > len(entries) {
			fmt.Println("Invalid selection")
			os.Exit(1)
		}
		selectedEntry = entries[choice-1]
	}

	fmt.Printf("Are you sure you want to delete the password for %s (%s)? (y/n): ",
		service, selectedEntry.Username)

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		os.Exit(1)
	}

	response = strings.TrimSpace(strings.ToLower(response))
	if response != "y" && response != "yes" {
		fmt.Println("Deletion cancelled.")
		return
	}

	err = internal.DeletePassword(service, selectedEntry.Username)
	if err != nil {
		fmt.Printf("Error deleting password: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Password for %s (%s) deleted successfully.\n", service, selectedEntry.Username)
}
