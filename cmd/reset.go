package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/anmhrk/passvault/internal"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset the password vault by wiping all data",
	Long:  `Completely wipe the password vault database. This action cannot be undone. Requires confirmation.`,
	Run:   resetVault,
}

func init() {
	rootCmd.AddCommand(resetCmd)
}

func resetVault(cmd *cobra.Command, args []string) {
	fmt.Println("⚠️  WARNING: This will permanently delete ALL stored passwords and reset your vault.")
	fmt.Println("This action cannot be undone!")

	fmt.Print("Are you sure you want to reset your password vault? (yes/no): ")
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading response: %v\n", err)
		os.Exit(1)
	}

	response = strings.TrimSpace(strings.ToLower(response))
	if response != "yes" {
		fmt.Println("Reset cancelled.")
		return
	}

	// Close the database connection first
	err = internal.CloseDB()
	if err != nil {
		fmt.Printf("Warning: Error closing database: %v\n", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error getting home directory: %v\n", err)
		os.Exit(1)
	}

	dbPath := filepath.Join(homeDir, ".passvault", "passvault.db")

	err = os.Remove(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Database file doesn't exist. Nothing to reset.")
		} else {
			fmt.Printf("Error deleting database file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Password vault has been completely reset.")
	}
}
