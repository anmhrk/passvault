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

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new password entry",
	Long:  `Create a new password entry by providing service, username/email, and password.`,
	Run:   createPassword,
}

func init() {
	rootCmd.AddCommand(createCmd)
}

func createPassword(cmd *cobra.Command, args []string) {
	masterPassword, err := internal.GetMasterPassword()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Service/Website: ")
	service, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading service: %v\n", err)
		os.Exit(1)
	}
	service = strings.TrimSpace(service)
	if service == "" {
		fmt.Println("Error: Service cannot be empty")
		os.Exit(1)
	}

	fmt.Print("Username/Email: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error reading username: %v\n", err)
		os.Exit(1)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Println("Error: Username cannot be empty")
		os.Exit(1)
	}

	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Printf("Error reading password: %v\n", err)
		os.Exit(1)
	}
	fmt.Println()

	password := string(passwordBytes)
	if password == "" {
		fmt.Println("Error: Password cannot be empty")
		os.Exit(1)
	}

	encryptedPassword, err := internal.EncryptPassword(password, masterPassword)
	if err != nil {
		fmt.Printf("Error encrypting password: %v\n", err)
		os.Exit(1)
	}

	err = internal.AddPassword(service, username, encryptedPassword)
	if err != nil {
		fmt.Printf("Error storing password: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Password for %s (%s) created successfully!\n", service, username)
}
