package main

import (
	"fmt"
	"log"
	"os"

	"github.com/anmhrk/passvault/cmd"
	"github.com/anmhrk/passvault/internal"
)

func main() {
	// Initialize database
	if err := internal.InitDB(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if err := internal.CloseDB(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing database: %v\n", err)
		}
	}()

	// Execute CLI commands
	cmd.Execute()
}
