package cmd

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anmhrk/passvault/internal"
	"github.com/spf13/cobra"
)

var (
	exportType string
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all passwords to CSV or JSON format",
	Long:  `Export all stored passwords to a file in CSV (default) or JSON format. Passwords are decrypted during export.`,
	Run:   exportPasswords,
}

func init() {
	exportCmd.Flags().StringVarP(&exportType, "type", "t", "csv", "Export format: csv or json")
	rootCmd.AddCommand(exportCmd)
}

// ExportEntry represents a password entry for export
type ExportEntry struct {
	Service   string `json:"service"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func exportPasswords(cmd *cobra.Command, args []string) {
	// Validate export type
	exportType = strings.ToLower(strings.TrimSpace(exportType))
	if exportType != "csv" && exportType != "json" {
		fmt.Printf("Error: Invalid export type '%s'. Supported types: csv, json\n", exportType)
		os.Exit(1)
	}

	masterPassword, err := internal.GetMasterPassword()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	entries, err := internal.ListPasswords()
	if err != nil {
		fmt.Printf("Error retrieving passwords: %v\n", err)
		os.Exit(1)
	}

	if len(entries) == 0 {
		fmt.Println("No passwords to export.")
		return
	}

	var exportEntries []ExportEntry
	for _, entry := range entries {
		encryptedPassword, err := internal.GetPassword(entry.Service, entry.Username)
		if err != nil {
			fmt.Printf("Error retrieving password for %s (%s): %v\n", entry.Service, entry.Username, err)
			continue
		}

		decryptedPassword, err := internal.DecryptPassword(encryptedPassword, masterPassword)
		if err != nil {
			fmt.Printf("Error decrypting password for %s (%s): %v\n", entry.Service, entry.Username, err)
			continue
		}

		exportEntries = append(exportEntries, ExportEntry{
			Service:   entry.Service,
			Username:  entry.Username,
			Password:  decryptedPassword,
			CreatedAt: entry.CreatedAt,
			UpdatedAt: entry.UpdatedAt,
		})
	}

	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("passvault_export_%s.%s", timestamp, exportType)

	switch exportType {
	case "csv":
		err = exportToCSV(filename, exportEntries)
	case "json":
		err = exportToJSON(filename, exportEntries)
	}

	if err != nil {
		fmt.Printf("Error exporting passwords: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully exported %d passwords to %s\n", len(exportEntries), filename)
	fmt.Printf("⚠️  WARNING: This file contains unencrypted passwords. Keep it secure and delete when no longer needed.\n")
}

func exportToCSV(filename string, entries []ExportEntry) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"Service", "Username", "Password", "Created At", "Updated At"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	for _, entry := range entries {
		record := []string{
			entry.Service,
			entry.Username,
			entry.Password,
			entry.CreatedAt,
			entry.UpdatedAt,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write record: %w", err)
		}
	}

	return nil
}

func exportToJSON(filename string, entries []ExportEntry) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	exportData := struct {
		ExportedAt string        `json:"exported_at"`
		Count      int           `json:"count"`
		Passwords  []ExportEntry `json:"passwords"`
	}{
		ExportedAt: time.Now().Format(time.RFC3339),
		Count:      len(entries),
		Passwords:  entries,
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(exportData); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}

	return nil
}
