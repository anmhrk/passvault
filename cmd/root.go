package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "passvault",
	Short: "Minimal CLI Password Manager",
	Long:  `Minimal and secure CLI-based Password Manager written in Go`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
