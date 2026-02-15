package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/gianlucabassani/gosint/internal/cli"
	"github.com/gianlucabassani/gosint/internal/storage"
)

func main() {
	// init db
	homeDir, err := os.UserHomeDir()
	if err != nil { 
		fmt.Fprintf(os.Stderr, "Error getting home directory: %v\n", err)
		os.Exit(1)
	}

	dbPath := filepath.Join(homeDir, ".gosint", "gosint.db")
	
	// Ensure .gosint directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating database directory: %v\n", err)
		os.Exit(1)
	}

	// Initialize database
	if _, err := storage.Initialize(dbPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing database: %v\n", err)
		os.Exit(1)
	}

	// Execute CLI
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
