package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// getEnvPath returns the absolute path to ~/.gosint/.env
func getEnvPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".gosint", ".env"), nil
}

// ensureEnvFile ensures the .env file exists with 0600 permissions
func ensureEnvFile(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		// Create file with 0600 permissions
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		file.Close()
	} else {
		// Ensure permissions are 0600
		os.Chmod(path, 0600)
	}
	return nil
}

// LoadEnv loads the variables from ~/.gosint/.env into the system environment.
func LoadEnv() error {
	path, err := getEnvPath()
	if err != nil {
		return err
	}

	if err := ensureEnvFile(path); err != nil {
		return err
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			// Remove surrounding quotes if present
			if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
				val = val[1 : len(val)-1]
			}

			os.Setenv(key, val)
		}
	}

	return scanner.Err()
}

// SaveAPIKey safely updates or appends a key to the ~/.gosint/.env file
func SaveAPIKey(keyName, keyValue string) error {
	path, err := getEnvPath()
	if err != nil {
		return err
	}

	if err := ensureEnvFile(path); err != nil {
		return err
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	keyFound := false
	prefix := keyName + "="

	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, prefix) {
			lines = append(lines, fmt.Sprintf("%s=%s", keyName, keyValue))
			keyFound = true
		} else {
			lines = append(lines, line)
		}
	}
	file.Close()

	if err := scanner.Err(); err != nil {
		return err
	}

	if !keyFound {
		lines = append(lines, fmt.Sprintf("%s=%s", keyName, keyValue))
	}

	output := strings.Join(lines, "\n")
	if len(lines) > 0 {
		output += "\n"
	}

	if err := os.WriteFile(path, []byte(output), 0600); err != nil {
		return err
	}

	// Update current environment immediately
	return os.Setenv(keyName, keyValue)
}

// GetAPIKeyStatus returns a map of API key configuration statuses
func GetAPIKeyStatus() map[string]bool {
	status := make(map[string]bool)
	keys := []string{"SHODAN_API_KEY", "HUNTER_API_KEY", "HIBP_API_KEY"}

	for _, key := range keys {
		status[key] = os.Getenv(key) != ""
	}

	return status
}
