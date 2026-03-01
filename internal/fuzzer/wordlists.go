package fuzzer

import (
	"bufio"
	"embed"
	"fmt"
	"os"
	"strings"
)

//go:embed wordlists/*.txt
var embeddedWordlists embed.FS

func LoadWordlist(path string) ([]string, error) {
	var words []string

	// Try embedded wordlists first
	if strings.HasPrefix(path, "embedded:") {
		wlName := strings.TrimPrefix(path, "embedded:")
		return loadEmbeddedWordlist(wlName)
	}

	// Load from file system
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return words, nil
}

func loadEmbeddedWordlist(name string) ([]string, error) {
	var words []string
	path := fmt.Sprintf("wordlists/%s.txt", name)

	data, err := embeddedWordlists.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("embedded wordlist not found: %s", name)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			words = append(words, line)
		}
	}

	return words, nil
}

// GetAvailableWordlists returns list of embedded wordlists
func GetAvailableWordlists() []string {
	return []string{
		"directories",
		"subdomains",
		"vhosts",
	}
}
