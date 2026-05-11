package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"
)

// CrtShEntry represents a single entry from crt.sh JSON response
type CrtShEntry struct {
	NameValue string `json:"name_value"`
}

// PassiveResult holds aggregated data from passive sources
type PassiveResult struct {
	Source     string
	Subdomains []string
	URLs       []string
	Errors     []error
}

// PassiveConfig configures passive reconnaissance behavior
type PassiveConfig struct {
	MaxRetries     int
	RetryDelay     time.Duration
	RequestTimeout time.Duration
}

// DefaultPassiveConfig returns sensible defaults
func DefaultPassiveConfig() PassiveConfig {
	return PassiveConfig{
		MaxRetries:     2, // Reduced from 3 — avoids 45s silent hang (Bug #1)
		RetryDelay:     2 * time.Second,
		RequestTimeout: 15 * time.Second,
	}
}

// RunPassiveRecon queries external services like crt.sh and Wayback Machine
// This is completely passive - we query public databases without touching the target
// NOW WITH: Parallelism, Retry Logic, Thread-Safe Result Collection
func RunPassiveRecon(domain string) (*PassiveResult, error) {
	config := DefaultPassiveConfig()

	result := &PassiveResult{
		Source: "External APIs (crt.sh, Wayback Machine)",
		Errors: []error{},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup

	// Launch crt.sh query in goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		pterm.Printf("   [*] Querying crt.sh for %s...\n", domain)
		subs, err := queryCrtShWithRetry(domain, config)

		mu.Lock()
		defer mu.Unlock()

		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("crt.sh: %w", err))
		} else {
			result.Subdomains = append(result.Subdomains, subs...)
		}
	}()

	// Launch Wayback Machine query in goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		pterm.Printf("   [*] Querying Wayback Machine for %s...\n", domain)
		urls, err := queryWaybackWithRetry(domain, config)

		mu.Lock()
		defer mu.Unlock()

		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("wayback: %w", err))
		} else {
			result.URLs = append(result.URLs, urls...)
		}
	}()

	wg.Wait()

	return result, nil
}

// queryCrtShWithRetry queries crt.sh with automatic retry on failure
func queryCrtShWithRetry(domain string, config PassiveConfig) ([]string, error) {
	var lastErr error

	for attempt := 1; attempt <= config.MaxRetries; attempt++ {
		subdomains, err := queryCrtSh(domain, config.RequestTimeout)
		if err == nil {
			return subdomains, nil
		}

		lastErr = err

		if attempt < config.MaxRetries {
			time.Sleep(config.RetryDelay)
		}
	}

	return nil, fmt.Errorf("all %d attempts failed: %w", config.MaxRetries, lastErr)
}

// queryWaybackWithRetry queries Wayback Machine with automatic retry
func queryWaybackWithRetry(domain string, config PassiveConfig) ([]string, error) {
	var lastErr error

	for attempt := 1; attempt <= config.MaxRetries; attempt++ {
		urls, err := queryWayback(domain, config.RequestTimeout)
		if err == nil {
			return urls, nil
		}

		lastErr = err

		if attempt < config.MaxRetries {
			time.Sleep(config.RetryDelay)
		}
	}

	return nil, fmt.Errorf("all %d attempts failed: %w", config.MaxRetries, lastErr)
}

// queryCrtSh queries the crt.sh API for certificates containing the domain
// Returns all unique subdomains found in certificate transparency logs
func queryCrtSh(domain string, timeout time.Duration) ([]string, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 502 {
		return nil, fmt.Errorf("service temporarily unavailable (502 Bad Gateway)")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var entries []CrtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Use map to deduplicate subdomains
	uniqueSubs := make(map[string]bool)
	for _, entry := range entries {
		// crt.sh can return multiple domains per line separated by newlines
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			// Filter: no wildcards, must be subdomain of target domain
			if name != "" && !strings.Contains(name, "*") && strings.HasSuffix(name, domain) {
				uniqueSubs[name] = true
			}
		}
	}

	// Convert map to slice
	var subdomains []string
	for sub := range uniqueSubs {
		subdomains = append(subdomains, sub)
	}

	return subdomains, nil
}

// queryWayback queries the Internet Archive CDX API for archived URLs
// Returns unique URLs that have been crawled by Internet Archive
func queryWayback(domain string, timeout time.Duration) ([]string, error) {
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=500", domain)

	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 502 {
		return nil, fmt.Errorf("service temporarily unavailable (502 Bad Gateway)")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	// CDX API returns JSON array of arrays
	var raw [][]string
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Skip first element (header row) and collect URLs
	var urls []string
	if len(raw) > 1 {
		for _, row := range raw[1:] {
			if len(row) > 0 && row[0] != "" {
				urls = append(urls, row[0])
			}
		}
	}

	return urls, nil
}
