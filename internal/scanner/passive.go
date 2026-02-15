package scanner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
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
}

// RunPassiveRecon queries external services like crt.sh and Wayback Machine
// This is completely passive - we query public databases without touching the target
func RunPassiveRecon(domain string) (*PassiveResult, error) {
	result := &PassiveResult{
		Source: "External APIs (crt.sh, Wayback Machine)",
	}

	// 1. Query crt.sh (Certificate Transparency Logs)
	// This queries a public database of SSL certificates, completely passive
	crtSubdomains, err := queryCrtSh(domain)
	if err != nil {
		fmt.Printf("    %s crt.sh query failed: %v\n", yellow("⚠"), err)
	} else {
		result.Subdomains = append(result.Subdomains, crtSubdomains...)
	}

	// 2. Query Wayback Machine (CDX API)
	// Also passive - queries Internet Archive's database
	waybackURLs, err := queryWayback(domain)
	if err != nil {
		fmt.Printf("    %s Wayback query failed: %v\n", yellow("⚠"), err)
	} else {
		result.URLs = append(result.URLs, waybackURLs...)
	}

	return result, nil
}

// queryCrtSh queries the crt.sh API for certificates containing the domain
// Returns all unique subdomains found in certificate transparency logs
func queryCrtSh(domain string) ([]string, error) {
	// Query format: crt.sh?q=%.domain.com to find all subdomains
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var entries []CrtShEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("failed to decode crt.sh response: %w", err)
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
func queryWayback(domain string) ([]string, error) {
	// CDX API query format: returns up to 500 most recent unique URLs
	url := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=500", domain)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("wayback request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("wayback returned status %d", resp.StatusCode)
	}

	// CDX API returns JSON array of arrays
	var raw [][]string
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("failed to decode wayback response: %w", err)
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
