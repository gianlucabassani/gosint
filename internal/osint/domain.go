package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DomainEnricher gathers supplementary intelligence about a domain:
//   - Wayback Machine historical URL count
//   - robots.txt content (passive, no auth)
//   - Shodan host data (requires SHODAN_API_KEY)
type DomainEnricher struct {
	keys   APIKeys
	client *RetryableHTTPClient
}

// NewDomainEnricher creates a DomainEnricher. Shodan enrichment is silently
// skipped if keys.Shodan is empty.
func NewDomainEnricher(keys APIKeys) *DomainEnricher {
	return &DomainEnricher{
		keys: keys,
		// Wayback and Shodan can be slow; use a longer timeout with 2 retries
		client: NewRetryableHTTPClientWithOptions(20*time.Second, 2, 2*time.Second, 0.5, 2),
	}
}

// Enrich runs all enrichment sources for a domain and returns a DomainProfile.
// Sources that require missing API keys are skipped with console notices.
func (e *DomainEnricher) Enrich(ctx context.Context, domain string) (*DomainProfile, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, fmt.Errorf("domain cannot be empty")
	}

	profile := &DomainProfile{
		Domain:    domain,
		ScannedAt: time.Now(),
	}

	// Wayback Machine — always run, no auth required
	count, urls, err := e.FetchWaybackSnapshots(ctx, domain)
	if err != nil {
		fmt.Printf("  [!] Wayback Machine query failed: %v\n", err)
	} else {
		profile.WaybackCount = count
		profile.WaybackURLs = urls
		fmt.Printf("  [+] Wayback Machine: %d archived URLs found\n", count)
	}

	// robots.txt — always run, simple HTTP GET
	robots, err := e.FetchRobotsTxt(ctx, domain)
	if err != nil {
		fmt.Printf("  [!] robots.txt fetch failed: %v\n", err)
	} else {
		profile.RobotsTxt = robots
		if robots != "" {
			lineCount := len(strings.Split(robots, "\n"))
			fmt.Printf("  [+] robots.txt: fetched (%d lines)\n", lineCount)
		} else {
			fmt.Printf("  [-] robots.txt: not found or empty\n")
		}
	}

	// Shodan — requires key, skipped gracefully if absent
	if e.keys.Shodan != "" {
		ip, err := resolveFirstIP(domain)
		if err != nil {
			fmt.Printf("  [!] Shodan skipped: could not resolve IP for %s: %v\n", domain, err)
		} else {
			fmt.Printf("  [*] Shodan: querying %s (%s)...\n", domain, ip)
			shodanInfo, err := e.FetchShodan(ctx, ip)
			if err != nil {
				fmt.Printf("  [!] Shodan query failed: %v\n", err)
			} else {
				profile.Shodan = shodanInfo
				fmt.Printf("  [+] Shodan: %s (%s) — %d open port(s)\n", shodanInfo.Organization, shodanInfo.Country, len(shodanInfo.Ports))
			}
		}
	} else {
		fmt.Printf("  [-] Shodan key not configured — host enrichment skipped\n")
	}

	return profile, nil
}

// FetchWaybackSnapshots queries the Internet Archive CDX API for archived URLs.
// Returns the total count and up to 500 sample URLs.
func (e *DomainEnricher) FetchWaybackSnapshots(ctx context.Context, domain string) (int, []string, error) {
	url := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=500",
		domain,
	)

	resp, err := e.client.Get(ctx, url, nil)
	if err != nil {
		return 0, nil, fmt.Errorf("wayback CDX: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("%w: Wayback returned HTTP %d", ErrServiceUnavailable, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("reading Wayback response: %w", err)
	}

	var raw [][]string
	if err := json.Unmarshal(body, &raw); err != nil {
		return 0, nil, fmt.Errorf("parsing Wayback response: %w", err)
	}

	// First row is the header ["original"]
	if len(raw) <= 1 {
		return 0, []string{}, nil
	}

	var urls []string
	for _, row := range raw[1:] {
		if len(row) > 0 && row[0] != "" {
			urls = append(urls, row[0])
		}
	}

	return len(urls), urls, nil
}

// FetchRobotsTxt retrieves and returns the raw robots.txt content for a domain.
// Returns an empty string (not an error) if the file doesn't exist (HTTP 404).
func (e *DomainEnricher) FetchRobotsTxt(ctx context.Context, domain string) (string, error) {
	url := fmt.Sprintf("https://%s/robots.txt", domain)

	resp, err := e.client.Get(ctx, url, nil)
	if err != nil {
		// Try plain HTTP as fallback
		url = fmt.Sprintf("http://%s/robots.txt", domain)
		resp, err = e.client.Get(ctx, url, nil)
		if err != nil {
			return "", fmt.Errorf("robots.txt fetch: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", nil // No robots.txt — normal, not an error
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("robots.txt: unexpected HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // cap at 64KB
	if err != nil {
		return "", fmt.Errorf("reading robots.txt: %w", err)
	}

	return string(body), nil
}

// FetchShodan queries the Shodan REST API for host information by IP address.
// Returns ErrAPIKeyMissing if no key is set, or a descriptive error if the key is invalid.
func (e *DomainEnricher) FetchShodan(ctx context.Context, ip string) (*ShodanInfo, error) {
	if e.keys.Shodan == "" {
		return nil, ErrAPIKeyMissing
	}

	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, e.keys.Shodan)

	resp, err := e.client.Get(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("Shodan request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Bug #3 fix: distinguish "key present but rejected" from "key absent"
		return nil, fmt.Errorf("Shodan API key is invalid or expired (HTTP 401)")
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: no Shodan data for %s", ErrNotFound, ip)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: Shodan returned HTTP %d", ErrServiceUnavailable, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading Shodan response: %w", err)
	}

	var info ShodanInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parsing Shodan response: %w", err)
	}

	return &info, nil
}

// resolveFirstIP resolves the first IPv4 address for a domain.
func resolveFirstIP(domain string) (string, error) {
	addrs, err := net.LookupHost(domain)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
			return addr, nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return "", fmt.Errorf("no addresses found for %s", domain)
}
