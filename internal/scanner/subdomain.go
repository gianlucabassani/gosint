package scanner

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pterm/pterm"
)

type SubdomainResult struct {
	Subdomain  string
	IP         string
	StatusCode int
}

func loadSubdomainWordlist(wordlistPath string) ([]string, error) {
	file, err := os.Open(wordlistPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subdomains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" && !strings.HasPrefix(word, "#") {
			subdomains = append(subdomains, word)
		}
	}
	return subdomains, scanner.Err()
}

func EnumerateSubdomains(domain string, limit int) ([]SubdomainResult, error) {
	// Try to load from wordlist file
	wordlistPath := filepath.Join("internal", "fuzzer", "wordlists", "subdomains.txt")
	subdomains, err := loadSubdomainWordlist(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}

	if limit > 0 && len(subdomains) > limit {
		subdomains = subdomains[:limit]
	}

	// Channels and sync
	const workers = 10
	workChan := make(chan string, len(subdomains))
	resultChan := make(chan *SubdomainResult, len(subdomains))
	var wg sync.WaitGroup
	var checked, found int64

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Create worker goroutines
	for i := 0; i < workers && i < len(subdomains); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range workChan {
				subdomain := fmt.Sprintf("%s.%s", word, domain)
				atomic.AddInt64(&checked, 1)

				// Try DNS lookup first
				var ip string
				ips, err := net.LookupIP(subdomain)
				if err == nil && len(ips) > 0 {
					ip = ips[0].String()
				}

				// Check HTTP response
				url := fmt.Sprintf("http://%s", subdomain)
				resp, err := client.Get(url)
				if err == nil {
					defer resp.Body.Close()

					// Valid status codes: 2xx and 3xx
					if resp.StatusCode >= 200 && resp.StatusCode < 400 {
						atomic.AddInt64(&found, 1)
						resultChan <- &SubdomainResult{
							Subdomain:  subdomain,
							IP:         ip,
							StatusCode: resp.StatusCode,
						}
						// Print finding in green as it's discovered
						pterm.Printf("    %s %s -> %s\n", pterm.Green(""), pterm.Cyan(subdomain), pterm.White(ip))
					}
				}
			}
		}()
	}

	// Send work to workers
	go func() {
		for _, word := range subdomains {
			workChan <- word
		}
		close(workChan)
	}()

	// Wait for all workers to finish
	wg.Wait()
	close(resultChan)

	// Collect results
	var results []*SubdomainResult
	for result := range resultChan {
		results = append(results, result)
	}

	// Convert pointers to values for return
	var finalResults []SubdomainResult
	for _, r := range results {
		if r != nil {
			finalResults = append(finalResults, *r)
		}
	}

	return finalResults, nil
}
