package scanner

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gianlucabassani/gosint/internal/fuzzer"
	"github.com/pterm/pterm"
)

type SubdomainResult struct {
	Subdomain  string
	IP         string
	StatusCode int
}

// EnumerateSubdomains performs active subdomain enumeration using the embedded
// wordlist. limit=0 means use the full list. threads controls concurrency.
func EnumerateSubdomains(domain string, limit, threads int) ([]SubdomainResult, error) {
	// Use the fuzzer's embedded wordlist loader — works regardless of CWD (Bug #5)
	subdomains, err := fuzzer.LoadWordlist("embedded:subdomains")
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded subdomain wordlist: %w", err)
	}

	if limit > 0 && len(subdomains) > limit {
		subdomains = subdomains[:limit]
	}

	if threads <= 0 {
		threads = 10
	}

	workChan := make(chan string, threads)
	resultChan := make(chan SubdomainResult, len(subdomains))
	var wg sync.WaitGroup
	var checked, found int64

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects — caller interprets 3xx
		},
	}

	// probeURL tries a URL and returns (statusCode, ok). Body is always closed. (Bug #9)
	probeURL := func(rawURL string) (int, bool) {
		resp, err := httpClient.Get(rawURL)
		if err != nil {
			return 0, false
		}
		resp.Body.Close() // Direct close, not deferred — no connection leak
		return resp.StatusCode, true
	}

	// Create worker goroutines
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range workChan {
				subdomain := fmt.Sprintf("%s.%s", word, domain)
				atomic.AddInt64(&checked, 1)

				// DNS lookup first — skip if no A record
				var ip string
				ips, err := net.LookupIP(subdomain)
				if err != nil || len(ips) == 0 {
					continue // No DNS = not live
				}
				for _, a := range ips {
					if a.To4() != nil {
						ip = a.String()
						break
					}
				}
				if ip == "" {
					ip = ips[0].String()
				}

				// Probe HTTP, then HTTPS as fallback (Improvement #3)
				var code int
				var ok bool
				code, ok = probeURL(fmt.Sprintf("http://%s", subdomain))
				if !ok {
					code, ok = probeURL(fmt.Sprintf("https://%s", subdomain))
				}
				if !ok {
					continue
				}

				if (code >= 200 && code < 400) || code == 401 || code == 403 {
					atomic.AddInt64(&found, 1)
					resultChan <- SubdomainResult{
						Subdomain:  subdomain,
						IP:         ip,
						StatusCode: code,
					}
					pterm.Printf("    %s %s -> %s [%d]\n",
						pterm.Green(""),
						pterm.Cyan(subdomain),
						pterm.White(ip),
						code,
					)
				}
			}
		}()
	}

	// Feed words to workers
	go func() {
		for _, word := range subdomains {
			workChan <- word
		}
		close(workChan)
	}()

	wg.Wait()
	close(resultChan)

	var finalResults []SubdomainResult
	for r := range resultChan {
		finalResults = append(finalResults, r)
	}

	_ = checked // used via atomic for future progress display
	_ = found
	return finalResults, nil
}
