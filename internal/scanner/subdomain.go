package scanner

import (
	"fmt"
	"io"
	"math/rand"
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
	Size       int
}

// EnumerateSubdomains performs active subdomain enumeration using the embedded
// wordlist. limit=0 means use the full list. threads controls concurrency.
//
// It automatically removes false positives caused by wildcard DNS / catch-all
// hosting — the situation where every random label resolves to the same IP and
// returns the same status code. This matters most in aggressive scans, which run
// with no manual filters configured.
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

	// resolveIPv4Set resolves a host and returns its IPs as a string set (empty if
	// the host does not resolve).
	resolveIPv4Set := func(host string) map[string]bool {
		set := map[string]bool{}
		ips, err := net.LookupIP(host)
		if err != nil {
			return set
		}
		for _, a := range ips {
			set[a.String()] = true
		}
		return set
	}

	// probeURL tries a URL and returns (statusCode, bodySize, ok). Body is always
	// read (for an accurate size) then closed — no connection leak. (Bug #9)
	probeURL := func(rawURL string) (int, int, bool) {
		resp, err := httpClient.Get(rawURL)
		if err != nil {
			return 0, 0, false
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, int(n), true
	}

	// Wildcard DNS calibration: resolve a few random labels that should not exist.
	// If they resolve, the union of their IPs is the wildcard target and any code
	// they serve is meaningless — subdomains matching both are dropped as noise.
	wildcardIPs := map[string]bool{}
	wildcardCodes := map[int]bool{}
	for i := 0; i < 4; i++ {
		probe := fmt.Sprintf("zzq%d%s", i, randomLabel())
		ipset := resolveIPv4Set(fmt.Sprintf("%s.%s", probe, domain))
		if len(ipset) == 0 {
			continue
		}
		for ip := range ipset {
			wildcardIPs[ip] = true
		}
		if code, _, ok := probeURL(fmt.Sprintf("http://%s.%s", probe, domain)); ok {
			wildcardCodes[code] = true
		}
	}
	if len(wildcardIPs) > 0 {
		pterm.Warning.Printf("    Wildcard DNS detected (%d IP(s)) — auto-filtering catch-all subdomains\n",
			len(wildcardIPs))
	}

	// isWildcard reports whether a resolved host is indistinguishable from the
	// calibrated wildcard: all of its IPs belong to the wildcard set and, when we
	// learned a wildcard status code, its response matches too.
	isWildcard := func(hostIPs map[string]bool, code int) bool {
		if len(wildcardIPs) == 0 || len(hostIPs) == 0 {
			return false
		}
		for ip := range hostIPs {
			if !wildcardIPs[ip] {
				return false // resolves somewhere distinct — a real, different host
			}
		}
		return len(wildcardCodes) == 0 || wildcardCodes[code]
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
				ipset := resolveIPv4Set(subdomain)
				if len(ipset) == 0 {
					continue // No DNS = not live
				}
				var ip string
				for a := range ipset {
					parsed := net.ParseIP(a)
					if parsed != nil && parsed.To4() != nil {
						ip = a
						break
					}
				}
				if ip == "" {
					for a := range ipset {
						ip = a
						break
					}
				}

				// Probe HTTP, then HTTPS as fallback (Improvement #3)
				var code, size int
				var ok bool
				code, size, ok = probeURL(fmt.Sprintf("http://%s", subdomain))
				if !ok {
					code, size, ok = probeURL(fmt.Sprintf("https://%s", subdomain))
				}
				if !ok {
					continue
				}

				// Drop wildcard/catch-all false positives.
				if isWildcard(ipset, code) {
					continue
				}

				if (code >= 200 && code < 400) || code == 401 || code == 403 {
					atomic.AddInt64(&found, 1)
					resultChan <- SubdomainResult{
						Subdomain:  subdomain,
						IP:         ip,
						StatusCode: code,
						Size:       size,
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

	var collected []SubdomainResult
	for r := range resultChan {
		collected = append(collected, r)
	}

	finalResults := filterSubdomainClusters(collected)

	_ = checked // used via atomic for future progress display
	_ = found
	return finalResults, nil
}

// filterSubdomainClusters is the adaptive safety net that runs after wildcard
// calibration: if an implausibly large group of results shares the same IP,
// status code AND body size, that cluster is catch-all noise the up-front probe
// missed, so it is removed. Body size is part of the key so that many legitimate
// subdomains sharing one CDN/reverse-proxy IP but serving distinct pages are kept.
func filterSubdomainClusters(results []SubdomainResult) []SubdomainResult {
	if len(results) == 0 {
		return results
	}

	threshold := 20
	if scaled := len(results) / 4; scaled > threshold {
		threshold = scaled
	}

	key := func(r SubdomainResult) string {
		return fmt.Sprintf("%s:%d:%d", r.IP, r.StatusCode, r.Size)
	}

	counts := map[string]int{}
	for _, r := range results {
		counts[key(r)]++
	}

	filtered := results[:0]
	removed := 0
	for _, r := range results {
		if counts[key(r)] > threshold {
			removed++
			continue
		}
		filtered = append(filtered, r)
	}

	if removed > 0 {
		pterm.Warning.Printf("    Auto-filtered %d subdomain false positive(s) (identical IP + status cluster)\n",
			removed)
	}
	return filtered
}

// randomLabel returns a random DNS-safe label used to probe wildcard behaviour.
func randomLabel() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
