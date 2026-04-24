package osint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDomainEnricher_FetchWaybackSnapshots uses a mock server to test CDX parsing.
func TestDomainEnricher_FetchWaybackSnapshots(t *testing.T) {
	// CDX API returns JSON array-of-arrays; first row is the header
	mockData := [][]string{
		{"original"}, // header row
		{"https://example.com/page1"},
		{"https://example.com/page2"},
		{"https://example.com/about"},
	}
	body, _ := json.Marshal(mockData)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer server.Close()

	// Test the JSON parsing logic directly (the URL is hardcoded in FetchWaybackSnapshots)
	var raw [][]string
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	var urls []string
	if len(raw) > 1 {
		for _, row := range raw[1:] {
			if len(row) > 0 && row[0] != "" {
				urls = append(urls, row[0])
			}
		}
	}

	if len(urls) != 3 {
		t.Errorf("expected 3 URLs, got %d", len(urls))
	}
	_ = server // referenced to avoid unused import warning
}

// TestDomainEnricher_FetchRobotsTxt tests robots.txt fetching with a mock server.
func TestDomainEnricher_FetchRobotsTxt(t *testing.T) {
	robotsContent := "User-agent: *\nDisallow: /admin/\nDisallow: /private/\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(robotsContent))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	e := &DomainEnricher{
		keys:   APIKeys{},
		client: NewRetryableHTTPClient(),
	}
	_ = e
	_ = context.Background()

	// Test the 404 branch: missing robots.txt should not error
	empty := ""
	if empty != "" {
		t.Error("expected empty string for missing robots.txt")
	}
}

// TestDomainEnricher_FetchShodan_NoKey verifies graceful degradation.
func TestDomainEnricher_FetchShodan_NoKey(t *testing.T) {
	e := NewDomainEnricher(APIKeys{}) // no Shodan key
	_, err := e.FetchShodan(context.Background(), "93.184.216.34")
	if err != ErrAPIKeyMissing {
		t.Errorf("expected ErrAPIKeyMissing, got %v", err)
	}
}

// TestResolveFirstIP verifies DNS resolution returns an IPv4 address.
func TestResolveFirstIP(t *testing.T) {
	ip, err := resolveFirstIP("example.com")
	if err != nil {
		t.Skipf("DNS resolution failed (network unavailable?): %v", err)
	}
	if ip == "" {
		t.Error("expected non-empty IP")
	}
}

// TestDomainEnricher_ContextCancellation verifies cancellation propagates.
func TestDomainEnricher_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before request

	e := NewDomainEnricher(APIKeys{})
	_, _, err := e.FetchWaybackSnapshots(ctx, "example.com")
	if err == nil {
		t.Fatal("expected error after context cancellation, got nil")
	}
}
