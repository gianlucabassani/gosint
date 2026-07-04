package scanner

import "testing"

func TestFilterSubdomainClustersRemovesNoise(t *testing.T) {
	var results []SubdomainResult
	// 40 identical catch-all responses (same IP + status + size) = noise.
	for i := 0; i < 40; i++ {
		results = append(results, SubdomainResult{
			Subdomain:  "x",
			IP:         "1.2.3.4",
			StatusCode: 200,
			Size:       1500,
		})
	}
	// A couple of genuinely distinct hosts.
	results = append(results,
		SubdomainResult{Subdomain: "api", IP: "5.6.7.8", StatusCode: 200, Size: 900},
		SubdomainResult{Subdomain: "mail", IP: "9.9.9.9", StatusCode: 403, Size: 120},
	)

	filtered := filterSubdomainClusters(results)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 real results after filtering noise, got %d", len(filtered))
	}
	for _, r := range filtered {
		if r.IP == "1.2.3.4" {
			t.Fatal("catch-all cluster leaked through the filter")
		}
	}
}

func TestFilterSubdomainClustersKeepsSharedIPDistinctSizes(t *testing.T) {
	var results []SubdomainResult
	// Many real subdomains behind one CDN IP, each serving a distinct page (size).
	for i := 0; i < 40; i++ {
		results = append(results, SubdomainResult{
			Subdomain:  "host",
			IP:         "10.0.0.1",
			StatusCode: 200,
			Size:       1000 + i, // distinct sizes
		})
	}
	filtered := filterSubdomainClusters(results)
	if len(filtered) != 40 {
		t.Fatalf("distinct-size hosts on a shared IP must be kept, got %d/40", len(filtered))
	}
}

func TestFilterSubdomainClustersEmpty(t *testing.T) {
	if got := filterSubdomainClusters(nil); got != nil {
		t.Fatalf("expected nil for empty input, got %v", got)
	}
}
