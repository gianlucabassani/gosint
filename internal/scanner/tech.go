package scanner

import (
	"net/http"
	"strings"
	"time"
)

func DetectTechnologies(url string) []string {
	var technologies []string

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return technologies
	}
	defer resp.Body.Close()

	// Check Server header
	if server := resp.Header.Get("Server"); server != "" {
		technologies = append(technologies, "Server: "+server)
	}

	// Check X-Powered-By
	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		technologies = append(technologies, "Powered-By: "+powered)
	}

	// Check for common frameworks in headers
	for key := range resp.Header {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "wordpress") {
			technologies = append(technologies, "WordPress")
		} else if strings.Contains(keyLower, "drupal") {
			technologies = append(technologies, "Drupal")
		}
	}

	return technologies
}