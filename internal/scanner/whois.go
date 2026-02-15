package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type WHOISResult struct {
	Domain     string
	Registrar  string
	Created    string
	Expires    string
	Updated    string
	NameServers []string
	Status     []string
}

func LookupWHOIS(domain string) (*WHOISResult, error) {
	// Simple WHOIS implementation (connects to whois.verisign-grs.com)
	conn, err := net.DialTimeout("tcp", "whois.verisign-grs.com:43", 10*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send query
	fmt.Fprintf(conn, "%s\r\n", domain)

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	response := string(buf[:n])
	result := parseWHOIS(response, domain)

	return result, nil
}

func parseWHOIS(data, domain string) *WHOISResult {
	result := &WHOISResult{Domain: domain}
	lines := strings.Split(data, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Registrar:") {
			result.Registrar = extractValue(line)
		} else if strings.Contains(line, "Creation Date:") {
			result.Created = extractValue(line)
		} else if strings.Contains(line, "Registry Expiry Date:") {
			result.Expires = extractValue(line)
		} else if strings.Contains(line, "Updated Date:") {
			result.Updated = extractValue(line)
		}
	}

	return result
}

func extractValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return ""
}