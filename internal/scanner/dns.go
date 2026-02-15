package scanner

import (
	"fmt"
	"net"
)

type DNSResult struct {
	A     []string
	AAAA  []string
	MX    []string
	NS    []string
	TXT   []string
	CNAME string
}

func LookupDNS(domain string) (*DNSResult, error) {
	result := &DNSResult{}

	// A records (IPv4)
	ips, _ := net.LookupIP(domain)
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			result.A = append(result.A, ipv4.String())
		} else {
			result.AAAA = append(result.AAAA, ip.String())
		}
	}

	// MX records
	mxRecords, _ := net.LookupMX(domain)
	for _, mx := range mxRecords {
		result.MX = append(result.MX, mx.Host)
	}

	// NS records
	nsRecords, _ := net.LookupNS(domain)
	for _, ns := range nsRecords {
		result.NS = append(result.NS, ns.Host)
	}

	// TXT records
	txtRecords, _ := net.LookupTXT(domain)
	result.TXT = txtRecords

	// CNAME record
	cname, _ := net.LookupCNAME(domain)
	if cname != domain+"." {
		result.CNAME = cname
	}

	if len(result.A) == 0 && len(result.AAAA) == 0 {
		return nil, fmt.Errorf("no DNS records found")
	}

	return result, nil
}