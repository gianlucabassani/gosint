package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/gianlucabassani/gosint/internal/storage"
)

type ScanMode string

const (
	ModeBasic      ScanMode = "basic"
	ModeDeep       ScanMode = "deep"
	ModeStealth    ScanMode = "stealth"
	ModeAggressive ScanMode = "aggressive"
)

type Scanner struct {
	target       string
	mode         ScanMode
	totalRequests int
	db 		 *storage.Database
}

type ScanReport struct {
	Target       string
	Mode         string
	DNS          *DNSResult
	WHOIS        *WHOISResult
	Subdomains   []SubdomainResult
	Technologies []string
	TotalRequests int
	Duration     time.Duration
	TargetID uint
}

var (
	cyan   = color.New(color.FgCyan).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	blue   = color.New(color.FgBlue).SprintFunc()
)


// used to create new scanner instance with target and mode 
func NewScanner(target string, mode ScanMode) *Scanner {
	return &Scanner{
		target: target,
		mode:   mode,
		db: storage.GetInstance(), // Get singleton DB instance
	}
}

func (s *Scanner) Scan(ctx context.Context) (*ScanReport, error) {
	startTime := time.Now()
	
	fmt.Printf("\n%s\n", blue("═══════════════════════════════════════════════════"))
	fmt.Printf("%s Starting %s scan for: %s\n", blue("█"), yellow(string(s.mode)), cyan(s.target))
	fmt.Printf("%s\n\n", blue("═══════════════════════════════════════════════════"))

	// Create or update target in database
	target, err := s.db.CreateOrUpdateTarget(s.target, "domain")
	if err != nil {
		return nil, fmt.Errorf("failed to create target: %w", err)
	}

	report := &ScanReport{
		Target:   s.target,
		Mode:     string(s.mode),
		TargetID: target.ID,
	}

	// All modes start with basic scan
	if err := s.runBasicScan(ctx, report); err != nil {
		return nil, err
	}

	// Deep scan adds more enumeration
	if s.mode == ModeDeep || s.mode == ModeAggressive {
		if err := s.runDeepScan(ctx, report); err != nil {
			fmt.Printf("%s Deep scan warning: %v\n", yellow("⚠"), err)
		}
	}

	// Stealth adds careful active probing
	if s.mode == ModeStealth {
		if err := s.runStealthScan(ctx, report); err != nil {
			fmt.Printf("%s Stealth scan warning: %v\n", yellow("⚠"), err)
		}
	}

	// Aggressive adds everything
	if s.mode == ModeAggressive {
		if err := s.runAggressiveScan(ctx, report); err != nil {
			fmt.Printf("%s Aggressive scan warning: %v\n", yellow("⚠"), err)
		}
	}

	report.TotalRequests = s.totalRequests
	report.Duration = time.Since(startTime)

	// Save final report summary
	s.saveScanSummary(report)

	// Print summary
	s.printSummary(report)

	return report, nil
}

func (s *Scanner) runBasicScan(ctx context.Context, report *ScanReport) error {
	fmt.Printf("%s Running basic passive scan...\n\n", blue("📘"))

	// DNS lookup
	fmt.Printf("  %s DNS enumeration\n", yellow("→"))
	dnsResult, err := LookupDNS(s.target)
	if err != nil {
		fmt.Printf("    %s DNS lookup failed: %v\n", red("✗"), err)
		return err
	}
	report.DNS = dnsResult
	s.totalRequests += 5

	// Print DNS results
	if len(dnsResult.A) > 0 {
		fmt.Printf("    %s A records: %v\n", green("✓"), dnsResult.A)
	}
	if len(dnsResult.AAAA) > 0 {
		fmt.Printf("    %s AAAA records: %v\n", green("✓"), dnsResult.AAAA)
	}
	if len(dnsResult.MX) > 0 {
		fmt.Printf("    %s MX records: %v\n", green("✓"), dnsResult.MX)
	}
	if len(dnsResult.NS) > 0 {
		fmt.Printf("    %s NS records: %v\n", green("✓"), dnsResult.NS)
	}
	if dnsResult.CNAME != "" {
		fmt.Printf("    %s CNAME: %s\n", green("✓"), dnsResult.CNAME)
	}

	// Save DNS results to database
	dnsData := map[string]interface{}{
		"a_records":    dnsResult.A,
		"aaaa_records": dnsResult.AAAA,
		"mx_records":   dnsResult.MX,
		"ns_records":   dnsResult.NS,
		"txt_records":  dnsResult.TXT,
		"cname":        dnsResult.CNAME,
	}
	s.db.SaveScanResult(report.TargetID, string(s.mode), "dns", dnsData, 5)

	fmt.Println()

	// WHOIS lookup
	fmt.Printf("  %s WHOIS query\n", yellow("→"))
	whoisResult, err := LookupWHOIS(s.target)
	if err != nil {
		fmt.Printf("    %s WHOIS lookup failed: %v\n", yellow("⚠"), err)
	} else {
		report.WHOIS = whoisResult
		s.totalRequests += 1

		if whoisResult.Registrar != "" {
			fmt.Printf("    %s Registrar: %s\n", green("✓"), whoisResult.Registrar)
		}
		if whoisResult.Created != "" {
			fmt.Printf("    %s Created: %s\n", green("✓"), whoisResult.Created)
		}
		if whoisResult.Expires != "" {
			fmt.Printf("    %s Expires: %s\n", green("✓"), whoisResult.Expires)
		}

		// Save WHOIS to database
		whoisData := map[string]interface{}{
			"domain":      whoisResult.Domain,
			"registrar":   whoisResult.Registrar,
			"created":     whoisResult.Created,
			"expires":     whoisResult.Expires,
			"updated":     whoisResult.Updated,
			"nameservers": whoisResult.NameServers,
			"status":      whoisResult.Status,
		}
		s.db.SaveScanResult(report.TargetID, string(s.mode), "whois", whoisData, 1)
	}

	fmt.Println()
	return nil
}

func (s *Scanner) runDeepScan(ctx context.Context, report *ScanReport) error {
	fmt.Printf("%s Running deep passive scan...\n\n", blue("📗"))

	// Subdomain enumeration
	fmt.Printf("  %s Subdomain discovery (wordlist-based)\n", yellow("→"))
	subdomains, err := EnumerateSubdomains(s.target, 100) // Limit to 100 for now
	if err != nil {
		fmt.Printf("    %s Subdomain enumeration failed: %v\n", yellow("⚠"), err)
	} else {
		report.Subdomains = subdomains
		s.totalRequests += len(subdomains)

		// Save subdomains to database
		for _, sub := range subdomains {
			s.db.SaveSubdomain(report.TargetID, sub.Subdomain, sub.IP, "active")
		}

		subdomainData := map[string]interface{}{
			"count":      len(subdomains),
			"subdomains": subdomains,
		}
		s.db.SaveScanResult(report.TargetID, string(s.mode), "subdomain", subdomainData, len(subdomains))
	}

	fmt.Println()

	// Technology detection
	fmt.Printf("  %s Technology detection\n", yellow("→"))
	techs := DetectTechnologies("https://" + s.target)
	if len(techs) > 0 {
		report.Technologies = techs
		s.totalRequests += 1

		for _, tech := range techs {
			fmt.Printf("    %s %s\n", green("✓"), tech)
			// Save to database
			s.db.SaveTechnology(report.TargetID, tech, "", "detected")
		}

		techData := map[string]interface{}{
			"technologies": techs,
		}
		s.db.SaveScanResult(report.TargetID, string(s.mode), "technology", techData, 1)
	} else {
		fmt.Printf("    %s No technologies detected\n", yellow("⚠"))
	}

	fmt.Println()
	return nil
}

func (s *Scanner) runStealthScan(ctx context.Context, report *ScanReport) error {
	fmt.Printf("%s Running stealth active scan...\n\n", blue("📙"))
	fmt.Printf("  %s Slow port scan (common ports: 80, 443, 22, 21)\n", yellow("→"))
	fmt.Printf("    %s Rate-limited: 1 port every 2 seconds\n", cyan("ℹ"))
	fmt.Printf("    %s This feature will be fully implemented in Phase 3\n", yellow("⚠"))
	
	// TODO: Implement slow port scanning
	s.totalRequests += 4

	fmt.Println()
	return nil
}

func (s *Scanner) runAggressiveScan(ctx context.Context, report *ScanReport) error {
	fmt.Printf("%s Running aggressive scan...\n\n", blue("📕"))
	fmt.Printf("  %s Full port scan\n", yellow("→"))
	fmt.Printf("    %s This feature will be fully implemented in Phase 3\n", yellow("⚠"))
	
	// TODO: Implement full port scanning
	s.totalRequests += 100

	fmt.Println()
	return nil
}

func (s *Scanner) saveScanSummary(report *ScanReport) {
	summaryData := map[string]interface{}{
		"mode":           report.Mode,
		"duration":       report.Duration.String(),
		"total_requests": report.TotalRequests,
		"dns_records":    report.DNS != nil,
		"whois_data":     report.WHOIS != nil,
		"subdomains":     len(report.Subdomains),
		"technologies":   len(report.Technologies),
	}

	s.db.SaveScanResult(report.TargetID, string(s.mode), "summary", summaryData, report.TotalRequests)
}

func (s *Scanner) printSummary(report *ScanReport) {
	fmt.Printf("\n%s\n", blue("═══════════════════════════════════════════════════"))
	fmt.Printf("%s SCAN COMPLETE\n", blue("█"))
	fmt.Printf("%s\n", blue("═══════════════════════════════════════════════════"))
	fmt.Printf("  Target: %s\n", cyan(report.Target))
	fmt.Printf("  Mode: %s\n", yellow(report.Mode))
	fmt.Printf("  Duration: %s\n", report.Duration.Round(time.Millisecond))
	fmt.Printf("  Total Requests: %d\n", report.TotalRequests)
	fmt.Println()
	fmt.Printf("  %s DNS Records: %s\n", green("✓"), getBoolIcon(report.DNS != nil))
	fmt.Printf("  %s WHOIS Data: %s\n", green("✓"), getBoolIcon(report.WHOIS != nil))
	fmt.Printf("  %s Subdomains Found: %d\n", green("✓"), len(report.Subdomains))
	fmt.Printf("  %s Technologies Detected: %d\n", green("✓"), len(report.Technologies))
	fmt.Printf("%s\n\n", blue("═══════════════════════════════════════════════════"))

	// Offer report generation
	fmt.Printf("%s Scan data saved to database (ID: %d)\n", green("✓"), report.TargetID)
	fmt.Printf("%s Generate report: %s\n", cyan("ℹ"), yellow("gosint export -t "+report.Target+" -f json"))
	fmt.Println()
}

func getBoolIcon(value bool) string {
	if value {
		return green("Yes")
	}
	return red("No")
}