package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/gianlucabassani/gosint/internal/fuzzer"
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
	target        string
	mode          ScanMode
	totalRequests int
	db            *storage.Database
}

type ScanReport struct {
	Target       string
	Mode         string
	DNS          *DNSResult
	WHOIS        *WHOISResult
	Subdomains   []SubdomainResult      // Active subdomains found
	PassiveSubs  []string               // Passive subdomains from crt.sh, etc
	Technologies []string
	TotalRequests int
	Duration     time.Duration
	TargetID     uint
}

var (
	cyan   = color.New(color.FgCyan).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	blue   = color.New(color.FgBlue).SprintFunc()
)

// NewScanner creates a new scanner instance with target and mode
func NewScanner(target string, mode ScanMode) *Scanner {
	return &Scanner{
		target: target,
		mode:   mode,
		db:     storage.GetInstance(), // Get singleton DB instance
	}
}

func (s *Scanner) Scan(ctx context.Context) (*ScanReport, error) {
	startTime := time.Now()
	
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

	// 1. BASIC: The Foundation (DNS, Whois, Tech)
	if err := s.runBasicScan(ctx, report); err != nil {
		return nil, err
	}

	// 2. DEEP: External Passive Data (Cumulative for Deep, Stealth, Aggressive)
	if s.mode != ModeBasic {
		if err := s.runDeepScan(ctx, report); err != nil {
			fmt.Printf("%s Deep scan warning: %v\n", yellow("⚠"), err)
		}
	}

	// 3. STEALTH: Careful Active Probing
	if s.mode == ModeStealth {
		if err := s.runStealthScan(ctx, report); err != nil {
			fmt.Printf("%s Stealth scan warning: %v\n", yellow("⚠"), err)
		}
	}

	// 4. AGGRESSIVE: Loud Active Enumeration & Fuzzing
	if s.mode == ModeAggressive {
		if err := s.runAggressiveScan(ctx, report); err != nil {
			fmt.Printf("%s Aggressive scan warning: %v\n", yellow("⚠"), err)
		}
	}

	report.TotalRequests = s.totalRequests
	report.Duration = time.Since(startTime)

	s.saveScanSummary(report)
	s.printSummary(report)

	return report, nil
}

// BASIC: Tech Stack + DNS + WHOIS (Minimal Contact)
func (s *Scanner) runBasicScan(ctx context.Context, report *ScanReport) error {
	fmt.Printf("\n%s BASIC Mode: Tech stack analysis + Passive scans\n", blue("📘"))
	fmt.Printf("%s Performing DNS queries and WHOIS lookups\n\n", cyan("ℹ"))

	// 1. DNS
	fmt.Printf("  %s DNS enumeration\n", yellow("→"))
	dnsResult, err := LookupDNS(s.target)
	if err == nil {
		report.DNS = dnsResult
		s.totalRequests += 5
		
		// Detailed print
		if len(dnsResult.A) > 0 { fmt.Printf("    %s A records: %v\n", green("✓"), dnsResult.A) }
		if len(dnsResult.AAAA) > 0 { fmt.Printf("    %s AAAA records: %v\n", green("✓"), dnsResult.AAAA) }
		if len(dnsResult.MX) > 0 { fmt.Printf("    %s MX records: %v\n", green("✓"), dnsResult.MX) }
		if len(dnsResult.NS) > 0 { fmt.Printf("    %s NS records: %v\n", green("✓"), dnsResult.NS) }
		
		// Save DNS
		dnsData := map[string]interface{}{"a": dnsResult.A, "mx": dnsResult.MX, "ns": dnsResult.NS, "txt": dnsResult.TXT}
		s.db.SaveScanResult(report.TargetID, "basic", "dns", dnsData, 5)
	} else {
		fmt.Printf("    %s DNS lookup failed: %v\n", red("✗"), err)
	}

	// 2. WHOIS
	fmt.Printf("\n  %s WHOIS query\n", yellow("→"))
	whoisResult, err := LookupWHOIS(s.target)
	if err == nil {
		report.WHOIS = whoisResult
		s.totalRequests++
		if whoisResult.Registrar != "" { fmt.Printf("    %s Registrar: %s\n", green("✓"), whoisResult.Registrar) }
		if whoisResult.Created != "" { fmt.Printf("    %s Created: %s\n", green("✓"), whoisResult.Created) }
		if whoisResult.Expires != "" { fmt.Printf("    %s Expires: %s\n", green("✓"), whoisResult.Expires) }
		
		// Save WHOIS
		whoisData := map[string]interface{}{"registrar": whoisResult.Registrar, "created": whoisResult.Created}
		s.db.SaveScanResult(report.TargetID, "basic", "whois", whoisData, 1)
	}

	// 3. Tech Stack (Ported logic)
	fmt.Printf("\n  %s Technology stack analysis\n", yellow("→"))
	techRes, err := AnalyzeTech(s.target)
	if err == nil {
		if techRes.WebServer != "" { fmt.Printf("    %s Server: %s\n", green("✓"), techRes.WebServer) }
		if len(techRes.Frameworks) > 0 { fmt.Printf("    %s Frameworks: %v\n", green("✓"), techRes.Frameworks) }
		if len(techRes.JSLibraries) > 0 { fmt.Printf("    %s JS Libraries: %v\n", green("✓"), techRes.JSLibraries) }
		
		report.Technologies = append(report.Technologies, techRes.Frameworks...)
		report.Technologies = append(report.Technologies, techRes.JSLibraries...)
		s.totalRequests++

		// Save Tech
		for _, t := range report.Technologies {
			s.db.SaveTechnology(report.TargetID, t, "", "detected")
		}
	} else {
		fmt.Printf("    %s Tech analysis failed: %v\n", red("✗"), err)
	}

	return nil
}

// DEEP: External Passive Resources (No direct probing)
func (s *Scanner) runDeepScan(ctx context.Context, report *ScanReport) error {
	fmt.Printf("\n%s DEEP Mode: Passive external resource queries\n", blue("📗"))
	fmt.Printf("%s Querying Certificate Transparency and Archive data\n\n", cyan("ℹ"))

	fmt.Printf("  %s Querying external resources\n", yellow("→"))
	passiveRes, err := RunPassiveRecon(s.target)
	if err != nil {
		return err
	}

	// Handle results
	if len(passiveRes.Subdomains) > 0 {
		fmt.Printf("    %s crt.sh found %d subdomains\n", green("✓"), len(passiveRes.Subdomains))
		// Save to DB
		for _, sub := range passiveRes.Subdomains {
			s.db.SaveSubdomain(report.TargetID, sub, "", "passive_crt")
		}
	} else {
		fmt.Printf("    %s No subdomains found in crt.sh\n", yellow("⚠"))
	}

	if len(passiveRes.URLs) > 0 {
		fmt.Printf("    %s Wayback found %d URLs\n", green("✓"), len(passiveRes.URLs))
	} else {
		fmt.Printf("    %s No archived URLs found\n", yellow("⚠"))
	}
	s.totalRequests += 2
	
	return nil
}

// STEALTH: Slow Active Enumeration (Small wordlist)
func (s *Scanner) runStealthScan(ctx context.Context, report *ScanReport) error {
	fmt.Printf("\n%s STEALTH Mode: Slow active enumeration (low-hanging fruit)\n", blue("📙"))
	fmt.Printf("%s Active subdomain enumeration with reduced aggressiveness\n\n", cyan("ℹ"))

	fmt.Printf("  %s Active Subdomain Enumeration (Wordlist)\n", yellow("→"))
	fmt.Printf("    %s Using reduced wordlist for stealth (first 50 entries)\n", cyan("ℹ"))
	
	// Use small limit (50) for stealth
	subdomains, err := EnumerateSubdomains(s.target, 50)
	if err == nil {
		report.Subdomains = subdomains
		s.totalRequests += len(subdomains)
		
		if len(subdomains) > 0 {
			fmt.Printf("    %s Found %d subdomains\n", green("✓"), len(subdomains))
			for _, sub := range subdomains {
				s.db.SaveSubdomain(report.TargetID, sub.Subdomain, sub.IP, "active_stealth")
			}
		} else {
			fmt.Printf("    %s No subdomains found active\n", yellow("⚠"))
		}
	}
	
	return nil
}

// AGGRESSIVE: Full Active + Fuzzing
func (s *Scanner) runAggressiveScan(ctx context.Context, report *ScanReport) error {
	fmt.Printf("\n%s AGGRESSIVE Mode: Full active scan + Fuzzing\n", blue("📕"))
	fmt.Printf("%s This mode will make significant noise\n\n", cyan("ℹ"))

	// 1. Full Subdomain Scan
	fmt.Printf("  %s Full Subdomain Enumeration (Large List)\n", yellow("→"))
	subdomains, _ := EnumerateSubdomains(s.target, 1000) 
	report.Subdomains = append(report.Subdomains, subdomains...)
	s.totalRequests += len(subdomains)
	
	for _, sub := range subdomains {
		s.db.SaveSubdomain(report.TargetID, sub.Subdomain, sub.IP, "active_aggressive")
	}

	// 2. Directory Fuzzing
	fmt.Printf("\n  %s Directory Fuzzing\n", yellow("→"))
	
	fuzzConfig := fuzzer.FuzzerConfig{
		Target:      "https://" + s.target,
		Mode:        fuzzer.ModeDirectory,
		Wordlist:    "embedded:directories",
		Threads:     50, 
		Timeout:     5,
		MatchCodes:  []int{200, 301, 302, 403},
	}
	
	f := fuzzer.NewFuzzer(fuzzConfig)
	results, err := f.Start(ctx)
	if err == nil {
		fmt.Printf("    %s Fuzzer found %d paths\n", green("✓"), len(results))
		for _, res := range results {
			s.db.SaveFuzzResult(report.TargetID, "directory", res.URL, res.StatusCode, res.Size, res.WordUsed)
		}
	}

	return nil
}

func (s *Scanner) saveScanSummary(report *ScanReport) {
	summaryData := map[string]interface{}{
		"mode":           report.Mode,
		"duration":       report.Duration.String(),
		"active_subs":    len(report.Subdomains),
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
	fmt.Printf("  %s Technologies Detected: %d\n", green("✓"), len(report.Technologies))
	fmt.Printf("  %s Active Subdomains: %d\n", green("✓"), len(report.Subdomains))
	fmt.Printf("  %s Passive Subdomains: %d\n", green("✓"), len(report.PassiveSubs))
	fmt.Printf("%s\n\n", blue("═══════════════════════════════════════════════════"))

	// Offer report generation
	fmt.Printf("%s Scan data saved to database (Target ID: %d)\n", green("✓"), report.TargetID)
	fmt.Printf("%s Generate report: %s\n", cyan("ℹ"), yellow("gosint export -t "+report.Target+" -f json"))
	fmt.Println()
}

func getBoolIcon(value bool) string {
	if value {
		return green("Yes")
	}
	return red("No")
}