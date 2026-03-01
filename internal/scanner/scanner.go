package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gianlucabassani/gosint/internal/fuzzer"
	"github.com/gianlucabassani/gosint/internal/storage"
	"github.com/pterm/pterm"
)

// ScanMode defines the intensity level of the scan
type ScanMode string

const (
	ModeBasic      ScanMode = "basic"      //  The Handshake - Zero intrusion
	ModeDeep       ScanMode = "deep"       //  The Historian - Public records only
	ModeStealth    ScanMode = "stealth"    //  The Ninja - Quiet active probing
	ModeAggressive ScanMode = "aggressive" //  The Tank - Full enumeration
	ModeCustom     ScanMode = "custom"     //   User-defined configuration
)

// ScanConfig holds all customizable scan parameters
type ScanConfig struct {
	// Core settings
	Mode   ScanMode
	Target string

	// Feature toggles
	EnableDNS           bool
	EnableWHOIS         bool
	EnableTechDetection bool
	EnablePassive       bool
	EnableSubdomains    bool
	EnableFuzzing       bool

	// Performance settings
	SubdomainLimit   int
	SubdomainThreads int
	FuzzThreads      int
	HTTPTimeout      int
	DNSTimeout       int

	// Subdomain settings
	SubdomainWordlist  string
	SubdomainMinLength int
	SubdomainMaxLength int

	// Fuzzing settings
	FuzzDirectories bool
	FuzzVHosts      bool
	FuzzWordlist    string
	FuzzMatchCodes  []int

	// Output settings
	Verbose      bool
	ShowProgress bool
	SaveToDB     bool
}

// Scanner orchestrates reconnaissance operations
type Scanner struct {
	config        ScanConfig
	totalRequests int
	db            *storage.Database
}

// ScanReport contains all scan results
type ScanReport struct {
	Target            string
	Mode              string
	StartTime         time.Time
	EndTime           time.Time
	Duration          time.Duration
	DNS               *DNSResult
	WHOIS             *WHOISResult
	Technologies      []string
	ActiveSubdomains  []SubdomainResult
	PassiveSubdomains []string
	PassiveURLs       []string
	FuzzResults       []FuzzSummary
	TotalRequests     int
	TargetID          uint
	Errors            []string
}

// FuzzSummary aggregates fuzzing results
type FuzzSummary struct {
	Type    string
	Found   int
	Results []fuzzer.FuzzResult
}

// NewScanner creates a scanner with the given configuration
func NewScanner(config ScanConfig) *Scanner {
	if config.Mode != ModeCustom {
		config = applyModeDefaults(config)
	}

	return &Scanner{
		config: config,
		db:     storage.GetInstance(),
	}
}

// NewScannerWithMode creates a scanner with a predefined mode (legacy compatibility)
func NewScannerWithMode(target string, mode ScanMode) *Scanner {
	config := ScanConfig{
		Target: target,
		Mode:   mode,
	}
	return NewScanner(config)
}

// applyModeDefaults sets feature flags based on scan mode
func applyModeDefaults(config ScanConfig) ScanConfig {
	// Base defaults
	config.SaveToDB = true
	config.ShowProgress = true
	config.HTTPTimeout = 10
	config.DNSTimeout = 5
	config.SubdomainThreads = 10
	config.FuzzThreads = 40
	config.FuzzMatchCodes = []int{200, 204, 301, 302, 307, 401, 403}

	switch config.Mode {
	case ModeBasic:
		config.EnableDNS = true
		config.EnableWHOIS = true
		config.EnableTechDetection = true
		config.EnablePassive = false
		config.EnableSubdomains = false
		config.EnableFuzzing = false
		config.Verbose = false

	case ModeDeep:
		config.EnableDNS = true
		config.EnableWHOIS = true
		config.EnableTechDetection = true
		config.EnablePassive = true
		config.EnableSubdomains = false
		config.EnableFuzzing = false
		config.Verbose = true

	case ModeStealth:
		config.EnableDNS = true
		config.EnableWHOIS = true
		config.EnableTechDetection = true
		config.EnablePassive = true
		config.EnableSubdomains = true
		config.EnableFuzzing = false
		config.SubdomainLimit = 50
		config.SubdomainThreads = 5
		config.HTTPTimeout = 15
		config.Verbose = true

	case ModeAggressive:
		config.EnableDNS = true
		config.EnableWHOIS = true
		config.EnableTechDetection = true
		config.EnablePassive = true
		config.EnableSubdomains = true
		config.EnableFuzzing = true
		config.SubdomainLimit = 0
		config.SubdomainThreads = 20
		config.FuzzThreads = 50
		config.FuzzDirectories = true
		config.FuzzVHosts = false
		config.Verbose = true
	}

	return config
}

// Scan executes the configured reconnaissance
func (s *Scanner) Scan(ctx context.Context) (*ScanReport, error) {
	report := &ScanReport{
		Target:    s.config.Target,
		Mode:      string(s.config.Mode),
		StartTime: time.Now(),
		Errors:    []string{},
	}

	// Create or update target in database
	if s.config.SaveToDB {
		target, err := s.db.CreateOrUpdateTarget(s.config.Target, "domain")
		if err != nil {
			return nil, fmt.Errorf("failed to create target: %w", err)
		}
		report.TargetID = target.ID
	}

	s.printScanHeader()

	// Execute scan phases based on configuration
	if s.config.EnableDNS {
		if err := s.runDNSPhase(ctx, report); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("DNS: %v", err))
		}
	}

	if s.config.EnableWHOIS {
		if err := s.runWHOISPhase(ctx, report); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("WHOIS: %v", err))
		}
	}

	if s.config.EnableTechDetection {
		if err := s.runTechPhase(ctx, report); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Tech: %v", err))
		}
	}

	if s.config.EnablePassive {
		if err := s.runPassivePhase(ctx, report); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Passive: %v", err))
		}
	}

	if s.config.EnableSubdomains {
		if err := s.runSubdomainPhase(ctx, report); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Subdomains: %v", err))
		}
	}

	if s.config.EnableFuzzing {
		if err := s.runFuzzingPhase(ctx, report); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Fuzzing: %v", err))
		}
	}

	// Finalize report
	report.EndTime = time.Now()
	report.Duration = report.EndTime.Sub(report.StartTime)
	report.TotalRequests = s.totalRequests

	if s.config.SaveToDB {
		s.saveScanSummary(report)
	}

	s.printSummary(report)

	return report, nil
}

// runDNSPhase performs DNS enumeration with pterm UI
func (s *Scanner) runDNSPhase(ctx context.Context, report *ScanReport) error {
	pterm.Println(pterm.LightCyan(" Resolving DNS records..."))

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	dnsResult, err := LookupDNS(s.config.Target)
	if err != nil {
		if s.config.Verbose {
			pterm.Println(pterm.Red("  ✗ DNS lookup failed"))
		}
		return err
	}

	report.DNS = dnsResult
	s.totalRequests += 5

	// Display results clean like Browsint
	if s.config.Verbose && dnsResult != nil {
		pterm.Println()
		pterm.Println(pterm.LightCyan("┏━━━━━━━━━━━━━━━━━━━ DNS RECORDS ━━━━━━━━━━━━━━━━━━━┓"))

		if len(dnsResult.A) > 0 {
			pterm.Printf("  ┌─ Record A:\n")
			for _, record := range dnsResult.A {
				pterm.Printf("  │  └─ %s\n", pterm.Green(record))
			}
		}

		if len(dnsResult.MX) > 0 {
			pterm.Printf("  ┌─ Record MX:\n")
			for _, record := range dnsResult.MX {
				pterm.Printf("  │  └─ %s\n", pterm.Green(record))
			}
		}

		if len(dnsResult.NS) > 0 {
			pterm.Printf("  ┌─ Record NS:\n")
			for _, record := range dnsResult.NS {
				pterm.Printf("  │  └─ %s\n", pterm.Green(record))
			}
		}

		if len(dnsResult.TXT) > 0 {
			pterm.Printf("  ┌─ Record TXT:\n")
			for _, record := range dnsResult.TXT {
				pterm.Printf("  │  └─ %s\n", pterm.Green(record))
			}
		}

		pterm.Println(pterm.LightCyan("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"))
	}

	if s.config.SaveToDB {
		dnsData := map[string]interface{}{
			"a":    dnsResult.A,
			"aaaa": dnsResult.AAAA,
			"mx":   dnsResult.MX,
			"ns":   dnsResult.NS,
			"txt":  dnsResult.TXT,
		}
		s.db.SaveScanResult(report.TargetID, string(s.config.Mode), "dns", dnsData, 5)
	}

	return nil
}

// runWHOISPhase performs WHOIS lookup with pterm UI
func (s *Scanner) runWHOISPhase(ctx context.Context, report *ScanReport) error {
	pterm.Println(pterm.LightCyan(" Querying WHOIS database..."))

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	whoisResult, err := LookupWHOIS(s.config.Target)
	if err != nil {
		if s.config.Verbose {
			pterm.Println(pterm.Red("  ✗ WHOIS lookup failed"))
		}
		return err
	}

	report.WHOIS = whoisResult
	s.totalRequests++

	if s.config.Verbose && whoisResult != nil {
		pterm.Println()
		pterm.Println(pterm.LightCyan("┏━━━━━━━━━━━━━━━━━ WHOIS DATA ━━━━━━━━━━━━━━━━━┓"))

		if whoisResult.Registrar != "" {
			pterm.Printf("  ┌─ Registrar:  %s\n", pterm.Green(whoisResult.Registrar))
		}
		if whoisResult.Created != "" {
			pterm.Printf("  ├─ Created:    %s\n", pterm.White(whoisResult.Created))
		}
		if whoisResult.Expires != "" {
			pterm.Printf("  └─ Expires:    %s\n", pterm.White(whoisResult.Expires))
		}

		pterm.Println(pterm.LightCyan("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"))
	}

	if s.config.SaveToDB {
		whoisData := map[string]interface{}{
			"registrar": whoisResult.Registrar,
			"created":   whoisResult.Created,
			"expires":   whoisResult.Expires,
		}
		s.db.SaveScanResult(report.TargetID, string(s.config.Mode), "whois", whoisData, 1)
	}

	return nil
}

// runTechPhase performs technology detection with pterm UI
func (s *Scanner) runTechPhase(ctx context.Context, report *ScanReport) error {
	pterm.Println(pterm.LightCyan(" Analyzing technology stack..."))

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	techResult, err := AnalyzeTech(s.config.Target)
	if err != nil {
		return err
	}

	s.totalRequests++

	// Build technology list
	if s.config.Verbose && techResult != nil {
		pterm.Println()
		pterm.Println(pterm.LightCyan("┏━━━━━━━━━━━━ TECHNOLOGIES & CONFIGURATION ━━━━━━━━━━━━┓"))

		if techResult.WebServer != "" {
			pterm.Printf("  ┌─ Web Server: %s\n", pterm.Green(techResult.WebServer))
		}

		if len(techResult.Frameworks) > 0 {
			pterm.Printf("  ├─ CMS / Framework: %s\n", pterm.Green(strings.Join(techResult.Frameworks, ", ")))
		}

		if len(techResult.JSLibraries) > 0 {
			pterm.Printf("  ├─ JavaScript Libraries: %s\n", pterm.Green(strings.Join(techResult.JSLibraries, ", ")))
		}

		if len(techResult.Analytics) > 0 {
			pterm.Printf("  └─ Analytics: %s\n", pterm.Green(strings.Join(techResult.Analytics, ", ")))
		}

		pterm.Println(pterm.LightCyan("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"))
	}

	report.Technologies = append(report.Technologies, techResult.Frameworks...)
	report.Technologies = append(report.Technologies, techResult.JSLibraries...)

	if s.config.SaveToDB {
		for _, t := range report.Technologies {
			s.db.SaveTechnology(report.TargetID, t, "", "detected")
		}
	}

	return nil
}

// runPassivePhase queries external passive sources
func (s *Scanner) runPassivePhase(ctx context.Context, report *ScanReport) error {
	pterm.Println(pterm.LightCyan(" Starting passive reconnaissance (crt.sh, Wayback Machine)"))

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// The passive module now handles its own parallel execution
	passiveResult, err := RunPassiveRecon(s.config.Target)
	if err != nil {
		return err
	}

	s.totalRequests += 2

	pterm.Println()
	pterm.Println(pterm.LightCyan("┏━━━━━━━━━━━━━━━ PASSIVE INTELLIGENCE ━━━━━━━━━━━━━━┓"))

	if len(passiveResult.Subdomains) > 0 {
		report.PassiveSubdomains = passiveResult.Subdomains
		pterm.Printf("   Subdomains (crt.sh): %s\n", pterm.Green(fmt.Sprintf("%d found", len(passiveResult.Subdomains))))

		if s.config.SaveToDB {
			for _, sub := range passiveResult.Subdomains {
				s.db.SaveSubdomain(report.TargetID, sub, "", "passive_crt")
			}
		}
	} else {
		pterm.Printf("   Subdomains (crt.sh): %s\n", pterm.White("None"))
	}

	if len(passiveResult.URLs) > 0 {
		report.PassiveURLs = passiveResult.URLs
		pterm.Printf("   Archived URLs (Wayback): %s\n", pterm.Green(fmt.Sprintf("%d found", len(passiveResult.URLs))))
	} else {
		pterm.Printf("   Archived URLs (Wayback): %s\n", pterm.White("None"))
	}

	pterm.Println(pterm.LightCyan("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"))

	return nil
}

// runSubdomainPhase performs active subdomain enumeration with progress bar
func (s *Scanner) runSubdomainPhase(ctx context.Context, report *ScanReport) error {
	pterm.Println(pterm.LightCyan(" Starting active subdomain enumeration"))

	if s.config.SubdomainLimit > 0 {
		pterm.Printf("  └─ Limited to %d wordlist entries\n", s.config.SubdomainLimit)
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	subdomains, err := EnumerateSubdomains(s.config.Target, s.config.SubdomainLimit)
	if err != nil {
		return err
	}

	report.ActiveSubdomains = subdomains
	s.totalRequests += len(subdomains)

	pterm.Println()
	if len(subdomains) > 0 {
		pterm.Printf("  %s %d active subdomains\n", pterm.Green(""), len(subdomains))
	} else {
		pterm.Println(pterm.White("   No active subdomains found"))
	}

	if s.config.SaveToDB {
		for _, sub := range subdomains {
			s.db.SaveSubdomain(report.TargetID, sub.Subdomain, sub.IP, "active")
		}
	}

	return nil
}

// runFuzzingPhase performs directory and vhost fuzzing
func (s *Scanner) runFuzzingPhase(ctx context.Context, report *ScanReport) error {
	pterm.Info.Println("Starting fuzzing phase")

	if s.config.FuzzDirectories {
		if err := s.runDirectoryFuzzing(ctx, report); err != nil {
			return err
		}
	}

	if s.config.FuzzVHosts {
		if err := s.runVHostFuzzing(ctx, report); err != nil {
			return err
		}
	}

	return nil
}

// runDirectoryFuzzing fuzzes web directories
func (s *Scanner) runDirectoryFuzzing(ctx context.Context, report *ScanReport) error {
	wordlist := s.config.FuzzWordlist
	if wordlist == "" {
		wordlist = "embedded:directories"
	}

	fuzzConfig := fuzzer.FuzzerConfig{
		Target:     "https://" + s.config.Target,
		Mode:       fuzzer.ModeDirectory,
		Wordlist:   wordlist,
		Threads:    s.config.FuzzThreads,
		Timeout:    s.config.HTTPTimeout,
		MatchCodes: s.config.FuzzMatchCodes,
	}

	f := fuzzer.NewFuzzer(fuzzConfig)
	results, err := f.Start(ctx)
	if err != nil {
		return err
	}

	if len(results) > 0 {
		report.FuzzResults = append(report.FuzzResults, FuzzSummary{
			Type:    "directory",
			Found:   len(results),
			Results: results,
		})

		pterm.Success.Printf("Directory fuzzing: %d paths found\n", len(results))

		if s.config.SaveToDB {
			for _, res := range results {
				s.db.SaveFuzzResult(report.TargetID, "directory", res.URL, res.StatusCode, res.Size, res.WordUsed)
			}
		}
	}

	return nil
}

// runVHostFuzzing fuzzes virtual hosts
func (s *Scanner) runVHostFuzzing(ctx context.Context, report *ScanReport) error {
	wordlist := s.config.FuzzWordlist
	if wordlist == "" {
		wordlist = "embedded:vhosts"
	}

	fuzzConfig := fuzzer.FuzzerConfig{
		Target:     s.config.Target,
		Mode:       fuzzer.ModeVHost,
		Wordlist:   wordlist,
		Threads:    s.config.FuzzThreads,
		Timeout:    s.config.HTTPTimeout,
		MatchCodes: s.config.FuzzMatchCodes,
	}

	f := fuzzer.NewFuzzer(fuzzConfig)
	results, err := f.Start(ctx)
	if err != nil {
		return err
	}

	if len(results) > 0 {
		report.FuzzResults = append(report.FuzzResults, FuzzSummary{
			Type:    "vhost",
			Found:   len(results),
			Results: results,
		})

		pterm.Success.Printf("VHost fuzzing: %d hosts found\n", len(results))

		if s.config.SaveToDB {
			for _, res := range results {
				s.db.SaveFuzzResult(report.TargetID, "vhost", res.URL, res.StatusCode, res.Size, res.WordUsed)
			}
		}
	}

	return nil
}

// printScanHeader displays the scan configuration
func (s *Scanner) printScanHeader() {
	// Mode descriptions
	modeDesc := map[ScanMode]string{
		ModeBasic:      " The Handshake - Zero intrusion (DNS, WHOIS, Tech)",
		ModeDeep:       " The Historian - Public records only (crt.sh, Wayback)",
		ModeStealth:    " The Ninja - Quiet active probing (rate-limited)",
		ModeAggressive: " The Tank - Full enumeration (high noise)",
		ModeCustom:     "  Custom Configuration",
	}

	pterm.Println()
	pterm.Println(pterm.LightCyan("╔════════════════════════════════════════════════════════╗"))
	pterm.Println(pterm.LightCyan("║") + pterm.Bold.Sprint("           DOMAIN RECONNAISSANCE SCAN            ") + pterm.LightCyan("║"))
	pterm.Println(pterm.LightCyan("╚════════════════════════════════════════════════════════╝"))
	pterm.Println()
	pterm.Printf("┌─ Target:      %s\n", pterm.Cyan(s.config.Target))
	pterm.Printf("├─ Mode:        %s\n", pterm.Yellow(s.config.Mode))
	pterm.Printf("└─ Description: %s\n", pterm.White(modeDesc[s.config.Mode]))
	pterm.Println()

	// Display enabled features
	features := []string{}
	if s.config.EnableDNS {
		features = append(features, "DNS")
	}
	if s.config.EnableWHOIS {
		features = append(features, "WHOIS")
	}
	if s.config.EnableTechDetection {
		features = append(features, "Tech")
	}
	if s.config.EnablePassive {
		features = append(features, "Passive")
	}
	if s.config.EnableSubdomains {
		features = append(features, "Subdomains")
	}
	if s.config.EnableFuzzing {
		features = append(features, "Fuzzing")
	}

	pterm.Printf("   Enabled modules: %s\n", pterm.LightGreen(strings.Join(features, ", ")))
	pterm.Println()
}

// saveScanSummary saves the scan report to database
func (s *Scanner) saveScanSummary(report *ScanReport) {
	summaryData := map[string]interface{}{
		"mode":               report.Mode,
		"duration":           report.Duration.String(),
		"active_subdomains":  len(report.ActiveSubdomains),
		"passive_subdomains": len(report.PassiveSubdomains),
		"technologies":       len(report.Technologies),
		"fuzz_results":       len(report.FuzzResults),
		"errors":             len(report.Errors),
	}
	s.db.SaveScanResult(report.TargetID, string(s.config.Mode), "summary", summaryData, report.TotalRequests)
}

// printSummary displays the scan results using pterm
func (s *Scanner) printSummary(report *ScanReport) {
	pterm.Println()
	pterm.Println(pterm.LightCyan("╔════════════════════════════════════════════════════════╗"))
	pterm.Println(pterm.LightCyan("║") + pterm.Bold.Sprint("                  SCAN COMPLETE                     ") + pterm.LightCyan("║"))
	pterm.Println(pterm.LightCyan("╚════════════════════════════════════════════════════════╝"))
	pterm.Println()

	// Summary info
	pterm.Printf("┌─ Target:          %s\n", pterm.Cyan(report.Target))
	pterm.Printf("├─ Mode:            %s\n", pterm.Yellow(report.Mode))
	pterm.Printf("├─ Duration:        %s\n", pterm.White(report.Duration.Round(time.Millisecond).String()))
	pterm.Printf("└─ Total Requests:  %s\n", pterm.White(fmt.Sprintf("%d", report.TotalRequests)))
	pterm.Println()

	// Results summary
	pterm.Println(pterm.LightCyan("┏━━━━━━━━━━━━━━ SCAN RESULTS SUMMARY ━━━━━━━━━━━━━━┓"))

	if report.DNS != nil {
		pterm.Printf("   DNS Records:         %s\n", pterm.Green(fmt.Sprintf("%d", len(report.DNS.A)+len(report.DNS.MX)+len(report.DNS.NS))))
	}

	if report.WHOIS != nil {
		pterm.Printf("   WHOIS Data:          %s\n", pterm.Green("Available"))
	}

	if len(report.Technologies) > 0 {
		pterm.Printf("   Technologies:        %s\n", pterm.Green(fmt.Sprintf("%d detected", len(report.Technologies))))
	}

	if len(report.ActiveSubdomains) > 0 {
		pterm.Printf("   Active Subdomains:   %s\n", pterm.Green(fmt.Sprintf("%d", len(report.ActiveSubdomains))))
	}

	if len(report.PassiveSubdomains) > 0 {
		pterm.Printf("   Passive Subdomains:  %s\n", pterm.Green(fmt.Sprintf("%d", len(report.PassiveSubdomains))))
	}

	if len(report.PassiveURLs) > 0 {
		pterm.Printf("   Archived URLs:       %s\n", pterm.Green(fmt.Sprintf("%d", len(report.PassiveURLs))))
	}

	for _, fuzz := range report.FuzzResults {
		pterm.Printf("   Fuzzing (%s):      %s\n", fuzz.Type, pterm.Green(fmt.Sprintf("%d paths", fuzz.Found)))
	}

	pterm.Println(pterm.LightCyan("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"))

	// Errors section
	if len(report.Errors) > 0 {
		pterm.Println()
		pterm.Println(pterm.Yellow("  Encountered errors during scan:"))
		for _, err := range report.Errors {
			pterm.Printf("    • %s\n", pterm.White(err))
		}
	}

	// Database save confirmation
	if s.config.SaveToDB {
		pterm.Println()
		pterm.Printf("  %s Data saved to database (Target ID: %d)\n", pterm.Green("✓"), report.TargetID)
		pterm.Printf("  %s Export: gosint export -t %s -f [json|html|csv|pdf]\n", pterm.White(""), report.Target)
	}

	pterm.Println()
	pterm.Println(pterm.LightCyan("╚════════════════════════════════════════════════════════╝"))
	pterm.Println()
}
