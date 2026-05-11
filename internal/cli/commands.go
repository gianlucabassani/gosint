package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gianlucabassani/gosint/internal/crawler"
	"github.com/gianlucabassani/gosint/internal/fuzzer"
	"github.com/gianlucabassani/gosint/internal/osint"
	"github.com/gianlucabassani/gosint/internal/reports"
	"github.com/gianlucabassani/gosint/internal/scanner"
	"github.com/gianlucabassani/gosint/internal/storage"
	"github.com/spf13/cobra"
)

// CreateCancellableContext creates a context that cancels on CTRL+C signal
func CreateCancellableContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())

	opSigChan := make(chan os.Signal, 1)
	signal.Notify(opSigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-opSigChan
		fmt.Printf("\n\n  Received interrupt signal, stopping operation...\n\n")
		cancel()
	}()

	return ctx, cancel
}

var rootCmd = &cobra.Command{
	Use:   "gosint",
	Short: "GOSINT - Open Source Intelligence Toolkit",
	Long: `GOSINT is a powerful OSINT tool built in Go for domain reconnaissance,
web crawling, and intelligence gathering.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			LaunchInteractiveMenu()
		}
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a target domain with various intensity levels or custom configuration",
	Long: `Scan a target domain with different modes:
	
Predefined Modes:
  --basic (-b):      Passive reconnaissance (DNS, WHOIS, public records)
  --deep (-d):       Deep passive scan (subdomains, tech detection, extensive enumeration)
  --stealth (-s):    Active but stealthy scan (slow, rate-limited probing)
  --aggressive (-a): Full active + passive scan (fast, comprehensive, may trigger alerts)

Custom Mode:
  --custom (-c):     Use custom flags to configure exactly what you want

Custom Flags (only work with --custom):
  --enable-dns            Enable DNS enumeration
  --enable-whois          Enable WHOIS lookup
  --enable-tech           Enable technology detection
  --enable-passive        Enable passive recon (crt.sh, Wayback)
  --enable-subdomains     Enable subdomain enumeration
  --enable-fuzzing        Enable directory/vhost fuzzing
  --subdomain-limit N     Limit subdomain wordlist to N entries (0=unlimited)
  --subdomain-threads N   Number of concurrent subdomain checks (default: 10)
  --fuzz-threads N        Number of concurrent fuzzing threads (default: 40)
  --fuzz-directories      Enable directory fuzzing
  --fuzz-vhosts           Enable virtual host fuzzing
  --http-timeout N        HTTP request timeout in seconds (default: 10)
  --verbose               Show detailed output

Examples:
  # Predefined mode
  gosint scan -t example.com --basic
  
  # Custom scan: Only DNS + Tech detection
  gosint scan -t example.com --custom --enable-dns --enable-tech
  
  # Custom scan: Everything but fuzzing, verbose output
  gosint scan -t example.com --custom --enable-dns --enable-whois --enable-tech \
    --enable-passive --enable-subdomains --verbose
  
  # Custom scan: Aggressive subdomain enum only
  gosint scan -t example.com --custom --enable-subdomains --subdomain-limit 0 \
    --subdomain-threads 50 --verbose
`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		if target == "" {
			fmt.Println(" Error: --target/-t flag is required")
			os.Exit(1)
		}

		// Check if custom mode
		custom, _ := cmd.Flags().GetBool("custom")

		var config scanner.ScanConfig

		if custom {
			// Build custom configuration from flags
			config = buildCustomConfig(cmd, target)
		} else {
			// Use predefined mode
			mode := getSelectedMode(cmd)
			config = scanner.ScanConfig{
				Target: target,
				Mode:   mode,
			}
		}

		// Execute scan
		s := scanner.NewScanner(config)
		ctx, cancel := CreateCancellableContext()
		defer cancel()

		report, err := s.Scan(ctx)
		if err != nil {
			if ctx.Err() == context.Canceled {
				fmt.Printf("\n%s Scan interrupted by user\n", "")
			} else {
				fmt.Printf("\n Scan failed: %v\n", err)
			}
			return
		}

		offerReportGeneration(report.Target)
	},
}

// getSelectedMode determines which predefined mode was selected
func getSelectedMode(cmd *cobra.Command) scanner.ScanMode {
	basic, _ := cmd.Flags().GetBool("basic")
	deep, _ := cmd.Flags().GetBool("deep")
	stealth, _ := cmd.Flags().GetBool("stealth")
	aggressive, _ := cmd.Flags().GetBool("aggressive")

	modeCount := 0
	if basic {
		modeCount++
	}
	if deep {
		modeCount++
	}
	if stealth {
		modeCount++
	}
	if aggressive {
		modeCount++
	}

	if modeCount > 1 {
		fmt.Println(" Error: Only one scan mode can be selected at a time")
		os.Exit(1)
	}

	switch {
	case deep:
		return scanner.ModeDeep
	case stealth:
		return scanner.ModeStealth
	case aggressive:
		return scanner.ModeAggressive
	default:
		return scanner.ModeBasic
	}
}

// buildCustomConfig creates a ScanConfig from custom flags
func buildCustomConfig(cmd *cobra.Command, target string) scanner.ScanConfig {
	config := scanner.ScanConfig{
		Target: target,
		Mode:   scanner.ModeCustom,
	}

	// Feature toggles
	config.EnableDNS, _ = cmd.Flags().GetBool("enable-dns")
	config.EnableWHOIS, _ = cmd.Flags().GetBool("enable-whois")
	config.EnableTechDetection, _ = cmd.Flags().GetBool("enable-tech")
	config.EnablePassive, _ = cmd.Flags().GetBool("enable-passive")
	config.EnableSubdomains, _ = cmd.Flags().GetBool("enable-subdomains")
	config.EnableFuzzing, _ = cmd.Flags().GetBool("enable-fuzzing")

	// Performance settings
	config.SubdomainLimit, _ = cmd.Flags().GetInt("subdomain-limit")
	config.SubdomainThreads, _ = cmd.Flags().GetInt("subdomain-threads")
	config.FuzzThreads, _ = cmd.Flags().GetInt("fuzz-threads")
	config.HTTPTimeout, _ = cmd.Flags().GetInt("http-timeout")

	// Fuzzing settings
	config.FuzzDirectories, _ = cmd.Flags().GetBool("fuzz-directories")
	config.FuzzVHosts, _ = cmd.Flags().GetBool("fuzz-vhosts")
	config.FuzzWordlist, _ = cmd.Flags().GetString("fuzz-wordlist")

	// Output settings
	config.Verbose, _ = cmd.Flags().GetBool("verbose")
	config.ShowProgress = true
	config.SaveToDB = true

	// Apply defaults for unset values
	if config.SubdomainThreads == 0 {
		config.SubdomainThreads = 10
	}
	if config.FuzzThreads == 0 {
		config.FuzzThreads = 40
	}
	if config.HTTPTimeout == 0 {
		config.HTTPTimeout = 10
	}

	// Validate: at least one feature must be enabled
	if !config.EnableDNS && !config.EnableWHOIS && !config.EnableTechDetection &&
		!config.EnablePassive && !config.EnableSubdomains && !config.EnableFuzzing {
		fmt.Println(" Error: At least one feature must be enabled in custom mode")
		fmt.Println("   Use flags like --enable-dns, --enable-whois, etc.")
		os.Exit(1)
	}

	return config
}

var crawlCmd = &cobra.Command{
	Use:   "crawl",
	Short: "Crawl a website for OSINT data (Emails, Phones, etc.)",
	Run: func(cmd *cobra.Command, args []string) {
		urlStr, _ := cmd.Flags().GetString("url")
		depth, _ := cmd.Flags().GetInt("depth")

		if urlStr == "" {
			fmt.Println(" Error: --url/-u flag is required")
			os.Exit(1)
		}

		if !strings.HasPrefix(urlStr, "http") {
			urlStr = "https://" + urlStr
		}

		db := storage.GetInstance()
		targetObj, _ := db.CreateOrUpdateTarget(urlStr, "url")

		fmt.Printf("  Starting OSINT Crawl: %s (Depth: %d)\n", urlStr, depth)

		config := crawler.CrawlerConfig{
			TargetURL:     urlStr,
			MaxDepth:      depth,
			MaxConcurrent: 10,
			Timeout:       5 * time.Second,
			TargetID:      targetObj.ID,
		}

		ctx, cancel := CreateCancellableContext()
		defer cancel()

		c := crawler.NewCrawler(config)
		results, err := c.Start(ctx)
		if err != nil {
			if ctx.Err() == context.Canceled {
				fmt.Printf("\n%s Crawl interrupted by user\n", "")
			} else {
				fmt.Printf("\n Crawl failed: %v\n", err)
			}
			return
		}

		var emails, phones int
		for _, r := range results {
			emails += len(r.OSINT.Emails)
			phones += len(r.OSINT.Phones)
		}

		fmt.Printf("\n Crawl Complete\n")
		fmt.Printf("   Pages Visited: %d\n", len(results))
		fmt.Printf("   Emails Found:  %d\n", emails)
		fmt.Printf("   Phones Found:  %d\n", phones)
		fmt.Printf("   Data saved to database for target ID: %d\n", targetObj.ID)

		offerReportGeneration(urlStr)
	},
}

func offerReportGeneration(target string) {
	fmt.Println("\n" + strings.Repeat("─", 50))
	fmt.Println(" Scan completed! Generate report?")
	fmt.Println("Available formats: JSON, HTML, CSV, PDF")
	fmt.Println("Run: gosint export --target " + target + " --format [json|html|csv|pdf]")
	fmt.Println("Or use the interactive menu to generate reports.")
	fmt.Println(strings.Repeat("─", 50))
}

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export scan results in various formats",
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")

		if target == "" {
			fmt.Println(" Error: --target flag is required")
			os.Exit(1)
		}

		validFormats := []string{"json", "html", "csv", "pdf"}
		isValid := false
		for _, f := range validFormats {
			if format == f {
				isValid = true
				break
			}
		}

		if !isValid {
			fmt.Printf(" Error: Invalid format '%s'. Choose: json, html, csv, pdf\n", format)
			os.Exit(1)
		}

		if err := ExecuteExport(target, format, output); err != nil {
			fmt.Printf(" Error: %v\n", err)
			os.Exit(1)
		}
	},
}

// ExecuteExport handles the report generation logic
func ExecuteExport(target, format, output string) error {
	fmt.Printf("Exporting %s report for %s\n", format, target)

	// Prepare output directory and filename (Improvement #5: use $HOME/.gosint/reports/ not CWD)
	if output == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("could not determine home directory: %w", err)
		}
		// Sanitize target for use as directory name
		safeTarget := strings.NewReplacer("/", "_", ":", "", ".", ".").Replace(target)
		targetDir := filepath.Join(homeDir, ".gosint", "reports", safeTarget)
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("creating directory %s: %w", targetDir, err)
		}

		timestamp := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("report_%s.%s", timestamp, format)
		output = filepath.Join(targetDir, filename)
	}

	fmt.Printf("Output: %s\n", output)

	db := storage.GetInstance()
	targetObj, err := db.GetTargetReportData(target)
	if err != nil {
		return fmt.Errorf("fetching data: %w", err)
	}

	// Prepare report data
	reportData := reports.ReportData{
		Target:    targetObj.Domain,
		ScanDate:  targetObj.LastScanned,
		ScanMode:  "Unknown",
		TargetObj: targetObj,
		Technologies: targetObj.Technologies,
		Subdomains:   targetObj.Subdomains,
		Fuzzing:      targetObj.FuzzResults,
	}

	// Filter ScanResults into specific categories
	for _, sr := range targetObj.ScanResults {
		if sr.Type == "dns" {
			reportData.DNS = append(reportData.DNS, sr)
		} else if sr.Type == "whois" {
			reportData.WHOIS = sr
		}
	}

	reportData.Duration = "N/A"

	if err := reports.GenerateReport(format, output, reportData); err != nil {
		return fmt.Errorf("generating report: %w", err)
	}

	fmt.Printf(" Report generated successfully: %s\n", output)
	return nil
}

var fuzzCmd = &cobra.Command{
	Use:   "fuzz",
	Short: "Fuzz directories, vhosts, or subdomains",
	Long: `Fuzzing modes:
  
  directory: Fuzz web directories (similar to ffuf/gobuster)
  vhost:     Fuzz virtual hosts
  subdomain: Fuzz subdomains via DNS
	
Example:
  gosint fuzz -u https://example.com -m directory -w wordlist.txt
  gosint fuzz -t example.com -m subdomain -w embedded:subdomains`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		urlStr, _ := cmd.Flags().GetString("url")
		modeStr, _ := cmd.Flags().GetString("mode")
		wordlist, _ := cmd.Flags().GetString("wordlist")
		threads, _ := cmd.Flags().GetInt("threads")

		effectiveTarget := urlStr
		if effectiveTarget == "" {
			effectiveTarget = target
		}

		if effectiveTarget == "" {
			fmt.Println(" Error: --url or --target is required")
			os.Exit(1)
		}

		if modeStr == "" {
			fmt.Println(" Error: --mode is required (directory, vhost, subdomain)")
			os.Exit(1)
		}

		var mode fuzzer.FuzzMode
		switch modeStr {
		case "directory":
			mode = fuzzer.ModeDirectory
		case "vhost":
			mode = fuzzer.ModeVHost
		case "subdomain":
			mode = fuzzer.ModeSubdomain
		default:
			fmt.Println(" Error: Invalid mode. Use directory, vhost, or subdomain")
			os.Exit(1)
		}

		if wordlist == "" {
			switch mode {
			case fuzzer.ModeDirectory:
				wordlist = "embedded:directories"
			case fuzzer.ModeSubdomain:
				wordlist = "embedded:subdomains"
			case fuzzer.ModeVHost:
				wordlist = "embedded:vhosts"
			}
		}

		config := fuzzer.FuzzerConfig{
			Target:   effectiveTarget,
			Mode:     mode,
			Wordlist: wordlist,
			Threads:  threads,
			Timeout:  10,
		}

		fmt.Printf(" Starting %s fuzzing on %s\n", modeStr, effectiveTarget)
		fmt.Printf("   Wordlist: %s\n", wordlist)
		fmt.Printf("   Threads: %d\n", threads)

		ctx, cancel := CreateCancellableContext()
		defer cancel()

		f := fuzzer.NewFuzzer(config)
		results, err := f.Start(ctx)
		if err != nil {
			if ctx.Err() == context.Canceled {
				fmt.Printf("\n%s Fuzzing interrupted by user\n", "")
			} else {
				fmt.Printf("\n Fuzzing failed: %v\n", err)
			}
			return
		}

		fmt.Printf("\n Fuzzing Complete: Found %d items\n", len(results))
	},
}

func init() {
	// Scan command flags
	scanCmd.Flags().StringP("target", "t", "", "Target domain to scan (required)")
	scanCmd.MarkFlagRequired("target")

	// Predefined modes
	scanCmd.Flags().BoolP("basic", "b", false, "Basic passive scan (default)")
	scanCmd.Flags().BoolP("deep", "d", false, "Deep passive scan")
	scanCmd.Flags().BoolP("stealth", "s", false, "Stealth active scan")
	scanCmd.Flags().BoolP("aggressive", "a", false, "Aggressive active + passive scan")

	// Custom mode
	scanCmd.Flags().BoolP("custom", "c", false, "Custom configuration mode")

	// Custom mode feature toggles
	scanCmd.Flags().Bool("enable-dns", false, "Enable DNS enumeration (custom mode)")
	scanCmd.Flags().Bool("enable-whois", false, "Enable WHOIS lookup (custom mode)")
	scanCmd.Flags().Bool("enable-tech", false, "Enable technology detection (custom mode)")
	scanCmd.Flags().Bool("enable-passive", false, "Enable passive recon (custom mode)")
	scanCmd.Flags().Bool("enable-subdomains", false, "Enable subdomain enumeration (custom mode)")
	scanCmd.Flags().Bool("enable-fuzzing", false, "Enable fuzzing (custom mode)")

	// Custom mode performance settings
	scanCmd.Flags().Int("subdomain-limit", 0, "Subdomain wordlist limit (0=unlimited)")
	scanCmd.Flags().Int("subdomain-threads", 10, "Concurrent subdomain checks")
	scanCmd.Flags().Int("fuzz-threads", 40, "Concurrent fuzzing threads")
	scanCmd.Flags().Int("http-timeout", 10, "HTTP timeout in seconds")

	// Custom mode fuzzing settings
	scanCmd.Flags().Bool("fuzz-directories", false, "Enable directory fuzzing")
	scanCmd.Flags().Bool("fuzz-vhosts", false, "Enable vhost fuzzing")
	scanCmd.Flags().String("fuzz-wordlist", "", "Custom fuzzing wordlist path")

	// Custom mode output settings
	scanCmd.Flags().Bool("verbose", false, "Verbose output")

	// Crawl command flags
	crawlCmd.Flags().StringP("url", "u", "", "URL to crawl (required)")
	crawlCmd.Flags().IntP("depth", "D", 2, "Crawl depth limit")
	crawlCmd.MarkFlagRequired("url")

	// Export command flags
	exportCmd.Flags().StringP("target", "t", "", "Target to export data for (required)")
	exportCmd.Flags().StringP("format", "f", "json", "Output format (json, html, csv, pdf)")
	exportCmd.Flags().StringP("output", "o", "", "Output file path (optional)")
	exportCmd.MarkFlagRequired("target")

	// Fuzz command flags
	fuzzCmd.Flags().StringP("target", "t", "", "Target domain")
	fuzzCmd.Flags().StringP("url", "u", "", "Target URL")
	fuzzCmd.Flags().StringP("mode", "m", "", "Fuzzing mode: directory, vhost, subdomain (required)")
	fuzzCmd.Flags().StringP("wordlist", "w", "", "Wordlist path or 'embedded:name'")
	fuzzCmd.Flags().IntP("threads", "T", 40, "Concurrent threads")
	fuzzCmd.Flags().IntP("timeout", "x", 10, "HTTP timeout in seconds")
	fuzzCmd.Flags().IntSlice("mc", []int{200, 204, 301, 302, 307, 401, 403}, "Match HTTP status codes")
	fuzzCmd.Flags().IntSlice("fc", []int{}, "Filter HTTP status codes")
	fuzzCmd.Flags().Int("fs", 0, "Filter response size")
	fuzzCmd.Flags().Bool("follow-redirects", false, "Follow HTTP redirects")
	fuzzCmd.MarkFlagRequired("mode")

	// OSINT command flags
	osintEmailCmd.Flags().StringP("target", "t", "", "Email address to profile (required)")
	osintEmailCmd.MarkFlagRequired("target")

	osintSocialCmd.Flags().StringP("username", "u", "", "Username to search (required)")
	osintSocialCmd.MarkFlagRequired("username")

	osintDomainCmd.Flags().StringP("target", "t", "", "Domain to enrich (required)")
	osintDomainCmd.MarkFlagRequired("target")

	osintCmd.AddCommand(osintEmailCmd, osintSocialCmd, osintDomainCmd)

	rootCmd.AddCommand(scanCmd, crawlCmd, exportCmd, fuzzCmd, osintCmd)
}

func Execute() error {
	return rootCmd.Execute()
}

// ---------------------------------------------------------------------------
// OSINT command group
// ---------------------------------------------------------------------------

var osintCmd = &cobra.Command{
	Use:   "osint",
	Short: "OSINT profiling: email breaches, social presence, domain enrichment",
	Long: `OSINT Investigation commands:

  email   Profile an email address (breach check, deliverability, disposable detection)
  social  Enumerate social media presence for a username via Sherlock
  domain  Enrich a domain with Wayback Machine history, robots.txt, and Shodan data

Examples:
  gosint osint email -t user@example.com
  gosint osint social -u johndoe
  gosint osint domain -t example.com`,
}

var osintEmailCmd = &cobra.Command{
	Use:   "email",
	Short: "Profile an email address for breaches and deliverability",
	Run: func(cmd *cobra.Command, args []string) {
		email, _ := cmd.Flags().GetString("target")
		if email == "" {
			fmt.Println(" Error: --target/-t flag is required (provide email address)")
			os.Exit(1)
		}

		keys := osint.LoadAPIKeys()
		s := osint.NewEmailScanner(keys)

		ctx, cancel := CreateCancellableContext()
		defer cancel()

		fmt.Printf("\n  Profiling email: %s\n", email)
		fmt.Println(strings.Repeat("─", 50))

		profile, err := s.Profile(ctx, email)
		if err != nil {
			if ctx.Err() == context.Canceled {
				fmt.Println("\n  Scan interrupted by user")
			} else {
				fmt.Printf("\n  Email profile failed: %v\n", err)
			}
			return
		}

		printEmailProfile(profile)
		saveEmailProfileToDB(profile, 0)
	},
}

var osintSocialCmd = &cobra.Command{
	Use:   "social",
	Short: "Enumerate social media profiles for a username via Sherlock",
	Run: func(cmd *cobra.Command, args []string) {
		username, _ := cmd.Flags().GetString("username")
		if username == "" {
			fmt.Println(" Error: --username/-u flag is required")
			os.Exit(1)
		}

		s := osint.NewSocialScanner()
		if !s.IsAvailable() {
			fmt.Println(" Error: sherlock is not installed.")
			fmt.Println("   Install with: pip install sherlock-project")
			os.Exit(1)
		}

		ctx, cancel := CreateCancellableContext()
		defer cancel()

		fmt.Printf("\n  Searching social profiles for: %s\n", username)
		fmt.Println(strings.Repeat("─", 50))

		profiles, err := s.FindProfiles(ctx, username)
		if err != nil {
			if errors.Is(err, osint.ErrServiceUnavailable) {
				fmt.Printf("\n  Service unavailable: %v\n", err)
			} else if ctx.Err() == context.Canceled {
				fmt.Println("\n  Search interrupted by user")
			} else {
				fmt.Printf("\n  Social search failed: %v\n", err)
			}
			return
		}

		fmt.Printf("\n  Found %d profile(s) for '%s'\n", len(profiles), username)
		saveSocialProfilesToDB(username, profiles, 0)
	},
}

var osintDomainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Enrich a domain with Wayback Machine, robots.txt, and Shodan data",
	Run: func(cmd *cobra.Command, args []string) {
		domain, _ := cmd.Flags().GetString("target")
		if domain == "" {
			fmt.Println(" Error: --target/-t flag is required")
			os.Exit(1)
		}

		keys := osint.LoadAPIKeys()
		e := osint.NewDomainEnricher(keys)

		ctx, cancel := CreateCancellableContext()
		defer cancel()

		fmt.Printf("\n  Enriching domain: %s\n", domain)
		fmt.Println(strings.Repeat("─", 50))

		profile, err := e.Enrich(ctx, domain)
		if err != nil {
			if ctx.Err() == context.Canceled {
				fmt.Println("\n  Enrichment interrupted by user")
			} else {
				fmt.Printf("\n  Domain enrichment failed: %v\n", err)
			}
			return
		}

		printDomainProfile(profile)
	},
}

// printEmailProfile displays a formatted email profile to stdout.
func printEmailProfile(p *osint.EmailProfile) {
	fmt.Println()
	fmt.Printf("  Email          : %s\n", p.Email)
	fmt.Printf("  Disposable     : %v\n", p.Disposable)
	fmt.Printf("  Breach Count   : %d\n", p.BreachCount)

	if p.Deliverability != nil {
		d := p.Deliverability
		fmt.Printf("  Deliverable    : %s (score: %d)\n", d.Result, d.Score)
		fmt.Printf("  MX Records     : %v\n", d.MXRecords)
	}

	if len(p.Breaches) > 0 {
		fmt.Println()
		fmt.Println("  ── Breaches ─────────────────────────────")
		for _, b := range p.Breaches {
			fmt.Printf("  [!] %-25s %s  (%d accounts)\n", b.Name+":", b.BreachDate, b.PwnCount)
			if len(b.DataClasses) > 0 {
				fmt.Printf("      Data: %s\n", strings.Join(b.DataClasses, ", "))
			}
		}
	}
	fmt.Println()
}

// printDomainProfile displays a formatted domain profile to stdout.
func printDomainProfile(p *osint.DomainProfile) {
	fmt.Println()
	fmt.Printf("  Domain         : %s\n", p.Domain)
	fmt.Printf("  Wayback URLs   : %d\n", p.WaybackCount)

	if p.RobotsTxt != "" {
		lines := strings.Split(p.RobotsTxt, "\n")
		fmt.Printf("  robots.txt     : %d lines\n", len(lines))
	} else {
		fmt.Println("  robots.txt     : not found")
	}

	if p.Shodan != nil {
		s := p.Shodan
		fmt.Println()
		fmt.Println("  ── Shodan ───────────────────────────────")
		fmt.Printf("  Organization   : %s\n", s.Organization)
		fmt.Printf("  ISP            : %s\n", s.ISP)
		fmt.Printf("  Country        : %s\n", s.Country)
		fmt.Printf("  Open Ports     : %v\n", s.Ports)
		if len(s.Vulns) > 0 {
			fmt.Printf("  Vulns          : %s\n", strings.Join(s.Vulns, ", "))
		}
	}
	fmt.Println()
}

// saveEmailProfileToDB persists a scanned email profile to the database.
func saveEmailProfileToDB(profile *osint.EmailProfile, targetID uint) {
	db := storage.GetInstance()

	deliverable := ""
	score := 0
	if profile.Deliverability != nil {
		deliverable = profile.Deliverability.Result
		score = profile.Deliverability.Score
	}

	type breachRow struct {
		Name, Domain, BreachDate, DataClasses string
		PwnCount                              int
	}

	var breaches []struct {
		Name, Domain, BreachDate, DataClasses string
		PwnCount                              int
	}
	for _, b := range profile.Breaches {
		dc, _ := json.Marshal(b.DataClasses)
		breaches = append(breaches, struct {
			Name, Domain, BreachDate, DataClasses string
			PwnCount                              int
		}{b.Name, b.Domain, b.BreachDate, string(dc), b.PwnCount})
	}

	_, err := db.SaveEmailProfile(targetID, profile.Email, deliverable, score, profile.Disposable, profile.BreachCount, breaches)
	if err != nil {
		fmt.Printf("  [!] Failed to save email profile to DB: %v\n", err)
	} else {
		fmt.Println("  [+] Email profile saved to database")
	}
}

// saveSocialProfilesToDB persists social profiles to the database.
func saveSocialProfilesToDB(username string, profiles []osint.SocialProfile, targetID uint) {
	if len(profiles) == 0 {
		return
	}

	db := storage.GetInstance()
	var rows []struct {
		Platform, URL string
		Confirmed     bool
	}
	for _, p := range profiles {
		rows = append(rows, struct {
			Platform, URL string
			Confirmed     bool
		}{p.Platform, p.URL, p.Confirmed})
	}

	if err := db.SaveSocialProfiles(targetID, username, rows); err != nil {
		fmt.Printf("  [!] Failed to save social profiles to DB: %v\n", err)
	} else {
		fmt.Printf("  [+] %d social profile(s) saved to database\n", len(profiles))
	}
}
