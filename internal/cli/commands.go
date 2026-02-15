package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gianlucabassani/gosint/internal/crawler"
	"github.com/gianlucabassani/gosint/internal/fuzzer"
	"github.com/gianlucabassani/gosint/internal/scanner"
	"github.com/gianlucabassani/gosint/internal/storage"
	"github.com/spf13/cobra"
)

// CreateCancellableContext creates a context that cancels on CTRL+C signal
// Used for long-running operations - Ctrl+C will cancel the operation but return to menu
func CreateCancellableContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create a local signal channel for this operation
	opSigChan := make(chan os.Signal, 1)
	signal.Notify(opSigChan, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-opSigChan
		fmt.Printf("\n\n⚠️  Received interrupt signal, stopping operation...\n\n")
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
		// If no subcommand, launch interactive menu
		if len(args) == 0 {
			LaunchInteractiveMenu()
		}
	},
}

// ✅ ENHANCED: Scan command with 4 scan modes
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a target domain with various intensity levels",
	Long: `Scan a target domain with different modes:
	
  --basic (-b):      Passive reconnaissance (DNS, WHOIS, public records)
  --deep (-d):       Deep passive scan (subdomains, tech detection, extensive enumeration)
  --stealth (-s):    Active but stealthy scan (slow, rate-limited probing)
  --aggressive (-a): Full active + passive scan (fast, comprehensive, may trigger alerts)
	
Only ONE mode can be active at a time.`,
	Run: func(cmd *cobra.Command, args []string) {
		target, _ := cmd.Flags().GetString("target")
		basic, _ := cmd.Flags().GetBool("basic")
		deep, _ := cmd.Flags().GetBool("deep")
		stealth, _ := cmd.Flags().GetBool("stealth")
		aggressive, _ := cmd.Flags().GetBool("aggressive")
		
		if target == "" {
			fmt.Println("Error: --target/-t flag is required")
			os.Exit(1)
		}
		
		// Validate only one mode is selected
		modeCount := 0
		selectedMode := "basic" // Default
		
		if basic {
			modeCount++
			selectedMode = "basic"
		}
		if deep {
			modeCount++
			selectedMode = "deep"
		}
		if stealth {
			modeCount++
			selectedMode = "stealth"
		}
		if aggressive {
			modeCount++
			selectedMode = "aggressive"
		}
		
		if modeCount > 1 {
			fmt.Println("❌ Error: Only one scan mode can be selected at a time")
			os.Exit(1)
		}
		
		// Convert mode string to scanner.ScanMode
		var mode scanner.ScanMode
		switch selectedMode {
		case "basic":
			mode = scanner.ModeBasic
		case "deep":
			mode = scanner.ModeDeep
		case "stealth":
			mode = scanner.ModeStealth
		case "aggressive":
			mode = scanner.ModeAggressive
		}
		
		// Execute the scan
		s := scanner.NewScanner(target, mode)
		
		// Create cancellable context for graceful shutdown on CTRL+C
		ctx, cancel := CreateCancellableContext()
		defer cancel()
		
		report, err := s.Scan(ctx)
		if err != nil {
			if ctx.Err() == context.Canceled {
				fmt.Printf("\n%s Scan interrupted by user\n", "⚠️")
			} else {
				fmt.Printf("\n❌ Scan failed: %v\n", err)
			}
			return
		}
		
		// After scan completes, offer report generation
		offerReportGeneration(report.Target)
	},
}

var crawlCmd = &cobra.Command{
	Use:   "crawl",
	Short: "Crawl a website for OSINT data (Emails, Phones, etc.)",
	Run: func(cmd *cobra.Command, args []string) {
		urlStr, _ := cmd.Flags().GetString("url")
		depth, _ := cmd.Flags().GetInt("depth")
		
		if urlStr == "" {
			fmt.Println("❌ Error: --url/-u flag is required")
			os.Exit(1)
		}
		
		// Add protocol if missing
		if !strings.HasPrefix(urlStr, "http") {
			urlStr = "https://" + urlStr
		}

		// Create target in DB to attach results
		db := storage.GetInstance()
		targetObj, _ := db.CreateOrUpdateTarget(urlStr, "url")
		
		fmt.Printf("🕷️  Starting OSINT Crawl: %s (Depth: %d)\n", urlStr, depth)

		config := crawler.CrawlerConfig{
			TargetURL:     urlStr,
			MaxDepth:      depth,
			MaxConcurrent: 10,
			Timeout:       5 * time.Second,
			TargetID:      targetObj.ID,
		}

		// Create cancellable context for graceful shutdown on CTRL+C
		ctx, cancel := CreateCancellableContext()
		defer cancel()

		c := crawler.NewCrawler(config)
		results, err := c.Start(ctx)
		if err != nil {
			if ctx.Err() == context.Canceled {
				fmt.Printf("\n%s Crawl interrupted by user\n", "⚠️")
			} else {
				fmt.Printf("\n❌ Crawl failed: %v\n", err)
			}
			return
		}

		// Summary
		var emails, phones int
		for _, r := range results {
			emails += len(r.OSINT.Emails)
			phones += len(r.OSINT.Phones)
		}

		fmt.Printf("\n✅ Crawl Complete\n")
		fmt.Printf("   Pages Visited: %d\n", len(results))
		fmt.Printf("   Emails Found:  %d\n", emails)
		fmt.Printf("   Phones Found:  %d\n", phones)
		fmt.Printf("   Data saved to database for target ID: %d\n", targetObj.ID)
		
		offerReportGeneration(urlStr)
	},
}

func printScanModeInfo(mode string) {
	modeInfo := map[string]string{
		"basic":      " BASIC: DNS lookups, WHOIS, public records (fully passive)",
		"deep":       " DEEP: Extended enumeration, subdomain discovery, tech fingerprinting (passive)",
		"stealth":    " STEALTH: Low-profile active probing, rate-limited (may be detected)",
		"aggressive": " AGGRESSIVE: Full active + passive scan, fast & comprehensive (will be detected)",
	}
	
	fmt.Println(modeInfo[mode])
}

func offerReportGeneration(target string) {
	fmt.Println("\n" + strings.Repeat("─", 50))
	fmt.Println("📊 Scan completed! Generate report?")
	fmt.Println("Available formats: JSON, HTML, CSV, PDF")
	fmt.Println("Run: gosint export --target " + target + " --format [json|html|csv|pdf]")
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
			fmt.Println("❌ Error: --target flag is required")
			os.Exit(1)
		}
		
		// Validate format
		validFormats := []string{"json", "html", "csv", "pdf"}
		isValid := false
		for _, f := range validFormats {
			if format == f {
				isValid = true
				break
			}
		}
		
		if !isValid {
			fmt.Printf("❌ Error: Invalid format '%s'. Choose: json, html, csv, pdf\n", format)
			os.Exit(1)
		}
		
		fmt.Printf("Exporting %s report for %s\n", format, target)
		if output != "" {
			fmt.Printf("Output: %s\n", output)
		}
		
		// TODO: Implement export logic in Phase 2
		fmt.Println("⚠  Export feature coming in Phase 2")
	},
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
			fmt.Println("❌ Error: --url or --target is required")
			os.Exit(1)
		}

		if modeStr == "" {
			fmt.Println("❌ Error: --mode is required (directory, vhost, subdomain)")
			os.Exit(1)
		}

		// Map CLI mode string to fuzzer mode enum
		var mode fuzzer.FuzzMode
		switch modeStr {
		case "directory":
			mode = fuzzer.ModeDirectory
		case "vhost":
			mode = fuzzer.ModeVHost
		case "subdomain":
			mode = fuzzer.ModeSubdomain
		default:
			fmt.Println("❌ Error: Invalid mode. Use directory, vhost, or subdomain")
			os.Exit(1)
		}

		if wordlist == "" {
			// Auto-select embedded lists
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

		fmt.Printf("🎯 Starting %s fuzzing on %s\n", modeStr, effectiveTarget)
		fmt.Printf("   Wordlist: %s\n", wordlist)
		fmt.Printf("   Threads: %d\n", threads)

		// Create cancellable context for graceful shutdown on CTRL+C
		ctx, cancel := CreateCancellableContext()
		defer cancel()

		f := fuzzer.NewFuzzer(config)
		results, err := f.Start(ctx)
		if err != nil {
			if ctx.Err() == context.Canceled {
				fmt.Printf("\n%s Fuzzing interrupted by user\n", "⚠️")
			} else {
				fmt.Printf("\n❌ Fuzzing failed: %v\n", err)
			}
			return
		}

		fmt.Printf("\n✨ Fuzzing Complete: Found %d items\n", len(results))
		
		// TODO: Save to DB (Phase 3 enhancement)
	},
}

func init() {
	scanCmd.Flags().StringP("target", "t", "", "Target domain to scan (required)")
	scanCmd.Flags().BoolP("basic", "b", false, "Basic passive scan (default)")
	scanCmd.Flags().BoolP("deep", "d", false, "Deep passive scan")
	scanCmd.Flags().BoolP("stealth", "s", false, "Stealth active scan")
	scanCmd.Flags().BoolP("aggressive", "a", false, "Aggressive active + passive scan")
	scanCmd.MarkFlagRequired("target")
	
	// Crawl command flags
	crawlCmd.Flags().StringP("url", "u", "", "URL to crawl (required)")
	crawlCmd.Flags().IntP("depth", "D", 2, "Crawl depth limit")
	crawlCmd.MarkFlagRequired("url")
	
	exportCmd.Flags().StringP("target", "t", "", "Target to export data for (required)")
	exportCmd.Flags().StringP("format", "f", "json", "Output format (json, html, csv, pdf)")
	exportCmd.Flags().StringP("output", "o", "", "Output file path (optional, defaults to ./reports/)")
	exportCmd.MarkFlagRequired("target")
	
	fuzzCmd.Flags().StringP("target", "t", "", "Target domain (for subdomain/vhost fuzzing)")
	fuzzCmd.Flags().StringP("url", "u", "", "Target URL (for directory fuzzing)")
	fuzzCmd.Flags().StringP("mode", "m", "", "Fuzzing mode: directory, vhost, subdomain (required)")
	fuzzCmd.Flags().StringP("wordlist", "w", "", "Path to wordlist or 'embedded:name' (auto-selects if empty)")
	fuzzCmd.Flags().IntP("threads", "T", 40, "Number of concurrent threads")
	fuzzCmd.Flags().IntP("timeout", "x", 10, "HTTP timeout in seconds")
	fuzzCmd.Flags().IntSlice("mc", []int{200, 204, 301, 302, 307, 401, 403}, "Match HTTP status codes")
	fuzzCmd.Flags().IntSlice("fc", []int{}, "Filter HTTP status codes")
	fuzzCmd.Flags().Int("fs", 0, "Filter response size")
	fuzzCmd.Flags().Bool("follow-redirects", false, "Follow HTTP redirects")
	fuzzCmd.MarkFlagRequired("mode")

	// Add subcommands to root
	rootCmd.AddCommand(scanCmd, crawlCmd, exportCmd, fuzzCmd)
}

func Execute() error {
	return rootCmd.Execute()
}