package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gianlucabassani/gosint/internal/config"
	"github.com/gianlucabassani/gosint/internal/crawler"
	"github.com/gianlucabassani/gosint/internal/fuzzer"
	"github.com/gianlucabassani/gosint/internal/osint"
	"github.com/gianlucabassani/gosint/internal/scanner"
	"github.com/gianlucabassani/gosint/internal/storage"
	"github.com/pterm/pterm"
)

func LaunchInteractiveMenu() {
	showBanner()

	reader := bufio.NewReader(os.Stdin)
	running := true

	// Set up signal handler for menu
	menuSigChan := make(chan os.Signal, 1)
	signal.Notify(menuSigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-menuSigChan
		fmt.Println("\nExiting GOSINT...")
		os.Exit(0)
	}()

	for running {
		showMainMenu()
		choice := promptInput(reader, pterm.Cyan("Choice: "))

		switch choice {
		case "1":
			domainReconMenu(reader)
		case "2":
			crawlerMenu(reader)
		case "3":
			fuzzingMenu(reader)
		case "4":
			osintMenu(reader)
		case "5":
			settingsMenu(reader)
		case "0":
			running = false
		default:
			pterm.Error.Println("Invalid choice.")
		}
	}
}

func showBanner() {
	clearScreen()
	banner := `
 ██████╗  ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔════╝ ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║  ███╗██║   ██║███████╗██║██╔██╗ ██║   ██║   
██║   ██║██║   ██║╚════██║██║██║╚██╗██║   ██║   
╚██████╔╝╚██████╔╝███████║██║██║ ╚████║   ██║   
 ╚═════╝  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
`
	fmt.Println(pterm.LightCyan(banner))
	fmt.Println(pterm.Yellow(" GOSINT - Open Source Intelligence Toolkit"))
	fmt.Println(pterm.Cyan(" ----------------------------------------"))
}

func showMainMenu() {
	fmt.Println()
	printHeader("MAIN MENU")
	fmt.Println("1. Domain Reconnaissance")
	fmt.Println("2. Web Crawler & OSINT Scraping")
	fmt.Println("3. Fuzzing")
	fmt.Println("4. OSINT Investigation")
	fmt.Println("5. Settings")
	fmt.Println("0. Exit")
	fmt.Println()
}

func domainReconMenu(reader *bufio.Reader) {
	clearScreen()
	printHeader("DOMAIN RECONNAISSANCE")

	domain := promptInput(reader, "Enter domain: ")
	if domain == "" {
		return
	}

	fmt.Println("\nSelect Scan Mode:")
	fmt.Println("1. Basic      (Passive: DNS, WHOIS, Tech)")
	fmt.Println("2. Deep       (Passive: Basic + Archives)")
	fmt.Println("3. Stealth    (Active:  Slow enumeration)")
	fmt.Println("4. Aggressive (Active:  Fast enumeration + Fuzzing)")
	fmt.Println("5. Custom     (Configure manually)")

	modeChoice := promptInput(reader, pterm.Cyan("Mode: "))
	var config scanner.ScanConfig

	// Default values
	config.Target = domain
	config.HTTPTimeout = 10
	config.ShowProgress = true
	config.SaveToDB = true

	switch modeChoice {
	case "1":
		config.Mode = scanner.ModeBasic
		config.EnableDNS = true
		config.EnableWHOIS = true
		config.EnableTechDetection = true
	case "2":
		config.Mode = scanner.ModeDeep
		config.EnableDNS = true
		config.EnableWHOIS = true
		config.EnableTechDetection = true
		config.EnablePassive = true
	case "3":
		config.Mode = scanner.ModeStealth
		config.EnableDNS = true
		config.EnableTechDetection = true
		config.EnablePassive = true
		config.EnableSubdomains = true
		config.SubdomainLimit = 50
		config.SubdomainThreads = 5
	case "4":
		config.Mode = scanner.ModeAggressive
		config.EnableDNS = true
		config.EnableTechDetection = true
		config.EnablePassive = true
		config.EnableSubdomains = true
		config.SubdomainLimit = 1000
		config.EnableFuzzing = true
		config.FuzzDirectories = true
		config.FuzzThreads = 50
	case "5":
		config = buildCustomScanConfig(reader, domain)
	default:
		pterm.Error.Println("Invalid mode.")
		return
	}

	s := scanner.NewScanner(config)
	ctx, cancel := CreateCancellableContext()
	defer cancel()

	// Capture report to get correct target name/domain
	report, err := s.Scan(ctx)
	if err != nil {
		pterm.Error.Printf("Scan failed: %v\n", err)
	}

	if report != nil {
		handleReportExport(reader, report.Target)
	} else {
		handleReportExport(reader, domain) // Fallback
	}

	pressEnterToContinue(reader)
}

func handleReportExport(reader *bufio.Reader, target string) {
	fmt.Println()
	printHeader("REPORT GENERATION")
	fmt.Println("Select format to export:")
	fmt.Println("1. JSON")
	fmt.Println("2. HTML")
	fmt.Println("3. CSV")
	fmt.Println("4. PDF")
	fmt.Println("5. All Formats")
	fmt.Println("0. Skip")

	choice := promptInput(reader, pterm.Cyan("Choice: "))

	switch choice {
	case "1":
		ExecuteExport(target, "json", "")
	case "2":
		ExecuteExport(target, "html", "")
	case "3":
		ExecuteExport(target, "csv", "")
	case "4":
		ExecuteExport(target, "pdf", "")
	case "5":
		formats := []string{"json", "html", "csv", "pdf"}
		for _, f := range formats {
			ExecuteExport(target, f, "")
		}
	default:
		// Skip
	}
}

// buildCustomScanConfig creates a config via simple y/n prompts
func buildCustomScanConfig(reader *bufio.Reader, domain string) scanner.ScanConfig {
	fmt.Println("\n-- Custom Configuration --")

	config := scanner.ScanConfig{
		Target:       domain,
		Mode:         scanner.ModeCustom,
		SaveToDB:     true,
		ShowProgress: true,
		Verbose:      true,
	}

	config.EnableDNS = promptYesNo(reader, "Enable DNS enumeration?", true)
	config.EnableWHOIS = promptYesNo(reader, "Enable WHOIS lookup?", true)
	config.EnableTechDetection = promptYesNo(reader, "Enable Tech Detection?", true)
	config.EnablePassive = promptYesNo(reader, "Enable Passive Recon (crt.sh/Wayback)?", true)

	config.EnableSubdomains = promptYesNo(reader, "Enable Active Subdomain Enumeration?", false)
	if config.EnableSubdomains {
		limitStr := promptInput(reader, "  Limit (default 1000): ")
		if limitStr == "" {
			config.SubdomainLimit = 1000
		} else {
			if v, err := strconv.Atoi(limitStr); err == nil {
				config.SubdomainLimit = v
			}
		}
	}

	config.EnableFuzzing = promptYesNo(reader, "Enable Fuzzing?", false)
	if config.EnableFuzzing {
		config.FuzzDirectories = promptYesNo(reader, "  Fuzz Directories?", true)
		config.FuzzVHosts = promptYesNo(reader, "  Fuzz VHosts?", false)

		threadStr := promptInput(reader, "  Threads (default 40): ")
		if threadStr == "" {
			config.FuzzThreads = 40
		} else {
			if v, err := strconv.Atoi(threadStr); err == nil {
				config.FuzzThreads = v
			}
		}
	}

	return config
}

func crawlerMenu(reader *bufio.Reader) {
	clearScreen()
	printHeader("WEB CRAWLER")

	url := promptInput(reader, "Enter URL: ")
	if url == "" {
		return
	}

	depthStr := promptInput(reader, "Depth (default 2): ")
	depth := 2
	if d, err := strconv.Atoi(depthStr); err == nil {
		depth = d
	}

	if !strings.HasPrefix(url, "http") {
		url = "https://" + url
	}

	printHeader(fmt.Sprintf("CRAWLING: %s", url))

	db := storage.GetInstance()
	targetObj, _ := db.CreateOrUpdateTarget(url, "url")

	cfg := crawler.CrawlerConfig{
		TargetURL:     url,
		MaxDepth:      depth,
		MaxConcurrent: 10,
		Timeout:       5 * time.Second,
		TargetID:      targetObj.ID,
	}

	ctx, cancel := CreateCancellableContext()
	defer cancel()

	c := crawler.NewCrawler(cfg)
	results, err := c.Start(ctx)

	if err != nil {
		pterm.Error.Printf("Crawl failed: %v\n", err)
	} else {
		// Calculate stats
		emails, phones := 0, 0
		for _, r := range results {
			emails += len(r.OSINT.Emails)
			phones += len(r.OSINT.Phones)
		}

		fmt.Println()
		pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(pterm.TableData{
			{"Metric", "Count"},
			{"Pages Visited", fmt.Sprintf("%d", len(results))},
			{"Emails", fmt.Sprintf("%d", emails)},
			{"Phones", fmt.Sprintf("%d", phones)},
		}).Render()
	}
	pressEnterToContinue(reader)
}

func fuzzingMenu(reader *bufio.Reader) {
	clearScreen()
	printHeader("FUZZING")
	fmt.Println("1. Directories")
	fmt.Println("2. Virtual Hosts")
	fmt.Println("3. Subdomains")

	choice := promptInput(reader, pterm.Cyan("Mode: "))
	var mode fuzzer.FuzzMode

	switch choice {
	case "1":
		mode = fuzzer.ModeDirectory
	case "2":
		mode = fuzzer.ModeVHost
	case "3":
		mode = fuzzer.ModeSubdomain
	default:
		return
	}

	target := promptInput(reader, "Target: ")
	if target == "" {
		return
	}

	cfg := fuzzer.FuzzerConfig{
		Target:   target,
		Mode:     mode,
		Wordlist: "embedded:directories",
		Threads:  40,
		Timeout:  10,
	}
	if mode == fuzzer.ModeSubdomain {
		cfg.Wordlist = "embedded:subdomains"
	}
	if mode == fuzzer.ModeVHost {
		cfg.Wordlist = "embedded:vhosts"
	}

	ctx, cancel := CreateCancellableContext()
	defer cancel()

	f := fuzzer.NewFuzzer(cfg)
	_, err := f.Start(ctx)
	if err != nil {
		pterm.Error.Printf("Fuzzing error: %v\n", err)
	}
	pressEnterToContinue(reader)
}

func osintMenu(reader *bufio.Reader) {
	for {
		clearScreen()
		printHeader("OSINT INVESTIGATION")
		fmt.Println("1. Email Profile    (breaches, deliverability, disposable check)")
		fmt.Println("2. Social Search    (enumerate platforms via Sherlock)")
		fmt.Println("3. Domain Enrichment (Wayback Machine, robots.txt, Shodan)")
		fmt.Println("0. Back")
		fmt.Println()

		choice := promptInput(reader, pterm.Cyan("Choice: "))

		switch choice {
		case "1":
			osintEmailMenu(reader)
		case "2":
			osintSocialMenu(reader)
		case "3":
			osintDomainMenu(reader)
		case "0":
			return
		default:
			pterm.Error.Println("Invalid choice.")
			time.Sleep(1 * time.Second)
		}
	}
}

func osintEmailMenu(reader *bufio.Reader) {
	clearScreen()
	printHeader("EMAIL PROFILE")

	email := promptInput(reader, "Enter email address: ")
	if email == "" {
		return
	}

	keys := osint.LoadAPIKeys()
	s := osint.NewEmailScanner(keys)

	ctx, cancel := CreateCancellableContext()
	defer cancel()

	fmt.Printf("\n  Profiling: %s\n", email)
	fmt.Println()

	profile, err := s.Profile(ctx, email)
	if err != nil {
		pterm.Error.Printf("Email profile failed: %v\n", err)
		pressEnterToContinue(reader)
		return
	}

	printEmailProfile(profile)

	if promptYesNo(reader, "Save to database?", true) {
		saveEmailProfileToDB(profile, 0)
	}

	pressEnterToContinue(reader)
}

func osintSocialMenu(reader *bufio.Reader) {
	clearScreen()
	printHeader("SOCIAL SEARCH")

	s := osint.NewSocialScanner()
	if !s.IsAvailable() {
		pterm.Warning.Println("Sherlock is not installed.")
		pterm.Info.Println("Install it with: pip install sherlock-project")
		pressEnterToContinue(reader)
		return
	}

	username := promptInput(reader, "Enter username: ")
	if username == "" {
		return
	}

	ctx, cancel := CreateCancellableContext()
	defer cancel()

	fmt.Printf("\n  Searching profiles for: %s\n", username)
	fmt.Println()

	profiles, err := s.FindProfiles(ctx, username)
	if err != nil {
		pterm.Error.Printf("Social search failed: %v\n", err)
		pressEnterToContinue(reader)
		return
	}

	fmt.Printf("\n  Found %d confirmed profile(s)\n", len(profiles))

	if len(profiles) > 0 && promptYesNo(reader, "Save to database?", true) {
		saveSocialProfilesToDB(username, profiles, 0)
	}

	pressEnterToContinue(reader)
}

func osintDomainMenu(reader *bufio.Reader) {
	clearScreen()
	printHeader("DOMAIN ENRICHMENT")

	domain := promptInput(reader, "Enter domain: ")
	if domain == "" {
		return
	}

	keys := osint.LoadAPIKeys()
	e := osint.NewDomainEnricher(keys)

	ctx, cancel := CreateCancellableContext()
	defer cancel()

	fmt.Printf("\n  Enriching: %s\n", domain)
	fmt.Println()

	profile, err := e.Enrich(ctx, domain)
	if err != nil {
		pterm.Error.Printf("Domain enrichment failed: %v\n", err)
		pressEnterToContinue(reader)
		return
	}

	printDomainProfile(profile)
	pressEnterToContinue(reader)
}

func settingsMenu(reader *bufio.Reader) {
	clearScreen()
	printHeader("SETTINGS")
	fmt.Println("1. Database Stats")
	fmt.Println("2. Clear Database")
	fmt.Println("3. Manage API Keys")
	fmt.Println("0. Back")

	choice := promptInput(reader, pterm.Cyan("Choice: "))
	db := storage.GetInstance()

	if choice == "1" {
		stats := db.GetDatabaseStats()
		fmt.Println()
		for k, v := range stats {
			fmt.Printf("%-15s : %d\n", k, v)
		}
		pressEnterToContinue(reader)
	} else if choice == "2" {
		confirm := promptInput(reader, pterm.Red("Type 'DELETE' to confirm: "))
		if confirm == "DELETE" {
			db.ClearAllTables()
			pterm.Success.Println("Database cleared.")
		}
		pressEnterToContinue(reader)
	} else if choice == "3" {
		apiKeyMenu(reader)
	}
}

// --- Helpers ---

func apiKeyMenu(reader *bufio.Reader) {
	for {
		clearScreen()
		printHeader("MANAGE API KEYS")

		status := config.GetAPIKeyStatus()

		pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(pterm.TableData{
			{"Service", "Status"},
			{"1. Shodan", getStatusColor(status["SHODAN_API_KEY"])},
			{"2. Hunter.io", getStatusColor(status["HUNTER_API_KEY"])},
			{"3. HaveIBeenPwned", getStatusColor(status["HIBP_API_KEY"])},
		}).Render()

		fmt.Println("\n0. Back")

		choice := promptInput(reader, pterm.Cyan("\nSelect service to update (0-3): "))

		var keyName string
		switch choice {
		case "1":
			keyName = "SHODAN_API_KEY"
		case "2":
			keyName = "HUNTER_API_KEY"
		case "3":
			keyName = "HIBP_API_KEY"
		case "0":
			return
		default:
			pterm.Error.Println("Invalid choice.")
			time.Sleep(1 * time.Second)
			continue
		}

		fmt.Println()
		apiKey, err := pterm.DefaultInteractiveTextInput.WithMask("*").Show("Enter API Key")
		if err != nil {
			pterm.Error.Printf("Error reading input: %v\n", err)
			time.Sleep(2 * time.Second)
			continue
		}

		apiKey = strings.TrimSpace(apiKey)
		if apiKey == "" {
			pterm.Warning.Println("Empty API Key entirely. Not updating.")
			time.Sleep(2 * time.Second)
			continue
		}

		if err := config.SaveAPIKey(keyName, apiKey); err != nil {
			pterm.Error.Printf("Failed to save API Key: %v\n", err)
			time.Sleep(2 * time.Second)
		} else {
			pterm.Success.Printf("Successfully updated %s\n", keyName)
			time.Sleep(2 * time.Second)
		}
	}
}

func getStatusColor(isConfigured bool) string {
	if isConfigured {
		return pterm.Green("Configured")
	}
	return pterm.Red("Not Configured")
}

func printHeader(title string) {
	fmt.Printf("%s\n", pterm.Blue("═══════════════════════════════════════════════════"))
	fmt.Printf("█ %s\n", pterm.Blue(title))
	fmt.Printf("%s\n", pterm.Blue("═══════════════════════════════════════════════════"))
}

func promptInput(reader *bufio.Reader, text string) string {
	fmt.Print(text)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func promptYesNo(reader *bufio.Reader, prompt string, defaultYes bool) bool {
	suffix := " [Y/n]: "
	if !defaultYes {
		suffix = " [y/N]: "
	}

	response := promptInput(reader, prompt+suffix)
	response = strings.ToLower(response)

	if response == "" {
		return defaultYes
	}
	return response == "y" || response == "yes"
}

func pressEnterToContinue(reader *bufio.Reader) {
	fmt.Println()
	fmt.Print(pterm.Cyan("Press ENTER to continue..."))
	reader.ReadString('\n')
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}
