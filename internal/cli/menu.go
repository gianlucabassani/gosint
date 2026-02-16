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

	"github.com/gianlucabassani/gosint/internal/crawler"
	"github.com/gianlucabassani/gosint/internal/fuzzer"
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

	_, err := s.Scan(ctx)
	if err != nil {
		pterm.Error.Printf("Scan failed: %v\n", err)
	}

	pressEnterToContinue(reader)
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
		if limitStr == "" { config.SubdomainLimit = 1000 } else {
			if v, err := strconv.Atoi(limitStr); err == nil { config.SubdomainLimit = v }
		}
	}

	config.EnableFuzzing = promptYesNo(reader, "Enable Fuzzing?", false)
	if config.EnableFuzzing {
		config.FuzzDirectories = promptYesNo(reader, "  Fuzz Directories?", true)
		config.FuzzVHosts = promptYesNo(reader, "  Fuzz VHosts?", false)
		
		threadStr := promptInput(reader, "  Threads (default 40): ")
		if threadStr == "" { config.FuzzThreads = 40 } else {
			if v, err := strconv.Atoi(threadStr); err == nil { config.FuzzThreads = v }
		}
	}

	return config
}

func crawlerMenu(reader *bufio.Reader) {
	clearScreen()
	printHeader("WEB CRAWLER")

	url := promptInput(reader, "Enter URL: ")
	if url == "" { return }
	
	depthStr := promptInput(reader, "Depth (default 2): ")
	depth := 2
	if d, err := strconv.Atoi(depthStr); err == nil { depth = d }

	if !strings.HasPrefix(url, "http") { url = "https://" + url }

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
	case "1": mode = fuzzer.ModeDirectory
	case "2": mode = fuzzer.ModeVHost
	case "3": mode = fuzzer.ModeSubdomain
	default: return
	}

	target := promptInput(reader, "Target: ")
	if target == "" { return }

	cfg := fuzzer.FuzzerConfig{
		Target: target,
		Mode: mode,
		Wordlist: "embedded:directories",
		Threads: 40,
		Timeout: 10,
	}
	if mode == fuzzer.ModeSubdomain { cfg.Wordlist = "embedded:subdomains" }
	if mode == fuzzer.ModeVHost { cfg.Wordlist = "embedded:vhosts" }

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
	pterm.Warning.Println("Coming in Phase 3")
	pressEnterToContinue(reader)
}

func settingsMenu(reader *bufio.Reader) {
	clearScreen()
	printHeader("SETTINGS")
	fmt.Println("1. Database Stats")
	fmt.Println("2. Clear Database")
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
	}
}

// --- Helpers ---

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