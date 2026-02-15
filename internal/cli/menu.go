package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	
	"github.com/fatih/color"
	"github.com/gianlucabassani/gosint/internal/crawler"
	"github.com/gianlucabassani/gosint/internal/fuzzer"
	"github.com/gianlucabassani/gosint/internal/scanner"
	"github.com/gianlucabassani/gosint/internal/storage"
)

var (
	cyan    = color.New(color.FgCyan).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	blue    = color.New(color.FgBlue).SprintFunc()
)

func LaunchInteractiveMenu() {
	showBanner()
	
	reader := bufio.NewReader(os.Stdin)
	running := true
	
	// Set up signal handler for the menu
	// Ctrl+C while in menu will exit the program
	menuSigChan := make(chan os.Signal, 1)
	signal.Notify(menuSigChan, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-menuSigChan
		fmt.Println(yellow("\n👋 Thanks for using GOSINT! Goodbye!"))
		os.Exit(0)
	}()
	
	for running {
		showMainMenu()
		choice := promptInput(reader, cyan("Choice: "))
		
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
			fmt.Println(yellow("\n👋 Thanks for using GOSINT! Goodbye!"))
			running = false
		default:
			fmt.Println(red("✗ Invalid choice. Please try again."))
			pressEnterToContinue(reader)
		}
	}
}

func showBanner() {
	clearScreen()
	banner := cyan(`
 ██████╗  ██████╗ ███████╗██╗███╗   ██╗████████╗
██╔════╝ ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
██║  ███╗██║   ██║███████╗██║██╔██╗ ██║   ██║   
██║   ██║██║   ██║╚════██║██║██║╚██╗██║   ██║   
╚██████╔╝╚██████╔╝███████║██║██║ ╚████║   ██║   
 ╚═════╝  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
`) + yellow("         GO Intelligence Toolkit\n")
	
	fmt.Println(banner)
}

func showMainMenu() {
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "MAIN MENU")
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(yellow("1."), "Domain Reconnaissance")
	fmt.Println(yellow("2."), "Web Crawler & OSINT Scraping")
	fmt.Println(yellow("3."), "Fuzzing") 
	fmt.Println(yellow("4."), "OSINT Investigation")
	fmt.Println(yellow("5."), "Settings")
	fmt.Println()
	fmt.Println(yellow("0."), "Exit")
	fmt.Println()
}

func domainReconMenu(reader *bufio.Reader) {
	clearScreen()
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "DOMAIN RECONNAISSANCE")
	fmt.Println(blue("═══════════════════════════════════════════════════"))

	domain := promptInput(reader, cyan("Enter domain: "))
	if domain == "" {
		fmt.Println(red("✗ Domain cannot be empty"))
		pressEnterToContinue(reader)
		return
	}

	fmt.Println("\n" + yellow("Select scan mode:"))
	fmt.Println("  1. Basic (passive only)")
	fmt.Println("  2. Deep (passive + enumeration)")
	fmt.Println("  3. Stealth (careful active probing)")
	fmt.Println("  4. Aggressive (full scan)")

	modeChoice := promptInput(reader, cyan("Mode: "))
	var mode scanner.ScanMode
	switch modeChoice {
	case "1": mode = scanner.ModeBasic
	case "2": mode = scanner.ModeDeep
	case "3": mode = scanner.ModeStealth
	case "4": mode = scanner.ModeAggressive
	default: mode = scanner.ModeBasic
	}
	
	fmt.Printf("\n%s\n", blue("═══════════════════════════════════════════════════"))
	fmt.Printf("█ Starting %s scan for: %s\n", mode, domain)
	fmt.Printf("%s\n", blue("═══════════════════════════════════════════════════"))

	s := scanner.NewScanner(domain, mode)
	// Create cancellable context for graceful shutdown on CTRL+C
	ctx, cancel := CreateCancellableContext()
	defer cancel()
	
	_, err := s.Scan(ctx)
	if err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Printf("\n%s Scan interrupted by user\n", yellow("⚠️"))
		} else {
			fmt.Printf("\n%s Scan failed: %v\n", red("❌"), err)
		}
	}

	pressEnterToContinue(reader)
}

func crawlerMenu(reader *bufio.Reader) {
	clearScreen()
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "WEB CRAWLER - OSINT Data Extraction")
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	
	url := promptInput(reader, cyan("Enter URL: "))
	if url == "" { return }
	
	depthStr := promptInput(reader, cyan("Crawl depth (default: 2): "))
	depth := 2
	if depthStr != "" {
		if d, err := strconv.Atoi(depthStr); err == nil {
			depth = d
		}
	}
	
	if !strings.HasPrefix(url, "http") { url = "https://" + url }

	fmt.Printf("\n%s Starting OSINT Crawl: %s (Depth: %d)\n", green("✓"), url, depth)
	fmt.Printf("%s Extracting emails, phones, and metadata...\n", yellow("→"))
	
	// Create target DB entry
	db := storage.GetInstance()
	targetObj, _ := db.CreateOrUpdateTarget(url, "url")

	// Configure Crawler
	cfg := crawler.CrawlerConfig{
		TargetURL:     url,
		MaxDepth:      depth,
		MaxConcurrent: 10,
		Timeout:       5 * time.Second,
		TargetID:      targetObj.ID,
	}

	// Create cancellable context for graceful shutdown on CTRL+C
	ctx, cancel := CreateCancellableContext()
	defer cancel()

	c := crawler.NewCrawler(cfg)
	results, err := c.Start(ctx)
	
	if err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Printf("\n%s Crawl interrupted by user\n", yellow("⚠️"))
		} else {
			fmt.Printf("\n%s Crawl failed: %v\n", red("✗"), err)
		}
	} else {
		emails := 0
		phones := 0
		for _, r := range results {
			emails += len(r.OSINT.Emails)
			phones += len(r.OSINT.Phones)
		}

		fmt.Printf("\n\n%s CRAWL RESULTS\n", blue("═══════════════════════════════════════════════════"))
		fmt.Printf("  Pages Visited: %d\n", len(results))
		fmt.Printf("  Emails Found:  %d\n", emails)
		fmt.Printf("  Phones Found:  %d\n", phones)
		fmt.Printf("  Data saved to database (Target ID: %d)\n", targetObj.ID)
		fmt.Printf("%s\n\n", blue("═══════════════════════════════════════════════════"))
	}
	
	pressEnterToContinue(reader)
}

func fuzzingMenu(reader *bufio.Reader) {
	clearScreen()
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "FUZZING")
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(yellow("1."), "Directory Fuzzing (Web Paths)")
	fmt.Println(yellow("2."), "Virtual Host Fuzzing")
	fmt.Println(yellow("3."), "Subdomain Fuzzing (DNS)")
	fmt.Println(yellow("0."), "Back to Main Menu")
	fmt.Println()

	choice := promptInput(reader, cyan("Choice: "))

	switch choice {
	case "1":
		runInteractiveFuzz(reader, fuzzer.ModeDirectory)
	case "2":
		runInteractiveFuzz(reader, fuzzer.ModeVHost)
	case "3":
		runInteractiveFuzz(reader, fuzzer.ModeSubdomain)
	case "0":
		return
	default:
		fmt.Println(red("✗ Invalid choice"))
		pressEnterToContinue(reader)
	}
}

func runInteractiveFuzz(reader *bufio.Reader, mode fuzzer.FuzzMode) {
	clearScreen()
	title := "DIRECTORY FUZZING"
	targetPrompt := "Target URL (e.g., https://example.com): "
	
	if mode == fuzzer.ModeVHost {
		title = "VHOST FUZZING"
		targetPrompt = "Target Domain/IP: "
	} else if mode == fuzzer.ModeSubdomain {
		title = "SUBDOMAIN FUZZING"
		targetPrompt = "Target Domain: "
	}

	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), title)
	fmt.Println(blue("═══════════════════════════════════════════════════"))

	target := promptInput(reader, cyan(targetPrompt))
	if target == "" {
		fmt.Println(red("✗ Target cannot be empty"))
		pressEnterToContinue(reader)
		return
	}

	wordlist := selectWordlist(reader, mode)
	
	threadsStr := promptInput(reader, cyan("Threads (default: 40): "))
	threads := 40
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil {
			threads = t
		}
	}

	config := fuzzer.FuzzerConfig{
		Target:     target,
		Mode:       mode,
		Wordlist:   wordlist,
		Threads:    threads,
		Timeout:    10,
		MatchCodes: []int{200, 204, 301, 302, 307, 401, 403},
	}

	fmt.Printf("\n%s Starting fuzzing...\n", green("✓"))
	// Create cancellable context for graceful shutdown on CTRL+C
	ctx, cancel := CreateCancellableContext()
	defer cancel()
	
	f := fuzzer.NewFuzzer(config)
	results, err := f.Start(ctx)
	if err != nil {
		if ctx.Err() == context.Canceled {
			fmt.Printf("\n%s Fuzzing interrupted by user\n", yellow("⚠️"))
		} else {
			fmt.Printf("\n%s Error: %v\n", red("✗"), err)
		}
	} else {
		fmt.Printf("\n%s Fuzzing complete. Found %d items.\n", green("✓"), len(results))
	}

	pressEnterToContinue(reader)
}

func selectWordlist(reader *bufio.Reader, mode fuzzer.FuzzMode) string {
	fmt.Println("\n" + yellow("Wordlist options:"))
	fmt.Println("  1. Default Embedded List")
	fmt.Println("  2. Custom file path")

	choice := promptInput(reader, cyan("Wordlist choice: "))
	if choice == "2" {
		path := promptInput(reader, cyan("Enter wordlist path: "))
		if path == "" {
			fmt.Println(red("✗ Path cannot be empty, using default"))
		} else {
			return path
		}
	}

	switch mode {
	case fuzzer.ModeDirectory: return "embedded:directories"
	case fuzzer.ModeSubdomain: return "embedded:subdomains"
	case fuzzer.ModeVHost:     return "embedded:vhosts"
	}
	return "embedded:directories"
}

func osintMenu(reader *bufio.Reader) {
	clearScreen()
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "OSINT INVESTIGATION")
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(yellow("1."), "Profile Domain")
	fmt.Println(yellow("2."), "Profile Email")
	fmt.Println(yellow("3."), "Profile Username")
	fmt.Println(yellow("0."), "Back")
	fmt.Println()
	
	choice := promptInput(reader, cyan("Choice: "))
	
	switch choice {
	case "1", "2", "3":
		fmt.Println(yellow("⚠  OSINT features will be implemented in Phase 3"))
		pressEnterToContinue(reader)
	case "0":
		return
	default:
		fmt.Println(red("✗ Invalid choice"))
		pressEnterToContinue(reader)
	}
}

func settingsMenu(reader *bufio.Reader) {
	clearScreen()
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "SETTINGS")
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(yellow("1."), "Database Management")
	fmt.Println(yellow("2."), "API Keys Configuration")
	fmt.Println(yellow("3."), "Scan Preferences")
	fmt.Println(yellow("4."), "Export Settings")
	fmt.Println(yellow("0."), "Back to Main Menu")
	fmt.Println()
	
	choice := promptInput(reader, cyan("Choice: "))
	
	switch choice {
	case "1":
		databaseManagementMenu(reader)
	case "2", "3", "4":
		fmt.Println(yellow("⚠  This feature will be implemented in Phase 3"))
		pressEnterToContinue(reader)
	case "0":
		return
	default:
		fmt.Println(red("✗ Invalid choice"))
		pressEnterToContinue(reader)
	}
}

func databaseManagementMenu(reader *bufio.Reader) {
	db := storage.GetInstance()

	for {
		clearScreen()
		fmt.Println(blue("═══════════════════════════════════════════════════"))
		fmt.Println(blue("█"), "DATABASE MANAGEMENT")
		fmt.Println(blue("═══════════════════════════════════════════════════"))
		fmt.Println(yellow("1."), "View Database Statistics")
		fmt.Println(yellow("2."), "Clear Specific Table")
		fmt.Println(yellow("3."), "Clear All Data (Reset DB)")
		fmt.Println(yellow("0."), "Back to Main Menu")
		fmt.Println()
		
		choice := promptInput(reader, cyan("Choice: "))
		
		switch choice {
		case "1":
			showDatabaseStats(reader, db)
		case "2":
			clearTableMenu(reader, db)
		case "3":
			clearAllData(reader, db)
		case "0":
			return
		default:
			fmt.Println(red("✗ Invalid choice"))
			pressEnterToContinue(reader)
		}
	}
}

func showDatabaseStats(reader *bufio.Reader, db *storage.Database) {
	stats := db.GetDatabaseStats()
	
	fmt.Println("\n" + blue("📊 Database Statistics"))
	fmt.Println(strings.Repeat("─", 30))
	
	// Print in a specific order for better readability
	keys := []string{"targets", "subdomains", "technologies", "scans", "fuzzing_hits"}
	for _, key := range keys {
		val := stats[key]
		// Capitalize first letter
		label := strings.Title(strings.ReplaceAll(key, "_", " "))
		fmt.Printf("  %-15s : %s\n", label, green(val))
	}
	fmt.Println(strings.Repeat("─", 30))
	
	pressEnterToContinue(reader)
}

func clearTableMenu(reader *bufio.Reader, db *storage.Database) {
	fmt.Println("\n" + yellow("Select table to clear:"))
	fmt.Println("  1. Targets")
	fmt.Println("  2. Subdomains")
	fmt.Println("  3. Technologies")
	fmt.Println("  4. Fuzzing Results")
	fmt.Println("  5. Scan Results")
	fmt.Println("  0. Cancel")

	choice := promptInput(reader, cyan("Table: "))
	var tableName string

	switch choice {
	case "1": tableName = "targets"
	case "2": tableName = "subdomains"
	case "3": tableName = "technologies"
	case "4": tableName = "fuzz_results"
	case "5": tableName = "scan_results"
	case "0": return
	default:
		fmt.Println(red("✗ Invalid table choice"))
		pressEnterToContinue(reader)
		return
	}

	confirm := promptInput(reader, red(fmt.Sprintf("⚠ Are you sure you want to clear '%s'? (y/N): ", tableName)))
	if strings.ToLower(confirm) == "y" {
		if err := db.ClearTable(tableName); err != nil {
			fmt.Printf("%s Error clearing table: %v\n", red("✗"), err)
		} else {
			fmt.Printf("%s Table '%s' cleared successfully.\n", green("✓"), tableName)
		}
	} else {
		fmt.Println(yellow("Operation cancelled."))
	}
	pressEnterToContinue(reader)
}

func clearAllData(reader *bufio.Reader, db *storage.Database) {
	fmt.Println()
	fmt.Println(red("████ WARNING ████"))
	fmt.Println(red("This will delete ALL data from the database."))
	fmt.Println(red("This action cannot be undone."))
	
	confirm := promptInput(reader, red("Type 'DELETE' to confirm: "))
	if confirm == "DELETE" {
		fmt.Print(yellow("Resetting database... "))
		if err := db.ClearAllTables(); err != nil {
			fmt.Printf("\n%s Error: %v\n", red("✗"), err)
		} else {
			fmt.Println(green("Done!"))
			fmt.Println("All tables have been truncated.")
		}
	} else {
		fmt.Println(yellow("Operation cancelled."))
	}
	pressEnterToContinue(reader)
}

// viewDatabaseStats displays current database statistics
func viewDatabaseStats(reader *bufio.Reader) {
	db := storage.GetInstance()
	if db == nil {
		fmt.Println(red("✗ Database not initialized"))
		pressEnterToContinue(reader)
		return
	}

	clearScreen()
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "DATABASE STATISTICS")
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	
	stats := db.GetDatabaseStats()
	
	fmt.Printf("  %s Targets: %d\n", green("✓"), stats["targets"])
	fmt.Printf("  %s Scan Results: %d\n", green("✓"), stats["scans"])
	fmt.Printf("  %s Subdomains: %d\n", green("✓"), stats["subdomains"])
	fmt.Printf("  %s Technologies: %d\n", green("✓"), stats["technologies"])
	fmt.Printf("  %s Fuzzing Hits: %d\n", green("✓"), stats["fuzzing_hits"])
	
	fmt.Println()
	pressEnterToContinue(reader)
}

// clearAllDatabase prompts user to confirm and clear all database
func clearAllDatabase(reader *bufio.Reader) {
	clearScreen()
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "CLEAR ALL DATABASE")
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(red("⚠  WARNING: This will delete ALL scanned data!"))
	fmt.Println()
	
	confirm := promptInput(reader, cyan("Type 'DELETE' to confirm: "))
	
	if confirm == "DELETE" {
		db := storage.GetInstance()
		if db != nil {
			if err := db.ClearTable("targets"); err == nil {
				fmt.Printf("%s Database cleared successfully\n", green("✓"))
			} else {
				fmt.Printf("%s Failed to clear database: %v\n", red("✗"), err)
			}
		}
	} else {
		fmt.Println(yellow("↻ Operation cancelled"))
	}
	
	pressEnterToContinue(reader)
}

// Helper functions
func promptInput(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func pressEnterToContinue(reader *bufio.Reader) {
	fmt.Print(cyan("\nPress ENTER to continue..."))
	reader.ReadString('\n')
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}