package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	
	"github.com/fatih/color"
	"github.com/gianlucabassani/gosint/internal/scanner"
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
	fmt.Println(yellow("2."), "Web Crawler & Scraping")
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
	case "1", "":
		mode = scanner.ModeBasic
	case "2":
		mode = scanner.ModeDeep
	case "3":
		mode = scanner.ModeStealth
	case "4":
		mode = scanner.ModeAggressive
	default:
		fmt.Println(red("✗ Invalid choice, using basic mode"))
		mode = scanner.ModeBasic
	}

	// Run scan
	s := scanner.NewScanner(domain, mode)
	ctx := context.Background()

	_, err := s.Scan(ctx)
	if err != nil {
		fmt.Printf("\n%s Scan failed: %v\n", red("❌"), err)
	}

	pressEnterToContinue(reader)
}

func crawlerMenu(reader *bufio.Reader) {
	clearScreen()
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "WEB CRAWLER")
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	
	url := promptInput(reader, cyan("Enter URL: "))
	if url == "" {
		fmt.Println(red("✗ URL cannot be empty"))
		pressEnterToContinue(reader)
		return
	}
	
	depthStr := promptInput(reader, cyan("Crawl depth (default: 2): "))
	if depthStr == "" {
		depthStr = "2"
	}
	
	fmt.Printf("%s Starting crawl: %s (depth: %s)\n", green("✓"), url, depthStr)
	fmt.Println(yellow("⚠  This feature will be implemented in Phase 2"))
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
		directoryFuzzMenu(reader)
	case "2":
		vhostFuzzMenu(reader)
	case "3":
		subdomainFuzzMenu(reader)
	case "0":
		return
	default:
		fmt.Println(red("✗ Invalid choice"))
		pressEnterToContinue(reader)
	}
}

func directoryFuzzMenu(reader *bufio.Reader) {
	clearScreen()
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "DIRECTORY FUZZING")
	fmt.Println(blue("═══════════════════════════════════════════════════"))

	url := promptInput(reader, cyan("Target URL (e.g., https://example.com): "))
	if url == "" {
		fmt.Println(red("✗ URL cannot be empty"))
		pressEnterToContinue(reader)
		return
	}

	fmt.Println("\n" + yellow("Wordlist options:"))
	fmt.Println("  1. Small (embedded, ~100 entries)")
	fmt.Println("  2. Medium (embedded, ~1000 entries)")
	fmt.Println("  3. Large (embedded, ~10000 entries)")
	fmt.Println("  4. Custom file path")

	wlChoice := promptInput(reader, cyan("Wordlist choice: "))
	
	var wordlist string
	switch wlChoice {
	case "1":
		wordlist = "embedded:directories-small"
	case "2":
		wordlist = "embedded:directories"
	case "3":
		wordlist = "embedded:directories-large"
	case "4":
		wordlist = promptInput(reader, cyan("Enter wordlist path: "))
	default:
		wordlist = "embedded:directories"
	}

	threads := promptInput(reader, cyan("Threads (default: 40): "))
	if threads == "" {
		threads = "40"
	}

	fmt.Printf("\n%s Starting directory fuzzing...\n", green("✓"))
	fmt.Printf("  URL: %s\n", url)
	fmt.Printf("  Wordlist: %s\n", wordlist)
	fmt.Printf("  Threads: %s\n", threads)
	
	fmt.Println(yellow("\n⚠  Fuzzer will be integrated with scanner in Phase 2 completion"))
	pressEnterToContinue(reader)
}

func vhostFuzzMenu(reader *bufio.Reader) {
	// Similar implementation
	fmt.Println(yellow("⚠  VHost fuzzing coming soon"))
	pressEnterToContinue(reader)
}

func subdomainFuzzMenu(reader *bufio.Reader) {
	// Similar implementation
	fmt.Println(yellow("⚠  Subdomain fuzzing coming soon"))
	pressEnterToContinue(reader)
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
	clearScreen()
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(blue("█"), "DATABASE MANAGEMENT")
	fmt.Println(blue("═══════════════════════════════════════════════════"))
	fmt.Println(yellow("1."), "View Database Statistics")
	fmt.Println(yellow("2."), "Backup Database")
	fmt.Println(yellow("3."), "Clear Specific Table")
	fmt.Println(yellow("4."), "Clear All Data")
	fmt.Println(yellow("5."), "Export Data")
	fmt.Println(yellow("0."), "Back")
	fmt.Println()
	
	choice := promptInput(reader, cyan("Choice: "))
	
	switch choice {
	case "1", "2", "3", "4", "5":
		fmt.Println(yellow("⚠  Database features will be implemented in Phase 2"))
		pressEnterToContinue(reader)
	case "0":
		return
	default:
		fmt.Println(red("✗ Invalid choice"))
		pressEnterToContinue(reader)
	}
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