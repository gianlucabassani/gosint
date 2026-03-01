package fuzzer

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type FuzzMode string

const (
	ModeDirectory FuzzMode = "directory"
	ModeVHost     FuzzMode = "vhost"
	ModeSubdomain FuzzMode = "subdomain"
)

type FuzzerConfig struct {
	Target         string
	Mode           FuzzMode
	Wordlist       string
	Threads        int
	Timeout        int
	MatchCodes     []int
	FilterCodes    []int
	FilterSize     int
	FollowRedirect bool
}

type FuzzResult struct {
	URL        string
	StatusCode int
	Size       int
	WordUsed   string
	Duration   time.Duration
}

type Fuzzer struct {
	config  FuzzerConfig
	client  *http.Client
	results []FuzzResult
	mu      sync.Mutex
	total   int
	checked int
	found   int
}

func NewFuzzer(config FuzzerConfig) *Fuzzer {
	// Ensure target has scheme for directory mode
	if config.Mode == ModeDirectory && !strings.HasPrefix(config.Target, "http") {
		config.Target = "https://" + config.Target
	}

	if config.Threads == 0 {
		config.Threads = 40
	}
	if config.Timeout == 0 {
		config.Timeout = 10
	}
	if len(config.MatchCodes) == 0 {
		config.MatchCodes = []int{200, 204, 301, 302, 307, 401, 403}
	}

	return &Fuzzer{
		config: config,
		client: &http.Client{
			Timeout: time.Duration(config.Timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if config.FollowRedirect {
					return nil
				}
				return http.ErrUseLastResponse
			},
		},
	}
}

func (f *Fuzzer) Start(ctx context.Context) ([]FuzzResult, error) {
	startTime := time.Now()

	words, err := LoadWordlist(f.config.Wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}
	f.total = len(words)

	// FFUF-style banner
	fmt.Println(color.BlueString("════════════════════════════════════════════════════════════"))
	fmt.Printf(" :: Method           : %s\n", color.CyanString("GET"))
	fmt.Printf(" :: URL              : %s\n", color.CyanString(f.config.Target))
	fmt.Printf(" :: Wordlist         : %s (%d words)\n", color.CyanString(f.config.Wordlist), f.total)
	fmt.Printf(" :: Threads          : %d\n", f.config.Threads)
	fmt.Printf(" :: Match Codes      : %v\n", f.config.MatchCodes)
	fmt.Println(color.BlueString("════════════════════════════════════════════════════════════"))
	fmt.Println()

	// Header
	fmt.Printf("%-10s %-10s %-10s %-10s %-50s\n", "STATUS", "SIZE", "WORDS", "DURATION", "URL")
	fmt.Println(strings.Repeat("─", 100))

	wordChan := make(chan string, f.config.Threads)
	var wg sync.WaitGroup

	for i := 0; i < f.config.Threads; i++ {
		wg.Add(1)
		go f.worker(ctx, wordChan, &wg)
	}

	go func() {
		for _, word := range words {
			select {
			case wordChan <- word:
			case <-ctx.Done():
				break
			}
		}
		close(wordChan)
	}()

	wg.Wait()

	// Clear progress bar line
	fmt.Printf("\r\033[K")

	duration := time.Since(startTime)
	fmt.Println(color.BlueString("\n════════════════════════════════════════════════════════════"))
	fmt.Printf(" :: Scan Finished in : %s\n", duration)
	fmt.Printf(" :: Total Found      : %d\n", f.found)
	fmt.Println(color.BlueString("════════════════════════════════════════════════════════════"))

	return f.results, nil
}

func (f *Fuzzer) worker(ctx context.Context, words <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for word := range words {
		select {
		case <-ctx.Done():
			return
		default:
			f.processWord(word)
		}
	}
}

func (f *Fuzzer) processWord(word string) {
	var targetURL string
	switch f.config.Mode {
	case ModeDirectory:
		// Ensure clean slash handling
		base := strings.TrimRight(f.config.Target, "/")
		targetURL = fmt.Sprintf("%s/%s", base, word)
	case ModeVHost:
		targetURL = f.config.Target
	case ModeSubdomain:
		// Assume target is domain, prepend protocol if needed for request
		if !strings.HasPrefix(f.config.Target, "http") {
			targetURL = fmt.Sprintf("https://%s.%s", word, f.config.Target)
		} else {
			// Strip protocol to insert subdomain
			parts := strings.SplitN(f.config.Target, "://", 2)
			targetURL = fmt.Sprintf("%s://%s.%s", parts[0], word, parts[1])
		}
	}

	start := time.Now()
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		f.incrementChecked()
		return
	}

	if f.config.Mode == ModeVHost {
		// e.g. word.example.com
		req.Host = fmt.Sprintf("%s.%s", word, f.config.Target)
		req.URL.Host = f.config.Target // Request goes to IP/Domain
	}

	resp, err := f.client.Do(req)
	if err != nil {
		f.incrementChecked()
		return
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	if f.shouldSave(resp.StatusCode, int(resp.ContentLength)) {
		result := FuzzResult{
			URL:        targetURL,
			StatusCode: resp.StatusCode,
			Size:       int(resp.ContentLength),
			WordUsed:   word,
			Duration:   duration,
		}
		if f.config.Mode == ModeVHost {
			result.URL = fmt.Sprintf("%s.%s", word, f.config.Target) // Display Host header
		}

		f.addResult(result)
		f.printResult(result)
	}

	f.incrementChecked()
}

func (f *Fuzzer) shouldSave(code, size int) bool {
	if f.config.FilterSize > 0 && size == f.config.FilterSize {
		return false
	}
	for _, fc := range f.config.FilterCodes {
		if code == fc {
			return false
		}
	}
	for _, mc := range f.config.MatchCodes {
		if code == mc {
			return true
		}
	}
	return false
}

func (f *Fuzzer) addResult(result FuzzResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, result)
	f.found++
}

func (f *Fuzzer) incrementChecked() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checked++

	// Update progress every 50 requests
	if f.checked%50 == 0 || f.checked == f.total {
		prog := float64(f.checked) / float64(f.total) * 100
		fmt.Printf("\r\033[K[%s] %d/%d (%.1f%%)",
			color.CyanString("PROGRESS"), f.checked, f.total, prog)
	}
}

func (f *Fuzzer) printResult(r FuzzResult) {
	// Clear progress line first
	fmt.Printf("\r\033[K")

	// Colorize Status
	var statusStr string
	switch {
	case r.StatusCode >= 200 && r.StatusCode < 300:
		statusStr = color.GreenString("%d", r.StatusCode)
	case r.StatusCode >= 300 && r.StatusCode < 400:
		statusStr = color.BlueString("%d", r.StatusCode)
	case r.StatusCode >= 400 && r.StatusCode < 500:
		statusStr = color.YellowString("%d", r.StatusCode)
	case r.StatusCode >= 500:
		statusStr = color.RedString("%d", r.StatusCode)
	default:
		statusStr = fmt.Sprintf("%d", r.StatusCode)
	}

	// Format: Status | Size | Words | Duration | URL
	fmt.Printf("%-19s %-10d %-10d %-10v %s\n",
		statusStr,
		r.Size,
		len(r.WordUsed),
		r.Duration.Round(time.Millisecond),
		r.URL,
	)
}
