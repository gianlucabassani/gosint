package fuzzer

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type FuzzMode string

const (
	ModeDirectory FuzzMode = "directory"
	ModeVHost     FuzzMode = "vhost"
	ModeSubdomain FuzzMode = "subdomain"
)

type FuzzerConfig struct {
	Target       string
	Mode         FuzzMode
	Wordlist     string
	Threads      int
	Timeout      int
	MatchCodes   []int
	FilterCodes  []int
	FilterSize   int
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
	// Default values
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

	// Load wordlist
	words, err := LoadWordlist(f.config.Wordlist)
	if err != nil {
		return nil, fmt.Errorf("failed to load wordlist: %w", err)
	}
	f.total = len(words)

	fmt.Printf("\n🎯 Starting %s fuzzing\n", f.config.Mode)
	fmt.Printf("   Target: %s\n", f.config.Target)
	fmt.Printf("   Wordlist: %d words\n", f.total)
	fmt.Printf("   Threads: %d\n", f.config.Threads)
	fmt.Println()

	// Create worker pool
	wordChan := make(chan string, f.config.Threads)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < f.config.Threads; i++ {
		wg.Add(1)
		go f.worker(ctx, wordChan, &wg)
	}

	// Feed words to workers
	go func() {
		for _, word := range words {
			select {
			case wordChan <- word:
			case <-ctx.Done():
				close(wordChan)
				return
			}
		}
		close(wordChan)
	}()

	// Wait for completion
	wg.Wait()

	duration := time.Since(startTime)
	fmt.Printf("\n✅ Fuzzing complete in %v\n", duration)
	fmt.Printf("   Total: %d | Found: %d (%.2f%%)\n", f.total, f.found, float64(f.found)/float64(f.total)*100)

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
		targetURL = fmt.Sprintf("%s/%s", f.config.Target, word)
	case ModeVHost:
		targetURL = f.config.Target // Will modify Host header
	case ModeSubdomain:
		targetURL = fmt.Sprintf("http://%s.%s", word, f.config.Target)
	}

	start := time.Now()
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return
	}

	// VHost mode: modify Host header
	if f.config.Mode == ModeVHost {
		req.Host = fmt.Sprintf("%s.%s", word, f.config.Target)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		f.incrementChecked()
		return
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	// Check if result matches criteria
	if f.shouldSave(resp.StatusCode, int(resp.ContentLength)) {
		result := FuzzResult{
			URL:        targetURL,
			StatusCode: resp.StatusCode,
			Size:       int(resp.ContentLength),
			WordUsed:   word,
			Duration:   duration,
		}

		f.addResult(result)
		f.printResult(result)
	}

	f.incrementChecked()
}

func (f *Fuzzer) shouldSave(code, size int) bool {
	// Filter by size
	if f.config.FilterSize > 0 && size == f.config.FilterSize {
		return false
	}

	// Filter codes
	for _, fc := range f.config.FilterCodes {
		if code == fc {
			return false
		}
	}

	// Match codes
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

	// Print progress every 100 requests
	if f.checked%100 == 0 {
		progress := float64(f.checked) / float64(f.total) * 100
		fmt.Printf("\r   Progress: %d/%d (%.1f%%) | Found: %d", f.checked, f.total, progress, f.found)
	}
}

func (f *Fuzzer) printResult(result FuzzResult) {
	statusColor := getStatusColor(result.StatusCode)
	fmt.Printf("\n   %s [Status: %d] [Size: %d] %s", statusColor, result.StatusCode, result.Size, result.URL)
}

func getStatusColor(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "✓"
	case code >= 300 && code < 400:
		return "↻"
	case code == 401 || code == 403:
		return "🔒"
	case code >= 400 && code < 500:
		return "✗"
	case code >= 500:
		return "💥"
	default:
		return "?"
	}
}