package crawler

import (
	"context" // needed for cancellation and timeouts
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gianlucabassani/gosint/internal/storage"
)

type CrawlerConfig struct {
	TargetURL     string
	MaxDepth      int
	MaxConcurrent int
	Timeout       time.Duration
	TargetID      uint
}

type CrawlResult struct {
	URL   string
	Title string
	OSINT ExtractedData
	Links int
}

type Crawler struct {
	config  CrawlerConfig
	visited sync.Map
	db      *storage.Database
	client  *http.Client
}

func NewCrawler(config CrawlerConfig) *Crawler {
	return &Crawler{
		config: config,
		db:     storage.GetInstance(),
		client: &http.Client{Timeout: config.Timeout},
	}
}

func (c *Crawler) Start(ctx context.Context) ([]CrawlResult, error) {
	baseURL, err := url.Parse(c.config.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	fmt.Printf("\n%s\n", color.BlueString("════════════════════════════════════════════════════════════"))
	fmt.Printf(" :: Crawler Target   : %s\n", color.CyanString(c.config.TargetURL))
	fmt.Printf(" :: Max Depth        : %d\n", c.config.MaxDepth)
	fmt.Printf(" :: Max Threads      : %d\n", c.config.MaxConcurrent)
	fmt.Printf("%s\n\n", color.BlueString("════════════════════════════════════════════════════════════"))

	resultsChan := make(chan CrawlResult)              // channel (which is a goroutine-safe queue) to collect results from workers
	var wg sync.WaitGroup                              // limit concurrency with WaitGroup + buffered channel
	sem := make(chan struct{}, c.config.MaxConcurrent) // semaphore pattern to limit concurrent goroutines

	// Start crawling
	wg.Add(1) // add initial task for the root URL
	go c.crawl(ctx, c.config.TargetURL, baseURL.Host, 0, &wg, sem, resultsChan)

	// Monitor & Close
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var results []CrawlResult
	for res := range resultsChan {
		results = append(results, res)
		if len(res.OSINT.Emails) > 0 || len(res.OSINT.Phones) > 0 {
			c.saveOSINTToDB(res)
		}
	}

	return results, nil
}

func (c *Crawler) crawl(ctx context.Context, target string, scopeHost string, depth int, wg *sync.WaitGroup, sem chan struct{}, results chan<- CrawlResult) {
	defer wg.Done()

	// Check if context is cancelled
	select {
	case <-ctx.Done(): // return a channel that is closed when this context is cancelled / times out
		return
	default:
	}

	if depth > c.config.MaxDepth {
		return
	}
	if _, loaded := c.visited.LoadOrStore(target, true); loaded { // check if URL has already been visited (thread-safe)
		return
	}

	sem <- struct{}{}
	defer func() { <-sem }()

	// Real-time log
	indent := strings.Repeat("  ", depth)
	fmt.Printf("%s%s %s\n", indent, color.YellowString("→"), target)

	resp, err := c.client.Get(target)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	body := string(bodyBytes)

	// Extract data
	osintData := ExtractOSINT(body)
	links := extractLinks(body, target)
	title := extractTitle(body)

	// Real-time FINDINGS log
	if len(osintData.Emails) > 0 {
		for _, email := range osintData.Emails {
			fmt.Printf("%s  %s %s\n", indent, color.GreenString("[+] EMAIL:"), email)
		}
	}
	if len(osintData.Phones) > 0 {
		for _, phone := range osintData.Phones {
			fmt.Printf("%s  %s %s\n", indent, color.GreenString("[+] PHONE:"), phone)
		}
	}

	results <- CrawlResult{
		URL:   target,
		Title: title,
		OSINT: osintData,
		Links: len(links),
	}

	// Recurse
	for _, link := range links {
		u, err := url.Parse(link) // check the base domain of the link to ensure we stay within scope
		if err == nil && u.Host == scopeHost {
			wg.Add(1)
			go c.crawl(ctx, link, scopeHost, depth+1, wg, sem, results)
		}
	}
}

func (c *Crawler) saveOSINTToDB(res CrawlResult) {
	data := map[string]interface{}{
		"url":    res.URL,
		"title":  res.Title,
		"emails": res.OSINT.Emails,
		"phones": res.OSINT.Phones,
	}
	// We save this as a "crawl_osint" type result
	c.db.SaveScanResult(c.config.TargetID, "crawl", "osint", data, 1)
}

// Helpers
func extractLinks(html string, baseURL string) []string {
	var links []string
	// Basic regex for hrefs (faster than full parsing for high-speed crawling)
	re := regexp.MustCompile(`href=["'](.*?)["']`)
	matches := re.FindAllStringSubmatch(html, -1)
	base, _ := url.Parse(baseURL)

	for _, match := range matches {
		if len(match) > 1 {
			href := strings.TrimSpace(match[1])
			u, err := url.Parse(href)
			if err == nil {
				resolved := base.ResolveReference(u)
				if resolved.Scheme == "http" || resolved.Scheme == "https" {
					links = append(links, resolved.String())
				}
			}
		}
	}
	return links
}

func extractTitle(html string) string {
	re := regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
