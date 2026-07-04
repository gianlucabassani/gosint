package fuzzer

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pterm/pterm"
)

// userAgents is a pool of realistic browser User-Agent strings rotated per request.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
}

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
	RateLimit      int // max requests/second (0 = unlimited)

	// AutoFilter enables automatic false-positive removal (wildcard calibration
	// plus adaptive clustering of identical responses). It is a pointer so that
	// nil means "use the default" (enabled) — this is what makes aggressive scans,
	// which set no manual filters, self-clean without extra configuration.
	AutoFilter *bool
	// AutoFilterThreshold overrides how many identical responses (same status code
	// and body size) are tolerated before that signature is treated as noise.
	// 0 means derive a sensible value from the wordlist size.
	AutoFilterThreshold int
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

	// Automatic false-positive removal state.
	autoFilter    bool
	threshold     int             // identical-response count that trips the filter
	sigCounts     map[string]int  // "code:size" -> times seen among matches
	filteredSigs  map[string]bool // signatures adaptively flagged as noise mid-scan
	baselineSigs  map[string]bool // exact "code:size" signatures learned during calibration
	baselineCodes map[int]bool    // status codes that a wildcard/catch-all returns for anything
	suppressed    int             // total responses discarded as false positives
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

	autoFilter := true
	if config.AutoFilter != nil {
		autoFilter = *config.AutoFilter
	}

	return &Fuzzer{
		config:        config,
		autoFilter:    autoFilter,
		sigCounts:     make(map[string]int),
		filteredSigs:  make(map[string]bool),
		baselineSigs:  make(map[string]bool),
		baselineCodes: make(map[int]bool),
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

	// Derive the adaptive threshold from the wordlist size: a genuine target
	// rarely has hundreds of identical valid responses, but a catch-all does.
	f.threshold = f.config.AutoFilterThreshold
	if f.threshold <= 0 {
		f.threshold = 20
		if scaled := f.total / 50; scaled > f.threshold {
			f.threshold = scaled
		}
	}

	// ── Header ────────────────────────────────────────────────────────────
	pterm.Println()
	printTitleBox("GOSINT  ·  FUZZER")
	pterm.Println()
	treeLine("┌", "Target", pterm.Cyan(f.config.Target))
	treeLine("├", "Mode", pterm.Yellow(string(f.config.Mode)))
	treeLine("├", "Wordlist", pterm.White(fmt.Sprintf("%s  (%d words)", f.config.Wordlist, f.total)))
	treeLine("├", "Threads", pterm.White(fmt.Sprintf("%d", f.config.Threads)))
	treeLine("├", "Match", pterm.LightGreen(intsJoin(f.config.MatchCodes, " ")))
	if f.autoFilter {
		treeLine("└", "Auto-Filter", pterm.LightGreen("on")+pterm.Gray(fmt.Sprintf("  · flags ≥ %d identical responses", f.threshold)))
	} else {
		treeLine("└", "Auto-Filter", pterm.Gray("off"))
	}
	pterm.Println()

	// Calibrate against wildcard / catch-all behaviour before the real run so we
	// suppress its signature from the very first match instead of spamming it.
	f.calibrate(ctx)

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
				return // Bug #8 fix: return exits the goroutine, not just the select
			}
		}
		close(wordChan)
	}()

	wg.Wait()

	// Clear progress bar line
	fmt.Printf("\r\033[K")

	// ── Footer ────────────────────────────────────────────────────────────
	duration := time.Since(startTime)
	pterm.Println()
	printTitleBox("SCAN COMPLETE")
	pterm.Println()
	treeLine("┌", "Elapsed", pterm.White(duration.Round(time.Millisecond).String()))
	treeLine("├", "Requests", pterm.White(fmt.Sprintf("%d", f.checked)))
	if f.autoFilter && f.suppressed > 0 {
		treeLine("├", "Found", pterm.LightGreen(fmt.Sprintf("%d", f.found)))
		treeLine("└", "Filtered", pterm.Yellow(fmt.Sprintf("%d", f.suppressed))+pterm.Gray("  false positives removed"))
	} else {
		treeLine("└", "Found", pterm.LightGreen(fmt.Sprintf("%d", f.found)))
	}
	pterm.Println()

	return f.results, nil
}

// calibrate probes a handful of random, almost-certainly-nonexistent words. Any
// response that would otherwise count as a "match" is a wildcard/catch-all
// artefact, so its signature is recorded and suppressed for the real run.
func (f *Fuzzer) calibrate(ctx context.Context) {
	if !f.autoFilter {
		return
	}

	const probes = 5
	sigSeen := make(map[string]int)
	codeSeen := make(map[int]int)
	valid := 0

	for i := 0; i < probes; i++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, code, size, ok := f.doProbe(randomToken())
		if !ok || !f.shouldSave(code, size) {
			continue
		}
		valid++
		sigSeen[sigKey(code, size)]++
		codeSeen[code]++
	}

	if valid == 0 {
		return // Server correctly 404s garbage — no wildcard to calibrate against.
	}

	// An exact signature seen for multiple random inputs is a static catch-all page.
	for sig, c := range sigSeen {
		if c >= 2 {
			f.baselineSigs[sig] = true
		}
	}
	// The same status code for (nearly) every random input, even with varying
	// sizes, means that code is meaningless for this target — filter it wholesale.
	for code, c := range codeSeen {
		if c >= 3 && c >= valid {
			f.baselineCodes[code] = true
		}
	}

	if len(f.baselineSigs) > 0 || len(f.baselineCodes) > 0 {
		msg := "wildcard / catch-all detected — baseline responses will be auto-suppressed"
		if len(f.baselineCodes) > 0 {
			msg += pterm.Gray(fmt.Sprintf("  (codes: %s)", codeList(f.baselineCodes)))
		}
		fmt.Printf("  %s %s\n", pill("CALIBRATION", pterm.FgBlack, pterm.BgYellow), msg)
		pterm.Println()
	}
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
	start := time.Now()
	targetURL, code, size, ok := f.doProbe(word)
	if !ok {
		f.incrementChecked()
		return
	}
	duration := time.Since(start)

	if !f.shouldSave(code, size) {
		f.incrementChecked()
		return
	}

	result := FuzzResult{
		URL:        targetURL,
		StatusCode: code,
		Size:       size,
		WordUsed:   word,
		Duration:   duration,
	}
	if f.config.Mode == ModeVHost {
		result.URL = fmt.Sprintf("%s.%s", word, f.config.Target) // Display Host header
	}

	save, flaggedSig, flaggedCount := f.recordAndDecide(result)
	if flaggedSig != "" {
		f.printFilterNotice(flaggedSig, flaggedCount)
	}
	if save {
		f.printResult(result)
	}

	f.incrementChecked()
}

// doProbe issues one request for the given word according to the fuzz mode and
// returns the resolved URL, status code and the real response body size. Body
// size is measured (not taken from Content-Length) so it stays accurate for
// chunked responses — essential for signature-based false-positive detection.
func (f *Fuzzer) doProbe(word string) (targetURL string, code, size int, ok bool) {
	switch f.config.Mode {
	case ModeDirectory:
		base := strings.TrimRight(f.config.Target, "/")
		targetURL = fmt.Sprintf("%s/%s", base, word)
	case ModeVHost:
		targetURL = f.config.Target
	case ModeSubdomain:
		if !strings.HasPrefix(f.config.Target, "http") {
			targetURL = fmt.Sprintf("https://%s.%s", word, f.config.Target)
		} else {
			parts := strings.SplitN(f.config.Target, "://", 2)
			targetURL = fmt.Sprintf("%s://%s.%s", parts[0], word, parts[1])
		}
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return targetURL, 0, 0, false
	}

	// Rotate User-Agent per request (Improvement #2)
	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

	if f.config.Mode == ModeVHost {
		req.Host = fmt.Sprintf("%s.%s", word, f.config.Target)
		req.URL.Host = f.config.Target
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return targetURL, 0, 0, false
	}
	defer resp.Body.Close()

	n, _ := io.Copy(io.Discard, resp.Body)
	return targetURL, resp.StatusCode, int(n), true
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

// recordAndDecide applies automatic false-positive removal to a matched result.
// It returns whether the result should be kept/printed, and — when a signature
// first crosses the noise threshold — the flagged signature plus how many
// previously-recorded results were retroactively pruned.
func (f *Fuzzer) recordAndDecide(r FuzzResult) (save bool, flaggedSig string, flaggedCount int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.autoFilter {
		f.results = append(f.results, r)
		f.found++
		return true, "", 0
	}

	sig := sigKey(r.StatusCode, r.Size)

	// Known wildcard/catch-all noise learned during calibration.
	if f.baselineSigs[sig] || f.baselineCodes[r.StatusCode] {
		f.suppressed++
		return false, "", 0
	}

	// Signature already flagged as noise earlier in this run.
	if f.filteredSigs[sig] {
		f.suppressed++
		return false, "", 0
	}

	f.sigCounts[sig]++
	if f.sigCounts[sig] > f.threshold {
		// This many identical responses can't all be real findings — flag the
		// signature, drop the ones we already recorded, and suppress the rest.
		f.filteredSigs[sig] = true
		removed := f.pruneSignature(sig)
		f.suppressed += removed + 1
		return false, sig, removed + 1
	}

	f.results = append(f.results, r)
	f.found++
	return true, "", 0
}

// pruneSignature removes already-recorded results matching sig. Caller holds mu.
func (f *Fuzzer) pruneSignature(sig string) int {
	kept := f.results[:0]
	removed := 0
	for _, r := range f.results {
		if sigKey(r.StatusCode, r.Size) == sig {
			removed++
			continue
		}
		kept = append(kept, r)
	}
	f.results = kept
	f.found -= removed
	return removed
}

func (f *Fuzzer) incrementChecked() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checked++

	// Update progress every 50 requests
	if f.checked%50 == 0 || f.checked == f.total {
		frac := float64(f.checked) / float64(f.total)
		fmt.Printf("\r\033[K  %s %s  %s  %s",
			renderBar(frac, 24),
			pterm.Bold.Sprint(fmt.Sprintf("%5.1f%%", frac*100)),
			pterm.Gray(fmt.Sprintf("%d/%d", f.checked, f.total)),
			pterm.LightGreen(fmt.Sprintf("• %d hits", f.found)),
		)
	}
}

func (f *Fuzzer) printFilterNotice(sig string, removed int) {
	fmt.Printf("\r\033[K")
	fmt.Printf("  %s response %s exceeded %d hits — flagged as noise, %s discarded\n",
		pill("AUTO-FILTER", pterm.FgBlack, pterm.BgYellow),
		pterm.Cyan(sig),
		f.threshold,
		pterm.Yellow(fmt.Sprintf("%d result(s)", removed)),
	)
}

func (f *Fuzzer) printResult(r FuzzResult) {
	// Clear progress line first
	fmt.Printf("\r\033[K")

	fmt.Printf("  %s  %s  %s\n",
		statusBadge(r.StatusCode),
		pterm.Gray(fmt.Sprintf("%9s", humanSize(r.Size))),
		r.URL,
	)
}

// ── Presentation helpers ───────────────────────────────────────────────────

// printTitleBox draws a centered, double-ruled title box matching the scanner UI.
func printTitleBox(title string) {
	const inner = 58
	runes := len([]rune(title))
	pad := inner - runes
	if pad < 0 {
		pad = 0
	}
	left := pad / 2
	right := pad - left
	pterm.Println(pterm.LightCyan("╔" + strings.Repeat("═", inner) + "╗"))
	pterm.Println(pterm.LightCyan("║") +
		strings.Repeat(" ", left) +
		pterm.NewStyle(pterm.FgLightCyan, pterm.Bold).Sprint(title) +
		strings.Repeat(" ", right) +
		pterm.LightCyan("║"))
	pterm.Println(pterm.LightCyan("╚" + strings.Repeat("═", inner) + "╝"))
}

// treeLine prints one "┌─ Label   value" configuration/summary row.
func treeLine(branch, label, value string) {
	fmt.Printf("  %s─ %s %s\n", pterm.LightCyan(branch), pterm.Gray(fmt.Sprintf("%-12s", label)), value)
}

// statusBadge renders a status code as a colored pill, keyed by response class.
func statusBadge(code int) string {
	switch {
	case code >= 200 && code < 300:
		return pill(fmt.Sprintf("%d", code), pterm.FgBlack, pterm.BgGreen)
	case code >= 300 && code < 400:
		return pill(fmt.Sprintf("%d", code), pterm.FgBlack, pterm.BgCyan)
	case code >= 400 && code < 500:
		return pill(fmt.Sprintf("%d", code), pterm.FgBlack, pterm.BgYellow)
	case code >= 500:
		return pill(fmt.Sprintf("%d", code), pterm.FgWhite, pterm.BgRed)
	default:
		return pill(fmt.Sprintf("%d", code), pterm.FgBlack, pterm.BgWhite)
	}
}

// pill renders text as a padded, bold, background-colored badge.
func pill(text string, fg, bg pterm.Color) string {
	return pterm.NewStyle(fg, bg, pterm.Bold).Sprint(" " + text + " ")
}

// renderBar draws a fixed-width progress bar of filled/empty block glyphs.
func renderBar(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	filled := int(frac * float64(width))
	if filled > width {
		filled = width
	}
	return pterm.LightCyan(strings.Repeat("█", filled)) + pterm.Gray(strings.Repeat("░", width-filled))
}

// humanSize formats a byte count as a compact, human-readable string.
func humanSize(n int) string {
	if n < 0 {
		return "—"
	}
	f := float64(n)
	units := []string{"B", "KB", "MB", "GB", "TB"}
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

// sigKey builds the response signature used to cluster identical responses.
func sigKey(code, size int) string {
	return fmt.Sprintf("%d:%d", code, size)
}

// intsJoin renders a slice of ints as a sep-delimited string.
func intsJoin(xs []int, sep string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = fmt.Sprintf("%d", x)
	}
	return strings.Join(parts, sep)
}

// randomToken returns an unlikely-to-exist label used to probe wildcard behaviour.
func randomToken() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 16)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return "zzq" + string(b)
}

// codeList renders a set of status codes as a stable, comma-separated string.
func codeList(codes map[int]bool) string {
	parts := make([]string, 0, len(codes))
	for c := range codes {
		parts = append(parts, fmt.Sprintf("%d", c))
	}
	return strings.Join(parts, ",")
}
