package osint

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// sherlockPattern matches Sherlock's positive output lines:
//   [+] Reddit: https://www.reddit.com/user/johndoe
var sherlockPattern = regexp.MustCompile(`^\[\+\]\s+(.+?):\s+(https?://\S+)`)

// SocialScanner uses Sherlock to enumerate social media profiles for a username.
// Sherlock is a Python CLI tool run via os/exec with stdout streamed line-by-line
// so results appear in real time as they are found.
type SocialScanner struct {
	sherlockPath string // resolved path to the sherlock binary
}

// NewSocialScanner creates a SocialScanner. It resolves the sherlock binary
// location at construction time so the error surfaces early (not mid-scan).
// Returns a scanner even if sherlock is not found — FindProfiles will return
// ErrServiceUnavailable with a helpful message in that case.
func NewSocialScanner() *SocialScanner {
	path, _ := exec.LookPath("sherlock")
	return &SocialScanner{sherlockPath: path}
}

// FindProfiles runs Sherlock for the given username and collects all confirmed
// profiles. Output is streamed live to stdout so the user sees results as they
// arrive — matching GOSINT's existing live-output style.
//
// Context cancellation sends SIGKILL to the Sherlock subprocess.
func (s *SocialScanner) FindProfiles(ctx context.Context, username string) ([]SocialProfile, error) {
	if s.sherlockPath == "" {
		return nil, fmt.Errorf("%w: sherlock not found in PATH. Install with: pip install sherlock-project", ErrServiceUnavailable)
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}

	// Run Sherlock: --print-found suppresses "not found" lines for cleaner output
	// --timeout 10 prevents individual site checks from hanging
	cmd := exec.CommandContext(ctx, s.sherlockPath, "--print-found", "--timeout", "10", username)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating sherlock stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("%w: failed to start sherlock: %v", ErrServiceUnavailable, err)
	}

	var profiles []SocialProfile
	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {
		line := scanner.Text()

		// Print raw sherlock output for live feedback
		fmt.Printf("  %s\n", line)

		// Parse confirmed hits
		if matches := sherlockPattern.FindStringSubmatch(line); len(matches) == 3 {
			profiles = append(profiles, SocialProfile{
				Username:  username,
				Platform:  strings.TrimSpace(matches[1]),
				URL:       strings.TrimSpace(matches[2]),
				Confirmed: true,
				FoundAt:   time.Now(),
			})
		}
	}

	// Wait for the process to finish. Context cancellation causes exec.CommandContext
	// to kill the process automatically, so WaitDelay is not needed.
	if err := cmd.Wait(); err != nil {
		// A non-zero exit from sherlock is normal (e.g. username not found on some sites).
		// Only surface it if the context was cancelled.
		if ctx.Err() != nil {
			return profiles, ctx.Err()
		}
	}

	return profiles, nil
}

// IsAvailable returns true if sherlock is present on the system.
func (s *SocialScanner) IsAvailable() bool {
	return s.sherlockPath != ""
}
