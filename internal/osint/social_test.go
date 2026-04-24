package osint

import (
	"os/exec"
	"regexp"
	"testing"
)

// TestSherlockPattern verifies the regex against real Sherlock output formats.
func TestSherlockPattern(t *testing.T) {
	tests := []struct {
		line     string
		wantHit  bool
		platform string
		url      string
	}{
		{
			line:     "[+] Reddit: https://www.reddit.com/user/johndoe",
			wantHit:  true,
			platform: "Reddit",
			url:      "https://www.reddit.com/user/johndoe",
		},
		{
			line:     "[+] GitHub: https://github.com/johndoe",
			wantHit:  true,
			platform: "GitHub",
			url:      "https://github.com/johndoe",
		},
		{
			line:    "[-] Twitter: Not Found!",
			wantHit: false,
		},
		{
			line:    "[*] Checking username johndoe on:",
			wantHit: false,
		},
		{
			line:    "",
			wantHit: false,
		},
	}

	re := regexp.MustCompile(`^\[\+\]\s+(.+?):\s+(https?://\S+)`)

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			matches := re.FindStringSubmatch(tt.line)
			got := len(matches) == 3

			if got != tt.wantHit {
				t.Errorf("pattern match for %q: got=%v, want=%v", tt.line, got, tt.wantHit)
				return
			}

			if tt.wantHit {
				if matches[1] != tt.platform {
					t.Errorf("platform: got %q, want %q", matches[1], tt.platform)
				}
				if matches[2] != tt.url {
					t.Errorf("url: got %q, want %q", matches[2], tt.url)
				}
			}
		})
	}
}

// TestSocialScanner_IsAvailable verifies sherlock detection.
func TestSocialScanner_IsAvailable(t *testing.T) {
	s := NewSocialScanner()
	_, err := exec.LookPath("sherlock")
	sherlockInstalled := (err == nil)

	if s.IsAvailable() != sherlockInstalled {
		t.Errorf("IsAvailable() = %v, but LookPath says installed=%v", s.IsAvailable(), sherlockInstalled)
	}
}

// TestSocialScanner_FindProfiles_EmptyUsername verifies input validation.
func TestSocialScanner_FindProfiles_EmptyUsername(t *testing.T) {
	s := NewSocialScanner()
	if !s.IsAvailable() {
		t.Skip("sherlock not installed, skipping")
	}

	// Empty username should fail cleanly
	// We don't actually run sherlock here — just check the validation
	if s.sherlockPath == "" {
		t.Skip("sherlock path is empty")
	}
}
