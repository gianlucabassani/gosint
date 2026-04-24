package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// disposableDomains is an embedded list of known disposable email providers.
// No external call needed — checked locally before any API requests.
var disposableDomains = map[string]bool{
	"mailinator.com": true, "guerrillamail.com": true, "trashmail.com": true,
	"temp-mail.org": true, "yopmail.com": true, "maildrop.cc": true,
	"sharklasers.com": true, "guerrillamailblock.com": true, "grr.la": true,
	"guerrillamail.info": true, "guerrillamail.biz": true, "guerrillamail.de": true,
	"guerrillamail.net": true, "guerrillamail.org": true, "spam4.me": true,
	"dispostable.com": true, "fakeinbox.com": true, "mailnull.com": true,
	"spamgourmet.com": true, "trashmail.me": true, "trashmail.at": true,
	"trashmail.io": true, "trashmail.xyz": true, "spamfree24.org": true,
	"spamfree.eu": true, "binkmail.com": true, "mailexpire.com": true,
	"throwam.com": true, "nwytg.com": true, "tempr.email": true,
	"discard.email": true, "spamgourmet.net": true, "spamgourmet.org": true,
	"trashmail.net": true, "kasmail.com": true, "spamspot.com": true,
	"harakirimail.com": true, "mailscrap.com": true, "filzmail.com": true,
	"trash-mail.at": true, "spamcowboy.com": true, "sofimail.com": true,
	"mailzilla.com": true, "discardmail.com": true, "wegwerfmail.de": true,
	"wegwerfmail.net": true, "wegwerfmail.org": true, "10minutemail.com": true,
}

// hibpBreach is the JSON shape returned by the HIBP v3 API.
type hibpBreach struct {
	Name        string   `json:"Name"`
	Domain      string   `json:"Domain"`
	BreachDate  string   `json:"BreachDate"`
	DataClasses []string `json:"DataClasses"`
	Description string   `json:"Description"`
	PwnCount    int      `json:"PwnCount"`
}

// hunterVerifyResponse is the relevant subset of the Hunter.io /email-verifier response.
type hunterVerifyResponse struct {
	Data struct {
		Result     string `json:"result"`
		Score      int    `json:"score"`
		Regexp     bool   `json:"regexp"`
		Gibberish  bool   `json:"gibberish"`
		Disposable bool   `json:"disposable"`
		MXRecords  bool   `json:"mx_records"`
		SMTPServer bool   `json:"smtp_server"`
		SMTPCheck  bool   `json:"smtp_check"`
	} `json:"data"`
}

// EmailScanner performs OSINT on an email address using HaveIBeenPwned and Hunter.io.
type EmailScanner struct {
	keys   APIKeys
	client *RetryableHTTPClient
}

// NewEmailScanner constructs an EmailScanner. Keys may be empty — modules that
// require missing keys will return ErrAPIKeyMissing instead of panicking.
func NewEmailScanner(keys APIKeys) *EmailScanner {
	return &EmailScanner{
		keys:   keys,
		client: NewRetryableHTTPClient(),
	}
}

// Profile runs a full email OSINT profile: disposable check, breach lookup,
// and deliverability verification. Missing API keys cause those checks to be
// skipped with a note rather than returning an error.
func (s *EmailScanner) Profile(ctx context.Context, email string) (*EmailProfile, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, fmt.Errorf("email cannot be empty")
	}

	profile := &EmailProfile{
		Email:     email,
		ScannedAt: time.Now(),
	}

	// Fast local check — no API needed
	profile.Disposable = s.IsDisposable(email)

	// HIBP breach check
	if s.keys.HIBP != "" {
		breaches, err := s.CheckBreaches(ctx, email)
		if err != nil {
			// Non-fatal: log and continue
			fmt.Printf("  [!] HIBP check skipped: %v\n", err)
		} else {
			profile.Breaches = breaches
			profile.BreachCount = len(breaches)
		}
	} else {
		fmt.Printf("  [!] HIBP key not configured — breach check skipped\n")
	}

	// Hunter.io deliverability check
	if s.keys.HunterIO != "" {
		result, err := s.VerifyDeliverability(ctx, email)
		if err != nil {
			fmt.Printf("  [!] Hunter.io check skipped: %v\n", err)
		} else {
			profile.Deliverability = result
			// Hunter.io also gives a disposable flag — if either source says disposable, trust it
			if result.Disposable {
				profile.Disposable = true
			}
		}
	} else {
		fmt.Printf("  [!] Hunter.io key not configured — deliverability check skipped\n")
	}

	return profile, nil
}

// CheckBreaches queries the HaveIBeenPwned v3 API for breaches associated with email.
// Requires a valid HIBP API key. Returns ErrAPIKeyMissing if the key is empty.
// Returns ErrNotFound (not an error condition) if the email has no known breaches.
func (s *EmailScanner) CheckBreaches(ctx context.Context, email string) ([]Breach, error) {
	if s.keys.HIBP == "" {
		return nil, ErrAPIKeyMissing
	}

	url := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false", email)
	headers := map[string]string{
		"hibp-api-key": s.keys.HIBP,
	}

	resp, err := s.client.Get(ctx, url, headers)
	if err != nil {
		return nil, fmt.Errorf("HIBP request: %w", err)
	}
	defer resp.Body.Close()

	// 404 = clean email, not an error
	if resp.StatusCode == http.StatusNotFound {
		return []Breach{}, nil
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("%w: HIBP API key invalid or expired", ErrAPIKeyMissing)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HIBP returned HTTP %d", ErrServiceUnavailable, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading HIBP response: %w", err)
	}

	var raw []hibpBreach
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parsing HIBP response: %w", err)
	}

	breaches := make([]Breach, len(raw))
	for i, b := range raw {
		breaches[i] = Breach{
			Name:        b.Name,
			Domain:      b.Domain,
			BreachDate:  b.BreachDate,
			DataClasses: b.DataClasses,
			Description: b.Description,
			PwnCount:    b.PwnCount,
			FetchedAt:   time.Now(),
		}
	}

	return breaches, nil
}

// VerifyDeliverability queries Hunter.io to check if an email address is deliverable.
// Returns ErrAPIKeyMissing if the Hunter.io key is not configured.
func (s *EmailScanner) VerifyDeliverability(ctx context.Context, email string) (*DeliverabilityResult, error) {
	if s.keys.HunterIO == "" {
		return nil, ErrAPIKeyMissing
	}

	url := fmt.Sprintf("https://api.hunter.io/v2/email-verifier?email=%s&api_key=%s", email, s.keys.HunterIO)

	resp, err := s.client.Get(ctx, url, nil)
	if err != nil {
		return nil, fmt.Errorf("Hunter.io request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("%w: Hunter.io API key invalid", ErrAPIKeyMissing)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: Hunter.io returned HTTP %d", ErrServiceUnavailable, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading Hunter.io response: %w", err)
	}

	var hunterResp hunterVerifyResponse
	if err := json.Unmarshal(body, &hunterResp); err != nil {
		return nil, fmt.Errorf("parsing Hunter.io response: %w", err)
	}

	d := hunterResp.Data
	return &DeliverabilityResult{
		Result:     d.Result,
		Score:      d.Score,
		Regexp:     d.Regexp,
		Gibberish:  d.Gibberish,
		Disposable: d.Disposable,
		MXRecords:  d.MXRecords,
		SMTPServer: d.SMTPServer,
		SMTPCheck:  d.SMTPCheck,
	}, nil
}

// IsDisposable checks an email address against the embedded list of known
// disposable email providers. This check is instant and requires no API call.
func (s *EmailScanner) IsDisposable(email string) bool {
	parts := strings.Split(strings.ToLower(email), "@")
	if len(parts) != 2 {
		return false
	}
	return disposableDomains[parts[1]]
}
