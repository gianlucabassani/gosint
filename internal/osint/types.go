package osint

import (
	"context"
	"time"
)

// ---------------------------------------------------------------------------
// API Key configuration
// ---------------------------------------------------------------------------

// APIKeys holds optional API credentials loaded from the environment.
// All fields are optional — modules degrade gracefully when keys are absent.
type APIKeys struct {
	HIBP     string // HIBP_API_KEY  — HaveIBeenPwned v3
	HunterIO string // HUNTER_API_KEY — Hunter.io email verifier
	Shodan   string // SHODAN_API_KEY — Shodan host lookup
}

// ---------------------------------------------------------------------------
// Email types
// ---------------------------------------------------------------------------

// Breach represents a single data breach from HaveIBeenPwned.
type Breach struct {
	Name        string    `json:"Name"`
	Domain      string    `json:"Domain"`
	BreachDate  string    `json:"BreachDate"`
	DataClasses []string  `json:"DataClasses"`
	Description string    `json:"Description"`
	PwnCount    int       `json:"PwnCount"`
	FetchedAt   time.Time `json:"FetchedAt"`
}

// DeliverabilityResult holds Hunter.io email verification data.
type DeliverabilityResult struct {
	Result     string `json:"result"`     // "deliverable", "undeliverable", "risky", "unknown"
	Score      int    `json:"score"`      // 0–100 confidence score
	Regexp     bool   `json:"regexp"`     // passes format check
	Gibberish  bool   `json:"gibberish"`  // looks auto-generated
	Disposable bool   `json:"disposable"` // known disposable domain
	MXRecords  bool   `json:"mx_records"` // domain has MX records
	SMTPServer bool   `json:"smtp_server"`
	SMTPCheck  bool   `json:"smtp_check"`
}

// EmailProfile is the top-level result of an email OSINT run.
type EmailProfile struct {
	Email          string                `json:"email"`
	Disposable     bool                  `json:"disposable"` // fast local check
	Breaches       []Breach              `json:"breaches"`   // from HIBP
	BreachCount    int                   `json:"breach_count"`
	Deliverability *DeliverabilityResult `json:"deliverability"` // from Hunter.io
	ScannedAt      time.Time             `json:"scanned_at"`
}

// ---------------------------------------------------------------------------
// Social types
// ---------------------------------------------------------------------------

// SocialProfile represents a confirmed or potential social media account.
type SocialProfile struct {
	Username  string    `json:"username"`
	Platform  string    `json:"platform"`
	URL       string    `json:"url"`
	Confirmed bool      `json:"confirmed"` // true = Sherlock returned [+]
	FoundAt   time.Time `json:"found_at"`
}

// SocialResult is the top-level result of a social OSINT run.
type SocialResult struct {
	Username  string          `json:"username"`
	Profiles  []SocialProfile `json:"profiles"`
	ScannedAt time.Time       `json:"scanned_at"`
}

// ---------------------------------------------------------------------------
// Domain enrichment types
// ---------------------------------------------------------------------------

// ShodanInfo holds relevant fields from a Shodan host lookup.
type ShodanInfo struct {
	IP           string   `json:"ip_str"`
	Organization string   `json:"org"`
	ISP          string   `json:"isp"`
	Country      string   `json:"country_name"`
	City         string   `json:"city"`
	Ports        []int    `json:"ports"`
	Tags         []string `json:"tags"`
	Vulns        []string `json:"vulns"`
	LastUpdate   string   `json:"last_update"`
}

// DomainProfile is the top-level result of a domain enrichment run.
type DomainProfile struct {
	Domain       string      `json:"domain"`
	WaybackCount int         `json:"wayback_count"`    // URLs in Internet Archive
	WaybackURLs  []string    `json:"wayback_urls"`     // up to 500 sample URLs
	RobotsTxt    string      `json:"robots_txt"`       // raw robots.txt content
	Shodan       *ShodanInfo `json:"shodan,omitempty"` // nil if no key or no result
	ScannedAt    time.Time   `json:"scanned_at"`
}

// ---------------------------------------------------------------------------
// Service interfaces (enables mock implementations in tests)
// ---------------------------------------------------------------------------

// EmailChecker defines the contract for email OSINT services.
type EmailChecker interface {
	CheckBreaches(ctx context.Context, email string) ([]Breach, error)
	VerifyDeliverability(ctx context.Context, email string) (*DeliverabilityResult, error)
}

// SocialChecker defines the contract for social media enumeration.
type SocialChecker interface {
	FindProfiles(ctx context.Context, username string) ([]SocialProfile, error)
}

// DomainEnricherIface defines the contract for domain enrichment services.
type DomainEnricherIface interface {
	Enrich(ctx context.Context, domain string) (*DomainProfile, error)
}
