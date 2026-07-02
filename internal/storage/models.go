package storage

import (
	"time"
)

// Target represents a scanned domain/IP — the *recon* hub (something we scanned).
// It optionally links to an Entity (the *OSINT* hub — someone/something we profile);
// the two are kept distinct rather than merged (see .agent/proposals/CONSOLIDATION.md).
type Target struct {
	ID             uint    `gorm:"primaryKey"`
	Domain         string  `gorm:"uniqueIndex;not null"`
	Type           string  `gorm:"default:'domain'"` // domain, ip, url
	EntityID       *uint   // optional link to the OSINT Entity this target belongs to
	Entity         *Entity `gorm:"foreignKey:EntityID"`
	CreatedAt      time.Time
	LastScanned    time.Time
	ScanResults    []ScanResult    `gorm:"foreignKey:TargetID"`
	FuzzResults    []FuzzResult    `gorm:"foreignKey:TargetID"`
	Subdomains     []Subdomain     `gorm:"foreignKey:TargetID"`
	Technologies   []Technology    `gorm:"foreignKey:TargetID"`
	EmailProfiles  []EmailProfile  `gorm:"foreignKey:TargetID"`
	SocialProfiles []SocialProfile `gorm:"foreignKey:TargetID"`
}

// Entity is the OSINT hub — a person, company, or domain under investigation.
// Mirrors browsint's `entities` table (see CONSOLIDATION.md). Distinct from Target:
// Target is "something we scanned", Entity is "someone/something we profile".
type Entity struct {
	ID         uint           `gorm:"primaryKey"`
	Type       string         `gorm:"not null"` // person, company, domain
	Name       string         `gorm:"not null"`
	Domain     *string        `gorm:"uniqueIndex"` // optional; pointer so multiple entities can have NULL (SQLite allows dup NULLs, not dup '')
	DomainInfo *DomainInfo    `gorm:"foreignKey:EntityID"`
	Profiles   []OSINTProfile `gorm:"foreignKey:EntityID"`
	Contacts   []Contact      `gorm:"foreignKey:EntityID"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// DomainInfo holds WHOIS-derived registration facts for a domain Entity.
// Mirrors browsint's `domain_info`; one row per entity (UNIQUE(entity_id)).
// Replaces stuffing WHOIS into a ScanResult JSON blob with structured storage.
type DomainInfo struct {
	ID               uint `gorm:"primaryKey"`
	EntityID         uint `gorm:"uniqueIndex;not null"`
	Registrar        string
	RegistrationDate string // kept as string — WHOIS date formats vary wildly
	ExpirationDate   string
	NameServers      string `gorm:"type:json"` // JSON-encoded []string
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// OSINTProfile stores one source's data about an Entity.
// Mirrors browsint's `osint_profiles`; UNIQUE(entity_id, source).
type OSINTProfile struct {
	ID              uint   `gorm:"primaryKey"`
	EntityID        uint   `gorm:"not null;uniqueIndex:idx_entity_source"`
	Source          string `gorm:"not null;uniqueIndex:idx_entity_source"` // e.g. hunter, hibp, shodan, crawl
	RawData         string `gorm:"type:json"`
	ExtractedFields string `gorm:"type:json"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Contact is an email/phone harvested for an Entity.
// Mirrors browsint's `contacts`; UNIQUE(entity_id, email, phone).
type Contact struct {
	ID        uint   `gorm:"primaryKey"`
	EntityID  uint   `gorm:"not null;uniqueIndex:idx_entity_contact"`
	Email     string `gorm:"uniqueIndex:idx_entity_contact"`
	Phone     string `gorm:"uniqueIndex:idx_entity_contact"`
	Source    string `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ScanResult stores reconnaissance data
type ScanResult struct {
	ID          uint   `gorm:"primaryKey"`
	TargetID    uint   `gorm:"not null"`
	ScanMode    string `gorm:"not null"`  // basic, deep, stealth, aggressive
	Type        string `gorm:"not null"`  // dns, whois, subdomain, tech
	Data        string `gorm:"type:json"` // JSON-encoded data
	TotRequests int    `gorm:"default:0"`
	CreatedAt   time.Time
}

// FuzzResult stores fuzzing discoveries
type FuzzResult struct {
	ID         uint   `gorm:"primaryKey"`
	TargetID   uint   `gorm:"not null"`
	FuzzType   string `gorm:"not null"` // directory, vhost, subdomain
	URL        string `gorm:"not null"`
	StatusCode int    `gorm:"default:0"`
	Size       int    `gorm:"default:0"`
	WordUsed   string // The wordlist entry that hit
	CreatedAt  time.Time
}

// Subdomain stores discovered subdomains
type Subdomain struct {
	ID        uint   `gorm:"primaryKey"`
	TargetID  uint   `gorm:"not null"`
	Subdomain string `gorm:"not null"`
	IP        string
	Status    string `gorm:"default:'active'"` // active, dead
	CreatedAt time.Time
}

// Technology tracks detected tech stack
type Technology struct {
	ID        uint   `gorm:"primaryKey"`
	TargetID  uint   `gorm:"not null"`
	Name      string `gorm:"not null"`
	Version   string
	Category  string // server, cms, framework, analytics
	CreatedAt time.Time
}

// EmailProfile stores the result of an email OSINT scan.
type EmailProfile struct {
	ID          uint   `gorm:"primaryKey"`
	TargetID    uint   `gorm:"index;not null"`
	Email       string `gorm:"not null"`
	Disposable  bool
	Deliverable string        // "deliverable", "undeliverable", "risky", "unknown", or ""
	Score       int           // Hunter.io confidence score 0–100
	Breaches    []BreachEntry `gorm:"foreignKey:EmailProfileID"`
	BreachCount int
	CreatedAt   time.Time
}

// BreachEntry stores a single data breach associated with an EmailProfile.
type BreachEntry struct {
	ID             uint `gorm:"primaryKey"`
	EmailProfileID uint `gorm:"index;not null"`
	Name           string
	Domain         string
	BreachDate     string
	DataClasses    string `gorm:"type:json"` // JSON-encoded []string
	PwnCount       int
	CreatedAt      time.Time
}

// SocialProfile stores a single social media account found via Sherlock.
type SocialProfile struct {
	ID        uint   `gorm:"primaryKey"`
	TargetID  uint   `gorm:"index;not null"`
	Username  string `gorm:"not null"`
	Platform  string `gorm:"not null"`
	URL       string
	Confirmed bool
	CreatedAt time.Time
}
