package storage

import (
	"time"
)

// Target represents a scanned domain/IP
type Target struct {
	ID             uint   `gorm:"primaryKey"`
	Domain         string `gorm:"uniqueIndex;not null"`
	Type           string `gorm:"default:'domain'"` // domain, ip, url
	CreatedAt      time.Time
	LastScanned    time.Time
	ScanResults    []ScanResult   `gorm:"foreignKey:TargetID"`
	FuzzResults    []FuzzResult   `gorm:"foreignKey:TargetID"`
	Subdomains     []Subdomain    `gorm:"foreignKey:TargetID"`
	Technologies   []Technology   `gorm:"foreignKey:TargetID"`
	EmailProfiles  []EmailProfile `gorm:"foreignKey:TargetID"`
	SocialProfiles []SocialProfile `gorm:"foreignKey:TargetID"`
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
	ID          uint         `gorm:"primaryKey"`
	TargetID    uint         `gorm:"index;not null"`
	Email       string       `gorm:"not null"`
	Disposable  bool
	Deliverable string        // "deliverable", "undeliverable", "risky", "unknown", or ""
	Score       int           // Hunter.io confidence score 0–100
	Breaches    []BreachEntry `gorm:"foreignKey:EmailProfileID"`
	BreachCount int
	CreatedAt   time.Time
}

// BreachEntry stores a single data breach associated with an EmailProfile.
type BreachEntry struct {
	ID             uint   `gorm:"primaryKey"`
	EmailProfileID uint   `gorm:"index;not null"`
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
