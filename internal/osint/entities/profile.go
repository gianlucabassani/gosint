package entities

import "time"

// Profile is the assembled OSINT view of an entity — the Go port of the dict
// returned by browsint's `_build_full_profile`.
type Profile struct {
	Entity     EntitySummary            `json:"entity"`
	DomainInfo *DomainInfoSummary       `json:"domain_info,omitempty"`
	Sources    map[string]SourceProfile `json:"profiles"`
	Contacts   []ContactSummary         `json:"contacts"`
}

type EntitySummary struct {
	ID     uint   `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	Domain string `json:"domain,omitempty"`
}

type DomainInfoSummary struct {
	Registrar        string   `json:"registrar"`
	RegistrationDate string   `json:"registration_date"`
	ExpirationDate   string   `json:"expiration_date"`
	NameServers      []string `json:"name_servers"`
}

// SourceProfile holds one source's data, with the JSON columns decoded back
// into maps for consumers (reports/CLI).
type SourceProfile struct {
	Extracted map[string]any `json:"extracted"`
	Raw       map[string]any `json:"raw"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type ContactSummary struct {
	ContactType string    `json:"contact_type"` // "email" | "phone"
	Value       string    `json:"value"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"created_at"`
}
