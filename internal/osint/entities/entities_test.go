package entities

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gianlucabassani/gosint/internal/storage"
)

var testDB *storage.Database

// TestMain initializes a single temp database for the package (storage.Initialize
// is a singleton). Individual tests call reset() for isolation.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gosint-entities-test")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	testDB, err = storage.Initialize(filepath.Join(dir, "entities_test.db"))
	if err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func reset(t *testing.T) *Extractor {
	t.Helper()
	if err := testDB.ClearAllTables(); err != nil {
		t.Fatalf("ClearAllTables: %v", err)
	}
	return New(testDB)
}

func TestGetOrCreateEntity_DomainVsPerson(t *testing.T) {
	e := reset(t)

	dom, err := e.GetOrCreateEntity("acme.test", "domain")
	if err != nil {
		t.Fatalf("domain entity: %v", err)
	}
	if dom.Domain == nil || *dom.Domain != "acme.test" {
		t.Fatalf("expected domain stored, got %v", dom.Domain)
	}

	// Idempotent: same identifier → same row.
	dom2, _ := e.GetOrCreateEntity("acme.test", "domain")
	if dom2.ID != dom.ID {
		t.Fatalf("expected same entity, got %d vs %d", dom.ID, dom2.ID)
	}

	person, err := e.GetOrCreateEntity("Alice", "person")
	if err != nil {
		t.Fatalf("person entity: %v", err)
	}
	if person.Domain != nil {
		t.Fatalf("expected NULL domain for person, got %v", *person.Domain)
	}
}

func TestHarvestFromData_Nested(t *testing.T) {
	data := map[string]any{
		"whois": map[string]any{
			"registrar": "Reg",
			"emails":    []any{"admin@acme.test"},
		},
		"page": map[string]any{
			"contact_email": "info@acme.test",
			"body":          "reach us at sales@acme.test or call +1 650-253-0000",
		},
		"nested": []any{
			map[string]any{"note": "backup: ops@acme.test"},
		},
	}

	emails, phones := HarvestFromData(data)

	want := map[string]bool{
		"admin@acme.test": true, "info@acme.test": true,
		"sales@acme.test": true, "ops@acme.test": true,
	}
	if len(emails) != len(want) {
		t.Fatalf("expected %d emails, got %d (%v)", len(want), len(emails), emails)
	}
	for _, em := range emails {
		if !want[em] {
			t.Errorf("unexpected email %q", em)
		}
	}
	if len(phones) != 1 || phones[0] != "+16502530000" {
		t.Fatalf("expected [+16502530000], got %v", phones)
	}
}

func TestIngestPersistsProfileAndContacts(t *testing.T) {
	e := reset(t)

	data := map[string]any{
		"whois": map[string]any{
			"registrar":       "Reg Co",
			"creation_date":   "2010-01-01",
			"expiration_date": "2030-01-01",
			"emails":          []any{"admin@acme.test"},
		},
	}

	profile, err := e.Ingest("acme.test", "domain", "domain", data)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// Source profile persisted with structured fields extracted.
	src, ok := profile.Sources["domain"]
	if !ok {
		t.Fatal("expected a 'domain' source profile")
	}
	if src.Extracted["registrar"] != "Reg Co" {
		t.Errorf("expected extracted registrar 'Reg Co', got %v", src.Extracted["registrar"])
	}
	if src.Raw["whois"] == nil {
		t.Error("expected raw whois data preserved")
	}

	// Contact harvested from the nested whois emails.
	if len(profile.Contacts) != 1 || profile.Contacts[0].Value != "admin@acme.test" {
		t.Fatalf("expected 1 harvested contact admin@acme.test, got %v", profile.Contacts)
	}

	// Re-ingesting the same data must not duplicate the contact (dedup).
	profile2, err := e.Ingest("acme.test", "domain", "domain", data)
	if err != nil {
		t.Fatalf("re-Ingest: %v", err)
	}
	if len(profile2.Contacts) != 1 {
		t.Fatalf("expected contact dedup, got %d contacts", len(profile2.Contacts))
	}
}

func TestBuildFullProfileIncludesDomainInfo(t *testing.T) {
	e := reset(t)

	ent, _ := e.GetOrCreateEntity("dominfo.test", "domain")
	if _, err := testDB.UpsertDomainInfo(ent.ID, "Reg", "2010", "2030", []string{"ns1.dominfo.test"}); err != nil {
		t.Fatalf("UpsertDomainInfo: %v", err)
	}

	profile, err := e.BuildFullProfile(ent.ID)
	if err != nil {
		t.Fatalf("BuildFullProfile: %v", err)
	}
	if profile.DomainInfo == nil {
		t.Fatal("expected DomainInfo in profile")
	}
	if profile.DomainInfo.Registrar != "Reg" || len(profile.DomainInfo.NameServers) != 1 {
		t.Fatalf("unexpected DomainInfo: %+v", profile.DomainInfo)
	}
}

func TestExtractStructuredFields(t *testing.T) {
	domain := ExtractStructuredFields(map[string]any{
		"whois": map[string]any{"registrar": "R", "expires": "2030"},
		"dns":   map[string]any{"A": []any{"1.2.3.4"}},
	}, "domain")
	if domain["registrar"] != "R" {
		t.Errorf("domain registrar: got %v", domain["registrar"])
	}
	if domain["expiration_date"] != "2030" { // falls back to "expires"
		t.Errorf("domain expiration_date fallback: got %v", domain["expiration_date"])
	}
	if domain["dns_records"] == nil {
		t.Error("expected dns_records passthrough")
	}

	email := ExtractStructuredFields(map[string]any{
		"breaches": []any{
			map[string]any{"Name": "SiteA"},
			map[string]any{"Name": "SiteB"},
		},
	}, "email")
	if email["breach_count"] != 2 {
		t.Errorf("breach_count: got %v", email["breach_count"])
	}

	social := ExtractStructuredFields(map[string]any{
		"profiles": map[string]any{
			"github":  map[string]any{"exists": true, "url": "u1"},
			"twitter": map[string]any{"exists": false, "url": "u2"},
		},
	}, "social")
	if social["platform_count"] != 1 {
		t.Errorf("platform_count: expected 1 (only existing), got %v", social["platform_count"])
	}
}
