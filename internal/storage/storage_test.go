package storage

import (
	"path/filepath"
	"testing"
)

// setupTestDB initializes a fresh SQLite database in a per-test temp dir.
// Initialize uses a package-level singleton, so we reset it (white-box, same
// package) to give every test an isolated database.
func setupTestDB(t *testing.T) *Database {
	t.Helper()
	dbInstance = nil
	dbPath := filepath.Join(t.TempDir(), "gosint_test.db")
	db, err := Initialize(dbPath)
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return db
}

func TestCreateOrUpdateEntity_IsIdempotentByDomain(t *testing.T) {
	db := setupTestDB(t)

	e1, err := db.CreateOrUpdateEntity("example.com", "domain", "example.com")
	if err != nil {
		t.Fatalf("first create: %v", err)
	}
	if e1.ID == 0 {
		t.Fatal("expected a non-zero entity ID")
	}
	if e1.Domain == nil || *e1.Domain != "example.com" {
		t.Fatalf("expected domain example.com, got %v", e1.Domain)
	}

	// Same domain → same row, not a duplicate.
	e2, err := db.CreateOrUpdateEntity("Example Inc", "domain", "example.com")
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if e2.ID != e1.ID {
		t.Fatalf("expected same entity ID %d, got %d", e1.ID, e2.ID)
	}
}

func TestEntityWithoutDomainStoresNull(t *testing.T) {
	db := setupTestDB(t)

	// Two person entities with no domain must both be creatable (NULL, not '').
	p1, err := db.CreateOrUpdateEntity("Alice", "person", "")
	if err != nil {
		t.Fatalf("create Alice: %v", err)
	}
	p2, err := db.CreateOrUpdateEntity("Bob", "person", "")
	if err != nil {
		t.Fatalf("create Bob (would fail if empty domains collide on unique index): %v", err)
	}
	if p1.ID == p2.ID {
		t.Fatal("Alice and Bob collapsed into one entity")
	}
	if p1.Domain != nil || p2.Domain != nil {
		t.Fatal("expected NULL domain for person entities")
	}
}

func TestUpsertDomainInfo(t *testing.T) {
	db := setupTestDB(t)
	e, _ := db.CreateOrUpdateEntity("acme.test", "domain", "acme.test")

	info, err := db.UpsertDomainInfo(e.ID, "Reg A", "2020-01-01", "2030-01-01", []string{"ns1.acme.test", "ns2.acme.test"})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	// Upsert again with a new registrar → same row, updated value.
	info2, err := db.UpsertDomainInfo(e.ID, "Reg B", "2020-01-01", "2031-01-01", nil)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if info2.ID != info.ID {
		t.Fatalf("expected one DomainInfo row, got IDs %d and %d", info.ID, info2.ID)
	}
	if info2.Registrar != "Reg B" || info2.ExpirationDate != "2031-01-01" {
		t.Fatalf("upsert did not update fields: %+v", info2)
	}
}

func TestSaveContactDedup(t *testing.T) {
	db := setupTestDB(t)
	e, _ := db.CreateOrUpdateEntity("dedup.test", "domain", "dedup.test")

	c1, err := db.SaveContact(e.ID, "a@dedup.test", "", "crawl")
	if err != nil {
		t.Fatalf("first contact: %v", err)
	}
	c2, err := db.SaveContact(e.ID, "a@dedup.test", "", "crawl")
	if err != nil {
		t.Fatalf("duplicate contact: %v", err)
	}
	if c1.ID != c2.ID {
		t.Fatalf("expected dedup to return the same contact, got %d and %d", c1.ID, c2.ID)
	}

	// A different phone is a distinct contact.
	c3, err := db.SaveContact(e.ID, "a@dedup.test", "+123", "crawl")
	if err != nil {
		t.Fatalf("distinct contact: %v", err)
	}
	if c3.ID == c1.ID {
		t.Fatal("expected a distinct contact for a different phone")
	}
}

func TestSaveOSINTProfileUpsert(t *testing.T) {
	db := setupTestDB(t)
	e, _ := db.CreateOrUpdateEntity("prof.test", "domain", "prof.test")

	p1, err := db.SaveOSINTProfile(e.ID, "hunter", `{"emails":1}`, `{"count":1}`)
	if err != nil {
		t.Fatalf("first profile: %v", err)
	}
	p2, err := db.SaveOSINTProfile(e.ID, "hunter", `{"emails":2}`, `{"count":2}`)
	if err != nil {
		t.Fatalf("upsert profile: %v", err)
	}
	if p1.ID != p2.ID {
		t.Fatal("expected one profile row per (entity, source)")
	}
	if p2.RawData != `{"emails":2}` {
		t.Fatalf("profile not updated: %q", p2.RawData)
	}
}

func TestGetEntityByDomainPreloads(t *testing.T) {
	db := setupTestDB(t)
	e, _ := db.CreateOrUpdateEntity("full.test", "domain", "full.test")
	db.UpsertDomainInfo(e.ID, "Reg", "2020", "2030", []string{"ns1.full.test"})
	db.SaveContact(e.ID, "c@full.test", "", "crawl")
	db.SaveOSINTProfile(e.ID, "shodan", "{}", "{}")

	got, err := db.GetEntityByDomain("full.test")
	if err != nil {
		t.Fatalf("GetEntityByDomain: %v", err)
	}
	if got.DomainInfo == nil {
		t.Fatal("expected DomainInfo preloaded")
	}
	if len(got.Contacts) != 1 {
		t.Fatalf("expected 1 contact, got %d", len(got.Contacts))
	}
	if len(got.Profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(got.Profiles))
	}
}

func TestDatabaseSizeAndBackup(t *testing.T) {
	db := setupTestDB(t)
	db.CreateOrUpdateEntity("size.test", "domain", "size.test")

	size, err := db.GetDatabaseSize()
	if err != nil {
		t.Fatalf("GetDatabaseSize: %v", err)
	}
	if size <= 0 {
		t.Fatalf("expected positive db size, got %d", size)
	}

	dest := filepath.Join(t.TempDir(), "backup", "gosint_backup.db")
	out, err := db.Backup(dest)
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if out != dest {
		t.Fatalf("expected backup at %s, got %s", dest, out)
	}

	// Backing up onto an existing file must fail rather than clobber.
	if _, err := db.Backup(dest); err == nil {
		t.Fatal("expected error backing up onto an existing file")
	}
}

func TestGetDatabaseStatsIncludesNewTables(t *testing.T) {
	db := setupTestDB(t)
	stats := db.GetDatabaseStats()
	for _, key := range []string{"entities", "domain_info", "osint_profiles", "contacts"} {
		if _, ok := stats[key]; !ok {
			t.Errorf("stats missing key %q", key)
		}
	}
}
